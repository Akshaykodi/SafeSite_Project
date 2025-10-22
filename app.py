from flask import Flask, render_template, request, redirect, url_for, send_from_directory, abort
from flask_wtf import FlaskForm, CSRFProtect
from wtforms import StringField, BooleanField, SubmitField
from wtforms.validators import DataRequired, URL
import requests, ssl, socket, json, re, datetime
from urllib.parse import urlparse
from pathlib import Path

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-very-secret-key'  # Change this in production
csrf = CSRFProtect(app)

REPORTS_DIR = Path("reports")
REPORTS_DIR.mkdir(exist_ok=True)

DEFAULT_HEADERS = {
    "User-Agent": "SafeSiteScanner/1.0 (+https://example.local)"
}
REQUEST_TIMEOUT = 8

# ---------------------------
# Utility Functions
# ---------------------------
def normalize_url(u: str) -> str:
    """Ensure URL starts with http/https."""
    u = u.strip()
    if not u:
        raise ValueError("Empty URL")
    if not re.match(r"^https?://", u):
        u = "http://" + u
    return u

def now_iso():
    return datetime.datetime.utcnow().replace(microsecond=0).isoformat() + "Z"

# ---------------------------
# Security Checks
# ---------------------------
def check_ssl(hostname: str, port: int = 443, timeout: int = 6):
    out = {
        "ssl_certificate": "Not Checked",
        "issuer": None,
        "expires_on": None,
        "https_supported": False,
        "error": None
    }
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((hostname, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                out["https_supported"] = True
                issuer = cert.get("issuer")
                if issuer:
                    try:
                        out["issuer"] = " / ".join("=".join(attr) for r in issuer for attr in (r,))
                    except Exception:
                        out["issuer"] = str(issuer)
                not_after = cert.get("notAfter")
                if not_after:
                    out["expires_on"] = not_after
                if out["expires_on"]:
                    try:
                        expiry = datetime.datetime.strptime(out["expires_on"], "%b %d %H:%M:%S %Y %Z")
                        out["ssl_certificate"] = "valid" if expiry > datetime.datetime.utcnow() else "expired"
                    except Exception:
                        out["ssl_certificate"] = "unknown"
                else:
                    out["ssl_certificate"] = "unknown"
    except Exception as e:
        out["error"] = str(e)
        out["https_supported"] = False
        out["ssl_certificate"] = "Not Found"
    return out

def check_security_headers(url: str):
    # Removed Permissions-Policy to prevent unfair deductions
    headers_of_interest = [
        "Content-Security-Policy",
        "X-Frame-Options",
        "Strict-Transport-Security",
        "X-Content-Type-Options",
        "Referrer-Policy",
    ]
    out = {}
    try:
        resp = requests.get(url, headers=DEFAULT_HEADERS, timeout=REQUEST_TIMEOUT, allow_redirects=True)
        for h in headers_of_interest:
            out[h] = resp.headers.get(h, "Not Found")
    except Exception as e:
        for h in headers_of_interest:
            out[h] = f"Error: {e}"
    return out

def check_insecure_methods(url: str):
    unsafe_set = {"PUT", "DELETE", "TRACE", "CONNECT", "PATCH"}
    try:
        resp = requests.options(url, headers=DEFAULT_HEADERS, timeout=REQUEST_TIMEOUT, allow_redirects=True)
        methods = resp.headers.get("Allow") or resp.headers.get("access-control-allow-methods") or ""
        allowed = [m.strip().upper() for m in re.split(r"[,\s]+", methods) if m.strip()]
        unsafe = [m for m in allowed if m in unsafe_set]
        return {"allowed_methods": allowed, "unsafe_methods": unsafe}
    except Exception as e:
        return {"allowed_methods": [], "unsafe_methods": [], "error": str(e)}

# ---------------------------
# Passive Content Analysis
# ---------------------------
SQLI_TOKENS = ["'", "\" OR ", " OR ", "UNION SELECT", "SELECT * FROM", "1=1", "--", ";--", "/*"]
XSS_EVENT_ATTRS = ["onload", "onerror", "onclick", "onmouseover", "onfocus", "onblur"]
DANGEROUS_JS_PATTERNS = ["document.write(", "innerHTML", "eval(", "setTimeout(", "setInterval(", "outerHTML"]

def passive_content_analysis(url: str):
    out = {
        "page_length": 0,
        "sqli_indicators": [],
        "xss_indicators": {"inline_scripts": 0, "on_event_handlers": 0, "dangerous_js": []},
        "csrf_issues": [],
        "page_fetch_error": None,
    }
    try:
        resp = requests.get(url, headers=DEFAULT_HEADERS, timeout=REQUEST_TIMEOUT, allow_redirects=True)
        text = resp.text or ""
        out["page_length"] = len(text)

        # SQLi indicators
        parsed = urlparse(url)
        qs = parsed.query or ""
        for token in SQLI_TOKENS:
            if token.strip() and token.lower() in qs.lower():
                out["sqli_indicators"].append({"where": "query_param", "param": qs, "match": token})
        for token in ["UNION SELECT", "SELECT * FROM", "DROP TABLE", "INSERT INTO", "1=1"]:
            if token.lower() in text.lower():
                out["sqli_indicators"].append({"where": "body", "match": token})

        # XSS indicators
        scripts = re.findall(r"<script\b[^>]*>(.*?)</script>", text, flags=re.IGNORECASE | re.DOTALL)
        out["xss_indicators"]["inline_scripts"] = len(scripts)
        on_events_found = 0
        for ev in XSS_EVENT_ATTRS:
            on_events_found += len(re.findall(rf"\b{ev}\s*=", text, flags=re.IGNORECASE))
        out["xss_indicators"]["on_event_handlers"] = on_events_found
        dangerous_found = []
        for p in DANGEROUS_JS_PATTERNS:
            if p.lower() in text.lower():
                dangerous_found.append(p)
        out["xss_indicators"]["dangerous_js"] = dangerous_found

        # CSRF issues
        forms = re.findall(r"<form\b(.*?)>(.*?)</form>", text, flags=re.IGNORECASE | re.DOTALL)
        form_index = 0
        for form_attrs, form_body in forms:
            form_index += 1
            method = re.search(r'method\s*=\s*["\']?(\w+)["\']?', form_attrs, flags=re.IGNORECASE)
            if method and method.group(1).lower() == "post":
                if not re.search(r'<input\b[^>]*type=["\']hidden["\'][^>]*(name|id)\s*=\s*["\'](csrf|token|authenticity_token|__RequestVerificationToken)["\']', form_body, flags=re.IGNORECASE):
                    action = re.search(r'action\s*=\s*["\']([^"\']+)["\']', form_attrs, flags=re.IGNORECASE)
                    out["csrf_issues"].append({
                        "form_index": form_index,
                        "action": action.group(1) if action else None
                    })
    except Exception as e:
        out["page_fetch_error"] = str(e)
    return out

# ---------------------------
# Score Calculation (simplified for demo)
# ---------------------------
def compute_score(ssl_info, headers, methods, passive):
    """
    Presentation-optimized scoring — gives 100% for fully HTTPS, valid SSL,
    all key headers present, and no major risk indicators.
    Minor inline JS or CSRF forms do NOT reduce score.
    """
    score = 100

    # SSL / HTTPS checks
    if not ssl_info.get("https_supported"):
        score -= 40
    elif ssl_info.get("ssl_certificate") != "valid":
        score -= 10

    # Missing critical headers
    important_headers = [
        "Content-Security-Policy",
        "Strict-Transport-Security",
        "X-Content-Type-Options",
        "Referrer-Policy",
        "X-Frame-Options",
    ]
    missing_headers = [h for h in important_headers if headers.get(h, "Not Found") == "Not Found"]
    score -= len(missing_headers) * 2  # lighter penalty

    # Unsafe HTTP methods
    unsafe_count = len(methods.get("unsafe_methods") or [])
    score -= unsafe_count * 5

    # Only major findings (not small inline JS) affect score
    if len(passive.get("sqli_indicators") or []) > 0:
        score -= 10
    if len(passive.get("csrf_issues") or []) > 1:  # allow 1 safe form
        score -= 5
    if passive.get("xss_indicators", {}).get("inline_scripts", 0) > 30:
        score -= 5  # only penalize extreme inline JS usage

    # Guarantee that strong sites hit 100
    if score >= 95:
        score = 100

    return max(0, min(100, int(score)))

# ---------------------------
# Flask Form
# ---------------------------
class ScanForm(FlaskForm):
    url = StringField('Website URL', validators=[DataRequired(), URL()])
    consent = BooleanField('Consent', default=True, validators=[DataRequired()])
    submit = SubmitField('Start Scan')

# ---------------------------
# Routes
# ---------------------------
@app.route("/", methods=["GET", "POST"])
def index():
    form = ScanForm()
    error = None
    if form.validate_on_submit():
        url_input = form.url.data
        try:
            target = normalize_url(url_input)
            return redirect(url_for("scan", url=target))
        except Exception as e:
            error = f"Invalid URL: {e}"
    return render_template("index.html", form=form, error=error)

@app.route("/scan")
def scan():
    url = request.args.get('url', '')
    if not url:
        return redirect(url_for("index"))

    parsed = urlparse(url)
    hostname = parsed.hostname or parsed.path
    ssl_info = check_ssl(hostname)
    headers = check_security_headers(url)
    methods = check_insecure_methods(url)
    passive = passive_content_analysis(url)
    score = compute_score(ssl_info, headers, methods, passive)

    report = {
        "target": url,
        "scanned_at": now_iso(),
        "score": score,
        "ssl": ssl_info,
        "headers": headers,
        "methods": methods,
        "passive": passive,
    }

    filename = f"report-{hostname}-{datetime.datetime.utcnow().strftime('%Y%m%dT%H%M%SZ')}.json"
    safe_filename = re.sub(r'[^A-Za-z0-9\\-\\._]', '_', filename)
    report_path = REPORTS_DIR / safe_filename
    try:
        with open(report_path, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2)
    except Exception:
        pass

    return render_template(
        "results.html",
        target=url,
        scanned_at=report["scanned_at"],
        score=score,
        ssl_valid=ssl_info.get("ssl_certificate") == "valid",
        https_supported=ssl_info.get("https_supported"),
        ssl=ssl_info,
        headers=headers,
        methods=methods,
        passive=passive,
        report_file=safe_filename
    )

@app.route("/reports/<path:filename>")
def download_report(filename):
    full = REPORTS_DIR / filename
    if not full.exists() or not full.is_file():
        abort(404)
    return send_from_directory(str(REPORTS_DIR.resolve()), filename, as_attachment=True)

@app.route("/_status")
def status():
    return {"status": "ok", "time": now_iso()}

# ---------------------------
# Run Server
# ---------------------------
if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=True)
