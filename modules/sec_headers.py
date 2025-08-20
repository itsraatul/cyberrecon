import requests
from urllib.parse import urlparse
from rich.table import Table
from rich.console import Console
from core.utils import save_json_report

console = Console()

RECOMMENDATIONS = {
    "Content-Security-Policy": "Use a strict CSP (e.g., default-src 'none'; script-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'none').",
    "Strict-Transport-Security": "e.g., max-age=15552000; includeSubDomains; preload (HTTPS only).",
    "X-Content-Type-Options": "Set to 'nosniff'.",
    "X-Frame-Options": "Set to 'DENY' or 'SAMEORIGIN'. Prefer CSP frame-ancestors.",
    "Referrer-Policy": "e.g., no-referrer or strict-origin-when-cross-origin.",
    "Permissions-Policy": "Disable unneeded features, e.g., camera=(), geolocation=().",
    "Cross-Origin-Resource-Policy": "e.g., same-origin (or same-site if required).",
    "Cross-Origin-Opener-Policy": "e.g., same-origin to mitigate XS-Leaks.",
    "Cross-Origin-Embedder-Policy": "e.g., require-corp when applicable.",
    "Cache-Control": "For dynamic pages: no-store, max-age=0, must-revalidate.",
}

def _best_url(target: str) -> str:
    # Accept domain or URL; prefer https then http
    parsed = urlparse(target if "://" in target else f"https://{target}")
    host = parsed.netloc or parsed.path
    https = f"https://{host}"
    http  = f"http://{host}"
    # Try HTTPS first, fallback to HTTP
    for url in (https, http):
        try:
            r = requests.get(url, timeout=6, allow_redirects=True, verify=True)
            if r.status_code < 500:
                return r.url  # final URL after redirects
        except requests.RequestException:
            continue
    return https  # last resort (may still fail in fetch)

def _grade_header(name: str, value: str | None, final_url: str):
    present = value is not None
    details = ""
    severity = "OK" if present else "HIGH"
    if not present:
        return {"header": name, "present": False, "severity": severity, "details": "Missing", "recommendation": RECOMMENDATIONS.get(name,"")}
    v = (value or "").strip().lower()

    # Heuristics per header (light but useful)
    if name == "Content-Security-Policy":
        if "default-src" in v and "'none'" in v:
            severity, details = "OK", "Strict default-src detected"
        elif "default-src" in v:
            severity, details = "MEDIUM", "CSP present but could be stricter"
        else:
            severity, details = "MEDIUM", "CSP lacks default-src"
    elif name == "Strict-Transport-Security":
        if final_url.startswith("https://"):
            if "max-age" in v:
                try:
                    maxage = int([p.split("=")[1] for p in v.split(";") if "max-age" in p][0])
                except Exception:
                    maxage = 0
                if maxage >= 15552000:  # 180 days
                    severity, details = "OK", "HSTS strong"
                else:
                    severity, details = "LOW", "HSTS present but short max-age"
            else:
                severity, details = "MEDIUM", "HSTS missing max-age"
        else:
            severity, details = "MEDIUM", "HSTS irrelevant on HTTP"
    elif name == "X-Content-Type-Options":
        severity, details = ("OK","nosniff set") if "nosniff" in v else ("MEDIUM","Should be 'nosniff'")
    elif name == "X-Frame-Options":
        severity, details = ("OK","Clickjacking protection") if ("deny" in v or "sameorigin" in v) else ("MEDIUM","Use DENY or SAMEORIGIN")
    elif name == "Referrer-Policy":
        good = {"no-referrer","strict-origin-when-cross-origin","same-origin"}
        severity, details = ("OK","Good policy") if any(g in v for g in good) else ("LOW","Consider stricter policy")
    elif name == "Permissions-Policy":
        severity, details = ("OK","Present") if "(" in v and ")" in v else ("LOW","Define explicit allowlists, e.g., camera=()")
    elif name == "Cross-Origin-Resource-Policy":
        severity, details = ("OK","CORP set") if ("same-origin" in v or "same-site" in v) else ("LOW","Consider CORP same-origin/site")
    elif name == "Cross-Origin-Opener-Policy":
        severity, details = ("OK","COOP set") if "same-origin" in v else ("LOW","Consider COOP same-origin")
    elif name == "Cross-Origin-Embedder-Policy":
        severity, details = ("OK","COEP set") if "require-corp" in v else ("LOW","Consider COEP require-corp")
    elif name == "Cache-Control":
        bad = ("no-store" in v or "max-age=0" in v or "no-cache" in v)
        severity, details = ("OK","Not cached") if bad else ("LOW","Consider no-store/must-revalidate for dynamic pages")
    else:
        details = "Checked"

    return {"header": name, "present": True, "severity": severity, "details": details, "recommendation": RECOMMENDATIONS.get(name,"")}

def run(target: str):
    console.print(f"[*] Security Header Analysis for [bold]{target}[/bold]")
    url = _best_url(target)

    try:
        r = requests.get(url, timeout=8, allow_redirects=True)
    except requests.RequestException as e:
        console.print(f"[red][!][/red] Failed to fetch {url}: {e}")
        return

    headers = r.headers or {}
    check_list = [
        "Content-Security-Policy",
        "Strict-Transport-Security",
        "X-Content-Type-Options",
        "X-Frame-Options",
        "Referrer-Policy",
        "Permissions-Policy",
        "Cross-Origin-Resource-Policy",
        "Cross-Origin-Opener-Policy",
        "Cross-Origin-Embedder-Policy",
        "Cache-Control",
    ]

    results = []
    for h in check_list:
        results.append(_grade_header(h, headers.get(h), r.url))

    # Pretty table
    table = Table(title=f"Security Headers — {r.url}")
    table.add_column("Header")
    table.add_column("Present")
    table.add_column("Severity")
    table.add_column("Details")

    sev_rank = {"HIGH":3, "MEDIUM":2, "LOW":1, "OK":0}
    for item in sorted(results, key=lambda x: sev_rank.get(x["severity"],0), reverse=True):
        table.add_row(
            item["header"],
            "Yes" if item["present"] else "No",
            item["severity"],
            item["details"]
        )
    console.print(table)

    # JSON report
    report_payload = {
        "target": target,
        "final_url": r.url,
        "status": r.status_code,
        "headers": {k: v for k, v in headers.items()},
        "analysis": results,
    }
    path = save_json_report(target, "sec_headers", report_payload)
    console.print(f"[green][+][/green] JSON report saved to: {path}")
