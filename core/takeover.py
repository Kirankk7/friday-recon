"""
Subdomain-takeover detector (v1.3 A2) — deterministic fingerprint match.

For each host: HTTP GET it and match the response body against a table of KNOWN "dangling / unclaimed
service" fingerprints (S3, GitHub Pages, Heroku, Fastly, …). A hit means the DNS still points at a
service resource that no longer exists — an attacker can register/claim it = subdomain takeover.

No cracking, no dependency: `urllib` GET + case-insensitive substring match. The fingerprints are
distinctive service error strings (adapted from the community can-i-take-over-xyz project) — generic
"404 Not Found" strings are deliberately EXCLUDED to keep precision high (Friday's discipline: no
noisy claims). The error body is what carries the fingerprint, so HTTP-error responses are read too.
Authorized targets only.
"""
import ssl
import urllib.request
import urllib.error

# (service, [distinctive fingerprint substrings], short note). Precision over recall — every string
# here is service-specific enough not to false-match a normal page. Generic 404s intentionally omitted.
_FINGERPRINTS = [
    ("AWS/S3",         ["NoSuchBucket", "The specified bucket does not exist"], "S3 bucket"),
    ("GitHub Pages",   ["There isn't a GitHub Pages site here", "For root URLs (like http://example.com/) you must provide an index.html file"], "GitHub Pages"),
    ("Heroku",         ["No such app", "herokucdn.com/error-pages/no-such-app.html"], "Heroku app"),
    ("Fastly",         ["Fastly error: unknown domain"], "Fastly"),
    ("Shopify",        ["Sorry, this shop is currently unavailable"], "Shopify store"),
    ("Zendesk",        ["Help Center Closed"], "Zendesk"),
    ("Bitbucket",      ["Repository not found"], "Bitbucket"),
    ("Ghost",          ["The thing you were looking for is no longer here"], "Ghost blog"),
    ("Pantheon",       ["The gods are wise, but do not know of the site which you seek"], "Pantheon"),
    ("Tumblr",         ["Whatever you were looking for doesn't currently exist at this address"], "Tumblr"),
    ("WordPress.com",  ["Do you want to register"], "WordPress.com"),
    ("Surge.sh",       ["project not found"], "Surge.sh"),
    ("Netlify",        ["Not Found - Request ID"], "Netlify"),
    ("Azure",          ["This web app is stopped", "404 Web Site not found"], "Azure App Service"),
    ("Readme.io",      ["Project doesnt exist... yet!"], "Readme.io"),
    ("Help Scout",     ["No settings were found for this company"], "Help Scout"),
    ("Cargo",          ["If you're moving your domain away from Cargo"], "Cargo"),
    ("Webflow",        ["The page you are looking for doesn't exist or has been moved. Webflow"], "Webflow"),
]


def _fetch(url, timeout=8):
    """(status, body) — reads error bodies too (the takeover fingerprint lives in the 404 page).
    Ignores TLS validity (dangling certs are common on abandoned services)."""
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        r = urllib.request.urlopen(url, timeout=timeout, context=ctx)
        return r.getcode(), r.read(20000).decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        try:
            return e.code, e.read(20000).decode("utf-8", "replace")
        except Exception:
            return e.code, ""
    except Exception:
        return None, None


def check(host, fetch=_fetch) -> dict:
    """One host -> {host, vulnerable, service, fingerprint, status}. `fetch` is injectable for tests."""
    url = host if str(host).startswith("http") else "https://" + str(host)
    status, body = fetch(url)
    if body is None:
        url = "http://" + str(host).split("//")[-1]        # retry plain http
        status, body = fetch(url)
    if not body:
        return {"host": host, "vulnerable": False, "service": None}
    low = body.lower()
    for service, sigs, note in _FINGERPRINTS:
        for s in sigs:
            if s.lower() in low:
                return {"host": host, "vulnerable": True, "service": service,
                        "fingerprint": s, "note": note, "status": status}
    return {"host": host, "vulnerable": False, "service": None}


def scan(hosts, fetch=_fetch) -> dict:
    """Scan a list of hosts. Returns {success, message, data:{findings, checked}}. Each takeover =
    one gate-ready finding (candidate — claim the resource to confirm)."""
    findings, checked = [], 0
    for h in hosts or []:
        h = (h or "").strip()
        if not h:
            continue
        checked += 1
        r = check(h, fetch)
        if r["vulnerable"]:
            findings.append({
                "template": "subdomain-takeover", "severity": "high", "url": h, "cve": None,
                "validated": False,
                "evidence": (f"{h} still resolves to {r['service']} ({r['note']}) but the service returns its "
                             f"'unclaimed resource' fingerprint (\"{r['fingerprint']}\", HTTP {r['status']}) — the "
                             f"DNS points at a {r['service']} resource that no longer exists. An attacker can "
                             f"register/claim it and serve content on {h} = subdomain takeover."),
                "repro": [f"dig/CNAME {h} -> confirm it points at {r['service']}",
                          f"GET {h} -> observe the '{r['fingerprint']}' fingerprint",
                          f"Claim the {r['service']} resource with the dangling name to confirm control"],
            })
    tt = ", ".join(f["url"] for f in findings) or "none"
    return {"success": True,
            "message": f"Subdomain takeover: {len(findings)} candidate(s) across {checked} host(s) — {tt}.",
            "data": {"findings": findings, "checked": checked}}
