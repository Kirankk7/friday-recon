"""
F1 — live intercept proxy capture.

A mitmproxy addon that streams your (authenticated) browsing into the SAME
endpoint / param / auth-tag inventory `burp_ingest` produces — with NO manual Burp
export. It reuses `burp_ingest._build_inventory` + `_tag`, so the schema is identical
by construction. A captured login auto-registers a `session_manager` principal, so the
authz oracle (`idor_check`) can replay as you with zero hand-pasted cookies.

That closes the exact gap that stalled the HotelTonight engagement ("next depth needs
app-traffic capture") — the manual Burp-export + hand-pasted-cookie friction is gone.

    Run the proxy:   python -m core.live_capture --port 8081     (needs: pip install mitmproxy)
             or:     mitmdump -s core/live_capture.py -p 8081
    Then point your browser/system proxy at 127.0.0.1:8081 and browse the target.
    Install the mitmproxy CA once (browse http://mitm.it through the proxy) for HTTPS.
    Ctrl-C stops the proxy and writes the per-host inventory.

Passive capture only — no active scanning (that stays nuclei's job). Authorized targets only.
"""
import os
import re
import sys
import json
import time
import subprocess

# mitmdump loads this file with core/ (not the repo root) on sys.path, so `from core import`
# would fail there. Pin the repo root explicitly. No-op when imported normally.
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from urllib.parse import urlsplit
from core import burp_ingest, session_manager

_CAP_DIR = os.path.join("data", "capture")

# Only capture app traffic — skip the third-party analytics/CDN noise a browser fires.
_SKIP_HOST = re.compile(r"(google|gstatic|googleapis|doubleclick|facebook|fbcdn|analytics|"
                        r"segment|sentry|cloudflareinsights|hotjar|mixpanel|recaptcha)\.", re.I)

# An object-id in the path (/rest/basket/6, /api/v1/orders/1001), a numeric id param
# (?id=42, &user_id=7), or a uuid — the endpoints worth an IDOR/BOLA check.
_ID_RE = re.compile(r"/\d+(?:$|[/?])|[?&]\w*id=\d+|/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-", re.I)


def _host_file(host: str) -> str:
    return os.path.join(_CAP_DIR, host.replace(":", "_") + ".json")


def _raw_request(method: str, path: str, headers: dict, body: str) -> str:
    lines = [f"{method} {path} HTTP/1.1"] + [f"{k}: {v}" for k, v in headers.items()]
    return "\r\n".join(lines) + "\r\n\r\n" + (body or "")


def _raw_response(status, headers: dict, body: str) -> str:
    lines = [f"HTTP/1.1 {status}"] + [f"{k}: {v}" for k, v in headers.items()]
    return "\r\n".join(lines) + "\r\n\r\n" + (body or "")


def build_from_records(records: list) -> dict:
    """records -> the burp_ingest inventory schema (shared, identical by construction)."""
    return burp_ingest._build_inventory(records)


def id_record_urls(records: list) -> list:
    """Full captured URLs (with query) that carry an object id — the IDOR candidates."""
    return sorted({r.get("url", "") for r in records if _ID_RE.search(r.get("url", "") or "")})


def _extract_principal(records: list) -> dict:
    """Pull an auth principal from captured traffic: a session Cookie the browser already
    sends, and/or a Bearer token. Returns {cookie, headers} or {} if nothing auth-ish."""
    cookie, headers = "", {}
    for r in records:
        req = r.get("request") or ""
        m = re.search(r"(?:^|\r?\n)[Aa]uthorization:\s*(Bearer\s+[A-Za-z0-9._-]+)", req)
        if m and "Authorization" not in headers:
            headers["Authorization"] = m.group(1)
        cm = re.search(r"(?:^|\r?\n)[Cc]ookie:\s*([^\r\n]+)", req)
        if cm and not cookie:
            cval = cm.group(1).strip()
            if re.search(r"(sess|sid|token|jwt|auth|security)", cval, re.I):
                cookie = cval
    return {"cookie": cookie, "headers": headers} if (cookie or headers) else {}


def load_records(host: str) -> list:
    try:
        with open(_host_file(host), "r", encoding="utf-8") as f:
            return json.load(f).get("records", [])
    except Exception:
        return []


def load_capture(host: str) -> dict:
    try:
        with open(_host_file(host), "r", encoding="utf-8") as f:
            return json.load(f).get("inventory", {})
    except Exception:
        return {}


def save_capture(host: str, records: list, register: bool = True) -> dict:
    """Merge records into the host's capture file, rebuild the inventory, and (by default)
    auto-register a 'captured' principal from the traffic. Returns the inventory."""
    os.makedirs(_CAP_DIR, exist_ok=True)
    # de-dup on (method, url) — keep the richest (longest response) sample of each.
    seen = {}
    for r in load_records(host) + records:
        key = (r.get("method", "GET"), r.get("url", ""))
        if key not in seen or len(r.get("response", "") or "") > len(seen[key].get("response", "") or ""):
            seen[key] = r
    merged = list(seen.values())
    inv = build_from_records(merged)
    with open(_host_file(host), "w", encoding="utf-8") as f:
        json.dump({"host": host, "updated": time.strftime("%Y-%m-%d %H:%M"),
                   "records": merged, "inventory": inv}, f, indent=2)
    if register:
        p = _extract_principal(merged)
        if p:
            session_manager.set_session("captured", cookie=p.get("cookie", ""),
                                        headers=p.get("headers", {}), role="user",
                                        note=f"auto-captured from {host}")
    return inv


def scan_captured(host: str, owner: str = "captured", attacker: str = "userB") -> dict:
    """Run idor_check across every captured object-id endpoint, owner vs attacker.
    Owner defaults to the auto-captured principal; register the attacker from a 2nd
    account's cookie first ('session set userB cookie ..')."""
    recs = load_records(host)
    urls = id_record_urls(recs)
    if not urls:
        return {"success": True, "data": {"findings": []},
                "message": f"No object-id endpoints captured for {host} — browse some id'd "
                           f"resources through the proxy first."}
    if session_manager.headers_for(owner) is None or session_manager.headers_for(attacker) is None:
        return {"success": False, "data": {},
                "message": f"Need two principals: '{owner}' (auto from capture) and '{attacker}'. "
                           f"Register the attacker: session set {attacker} cookie <2nd-account-cookie>."}
    from agents.ultron.ultron_agent import ultron_agent
    findings = []
    for u in urls[:40]:
        r = ultron_agent.idor_check(u, owner=owner, attacker=attacker)
        findings += (r.get("data", {}) or {}).get("findings", [])
    return {"success": True, "data": {"findings": findings},
            "message": f"Scanned {len(urls)} object-id endpoint(s) from capture: "
                       f"{len(findings)} IDOR/BOLA candidate(s). Confirm with two real accounts."}


class ProxyCapture:
    """mitmproxy addon — buffers flows per host, writes per-host inventory on shutdown."""

    def __init__(self):
        self._buf = {}

    def response(self, flow):
        try:
            req, resp = flow.request, flow.response
            host = req.pretty_host or ""
            if not host or _SKIP_HOST.search(host):
                return
            rec = {
                "url": req.pretty_url,
                "method": req.method,
                "status": resp.status_code if resp else "",
                "request": _raw_request(req.method, req.path, dict(req.headers),
                                        req.get_text(strict=False) or ""),
                "response": _raw_response(resp.status_code if resp else "",
                                          dict(resp.headers) if resp else {},
                                          (resp.get_text(strict=False) or "")[:20000] if resp else ""),
            }
            self._buf.setdefault(host, []).append(rec)
        except Exception:
            pass

    def done(self):
        for host, recs in self._buf.items():
            try:
                save_capture(host, recs)
                print(f"[capture] {host}: {len(recs)} requests -> {_host_file(host)}")
            except Exception as e:
                print(f"[capture] write failed for {host}: {e}")


addons = [ProxyCapture()]


def _run_proxy(port: int) -> int:
    try:
        import mitmproxy  # noqa: F401
    except Exception:
        print("mitmproxy not installed. Run:  pip install mitmproxy")
        return 1
    script = os.path.abspath(__file__)
    print(f"Capture proxy on 127.0.0.1:{port} — set your browser proxy there, then browse the target.")
    print("HTTPS: browse http://mitm.it through the proxy once to install the CA. Ctrl-C to stop + write inventory.")
    return subprocess.call(["mitmdump", "-s", script, "-p", str(port), "-q"])


if __name__ == "__main__":
    import argparse
    ap = argparse.ArgumentParser(description="F1 live-capture proxy (writes data/capture/<host>.json)")
    ap.add_argument("--port", type=int, default=8081)
    raise SystemExit(_run_proxy(ap.parse_args().port))
