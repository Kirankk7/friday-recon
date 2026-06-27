"""
Phase 40b — SSRF guard (adapted from OpenJarvis).

Blocks fetches to internal/private/reserved networks so a user request can't
make JARVIS reach into the local network (e.g. http://192.168.1.1/admin,
http://169.254.169.254/ cloud metadata, http://localhost:5000 self-loop).

Use for NON-security fetches (news, research, document URLs). Do NOT apply to
the Ultron security agent — scanning your own internal hosts is its purpose.
"""
import ipaddress
import socket
from urllib.parse import urlparse

# Schemes we allow to be fetched at all
_ALLOWED_SCHEMES = {"http", "https"}

# Cloud metadata + obvious internal hostnames blocked outright
_BLOCKED_HOSTNAMES = {
    "localhost", "metadata", "metadata.google.internal",
}


def _is_private_ip(ip_str: str) -> bool:
    try:
        ip = ipaddress.ip_address(ip_str)
    except ValueError:
        return False
    return (
        ip.is_private or ip.is_loopback or ip.is_link_local
        or ip.is_reserved or ip.is_multicast or ip.is_unspecified
    )


def _normalize_host(host: str) -> str:
    """
    Normalize integer / hex / octal encoded IPs to dotted form so the private-IP
    check can't be bypassed. http://2130706433/ , http://0x7f000001/ ,
    http://017700000001/ all == 127.0.0.1. Returns dotted IP if decodable, else
    the original host unchanged.
    """
    h = host.strip()
    try:
        if h.startswith(("0x", "0X")):              # hex: 0x7f000001
            return str(ipaddress.ip_address(int(h, 16)))
        if h.isdigit():                             # decimal int OR octal-with-leading-0
            val = int(h, 8) if h.startswith("0") and len(h) > 1 else int(h)
            return str(ipaddress.ip_address(val))
    except (ValueError, ipaddress.AddressValueError):
        pass
    return host


def is_safe_url(url: str) -> tuple[bool, str]:
    """Return (safe, reason). safe=True only for public http(s) hosts."""
    if not url or not isinstance(url, str):
        return False, "empty url"

    parsed = urlparse(url.strip())

    if parsed.scheme.lower() not in _ALLOWED_SCHEMES:
        return False, f"scheme '{parsed.scheme}' not allowed (http/https only)"

    host = (parsed.hostname or "").lower()
    if not host:
        return False, "no host"

    if host in _BLOCKED_HOSTNAMES:
        return False, f"blocked hostname '{host}'"

    # Normalize int/hex/octal-encoded IPs, then check the literal form
    host = _normalize_host(host)
    if _is_private_ip(host):
        return False, f"private/reserved IP '{host}'"

    # Resolve hostname → reject if ANY resolved address is internal
    # (defends against DNS rebinding to internal ranges)
    try:
        infos = socket.getaddrinfo(host, None)
    except Exception as e:
        return False, f"DNS resolution failed: {e}"

    for info in infos:
        ip_str = info[4][0]
        if _is_private_ip(ip_str):
            return False, f"host '{host}' resolves to internal IP {ip_str}"

    return True, "ok"


def assert_safe_url(url: str) -> None:
    """Raise ValueError if url is not safe to fetch."""
    safe, reason = is_safe_url(url)
    if not safe:
        raise ValueError(f"Blocked unsafe URL: {reason}")


def threat_check(url: str) -> tuple:
    """Reputation pre-check (#8): look the URL/host up in threat feeds before navigating —
    block known-malware destinations. OFF by default (config.URL_GUARD_INTEL) since it adds
    latency and the best domain/URL feeds need keys (DShield covers IPs no-key). Returns
    (safe, reason); fail-open (safe) on any error so it never breaks navigation."""
    try:
        from config import URL_GUARD_INTEL as _on
    except Exception:
        _on = False
    if not _on:
        return True, ""
    try:
        from urllib.parse import urlsplit
        from core import threat_intel
        host = urlsplit(url).hostname or url
        v = threat_intel.lookup(host)
        if (v.get("verdict") or "").lower() == "malicious":
            return False, f"threat-intel flagged {host} as MALICIOUS ({v.get('summary', '')[:80]})"
    except Exception:
        pass
    return True, ""


def safe_get(url: str, max_redirects: int = 5, timeout: int = 15):
    """
    SSRF-safe HTTP GET: validates the URL AND every redirect hop before
    following it (a public host that 302s to 169.254.169.254 is blocked).
    Returns a requests.Response, or raises ValueError on an unsafe hop.
    Use this instead of letting a library follow redirects unchecked.
    """
    import requests
    _ok, _why = threat_check(url)                       # reputation pre-check (opt-in, fail-open)
    if not _ok:
        raise ValueError(_why)
    current = url
    for _ in range(max_redirects + 1):
        assert_safe_url(current)                       # validate before each fetch
        resp = requests.get(current, allow_redirects=False, timeout=timeout,
                            headers={"User-Agent": "JARVIS/1.0"})
        if resp.status_code in (301, 302, 303, 307, 308) and "location" in resp.headers:
            nxt = resp.headers["location"]
            # resolve relative redirects against the current URL
            from urllib.parse import urljoin
            current = urljoin(current, nxt)
            continue
        return resp
    raise ValueError("too many redirects")
