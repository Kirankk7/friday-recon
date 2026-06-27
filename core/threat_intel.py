"""
Phase 66 — threat-intel IOC aggregator.

Feed it an IOC (IP / domain / URL / file hash) and it fans out to reputation
feeds, returning a single aggregated verdict. Local-first stays intact: the
LLM never touches this — it's a direct user-initiated lookup (same tradeoff as
vt_scan). The IOC DOES leave the machine to the public feeds.

Sources:
  - DShield / SANS ISC  : IP reputation. NO KEY. Always on.
  - URLhaus (abuse.ch)  : url/host/hash malware blocklist. Needs free ABUSE_CH_API_KEY.
  - AbuseIPDB           : IP abuse score. Needs free ABUSEIPDB_API_KEY.
  - AlienVault OTX       : ip/domain/url/hash pulses. Needs free OTX_API_KEY.

Every source degrades gracefully: missing key -> "nokey" (skipped, hinted),
network error -> "error" (noted). A source never crashes the aggregate.
"""

import re
import json
import urllib.request
import urllib.parse

from core.throttle import throttle

try:
    from config import ABUSE_CH_API_KEY, ABUSEIPDB_API_KEY, OTX_API_KEY
except Exception:
    ABUSE_CH_API_KEY = ABUSEIPDB_API_KEY = OTX_API_KEY = ""

_UA = "JARVIS-Ultron/1.0"
_HASH_RE = re.compile(r"^[a-fA-F0-9]{32}$|^[a-fA-F0-9]{40}$|^[a-fA-F0-9]{64}$")
_IP_RE = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")


def classify_ioc(ioc: str) -> str:
    """ip | hash | url | domain | unknown."""
    s = (ioc or "").strip()
    if not s:
        return "unknown"
    if s.startswith(("http://", "https://")):
        return "url"
    if _IP_RE.match(s):
        return "ip"
    if _HASH_RE.match(s):
        return "hash"
    if "." in s and " " not in s:
        return "domain"
    return "unknown"


def _get(url, headers=None, data=None, timeout=15):
    req = urllib.request.Request(url, data=data, headers={"User-Agent": _UA, **(headers or {})})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.loads(r.read().decode("utf-8", "replace"))


# ── sources ─────────────────────────────────────────────────────────────────
def _dshield(ip: str) -> dict:
    """SANS ISC IP reputation — no key."""
    try:
        throttle("dshield")
        d = _get(f"https://isc.sans.edu/api/ip/{urllib.parse.quote(ip)}?json").get("ip", {})
        feeds = list((d.get("threatfeeds") or {}).keys())
        count = d.get("count")
        try:
            count = int(count) if count is not None else 0
        except Exception:
            count = 0
        # Real attack reports = malicious. Mere threat-feed presence is too broad to call
        # malicious on its own (e.g. 8.8.8.8 is on 'openresolver') — flag it SUSPICIOUS and
        # name the feeds so a human can tell a Tor exit from benign infra.
        if count > 0:
            status = "malicious"
        elif feeds:
            status = "suspicious"
        else:
            status = "clean"
        bits = []
        if count:
            bits.append(f"{count} reported attacks")
        if feeds:
            bits.append("listed on feeds: " + ", ".join(feeds[:6]))
        if d.get("ascountry"):
            bits.append(f"AS{d.get('as')} {d.get('asname')} ({d.get('ascountry')})")
        return {"source": "DShield/ISC", "status": status,
                "detail": "; ".join(bits) or "no reports"}
    except Exception as e:
        return {"source": "DShield/ISC", "status": "error", "detail": str(e)[:80]}


def _urlhaus(ioc: str, kind: str) -> dict:
    if not ABUSE_CH_API_KEY:
        return {"source": "URLhaus", "status": "nokey",
                "detail": "set ABUSE_CH_API_KEY (free at auth.abuse.ch) for malware url/host/hash lookups"}
    endpoint, field = {
        "url": ("url", "url"), "domain": ("host", "host"),
        "ip": ("host", "host"), "hash": ("payload", "sha256_hash"),
    }.get(kind, (None, None))
    if not endpoint:
        return {"source": "URLhaus", "status": "skip", "detail": f"no URLhaus lookup for {kind}"}
    try:
        throttle("urlhaus")
        data = urllib.parse.urlencode({field: ioc}).encode()
        j = _get(f"https://urlhaus-api.abuse.ch/v1/{endpoint}/",
                 headers={"Auth-Key": ABUSE_CH_API_KEY}, data=data)
        qs = j.get("query_status")
        if qs == "no_results":
            return {"source": "URLhaus", "status": "clean", "detail": "not in URLhaus"}
        if qs == "ok":
            n = len(j.get("urls", []) or []) or 1
            tags = j.get("tags") or (j.get("urls", [{}])[0].get("tags") if j.get("urls") else None)
            return {"source": "URLhaus", "status": "malicious",
                    "detail": f"listed ({n} entr{'y' if n == 1 else 'ies'})" +
                              (f", tags: {', '.join(tags[:5])}" if tags else "")}
        return {"source": "URLhaus", "status": "error", "detail": f"query_status={qs}"}
    except Exception as e:
        return {"source": "URLhaus", "status": "error", "detail": str(e)[:80]}


def _abuseipdb(ip: str) -> dict:
    if not ABUSEIPDB_API_KEY:
        return {"source": "AbuseIPDB", "status": "nokey",
                "detail": "set ABUSEIPDB_API_KEY (free, 1k/day) for IP abuse scores"}
    try:
        throttle("abuseipdb")
        url = "https://api.abuseipdb.com/api/v2/check?" + urllib.parse.urlencode(
            {"ipAddress": ip, "maxAgeInDays": 90})
        d = _get(url, headers={"Key": ABUSEIPDB_API_KEY, "Accept": "application/json"}).get("data", {})
        score = d.get("abuseConfidenceScore", 0)
        st = "malicious" if score >= 50 else ("suspicious" if score >= 10 else "clean")
        return {"source": "AbuseIPDB", "status": st,
                "detail": f"abuse score {score}/100, {d.get('totalReports', 0)} reports"}
    except Exception as e:
        return {"source": "AbuseIPDB", "status": "error", "detail": str(e)[:80]}


def _otx(ioc: str, kind: str) -> dict:
    if not OTX_API_KEY:
        return {"source": "AlienVault OTX", "status": "nokey",
                "detail": "set OTX_API_KEY (free) for threat-pulse lookups"}
    section = {"ip": "IPv4", "domain": "domain", "url": "url", "hash": "file"}.get(kind)
    if not section:
        return {"source": "AlienVault OTX", "status": "skip", "detail": f"no OTX lookup for {kind}"}
    try:
        throttle("otx")
        ind = urllib.parse.quote(ioc, safe="")
        url = f"https://otx.alienvault.com/api/v1/indicators/{section}/{ind}/general"
        d = _get(url, headers={"X-OTX-API-KEY": OTX_API_KEY})
        pulses = (d.get("pulse_info") or {}).get("count", 0)
        return {"source": "AlienVault OTX", "status": "malicious" if pulses else "clean",
                "detail": f"{pulses} threat pulse(s)" if pulses else "no pulses"}
    except Exception as e:
        return {"source": "AlienVault OTX", "status": "error", "detail": str(e)[:80]}


# ── aggregate ───────────────────────────────────────────────────────────────
def lookup(ioc: str) -> dict:
    """Fan out to applicable sources for the IOC type, return aggregated verdict."""
    ioc = (ioc or "").strip()
    kind = classify_ioc(ioc)
    if kind == "unknown":
        return {"ioc": ioc, "kind": kind, "verdict": "unknown",
                "summary": f"Couldn't classify '{ioc}' as IP/domain/URL/hash.", "sources": []}

    sources = []
    if kind == "ip":
        sources += [_dshield(ioc), _abuseipdb(ioc)]
    sources.append(_urlhaus(ioc, kind))
    sources.append(_otx(ioc, kind))

    mal = [s for s in sources if s["status"] == "malicious"]
    susp = [s for s in sources if s["status"] == "suspicious"]
    checked = [s for s in sources if s["status"] in ("malicious", "suspicious", "clean")]
    if mal:
        verdict = "malicious"
    elif susp:
        verdict = "suspicious"
    elif checked:
        verdict = "clean"
    else:
        verdict = "unknown"   # nothing could actually check it (all nokey/error)

    flagged = ", ".join(s["source"] for s in mal + susp)
    summary = {
        "malicious": f"! MALICIOUS — {ioc} flagged by {flagged}.",
        "suspicious": f"! SUSPICIOUS — {ioc} flagged by {flagged}.",
        "clean": f"+ CLEAN — {ioc}: no source flagged it ({len(checked)} checked).",
        "unknown": f"? UNKNOWN — no source could check {ioc} (add API keys; DShield covers IPs no-key).",
    }[verdict]
    return {"ioc": ioc, "kind": kind, "verdict": verdict, "summary": summary, "sources": sources}
