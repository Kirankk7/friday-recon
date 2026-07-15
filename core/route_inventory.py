"""Unified Route Inventory — one normalized, deduped route store that every discovery SOURCE
fans into and every oracle (idor_check / auth_matrix / injection) fans out of.

The 2026-07-15 fleet battery proved detection is strong once handed URLs; the bottleneck is SEEING
the surface (hunt_lessons/2026-07-15-fleet-battery.md). The sources already exist but were siloed:
crawl (katana/crawl_site), SPA XHR (spa_crawl), OpenAPI (core/openapi), Burp history (core/burp_ingest),
JS endpoints (core/secrets.find_endpoints), and now HAR. This module unifies them: same route seen by
three sources = one entry with merged params + provenance. Deterministic, no network — pure aggregation.
Authorized targets only (the caller enforces scope).
"""
import re
from urllib.parse import urlsplit, urlunsplit, parse_qsl, urlencode

_ID_SEG = re.compile(r"/(\d+|[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})(/|$)", re.I)


class RouteInventory:
    def __init__(self):
        self._routes = {}   # (METHOD, scheme, netloc, path) -> route dict

    def add(self, url, method="GET", params=None, source="", auth=None, content_type=""):
        try:
            p = urlsplit(url.strip())
        except Exception:
            return self
        if p.scheme not in ("http", "https") or not p.netloc:
            return self
        method = (method or "GET").upper()
        path = p.path.rstrip("/") or "/"
        qp = {k for k, _ in parse_qsl(p.query, keep_blank_values=True)}
        qp |= set(params or [])
        key = (method, p.scheme, p.netloc, path)
        r = self._routes.get(key)
        if r is None:
            self._routes[key] = {
                "method": method, "url": urlunsplit((p.scheme, p.netloc, p.path, "", "")),
                "path": p.path, "params": set(qp),
                "sources": {source} if source else set(),
                "auth": auth, "content_type": content_type,
            }
        else:
            r["params"] |= qp
            if source:
                r["sources"].add(source)
            if auth is not None:
                r["auth"] = auth
            if content_type:
                r["content_type"] = content_type
        return self

    def add_many(self, urls, **kw):
        for u in urls or []:
            self.add(u, **kw)
        return self

    def routes(self):
        return list(self._routes.values())

    def urls(self, params_only=False):
        """Representative URLs for the oracles. A route with params gets a query string (seeded '1')
        so the injection/idor probes have something to mutate."""
        out = []
        for r in self._routes.values():
            u = r["url"]
            if r["params"]:
                u = u + "?" + urlencode({k: "1" for k in sorted(r["params"])})
            elif params_only:
                continue
            out.append(u)
        return list(dict.fromkeys(out))

    def id_bearing(self):
        """URLs whose path carries a numeric/uuid segment — BOLA candidates for idor_check/auth_matrix."""
        return [r["url"] for r in self._routes.values() if _ID_SEG.search(r["path"])]

    def summary(self):
        from collections import Counter
        c = Counter(s for r in self._routes.values() for s in r["sources"])
        return {"total": len(self._routes), "by_source": dict(c)}


def from_har(path):
    """Parse a Chrome/Firefox HAR export (File > network.har) into {url, method, content_type} records.
    One click in DevTools captures every real request the browser made — richer than any crawl."""
    import json
    try:
        with open(path, "r", encoding="utf-8") as f:
            har = json.load(f)
    except Exception as e:
        return []
    out = []
    for e in (har.get("log", {}) or {}).get("entries", []) or []:
        req = e.get("request", {}) or {}
        url = req.get("url", "")
        if not url:
            continue
        ct = ""
        for h in req.get("headers", []) or []:
            if (h.get("name", "") or "").lower() == "content-type":
                ct = h.get("value", ""); break
        out.append({"url": url, "method": req.get("method", "GET"), "content_type": ct})
    return out
