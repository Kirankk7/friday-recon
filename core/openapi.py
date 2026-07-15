"""OpenAPI / Swagger spec ingestion -> concrete route URLs.

Closes the crawl-blind-to-API gap surfaced by the crAPI dogfood (hunt_lessons/2026-07-crapi-dogfood.md):
a passive <a href> crawl can't see XHR-called API routes, but the spec *declares* every one of them.
This module only turns a spec into a list of reachable URLs — no new detection logic. The URLs feed the
EXISTING idor_check / auth_matrix oracles. Deterministic; the only network is the optional discover()/harvest().
Read-only. Authorized targets only (the caller enforces scope).
"""
import json
import re

# Common locations frameworks publish the spec at (Swagger-UI defaults, springdoc, drf-spectacular, etc.)
_SPEC_PATHS = (
    "/openapi.json", "/swagger.json", "/v3/api-docs", "/v2/api-docs",
    "/api-docs", "/api/openapi.json", "/swagger/v1/swagger.json", "/openapi",
)

_PARAM = re.compile(r"\{[^/}]+\}")                       # {vehicleId}, {postId}, ...
_UUID = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", re.I)
_INTID = re.compile(r'"(?:id|[a-z_]*_id|[a-z_]*Id)"\s*:\s*(\d{1,12})')


def discover(base_url, http_get):
    """Try the common spec locations; return (spec_url, spec_dict) for the first that parses as an
    OpenAPI/Swagger doc (has a `paths` object). http_get(url) must return an object with .status_code + .text.
    Returns (None, None) if none found."""
    base = base_url.rstrip("/")
    for p in _SPEC_PATHS:
        u = base + p
        try:
            r = http_get(u)
            if getattr(r, "status_code", 0) != 200:
                continue
            body = (r.text or "").lstrip()
            if not body.startswith("{"):
                continue
            spec = json.loads(body)
            if isinstance(spec, dict) and isinstance(spec.get("paths"), dict) and spec["paths"]:
                return u, spec
        except Exception:
            continue
    return None, None


def routes(spec, methods=("get",)):
    """[(method, path_template)] for each operation whose method is in `methods`.
    OpenAPI 3 and Swagger 2 both key operations under `paths`."""
    out = []
    for path, item in (spec.get("paths") or {}).items():
        if not isinstance(item, dict):
            continue
        for m in item:
            if isinstance(m, str) and m.lower() in methods:
                out.append((m.lower(), path))
    return out


def harvest_ids(base, spec, http_get, headers=None, cap=20):
    """GET every parameter-FREE route as the given principal and pull object ids (uuids + int ids) out of
    the JSON bodies. These are real, owned-by-the-principal ids so that templated routes become *reachable*
    (a '1' placeholder just 404s). Read-only; failures are swallowed per-route."""
    base = base.rstrip("/")
    ids = []
    for _m, path in routes(spec, ("get",)):
        if _PARAM.search(path):
            continue
        try:
            r = http_get(base + path, headers=headers or {})
            if getattr(r, "status_code", 0) != 200:
                continue
            t = r.text or ""
            ids += _UUID.findall(t)
            ids += _INTID.findall(t)
        except Exception:
            continue
        if len(ids) >= cap:
            break
    # dedupe, preserve order
    return list(dict.fromkeys(ids))[:cap]


def to_urls(base, spec, id_pool=None, methods=("get",), cap=80, per_route_ids=5):
    """Concrete URLs from the spec. Param-free routes pass through; templated routes ({id}) are expanded
    once per harvested id (so the owner's real object is in the set -> idor_check can actually reach it).
    Falls back to '1' when nothing was harvested. Deduped + capped."""
    base = base.rstrip("/")
    pool = list(dict.fromkeys(id_pool or [])) or ["1"]
    out, seen = [], set()
    for _m, path in routes(spec, methods):
        if _PARAM.search(path):
            for _id in pool[:per_route_ids]:
                u = base + _PARAM.sub(lambda _mo, _v=_id: str(_v), path)
                if u not in seen:
                    seen.add(u); out.append(u)
        else:
            u = base + path
            if u not in seen:
                seen.add(u); out.append(u)
        if len(out) >= cap:
            break
    return out
