"""
Request mutator (Tier-1 B2) — turn a real request into authz-test variants.

Pure transformation, no network. The "money-bug" engine: take a working request and
systematically mutate the security-relevant parts (object ids, ownership fields, role
flags, mass-assignment) so the replay layer can fire them as another principal and see
which ones leak. Pairs with session_manager (B1) to drive IDOR / BOLA / privilege bugs.
"""
import re
import json as _json
from urllib.parse import urlsplit, urlunsplit, parse_qsl, urlencode

_ID_FIELDS = ("id", "user_id", "userid", "uid", "account_id", "accountid", "owner_id",
              "ownerid", "tenant_id", "tenantid", "order_id", "orderid", "invoice_id",
              "customer_id", "profile_id", "doc_id", "file_id")
_ROLE_FIELDS = ("role", "is_admin", "isadmin", "admin", "is_staff", "superuser",
                "privileged", "is_superuser")


def _is_id(k: str) -> bool:
    k = (k or "").lower()
    return k in _ID_FIELDS or k.endswith("id")


def _neighbours(v) -> list:
    """A numeric id -> a few neighbour ids to try; non-numeric -> none (needs a real other id)."""
    if re.fullmatch(r"\d+", str(v)):
        n = int(v)
        return [str(x) for x in {n - 1, n + 1, 1, 0, n + 100} if x >= 0 and x != n]
    return []


def mutate_url(url: str) -> list:
    """Variants that swap an id in the QUERY or the PATH (IDOR / BOLA)."""
    out, parts = [], urlsplit(url)
    qs = parse_qsl(parts.query, keep_blank_values=True)
    for i, (k, v) in enumerate(qs):
        if _is_id(k):
            for nv in _neighbours(v):
                q = qs.copy(); q[i] = (k, nv)
                out.append({"label": f"query {k}={v}->{nv}",
                            "url": urlunsplit((parts.scheme, parts.netloc, parts.path, urlencode(q), "")),
                            "method": "GET", "body": None,
                            "why": f"swap object id in query param '{k}'"})
    segs = [s for s in parts.path.split("/") if s]
    if segs and re.fullmatch(r"\d+", segs[-1]):
        for nv in _neighbours(segs[-1]):
            np = "/" + "/".join(segs[:-1] + [nv])
            out.append({"label": f"path .../{segs[-1]} -> /{nv}",
                        "url": urlunsplit((parts.scheme, parts.netloc, np, parts.query, "")),
                        "method": "GET", "body": None,
                        "why": "swap object id in last path segment"})
    return out


def mutate_body(url: str, method: str, body: str, ctype: str = "") -> list:
    """JSON-body variants: drop an ownership id, swap an id, toggle a role flag, mass-assign admin."""
    out = []
    is_json = "json" in (ctype or "").lower() or (body or "").strip().startswith("{")
    if not is_json:
        return out
    try:
        obj = _json.loads(body)
    except Exception:
        return out
    if not isinstance(obj, dict):
        return out
    for k in list(obj):
        if _is_id(k):
            m = dict(obj); m.pop(k)
            out.append({"label": f"drop {k}", "url": url, "method": method,
                        "body": _json.dumps(m), "why": f"remove ownership field '{k}'"})
            for nv in _neighbours(obj[k]):
                m2 = dict(obj); m2[k] = int(nv) if str(nv).isdigit() else nv
                out.append({"label": f"{k}={obj[k]}->{nv}", "url": url, "method": method,
                            "body": _json.dumps(m2), "why": f"swap object id field '{k}'"})
    for k in list(obj):
        if k.lower() in _ROLE_FIELDS:
            nv = (not obj[k]) if isinstance(obj[k], bool) else "admin"
            m = dict(obj); m[k] = nv
            out.append({"label": f"toggle {k}={obj[k]}->{nv}", "url": url, "method": method,
                        "body": _json.dumps(m), "why": f"escalate via role field '{k}'"})
    for inj in ("isAdmin", "is_admin", "role", "admin"):
        if inj not in obj:
            m = dict(obj); m[inj] = "admin" if inj == "role" else True
            out.append({"label": f"mass-assign {inj}", "url": url, "method": method,
                        "body": _json.dumps(m), "why": f"mass-assignment: inject '{inj}'"})
    return out


def mutate(req: dict) -> list:
    """req = {url, method?, body?, ctype?} -> all authz-test variants (url + body)."""
    url = req.get("url", "")
    method = req.get("method", "GET")
    out = mutate_url(url)
    if req.get("body"):
        out += mutate_body(url, method, req["body"], req.get("ctype", ""))
    return out
