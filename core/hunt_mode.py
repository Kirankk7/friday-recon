"""Hunt Mode — OFFLINE analysis of a browser HAR into ranked authorization-test candidates.

FRIDAY's compliant play for mature programs that forbid automated scanning + sit behind bot-protection
(Cloudflare): the hunter's own browser captures real authenticated traffic (a HAR), and FRIDAY reasons over
it OFFLINE — NO network, NO fuzzing, NO automation. The browser is the crawler; FRIDAY is the analyst.

Turns a HAR into: JWT analysis, an object-ID map, GraphQL operations, and a ranked BOLA/IDOR candidate list
with a suggested single-request manual test for each. The hunter runs the one verifying request by hand.
Analyzing your OWN traffic — nothing a program can object to. Authorized targets only.
"""
import json
import re
from urllib.parse import urlsplit, parse_qsl

_JWT = re.compile(r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]*")  # sig may be empty (alg:none)
_UUID = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", re.I)
# an "id-ish" JSON/param key: orderId, addressId, customer_id, invoiceNumber, shipmentRef, cartId...
_IDKEY = re.compile(r"(?:^|[_.])((?:[a-z][a-z0-9]*?)?(?:id|uuid|number|reference|ref|token|key|hash))$", re.I)
# owner-scoped surface hints (path segment or GraphQL op name) — these carry other users' data
_OWNER_HINT = re.compile(
    r"order|address|invoice|shipment|payment|account|profile|customer|user|wishlist|cart|basket|"
    r"reservation|booking|ticket|voucher|coupon|loyalty|return|refund|billing|subscription|me\b", re.I)


def _load(har_or_path):
    if isinstance(har_or_path, dict):
        return har_or_path
    with open(har_or_path, "r", encoding="utf-8") as f:
        return json.load(f)


def _header(headers, name):
    for h in headers or []:
        if (h.get("name", "") or "").lower() == name.lower():
            return h.get("value", "")
    return ""


def _id_pairs(obj, prefix=""):
    """Recurse a parsed JSON structure, yielding (key, value) where the key looks like an object id."""
    out = []
    if isinstance(obj, dict):
        for k, v in obj.items():
            if isinstance(v, (dict, list)):
                out += _id_pairs(v, k)
            elif isinstance(v, (str, int)) and _IDKEY.search(str(k)):
                sval = str(v)
                if _UUID.search(sval) or (sval.isdigit() and len(sval) >= 3) or len(sval) >= 8:
                    out.append((k, sval))
    elif isinstance(obj, list):
        for it in obj[:20]:
            out += _id_pairs(it, prefix)
    return out


def analyze(har_or_path, cap=400):
    """Parse a HAR -> {jwts, objects, graphql_ops, candidates}. Deterministic, offline.
    candidates = owner-scoped, id-bearing endpoints/operations ranked as BOLA/IDOR test targets."""
    try:
        har = _load(har_or_path)
    except Exception as e:
        return {"success": False, "message": f"HAR load failed: {str(e)[:80]}", "data": {}}

    entries = (har.get("log", {}) or {}).get("entries", []) or []
    jwts, objects, gql_ops, cand = set(), {}, [], []
    seen_ep = set()

    for e in entries[:cap]:
        req = e.get("request", {}) or {}
        url = req.get("url", "")
        if not url:
            continue
        method = (req.get("method", "GET") or "GET").upper()
        p = urlsplit(url)
        host, path = p.netloc, p.path
        # JWTs from Authorization / cookies
        auth = _header(req.get("headers"), "authorization")
        for m in _JWT.findall(auth + " " + _header(req.get("headers"), "cookie")):
            jwts.add(m)

        # id-ish values: query params (REST) + request body (REST/GraphQL)
        found = []
        for k, v in parse_qsl(p.query, keep_blank_values=True):
            if _IDKEY.search(k) and (_UUID.search(v) or (v.isdigit() and len(v) >= 3)):
                found.append((k, v))
        body = ((req.get("postData", {}) or {}).get("text", "")) or ""
        is_gql = path.rstrip("/").endswith("graphql") or ('"query"' in body and ("operationName" in body or "variables" in body))
        op = ""
        if body:
            try:
                parsed = json.loads(body)
                cand_objs = parsed if isinstance(parsed, list) else [parsed]
                for pobj in cand_objs:
                    if isinstance(pobj, dict):
                        op = op or pobj.get("operationName", "") or ""
                        found += _id_pairs(pobj.get("variables", pobj))
            except Exception:
                pass
        if is_gql and op:
            gql_ops.append(op)

        label = f"{op} (GraphQL)" if is_gql and op else f"{method} {path}"
        # object map
        for k, v in found:
            objects.setdefault(k, set()).add(v)

        # candidate ranking: owner-scoped hint + carries an id + not already listed
        hint_src = (op or "") + " " + path
        if found and _OWNER_HINT.search(hint_src):
            key = (label, tuple(sorted({k for k, _ in found})))
            if key in seen_ep:
                continue
            seen_ep.add(key)
            idkeys = sorted({k for k, _ in found})
            sample = {k: v for k, v in found}
            score = 90 if (_OWNER_HINT.search(op or path) and any("id" in k.lower() or "uuid" in k.lower() for k in idkeys)) else 70
            cand.append({
                "label": label, "url": f"{host}{path}", "method": method,
                "is_graphql": bool(is_gql and op), "operation": op,
                "id_keys": idkeys, "sample_ids": sample, "score": score,
                "suggested_test": (
                    f"As account B, replay this {'GraphQL op ' + op if is_gql and op else method + ' ' + path} "
                    f"with account A's {idkeys[0]} value. If B receives A's data (and anon is denied) = BOLA/IDOR. "
                    f"One request, your own two accounts only."),
            })

    cand.sort(key=lambda c: (-c["score"], c["label"]))
    return {"success": True,
            "message": (f"Hunt Mode: {len(entries)} req analyzed -> {len(cand)} owner-scoped candidate(s), "
                        f"{len(jwts)} JWT(s), {len(gql_ops)} GraphQL op(s). Offline, no requests sent."),
            "data": {"jwts": sorted(jwts), "objects": {k: sorted(v) for k, v in objects.items()},
                     "graphql_ops": sorted(set(gql_ops)), "candidates": cand,
                     "entry_count": len(entries)}}
