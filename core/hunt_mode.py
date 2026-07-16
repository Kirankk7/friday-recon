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
# owner-scoped surface hints (path segment or GraphQL op name) — these carry other users' data.
# `dashboard` added after hunt #1: GetDashboardDataV3 was the real BOLA candidate and went unranked.
_OWNER_HINT = re.compile(
    r"order|address|invoice|shipment|payment|account|profile|customer|user|wishlist|cart|basket|dashboard|"
    r"reservation|booking|ticket|voucher|coupon|loyalty|return|refund|billing|subscription|receipt|me\b", re.I)
# USER-scoped id keys = a real ownership boundary (swap across accounts = BOLA).
_USER_ID = re.compile(r"party|customer|order|address|invoice|account|\buser|loyalty|payment|receipt|"
                      r"booking|reservation|ticket|subscription|cart|basket|wishlistitem", re.I)
# PUBLIC/global id keys = catalog data anyone can query (NOT an ownership boundary). hunt #1: productId FPs.
_PUBLIC_ID = re.compile(r"product|brand|manufactur|category|\bsku|gtin|article|model|group|store|\bplp|\bpdp", re.I)


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
        _qs = dict(parse_qsl(p.query, keep_blank_values=True))
        for k, v in _qs.items():
            if _IDKEY.search(k) and (_UUID.search(v) or (v.isdigit() and len(v) >= 3)):
                found.append((k, v))
        body = ((req.get("postData", {}) or {}).get("text", "")) or ""
        # GraphQL via GET: operationName + variables live in the URL QUERY STRING (not the body) —
        # e.g. MediaMarkt /api/v1/graphql?operationName=GetAddresses&variables={...}. hunt #1 taught this:
        # 49/51 ops were GET-in-URL and were invisible when we only parsed the body.
        _url_op = _qs.get("operationName", "")
        if "variables" in _qs:
            try:
                found += _id_pairs(json.loads(_qs["variables"]))
            except Exception:
                pass
        is_gql = (path.rstrip("/").endswith("graphql") or bool(_url_op)
                  or ('"query"' in body and ("operationName" in body or "variables" in body)))
        op = _url_op
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
            # user-scoped vs public ID: a partyId/orderId/addressId is a real ownership boundary; a
            # productId/brandId is public catalog data (NOT BOLA). Score on that + enumerability; drop
            # pure-public ops. hunt #1 taught both (productId FPs + the missed partyId dashboard op).
            user_ids = [k for k in idkeys if _USER_ID.search(k)]
            public_ids = [k for k in idkeys if _PUBLIC_ID.search(k)]
            strong_op = bool(re.search(r"dashboard|account|profile|order|address|invoice|payment|loyalty|customer|\buser|receipt", (op or "") + " " + path, re.I))
            enumerable = any(str(v).isdigit() and len(str(v)) >= 6 for _, v in found)
            score = 50
            if user_ids:
                score += 40
            if strong_op:
                score += 20
            if enumerable:
                score += 15   # numeric sequential id = enumerable = higher severity if it confirms
            if public_ids and not user_ids:
                score -= 60   # product/brand/catalog-only = public, not an ownership boundary
            if score <= 0:
                continue      # drop pure-public catalog ops (kills the productId FP class)
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
