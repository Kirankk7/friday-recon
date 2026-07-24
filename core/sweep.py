"""Coverage Sweep — turn captured traffic (HAR / Burp export) into the mandatory per-hunt class matrix.

THE EARNED RULE (hunt_lessons/HUNT_TRACKER.md #5): every hunt runs ALL attack classes, not the 1-2 the
operator is drawn to. Six straight hunts tunnel-visioned on BOLA because BOLA is what gets ranked; the one
confirmed finding of that stretch (a class-5 SSRF) surfaced ONLY when the operator forced a wider look.
That SOP has been applied by hand four times. This module is that checklist as an artifact.

For each class it answers exactly one question: **does the captured traffic expose surface for it?**
 - TESTABLE  -> which endpoints/params, and HOW verification would work (in methodology terms)
 - N/A       -> the reason no surface exists (so "tested-or-N/A" is provable, not remembered)

It deliberately stops short of emitting a runnable request: naming the class, the endpoint and the approach
is the co-pilot's job; deciding exactly what to send is the operator's, and that decision is where the scope
and legal risk actually sits. See docs/PRODUCT_BOUNDARIES.md ("the sweep's fence").

Analyst, not scanner: pure parsing of traffic the hunter ALREADY captured in their own browser. No requests
are sent, no payloads fired, nothing fuzzed — so it stays compliant on the mature/WAF'd programs that forbid
automated scanning, which is exactly where the scanner-shaped parts of the engine cannot go. Offline and
deterministic: same capture in, same matrix out.
"""
import json
import os
import re
import xml.etree.ElementTree as ET
import base64
from urllib.parse import urlsplit, parse_qsl

from core.hunt_mode import _IDKEY, _OWNER_HINT, _USER_ID, _PUBLIC_ID, _UUID

# ---------------------------------------------------------------- signal vocabulary
# Each regex = "this name/value suggests surface for class X". Hunt-earned entries are cited.
# SSRF keys = the SERVER-FETCH vocabulary only. Redirect-ish words (next/return/dest) live in the
# open-redirect micro-class, not here. A strong key still needs a non-trivial value: `send_image=0`
# is a telemetry flag, not a fetch sink (a real false positive found while dogfooding this on a capture).
_URLISH_KEY = re.compile(r"url|uri|endpoint|callback|webhook|src|link|feed|import|fetch|proxy|"
                         r"host|domain|image|avatar|document|remote|source|wsdl|xmlrpc", re.I)
_URLISH_VAL = re.compile(r"^(https?|ftp|file|gopher|dict)://", re.I)
# Third-party telemetry/support SaaS. Never in a program's scope, and their beacon params (idsite,
# urlref, _ref...) mimic real sinks. Excluded from the whole sweep so every class stays signal.
_THIRD_PARTY = re.compile(
    r"(^|\.)(google-analytics|googletagmanager|doubleclick|google\.com|gstatic|googleapis|"
    r"matomo|piwik|segment|mixpanel|amplitude|hotjar|fullstory|optimizely|"
    r"sentry\.io|datadoghq|newrelic|bugsnag|rollbar|"
    r"intercom|zendesk|zopim|drift|crisp|freshchat|"
    r"facebook|fbcdn|twitter|linkedin|tiktok|pendo\.io|cloudflareinsights)\.", re.I)
# Telemetry is often SELF-HOSTED on the target's own domain (matomo.php, sentry /envelope/), so the
# host list alone misses it — that beacon traffic then fakes SSRF/param surface. Match the path too.
_TELEMETRY_PATH = re.compile(r"/(matomo|piwik|ga|gtm|analytics|beacon|telemetry|rum)\.(php|js)$|"
                             r"/envelope/?$|/csp-report|/collect$|/batch/?$|"
                             # Segment's ingest API (identify/track/page/group/alias/batch). Routed through
                             # a FIRST-PARTY cname (t.<target>.com) so neither the host nor the file-name
                             # rules above catch it - its `traits.*` payload then fakes ~100 path/SSTI targets.
                             r"^/v1/[imtpgab]$", re.I)
_SEARCH_KEY = re.compile(r"search|query|\bq$|filter|sort|order_?by|where|term|keyword|lookup|find|"
                         r"select|field|column|group_?by|limit|offset", re.I)
_ADMIN_PATH = re.compile(r"admin|manage|internal|backoffice|console|staff|operator|sudo|impersonat|"
                         r"role|permission|privile|grant|owner|member", re.I)
_AUTHN_PATH = re.compile(r"login|logout|signin|signup|register|auth|oauth|token|session|password|"
                         r"reset|forgot|verify|confirm|otp|code|mfa|2fa|sso|saml", re.I)
_MONEY_KEY = re.compile(r"price|amount|total|cost|discount|percent|quantity|qty|balance|credit|"
                        r"currency|fee|tax|coupon|promo|voucher|status|state|plan|tier|expire", re.I)
_PRIV_FIELD = re.compile(r"role|is_?admin|admin|is_?staff|permission|scope|verified|approved|owner|"
                         r"tenant|account_?id|user_?id|active|enabled|level|plan|type", re.I)
# Path/LFI keys, matched as WHOLE words (delimiters or camelCase), never as substrings: bare `name`
# swallowed operationName/appName/firstName, `log` swallowed login, `load` swallowed upload/payload.
# Precision beats recall for a checklist - a class reporting 107 junk targets trains you to skip it.
# `page` is excluded on purpose: on JSON APIs it is pagination (`per_page`, `pageSize`) far more often
# than an LFI sink, and file/path/template/include already cover the real ones. `src`/`target` belong to
# the SSRF class, which owns URL-valued params.
_FILE_KEY = re.compile(r"(?:^|[_.\-]|(?<=[a-z]))(file|filename|filepath|path|dir|directory|folder|"
                       r"template|include|attachment|document)(?:$|[_.\-]|(?=[A-Z0-9]))", re.I)
_SECRET_VAL = re.compile(r"(?:api[_-]?key|secret|passwd|password|token|bearer|aws_|private[_-]?key|"
                         r"client[_-]?secret)[\"']?\s*[:=]\s*[\"']?[A-Za-z0-9_\-\.]{12,}", re.I)
_STACKTRACE = re.compile(r"Traceback \(most recent|Fatal error:|Warning: |Exception in thread|"
                         r"\.java:\d+\)|stack trace|SQLSTATE|ORA-\d{5}|at [\w.$]+\([\w]+\.java", re.I)
_JWT = re.compile(r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]*")
_WRITE = ("POST", "PUT", "PATCH", "DELETE")


# ---------------------------------------------------------------- normalizer (the missing piece)
# hunt_mode parses HAR, burp_ingest parses Burp XML, and neither emits the shape a sweep needs. Four
# throwaway parsers got written mid-hunt because of that. One shape, both formats, once.
def _rec(method, url, req_headers, body, status, resp_headers, resp_body):
    p = urlsplit(url)
    q = dict(parse_qsl(p.query, keep_blank_values=True))
    op = q.get("operationName", "")
    if not op and body:
        try:
            b = json.loads(body)
            for o in (b if isinstance(b, list) else [b]):
                if isinstance(o, dict) and o.get("operationName"):
                    op = o["operationName"]
                    break
        except Exception:
            pass
    return {
        "method": (method or "GET").upper(), "url": url, "host": p.netloc, "path": p.path,
        "query": q, "body": body or "", "status": str(status or ""),
        "req_headers": {k.lower(): v for k, v in (req_headers or {}).items()},
        "resp_headers": {k.lower(): v for k, v in (resp_headers or {}).items()},
        "resp_body": resp_body or "",
        "gql_op": op,
        "is_gql": bool(op) or p.path.rstrip("/").endswith("graphql"),
    }


def _from_har(path_or_dict) -> list:
    har = path_or_dict if isinstance(path_or_dict, dict) else json.load(
        open(path_or_dict, "r", encoding="utf-8"))
    out = []
    for e in (har.get("log", {}) or {}).get("entries", []) or []:
        req, resp = e.get("request", {}) or {}, e.get("response", {}) or {}
        out.append(_rec(
            req.get("method"), req.get("url", ""),
            {h.get("name", ""): h.get("value", "") for h in req.get("headers", []) or []},
            (req.get("postData", {}) or {}).get("text", ""),
            resp.get("status"),
            {h.get("name", ""): h.get("value", "") for h in resp.get("headers", []) or []},
            (resp.get("content", {}) or {}).get("text", "")))
    return [r for r in out if r["url"]]


def _raw_headers(raw: str) -> tuple:
    """Split a raw HTTP message into ({headers}, body)."""
    sep = "\r\n\r\n" if "\r\n\r\n" in raw else "\n\n"
    head, _, body = raw.partition(sep)
    hdrs = {}
    for line in head.splitlines()[1:]:
        k, _, v = line.partition(":")
        if v:
            hdrs[k.strip()] = v.strip()
    return hdrs, body


def _from_burp(path: str) -> list:
    root = ET.parse(path).getroot()
    out = []
    for it in root.findall(".//item"):
        url = (it.findtext("url") or "").strip()
        if not url:
            continue

        def _dec(node):
            if node is None:
                return ""
            t = node.text or ""
            if node.get("base64") == "true":
                try:
                    return base64.b64decode(t).decode("utf-8", "replace")
                except Exception:
                    return ""
            return t
        rq, rs = _dec(it.find("request")), _dec(it.find("response"))
        qh, qb = _raw_headers(rq)
        sh, sb = _raw_headers(rs)
        out.append(_rec(it.findtext("method"), url, qh, qb, it.findtext("status"), sh, sb))
    return out


def _records(src) -> list:
    """HAR (path or dict) or Burp XML path -> one normalized record list. Auto-detected by content."""
    if isinstance(src, dict):
        return _from_har(src)
    path = os.path.expanduser(str(src))
    if not os.path.exists(path):
        raise FileNotFoundError(path)
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        head = f.read(400).lstrip()
    return _from_burp(path) if head.startswith("<") else _from_har(path)


# ---------------------------------------------------------------- helpers
def _params(r: dict) -> dict:
    """Every attacker-controlled name->value on a request: query + form body + JSON body (flat)."""
    out = dict(r["query"])
    b = r["body"]
    if b:
        if b.lstrip().startswith(("{", "[")):
            try:
                parsed = json.loads(b)
                for o in (parsed if isinstance(parsed, list) else [parsed]):
                    if isinstance(o, dict):
                        for k, v in _flat(o).items():
                            out[k] = v
            except Exception:
                pass
        elif "=" in b:
            out.update(dict(parse_qsl(b, keep_blank_values=True)))
    return out


def _flat(obj, pre="") -> dict:
    out = {}
    if isinstance(obj, dict):
        for k, v in obj.items():
            key = f"{pre}.{k}" if pre else k
            if isinstance(v, (dict, list)):
                out.update(_flat(v, key))
            else:
                out[key] = str(v)
    elif isinstance(obj, list):
        for v in obj[:10]:
            out.update(_flat(v, pre))
    return out


def _path_ids(path: str) -> list:
    """`/3/drive/3585113/files/6` -> [('drive','3585113'), ('files','6')].

    REST puts the ownership boundary in the PATH (`/collection/{id}`), not the query — the preceding
    segment names the object type. Query/body-only extraction reported "no BOLA surface" on captures
    whose entire hunt WAS path-id swapping (`/drive/{id}/files/{id}`, `/accounts/{id}/conversations/{uuid}`
    shapes). Public catalog collections are dropped, same as hunt_mode.
    """
    segs = [s for s in path.split("/") if s]
    out = []
    for i, s in enumerate(segs[1:], start=1):
        if not (_UUID.fullmatch(s) or (s.isdigit() and len(s) >= 2)):
            continue
        coll = segs[i - 1]
        if not coll.isalpha() and not re.fullmatch(r"[a-z_\-]+", coll, re.I):
            continue          # a version segment like `/3/` names nothing
        if _PUBLIC_ID.search(coll):
            continue          # /products/123, /categories/5 = public catalog, not a boundary
        out.append((coll, s))
    return out


def _label(r: dict) -> str:
    return f"{r['gql_op']} (GraphQL)" if r["is_gql"] and r["gql_op"] else f"{r['method']} {r['path']}"


def _hit(targets, test, signal):
    """Dedup (a capture replays the same endpoint many times) then report. Count = unique targets."""
    uniq, seen = [], set()
    for t in targets:
        key = json.dumps(t, sort_keys=True, default=str)
        if key not in seen:
            seen.add(key)
            uniq.append(t)
    if not uniq:
        return _na(signal)
    return {"status": "TESTABLE", "targets": uniq[:8], "count": len(uniq),
            "test": test, "signal": signal}


def _na(reason):
    return {"status": "N/A", "targets": [], "count": 0, "test": "", "signal": reason}


# ---------------------------------------------------------------- the 10 classes
def _c1_bola(recs, ctx):
    """Owner-scoped endpoint carrying an object id = an ownership boundary to cross."""
    t, seen = [], set()
    for r in recs:
        # query/body ids still need the owner-hint gate (hunt #1: productId-style false positives).
        # Path ids are already filtered by collection name, so they stand on their own.
        ids = [(k, v) for k, v in _params(r).items() if _IDKEY.search(k.split(".")[-1])]
        if not _OWNER_HINT.search((r["gql_op"] or "") + " " + r["path"]):
            ids = []
        ids += [(f"path:{c}", v) for c, v in _path_ids(r["path"])]
        if not ids:
            continue
        key = (_label(r), tuple(sorted({k for k, _ in ids})))
        if key in seen:
            continue
        seen.add(key)
        user_ids = [k for k, _ in ids if _USER_ID.search(k) or _OWNER_HINT.search(k)]
        t.append({"where": _label(r),
                  "ids": sorted({k for k, _ in ids})[:5],
                  "sample": {k: v for k, v in ids[:3]},
                  "user_scoped": bool(user_ids)})
    t.sort(key=lambda x: (not x["user_scoped"], x["where"]))
    return _hit(t, "As account B, replay with account A's id value. B gets A's data (anon denied) = BOLA.",
                "owner-scoped endpoint carrying an object id") if t else \
        _na("no owner-scoped endpoint carries an object id in this capture")


def _c2_bfla(recs, ctx):
    """Function-level: privileged path, or a state-changing method on a shared resource."""
    t = [{"where": _label(r), "why": "admin/role-ish path"} for r in recs
         if _ADMIN_PATH.search(r["path"] + " " + (r["gql_op"] or ""))]
    t += [{"where": _label(r), "why": f"{r['method']} write"} for r in recs
          if r["method"] in _WRITE and _OWNER_HINT.search(r["path"] + " " + (r["gql_op"] or ""))]
    return _hit(t, "Replay as the LOWEST-privilege principal. Accepted = BFLA/vertical priv-esc.",
                "privileged or state-changing operation present") if t else \
        _na("no privileged path or state-changing operation in this capture")


def _c3_sqli(recs, ctx):
    t = [{"where": _label(r), "params": sorted({k for k in _params(r) if _SEARCH_KEY.search(k)})[:5]}
         for r in recs if any(_SEARCH_KEY.search(k) for k in _params(r))]
    return _hit(t, "Send `'` then a time-based payload; compare status/body/latency vs a clean control.",
                "search/filter/sort parameter reaches a data store") if t else \
        _na("no search/filter/sort parameter in this capture")


def _c4_xss(recs, ctx):
    """Reflection = a param value echoed back. Stored = text written now, rendered to someone later."""
    t = []
    for r in recs:
        body = r["resp_body"]
        ctype = r["resp_headers"].get("content-type", "")
        if not body:
            continue
        for k, v in _params(r).items():
            if len(str(v)) >= 6 and str(v) in body:
                t.append({"where": _label(r), "param": k,
                          "kind": "reflected" if "html" in ctype or "<" in body[:200] else "echoed-in-json"})
                break
    t += [{"where": _label(r), "param": k, "kind": "stored-candidate"}
          for r in recs if r["method"] in _WRITE
          for k, v in list(_params(r).items())[:40]
          if isinstance(v, str) and len(v) >= 3 and not _IDKEY.search(k.split(".")[-1])][:20]
    return _hit(t, "Probe with a benign tag (<u>) first: reflected raw = injectable, stripped/encoded = safe. "
                   "Stored fields need a SECOND account to view the render (cross-user = qualifying).",
                "user input reaches a response body or a stored field") if t else \
        _na("no parameter reflected in a response and no text-bearing write in this capture")


def _c5_ssrf(recs, ctx):
    """The class the operator kept missing — a param the SERVER dereferences."""
    t = [{"where": _label(r), "param": k, "value": str(v)[:60]}
         for r in recs for k, v in _params(r).items()
         if _URLISH_VAL.match(str(v).strip())
         or (_URLISH_KEY.search(k.split(".")[-1]) and len(str(v)) >= 4 and not str(v).isdigit())]
    return _hit(t, "Point it at an OOB listener. Callback from a SERVER ip (not yours) = SSRF. Then chase "
                   "IMPACT (reflection/internal reach) — blind-only is non-qualifying on most programs.",
                "parameter carries a URL the server may dereference") if t else \
        _na("no URL-bearing parameter in this capture")


def _c6_massassign(recs, ctx):
    t = [{"where": _label(r), "fields": sorted({k for k in _params(r) if _PRIV_FIELD.search(k)})[:5]}
         for r in recs if r["method"] in _WRITE and r["body"].lstrip().startswith(("{", "["))]
    t = [x for x in t if x["fields"]]
    return _hit(t, "Add a privileged field (role/owner/tenant/verified) to the JSON body; re-read the object "
                   "to see if it stuck. NOTE: dead if the API uses persisted queries with a fixed schema.",
                "JSON write echoes privilege-shaped fields") if t else \
        _na("no JSON write carrying privilege-shaped fields in this capture")


def _c7_bizlogic(recs, ctx):
    t = [{"where": _label(r), "params": sorted({k for k in _params(r) if _MONEY_KEY.search(k)})[:5]}
         for r in recs if any(_MONEY_KEY.search(k) for k in _params(r))]
    return _hit(t, "Tamper value/state (negative, zero, >100%, skipped step). Only file if a BOUNDARY is "
                   "crossed — self-owned tampering with no impact is noise.",
                "price/quantity/state parameter is client-supplied") if t else \
        _na("no money/quantity/state parameter in this capture")


def _c8_disclosure(recs, ctx):
    t = []
    for r in recs:
        b = r["resp_body"]
        if not b:
            continue
        if _SECRET_VAL.search(b):
            t.append({"where": _label(r), "why": "secret-shaped value in response"})
        elif _STACKTRACE.search(b):
            t.append({"where": _label(r), "why": "stack trace / verbose error"})
        elif r["path"].endswith((".js", ".map")):
            t.append({"where": _label(r), "why": "JS bundle / sourcemap (grep for keys + hidden routes)"})
    return _hit(t, "Verify the secret is LIVE and in-scope before filing; disclosure without impact is "
                   "non-qualifying nearly everywhere.",
                "response exposes secrets, traces, or source") if t else \
        _na("no secret-shaped value, trace, or JS bundle in this capture")


def _c9_auth(recs, ctx):
    t = [{"where": _label(r), "why": "auth-flow endpoint"} for r in recs if _AUTHN_PATH.search(r["path"])]
    t += [{"where": _label(r), "why": "credential/token in URL query"} for r in recs
          if any(re.search(r"token|auth|key|session|code", k, re.I) for k in r["query"])]
    return _hit(t, "Map the flow end-to-end, then attack the WEAKEST link: token entropy/ownership, OTP "
                   "destination tampering, step-skipping, and reuse across accounts.",
                "authentication/session flow is present") if t else \
        _na("no auth/session endpoint in this capture")


def _c10_inject(recs, ctx):
    # a path-ish key with a boolean/numeric value is a flag, not a traversal sink (`is_hosted_page=0`)
    t = [{"where": _label(r), "param": k} for r in recs for k, v in _params(r).items()
         if _FILE_KEY.search(k.split(".")[-1])
         and str(v).strip().lower() not in ("", "0", "1", "true", "false", "null", "none")
         and not str(v).isdigit()]
    t += [{"where": _label(r), "param": "multipart filename"} for r in recs
          if "multipart/form-data" in r["req_headers"].get("content-type", "")]
    t += [{"where": _label(r), "param": "XML body (XXE)"} for r in recs
          if "xml" in r["req_headers"].get("content-type", "")]
    return _hit(t, "Traversal (../, encoded, double-encoded) on path-ish params and the upload filename; "
                   "XXE on any XML body. A path/directory error that MOVES with your input = steering.",
                "file/path/template parameter or file+XML body present") if t else \
        _na("no file/path parameter, upload, or XML body in this capture")


# ---------------------------------------------------------------- micro-classes (Phase 2)
def _m_jwt(recs, ctx):
    t = [{"token": j[:28] + "..."} for j in ctx["jwts"]]
    return _hit(t, "Run `jwt <token>`: alg:none, weak-HS secret, kid/jku injection, exp/claims. "
                   "Managed IdPs (Auth0/Cognito) with RS256-only JWKS = forgery is dead; don't burn time.",
                "JWT in use") if t else _na("no JWT in this capture")


def _m_cors(recs, ctx):
    t = [{"where": _label(r), "acao": r["resp_headers"].get("access-control-allow-origin", ""),
          "creds": r["resp_headers"].get("access-control-allow-credentials", "")}
         for r in recs if r["resp_headers"].get("access-control-allow-origin")]
    return _hit(t, "Replay with an attacker Origin. Reflected ACAO + allow-credentials = cross-origin read.",
                "CORS headers present") if t else _na("no CORS headers in this capture")


def _m_csrf(recs, ctx):
    if ctx["auth"] == "bearer":
        return _na("Bearer-header auth — not ambient, so classic CSRF does not apply")
    t = [{"where": _label(r)} for r in recs if r["method"] in _WRITE
         and r["req_headers"].get("cookie")
         and not any(re.search(r"csrf|xsrf", k, re.I) for k in list(r["req_headers"]) + list(_params(r)))]
    return _hit(t, "Cookie-authed write with no CSRF token — verify SameSite before filing (Lax kills most).",
                "cookie-authed state change without a CSRF token") if t else \
        _na("state-changing requests carry a CSRF token (or none are cookie-authed)")


def _m_graphql(recs, ctx):
    ops = sorted({r["gql_op"] for r in recs if r["is_gql"] and r["gql_op"]})
    if not ops:
        return _na("no GraphQL operation in this capture")
    persisted = any("persistedQuery" in r["body"] or "sha256Hash" in r["url"] for r in recs)
    return _hit([{"operation": o} for o in ops],
                ("Persisted queries in use: the hash pins the schema, so field-injection/mass-assignment is "
                 "dead — replay by REUSING the hash and swapping variables." if persisted
                 else "Try introspection, then alias/batch abuse and field-level authz."),
                f"{len(ops)} GraphQL operation(s), persisted={persisted}")


def _m_openredirect(recs, ctx):
    t = [{"where": _label(r), "param": k} for r in recs for k in _params(r)
         if re.search(r"redirect|return|next|continue|dest|goto|callback|url$", k.split(".")[-1], re.I)]
    return _hit(t, "Point at an external host; a 30x Location to it = open redirect (often only pays as a "
                   "chain — check the program's non-qualifying list first).",
                "redirect-shaped parameter present") if t else _na("no redirect parameter in this capture")


def _m_upload(recs, ctx):
    t = [{"where": _label(r)} for r in recs
         if "multipart/form-data" in r["req_headers"].get("content-type", "")]
    return _hit(t, "Check extension/type enforcement, whether the stored path is attacker-influenced, and "
                   "whether served files get Content-Disposition: attachment (that kills upload-XSS).",
                "file upload present") if t else _na("no file upload in this capture")


_CLASSES = [
    ("1. BOLA / IDOR", _c1_bola), ("2. BFLA / priv-esc", _c2_bfla), ("3. SQLi / NoSQLi", _c3_sqli),
    ("4. XSS (refl+stored)", _c4_xss), ("5. SSRF / XSPA", _c5_ssrf), ("6. Mass assignment", _c6_massassign),
    ("7. Business logic", _c7_bizlogic), ("8. Secrets / disclosure", _c8_disclosure),
    ("9. Auth / session", _c9_auth), ("10. cmd/SSTI/XXE/path", _c10_inject),
]
_MICRO = [
    ("JWT", _m_jwt), ("CORS", _m_cors), ("CSRF", _m_csrf), ("GraphQL abuse", _m_graphql),
    ("Open redirect", _m_openredirect), ("File upload", _m_upload),
]


def _context(recs) -> dict:
    """Target model (sweep Phase 0): auth mechanism, hosts, API shape, JWTs, WAF fingerprint."""
    jwts, auth = set(), "none"
    for r in recs:
        a = r["req_headers"].get("authorization", "")
        jwts.update(_JWT.findall(a + " " + r["req_headers"].get("cookie", "")))
        if a.lower().startswith("bearer"):
            auth = "bearer"
        elif a.lower().startswith("basic"):
            auth = "basic" if auth == "none" else auth
        elif r["req_headers"].get("cookie") and auth == "none":
            auth = "cookie"
    servers = {r["resp_headers"].get("server", "") for r in recs} - {""}
    return {"hosts": sorted({r["host"] for r in recs if r["host"]}), "auth": auth,
            "jwts": sorted(jwts), "servers": sorted(servers),
            "api": "graphql" if any(r["is_gql"] for r in recs) else "rest",
            "writes": sorted({r["method"] for r in recs if r["method"] in _WRITE})}


def ingest(src) -> dict:
    """Any capture (HAR path/dict or Burp XML path) -> one inventory, written to the target profile.

    The last reason to reach for a scratch parser mid-hunt: `hunt_mode` reads HAR, `burp_ingest` reads
    Burp XML, and neither answers "what is this target, and what did I capture?" in one call. Four
    throwaway parsers got written during real hunts because of that gap, and none of what they learned
    reached the engine. This is the one entry point: format auto-detected, hosts/endpoints/params/ids
    and the auth mechanism extracted, profile updated. Offline; sends nothing.
    """
    try:
        recs = _records(src)
    except FileNotFoundError:
        return {"success": False, "message": "I couldn't find that capture file, boss.", "data": {}}
    except Exception as e:
        return {"success": False, "message": f"That capture didn't parse: {str(e)[:80]}", "data": {}}
    if not recs:
        return {"success": False, "message": "No HTTP requests in that capture.", "data": {}}

    total = len(recs)
    recs = [r for r in recs
            if not _THIRD_PARTY.search(r["host"]) and not _TELEMETRY_PATH.search(r["path"])]
    if not recs:
        return {"success": False, "message": f"All {total} request(s) were third-party telemetry.", "data": {}}

    ctx = _context(recs)
    endpoints, params, ids, gql = set(), set(), {}, set()
    for r in recs:
        endpoints.add(f"{r['method']} {r['host']}{r['path']}")
        params.update(_params(r).keys())
        for coll, val in _path_ids(r["path"]):
            ids.setdefault(f"path:{coll}", set()).add(val)
        for k, v in _params(r).items():
            if _IDKEY.search(k.split(".")[-1]):
                ids.setdefault(k, set()).add(str(v)[:60])
        if r["is_gql"] and r["gql_op"]:
            gql.add(r["gql_op"])

    data = {"hosts": ctx["hosts"], "auth": ctx["auth"], "api": ctx["api"],
            "endpoints": sorted(endpoints), "params": sorted(params),
            "object_ids": {k: sorted(v)[:10] for k, v in sorted(ids.items())},
            "graphql_ops": sorted(gql), "request_count": len(recs),
            "third_party_excluded": total - len(recs)}
    try:
        from core import target_profiles as _tp
        for host in ctx["hosts"][:5]:
            own = [e.split(" ", 1)[1] for e in endpoints if f" {host}" in e]
            _tp.record_endpoints(host, own[:200])
            _tp.record_scan(host, "ingest",
                            f"{len(own)} endpoint(s), {len(data['params'])} param(s), "
                            f"{len(data['object_ids'])} id key(s), auth={ctx['auth']}, api={ctx['api']}")
    except Exception:
        pass

    return {"success": True,
            "message": (f"Ingested {len(recs)} request(s): {len(endpoints)} endpoint(s) across "
                        f"{len(ctx['hosts'])} host(s), {len(params)} param(s), {len(ids)} object-id key(s)"
                        + (f", {len(gql)} GraphQL op(s)" if gql else "")
                        + f". auth={ctx['auth']} api={ctx['api']}"
                        + (f" ({data['third_party_excluded']} telemetry request(s) excluded)"
                           if data["third_party_excluded"] else "")
                        + ". Profile updated; run `sweep` on the same capture for the class matrix."),
            "data": data}


def sweep(src, micro: bool = True) -> dict:
    """Capture (HAR path/dict or Burp XML path) -> the coverage matrix. Offline; sends nothing."""
    try:
        recs = _records(src)
    except FileNotFoundError:
        return {"success": False, "message": "I couldn't find that capture file, boss.", "data": {}}
    except Exception as e:
        return {"success": False, "message": f"That capture didn't parse: {str(e)[:80]}", "data": {}}
    if not recs:
        return {"success": False, "message": "No HTTP requests in that capture.", "data": {}}

    total = len(recs)
    recs = [r for r in recs
            if not _THIRD_PARTY.search(r["host"]) and not _TELEMETRY_PATH.search(r["path"])]
    dropped = total - len(recs)
    if not recs:
        return {"success": False,
                "message": f"All {total} request(s) went to third-party telemetry — no target traffic.",
                "data": {}}

    ctx = _context(recs)
    classes = {name: fn(recs, ctx) for name, fn in _CLASSES}
    micros = {name: fn(recs, ctx) for name, fn in _MICRO} if micro else {}

    testable = [n for n, v in classes.items() if v["status"] == "TESTABLE"]
    rows = [f"  {'[TEST]' if v['status'] == 'TESTABLE' else '[ N/A]'} {n:<24} "
            f"{(str(v['count']) + ' target(s)') if v['status'] == 'TESTABLE' else v['signal']}"
            for n, v in classes.items()]
    if micros:
        rows.append("  --- micro-classes ---")
        rows += [f"  {'[TEST]' if v['status'] == 'TESTABLE' else '[ N/A]'} {n:<24} "
                 f"{(str(v['count']) + ' target(s)') if v['status'] == 'TESTABLE' else v['signal']}"
                 for n, v in micros.items()]

    msg = (f"Coverage sweep: {len(recs)} request(s) across {len(ctx['hosts'])} host(s) | "
           f"auth={ctx['auth']} api={ctx['api']}"
           + (f" | {dropped} third-party telemetry request(s) excluded\n" if dropped else "\n")
           + f"{len(testable)}/{len(classes)} classes have surface - the rest are N/A with a reason.\n"
           + "\n".join(rows) +
           "\n  Offline analysis, nothing sent. Each [TEST] is a lead — you choose and send the check.")
    return {"success": True, "message": msg,
            "data": {"context": ctx, "classes": classes, "micro": micros,
                     "testable": testable, "request_count": len(recs),
                     "third_party_excluded": dropped}}
