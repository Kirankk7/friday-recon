"""
JWT analyzer (v1.3 A1) — deterministic STRUCTURAL analysis of a JSON Web Token.

NOT a cracker: no brute force, no secret guessing, no signature verification. It base64url-decodes
the header + payload and flags structural weaknesses a triager cares about — `alg:none`, symmetric/weak
alg (secret-crack / RS->HS confusion surface), attacker-controlled key source (`jku`/`x5u` = SSRF/key-
injection), `kid` injection surface, missing/excessive `exp`, and privilege claims that become tamper
targets once a signature bypass exists. Deterministic string/JSON work, no LLM, no network. The findings
are CANDIDATES — each names the manual confirmation step. Authorized targets only.
"""
import json
import base64

# Sensitive/privilege claim names — the tamper targets once signature verification is bypassable.
_SENSITIVE = ("role", "roles", "is_admin", "isadmin", "admin", "scope", "scopes", "perm",
              "permission", "permissions", "priv", "privilege", "group", "groups", "access",
              "tier", "plan", "level", "authorities", "authority", "superuser")


def _b64d(seg: str) -> bytes:
    seg = seg + "=" * (-len(seg) % 4)          # restore base64url padding
    return base64.urlsafe_b64decode(seg)


def analyze(token: str) -> dict:
    """Decode + structurally analyse a JWT. Returns {success, message, data:{header,payload,findings}}."""
    token = (token or "").strip()
    for pre in ("Bearer ", "bearer ", "Authorization: Bearer ", "JWT "):
        if token.startswith(pre):
            token = token[len(pre):].strip()
    parts = token.split(".")
    if len(parts) < 2:
        return {"success": False, "message": "Not a JWT (need header.payload[.signature]).", "data": {}}
    try:
        header = json.loads(_b64d(parts[0]))
        payload = json.loads(_b64d(parts[1]))
    except Exception as e:
        return {"success": False, "message": f"Can't decode JWT header/payload: {e}", "data": {}}

    findings = []

    def _f(template, sev, ev, repro):
        findings.append({"template": template, "severity": sev, "url": "(observed JWT)", "cve": None,
                         "validated": False, "evidence": ev, "repro": repro})

    alg = str(header.get("alg", "")).lower()

    # ── algorithm ──
    if alg in ("none", ""):
        _f("jwt-alg-none", "critical",
           f"JWT header alg='{header.get('alg')}' — an unsigned/'none' algorithm. If the server accepts it, "
           f"an attacker forges ANY token (full authentication bypass / privilege escalation).",
           ["Take a valid token", "Set header alg to 'none' and strip the signature segment",
            "Tamper the payload (e.g. change sub/role), resend — if accepted the signature isn't verified"])
    elif alg.startswith("hs"):
        _f("jwt-weak-alg", "medium",
           f"JWT signed with symmetric {header.get('alg')} (HMAC) — two classic risks: (a) offline secret "
           f"cracking if the signing key is weak/guessable, and (b) RS256->HS256 key-confusion if the server "
           f"ALSO publishes an RSA public key it will accept as the HMAC secret.",
           ["Test a weak HMAC secret out-of-band (hashcat/jwt_tool — do NOT brute here)",
            "If an RS256 public key is exposed, sign an HS256 token using that pubkey as the HMAC secret (alg-confusion)"])

    # ── attacker-controlled key source: jku / x5u ──
    for k in ("jku", "x5u"):
        if header.get(k):
            _f("jwt-jku-ssrf", "high",
               f"JWT header '{k}'={header.get(k)} points at an external key source. If the server fetches it "
               f"unvalidated, an attacker hosts their own JWKS/cert and forges accepted tokens (key injection) — "
               f"and the fetch itself is an SSRF primitive.",
               [f"Point '{k}' at an attacker-controlled JWKS/cert URL", "Sign the token with the matching attacker key",
                "Server fetches + trusts the attacker key = forged token accepted"])

    # ── kid injection surface ──
    if header.get("kid") is not None:
        _f("jwt-kid-injection", "low",
           f"JWT header 'kid'={header.get('kid')!r} — the key-id is an injection surface: path traversal to a "
           f"known/empty file, or SQLi if 'kid' indexes a key table, can let an attacker control the verification key.",
           ["Try kid path-traversal (e.g. '../../../dev/null' + sign with an empty key) or SQLi in kid",
            "If you control the resolved key, forge a valid signature"])

    # ── expiry ──
    if "exp" not in payload:
        _f("jwt-missing-exp", "medium",
           "JWT has no 'exp' claim — the token never expires; a single leaked token is valid forever.",
           ["Confirm the token is still accepted long after issuance (no server-side expiry)"])
    else:
        try:
            exp, iat = int(payload["exp"]), int(payload.get("iat", 0))
            life = exp - iat if iat else 0
            if life > 31536000:                    # > 1 year
                _f("jwt-long-exp", "low",
                   f"JWT lifetime ~{life // 86400} days (>1 year) — an excessively long-lived token widens the "
                   f"window on any leak.", [f"Note the exp-iat delta ({life}s)"])
        except Exception:
            pass

    # ── privilege claims (tamper targets) ──
    hits = [c for c in payload if str(c).lower() in _SENSITIVE]
    if hits:
        _f("jwt-sensitive-claims", "info",
           f"JWT carries privilege/role claim(s) {hits} in the payload — these are the tamper target for "
           f"privilege escalation IF any signature bypass above holds (alg:none / weak-HS / kid / jku).",
           [f"With a signature bypass, flip {hits} (e.g. role->admin) and resend"])

    tmpls = ", ".join(f["template"] for f in findings) or "no structural issues"
    return {"success": True,
            "message": f"JWT: alg={header.get('alg')}, typ={header.get('typ')}, {len(findings)} finding(s) — {tmpls}.",
            "data": {"header": header, "payload": payload, "findings": findings}}
