"""
F3 — Evidence Object + exporters.

A gate-passed finding becomes ONE canonical Evidence Object (metadata, endpoint, CWE,
preliminary CVSS, request/response, curl repro, steps, impact, remediation). Output
formats — markdown submission, JSON — are just EXPORTERS off that object, so adding a
new format never means a new report generator.

Everything here is deterministic (no LLM): a class -> CWE/CVSS lookup + string assembly.
CVSS scores are PRELIMINARY, tool-suggested — always labelled as such.
"""
import re
import json
import datetime

# ── vulnerability class -> CWE ──
_CWE = [
    ("nosqli",         ("CWE-943", "Improper Neutralization of Data within a NoSQL Query")),
    ("sqli",           ("CWE-89",  "SQL Injection")),
    ("xss",            ("CWE-79",  "Cross-site Scripting")),
    ("idor",           ("CWE-639", "Authorization Bypass Through User-Controlled Key")),
    ("bola",           ("CWE-639", "Authorization Bypass Through User-Controlled Key")),
    ("ssrf",           ("CWE-918", "Server-Side Request Forgery")),
    ("lfi",            ("CWE-22",  "Path Traversal")),
    ("path",           ("CWE-22",  "Path Traversal")),
    ("rce",            ("CWE-78",  "OS Command Injection")),
    ("cmdi",           ("CWE-78",  "OS Command Injection")),
    ("ssti",           ("CWE-1336","Server-Side Template Injection")),
    ("open-redirect",  ("CWE-601", "Open Redirect")),
    ("redirect",       ("CWE-601", "Open Redirect")),
    ("csrf",           ("CWE-352", "Cross-Site Request Forgery")),
    ("xxe",            ("CWE-611", "XML External Entity Reference")),
    ("graphql",        ("CWE-863", "Incorrect Authorization")),
    ("auth",           ("CWE-287", "Improper Authentication")),
]

# ── class -> PRELIMINARY CVSS 3.1 (vector, base score, severity) ──
_CVSS = [
    ("nosqli",        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8, "Critical")),
    ("sqli",          ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8, "Critical")),
    ("rce",           ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8, "Critical")),
    ("cmdi",          ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8, "Critical")),
    ("ssti",          ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8, "Critical")),
    ("ssrf",          ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:L/A:N", 8.6, "High")),
    ("lfi",           ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", 7.5, "High")),
    ("path",          ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", 7.5, "High")),
    ("idor",          ("CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N", 6.5, "Medium")),
    ("bola",          ("CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N", 6.5, "Medium")),
    ("xss",           ("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N", 6.1, "Medium")),
    ("open-redirect", ("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:N/A:N", 6.1, "Medium")),
    ("redirect",      ("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:N/A:N", 6.1, "Medium")),
]

_SEV_FALLBACK = {"critical": 9.1, "high": 7.5, "medium": 5.3, "low": 3.1, "info": 0.0}

_IMPACT = {
    "sqli": "An attacker can read or modify arbitrary database contents — credential theft, data exfiltration, or full DB compromise.",
    "nosqli": "Operator injection lets an attacker bypass authentication or read/modify documents outside their scope.",
    "xss": "Attacker-controlled script runs in a victim's session — session theft, credential capture, or action-on-behalf.",
    "idor": "One user can read (or act on) another user's objects — broken object-level authorization.",
    "bola": "One user can read (or act on) another user's objects — broken object-level authorization.",
    "ssrf": "The server can be coerced into making requests to internal services or cloud metadata endpoints.",
    "lfi": "Arbitrary local files can be read from the server.",
    "rce": "Arbitrary commands run on the server — full host compromise.",
}
_REMEDIATION = {
    "sqli": "Use parameterized queries / prepared statements; never build SQL from untrusted input.",
    "nosqli": "Validate/whitelist input types; reject query operators ($ne, $gt) in user-supplied values.",
    "xss": "Context-aware output encoding + a strict Content-Security-Policy; never reflect raw input.",
    "idor": "Enforce object-level authorization server-side on every request — verify the caller owns the object.",
    "bola": "Enforce object-level authorization server-side on every request — verify the caller owns the object.",
    "ssrf": "Allowlist outbound hosts; block internal ranges + 169.254.169.254; resolve+validate the final URL.",
    "lfi": "Canonicalize and validate paths against an allowlist; never pass user input to file APIs.",
}


def _match(table, template):
    t = (template or "").lower()
    for key, val in table:
        if key in t:
            return val
    return None


def _vuln_class(template: str) -> str:
    t = (template or "").lower()
    for key, _ in _CWE:
        if key in t:
            return key
    return "finding"


def curl_for(finding: dict) -> str:
    url = finding.get("url", "") or ""
    method = (finding.get("method") or "GET").upper()
    body = finding.get("request_body") or ""
    flag = f" -X {method}" if method != "GET" else ""
    body_part = f" --data {json.dumps(body)}" if body else ""
    return f"curl -sk{flag}{body_part} '{url}'"


def build(finding: dict, target: str = "") -> dict:
    """A gate-passed finding -> the canonical Evidence Object."""
    tmpl = finding.get("template", "finding")
    sev = (finding.get("severity") or "info").lower()
    cls = _vuln_class(tmpl)
    cwe = _match(_CWE, tmpl) or ("CWE-Other", "Other")
    cvss = _match(_CVSS, tmpl)
    if cvss:
        cvss = {"vector": cvss[0], "score": cvss[1], "severity": cvss[2], "preliminary": True}
    else:
        cvss = {"vector": "", "score": _SEV_FALLBACK.get(sev, 0.0), "severity": sev.title(), "preliminary": True}
    gate = finding.get("_gate", {}) or {}
    return {
        # Bump when the shape changes (screenshots, replay_id, HTML exporter, …). The object is
        # IMMUTABLE: built once, every exporter reads from it — never edit it in place.
        "schema_version": 1,
        "metadata": {
            "target": target or finding.get("host", ""),
            "template": tmpl,
            "class": cls,
            "severity": sev,
            "tier": gate.get("tier", ""),
            "confidence": gate.get("confidence") or ("reproduced" if finding.get("validated") else "candidate"),
            "generated": datetime.datetime.now().strftime("%Y-%m-%d %H:%M"),
        },
        "endpoint": finding.get("url", ""),
        "cwe": {"id": cwe[0], "name": cwe[1]},
        "cvss": cvss,
        "evidence": finding.get("evidence", ""),
        "request": finding.get("request", "") or f"GET {finding.get('url','')} HTTP/1.1",
        "response": (finding.get("response", "") or "")[:2000],
        "curl": curl_for(finding),
        "steps": finding.get("repro", []) or [],
        "impact": _IMPACT.get(cls, "Impact depends on exploitation; confirm scope with a manual test."),
        "remediation": _REMEDIATION.get(cls, "Apply the vendor fix / input-validation control for this vulnerability class."),
        "notes": finding.get("notes", ""),
    }


# ── exporters ──
def to_json(obj: dict) -> str:
    return json.dumps(obj, indent=2)


def to_markdown(obj: dict) -> str:
    m = obj["metadata"]
    cvss, cwe = obj["cvss"], obj["cwe"]
    steps = "\n".join(f"{i+1}. {s}" for i, s in enumerate(obj["steps"])) or "1. See request/response below."
    prelim = " *(preliminary, tool-suggested)*" if cvss.get("preliminary") else ""
    L = [
        f"# {m['template']} — {m['severity'].title()}",
        "",
        f"**Target:** {m['target']}  ",
        f"**Endpoint:** `{obj['endpoint']}`  ",
        f"**Weakness:** {cwe['id']} — {cwe['name']}  ",
        f"**CVSS 3.1:** {cvss.get('score')} ({cvss.get('severity')}){prelim}  ",
        (f"`{cvss.get('vector')}`  " if cvss.get("vector") else ""),
        f"**Confidence:** {m['confidence']}  ·  **Tier:** {m['tier']}",
        "",
        "## Summary",
        obj["evidence"] or "See evidence below.",
        "",
        "## Steps to reproduce",
        steps,
        "",
        "## Reproduce with curl",
        "```bash", obj["curl"], "```",
        "",
        "## Request",
        "```http", (obj["request"] or "").strip(), "```",
        "",
        "## Response (excerpt)",
        "```http", (obj["response"] or "").strip() or "(not captured)", "```",
        "",
        "## Impact",
        obj["impact"],
        "",
        "## Remediation",
        obj["remediation"],
        "",
        f"*Generated by JARVIS Ultron — Evidence Object. CVSS is preliminary. Authorized targets only.*",
    ]
    return "\n".join(x for x in L if x is not None)


_REQUIRED = ["metadata", "endpoint", "cwe", "cvss", "evidence", "steps", "impact", "remediation", "curl"]


def lint(obj: dict) -> list:
    """Return a list of missing/empty required sections (empty list = submission-ready)."""
    missing = []
    for k in _REQUIRED:
        v = obj.get(k)
        if v in (None, "", [], {}):
            missing.append(k)
    if not obj.get("metadata", {}).get("target"):
        missing.append("metadata.target")
    return missing
