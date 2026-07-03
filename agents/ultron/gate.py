"""
Ultron — validation gate (Phase B extraction, move-only).

The 7-question quality gate that kills weak/noise findings before they reach a report,
lifted verbatim out of the ultron_agent god-class. Stateless free function: the agent
passes the program's out-of-scope types (from data/roe.json) in, so this module never
imports back into the agent (no cycle).

Adapted from shuvonsec/claude-bug-bounty (Phase 60).
"""

# Never-submit blacklist: template-id fragments that are noise / informational
# and get auto-closed as N/A on bug-bounty platforms. Findings matching these
# are dropped from the report regardless of severity.
NEVER_SUBMIT = (
    "ssl", "tls-version", "tech-detect", "tech-stack", "fingerprint",
    "missing-header", "security-header", "http-missing", "x-frame",
    "version-disclosure", "version-detect", "waf-detect", "wafw00f",
    "favicon", "robots-txt", "sitemap", "default-page", "dns-",
    "dmarc", "spf-", "cookie-without", "cors-misconfig-detect",
    "metatag", "openapi", "swagger-api", "weak-cipher",
)
# severity -> bug-bounty payout/priority tier (HackerOne-style)
PAYOUT_TIER = {
    "critical": "P1 (Critical)", "high": "P2 (High)", "medium": "P3 (Medium)",
    "low": "P4 (Low)", "info": "P5 (Informational)",
}


# Triage weights — a deterministic expected-value proxy for "work the best bug first".
# Base by severity, scaled by how sure we are (confidence), + a bonus when a public
# exploit exists (turns a report into a demonstrable compromise). No CVSS/LLM needed.
_TRIAGE_BASE = {"critical": 90, "high": 70, "medium": 45, "low": 20, "info": 5}
_TRIAGE_CONF = {"reproduced": 1.0, "supported": 0.85, "candidate": 0.6, "weak": 0.3}


def triage(severity: str, confidence: str, has_exploit: bool = False) -> int:
    """Deterministic triage priority 0-100: severity base x confidence, + exploit bonus.
    Ranks reportable findings so the hunter works the highest-value bug first."""
    base = _TRIAGE_BASE.get((severity or "").lower(), 5)
    score = base * _TRIAGE_CONF.get(confidence, 0.3)
    if has_exploit:
        score += 8
    return max(0, min(100, round(score)))


def validate_finding(f: dict, exploits_map: dict, oos_types: list = None) -> dict:
    """
    7-question quality gate. Returns {report, score, tier, reasons, drop}.
    Kills weak/noise findings before they reach the report.
    """
    oos_types = oos_types or []
    tmpl = (f.get("template") or "").lower()
    sev = (f.get("severity") or "info").lower()
    url = f.get("url") or ""
    cve = f.get("cve") or ""

    # hard blacklist -> never submit
    if any(bad in tmpl for bad in NEVER_SUBMIT):
        return {"report": False, "score": 0, "tier": PAYOUT_TIER.get(sev, "P5"),
                "reasons": [], "drop": "informational/noise class (never-submit list)"}

    # program-specific out-of-scope types (from a pasted policy via setup_scope -> roe.json)
    _blob = (tmpl + " " + (f.get("evidence") or "")).lower()
    for _t in oos_types:
        _tag = _t.replace("-", "").replace("_", "")
        if _t and (_t in _blob or _tag in _blob.replace("-", "").replace("_", "")):
            return {"report": False, "score": 0, "tier": PAYOUT_TIER.get(sev, "P5"),
                    "reasons": [], "drop": f"out-of-scope for this program ({_t})"}

    reasons, score = [], 0
    # Q1 — meaningful severity (info-only alone is not worth a report)
    if sev in ("critical", "high", "medium", "low"):
        score += 1; reasons.append("has actionable severity")
    # Q2 — concrete location
    if url:
        score += 1; reasons.append("has a concrete URL/location")
    # Q3 — confirmed reachable (re-probe in validate stage)
    if f.get("validated") is True:
        score += 1; reasons.append("confirmed live on re-probe")
    # Q4 — exploitability (CVE with a known PoC/exploit)
    if cve and exploits_map.get(cve):
        score += 1; reasons.append("known public exploit/PoC exists")
    elif cve:
        score += 1; reasons.append("maps to a tracked CVE")
    # Q5 — real impact (not purely informational template)
    if sev in ("critical", "high", "medium"):
        score += 1; reasons.append("impact is more than informational")
    # Q6 — specificity (template names a real class, not a generic probe)
    if tmpl and "detect" not in tmpl and "panel" not in tmpl:
        score += 1; reasons.append("specific vulnerability, not a generic probe")
    # Q7 — severity-weighted confidence
    if sev in ("critical", "high") and (f.get("validated") is True or cve):
        score += 1; reasons.append("high severity AND corroborated")

    # report only if it clears the bar (>=3 of 7), or any confirmed crit/high
    report = score >= 3 or (sev in ("critical", "high") and f.get("validated") is True)
    # B4 confidence ladder — a finding is not "confirmed" off one signal. Cross-principal
    # bugs (IDOR/BOLA) and unreproduced anomalies are CANDIDATES needing human confirmation;
    # a directly-reproduced high-severity signal is the strongest we claim locally.
    if f.get("validated") is True and score >= 5:
        confidence = "reproduced"      # probed + reproduced + corroborated
    elif f.get("validated") is True:
        confidence = "supported"       # a direct signal, but thin corroboration
    elif report:
        confidence = "candidate"       # report-worthy lead, NOT yet proven (e.g. IDOR needs 2 accounts)
    else:
        confidence = "weak"
    priority = triage(sev, confidence, has_exploit=bool(cve and exploits_map.get(cve)))
    return {"report": report, "score": score, "tier": PAYOUT_TIER.get(sev, "P5"),
            "reasons": reasons, "confidence": confidence, "priority": priority,
            "drop": None if report else f"failed quality gate ({score}/7)"}
