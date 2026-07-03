"""
Ultron — playbook knowledge cluster (Phase B extraction, move-only).

Recall / add attack techniques from the growing playbook, lifted verbatim out of the
ultron_agent god-class. Free functions with no `self` — the technique store itself lives
in core/playbook.py; these are the presentation + add wrappers. (kb_methodology / wordlist
already live in core/security_kb.py and are dispatched directly, so they stay there.)
"""


def playbook_recall(query: str = "", stack: str = "") -> dict:
    """Recall attack techniques from the growing playbook (proven + KB + PortSwigger),
    ranked for the query/stack. Proven techniques surface first."""
    from core import playbook as pb
    hits = pb.recall(query=query, stack=stack, top_k=8)
    if not hits:
        s = pb.stats()
        return {"success": True, "data": {"hits": []},
                "message": f"No playbook match for '{query}'. ({s['total']} techniques loaded.)"}
    lines = [f"Playbook — {len(hits)} technique(s) for '{query or stack}':", ""]
    for e in hits:
        tag = "PROVEN" if e.get("validated") else ("VERIFY" if e.get("verify") else "ref")
        lines.append(f"[{tag}] {e['class']}: {e['technique']}")
        if e.get("payload"): lines.append(f"   payload: {e['payload']}")
        if e.get("tell"):    lines.append(f"   tell:    {e['tell']}")
        if e.get("ref"):     lines.append(f"   ref:     {e['ref']}")
    return {"success": True, "message": "\n".join(lines), "data": {"hits": hits}}


def remember_technique(text: str, vuln_class: str = "manual", stack: str = "") -> dict:
    """Manually add a technique YOU found to the playbook (your creative finds become
    JARVIS's permanent knowledge)."""
    from core import playbook as pb
    r = pb.add(vuln_class, text, stack=stack, source="user", validated=True)
    if r["added"]:
        return {"success": True, "message": f"Remembered ({r['id']}): {text[:80]}", "data": r}
    return {"success": True, "message": f"Already known ({r['reason']}).", "data": r}
