"""
Ultron — evidence-bundle writer (Phase B extraction, move-only).

Writes the F3 canonical Evidence Object (json + platform-ready submission md) per
gate-passed finding, lifted verbatim out of the ultron_agent god-class. Stateless free
function (no `self`); the object shape + exporters live in core/evidence.py — this just
persists one pair of files per finding.
"""
import os
import re


def write_bundle(folder: str, target: str, reportable: list) -> int:
    """F3 — write one canonical Evidence Object (json + platform-ready submission md)
    per gate-passed finding into <report-folder>/evidence/. Deterministic, no LLM."""
    from core import evidence as _ev
    ev_dir = os.path.join(folder, "evidence")
    os.makedirs(ev_dir, exist_ok=True)
    n = 0
    for i, f in enumerate(reportable, 1):
        obj = _ev.build(f, target)
        slug = re.sub(r"[^a-z0-9]+", "-", (f.get("template", "finding") or "finding").lower()).strip("-")
        base = os.path.join(ev_dir, f"{i:02d}_{slug or 'finding'}")
        with open(base + ".json", "w", encoding="utf-8") as fh:
            fh.write(_ev.to_json(obj))
        with open(base + ".md", "w", encoding="utf-8") as fh:
            fh.write(_ev.to_markdown(obj))
        n += 1
    if n:
        print(f"[ultron] evidence bundle: {n} object(s) -> {ev_dir}")
    return n
