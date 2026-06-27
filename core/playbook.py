"""
Ultron Playbook — a GROWING technique library (the hunter's edge).

Stores attack techniques (proven + reference) so future hunts recall and reuse
them. The division: the human does true/false-positive judgment + creative
chaining + NEW techniques; JARVIS captures what works, recalls it per stack,
and replays the known payloads. Negates the repeated/mechanical manual work,
not the thinking.

Storage: data/playbook.json (gitignored — your personal edge). Each entry:
  {id, class, stack, difficulty, technique, payload, tell, source, ref,
   validated, verify, added}

  validated=True  -> proven by us on a real target (highest confidence)
  validated=False -> reference technique to try (KB / PortSwigger)
  verify=True     -> distillation is uncertain, wants a human eyes-on pass
"""

import os
import re
import json
import datetime
from collections import Counter

_PATH = os.path.join("data", "playbook.json")
_WORD = re.compile(r"[a-z0-9]+")
_STOP = {"the", "a", "an", "to", "of", "in", "on", "for", "and", "or", "with",
         "via", "is", "are", "by", "that", "this", "it", "as", "if", "then",
         "into", "from", "your", "you", "vulnerability", "attack", "lab"}


def _tok(text: str) -> list:
    return [w for w in _WORD.findall((text or "").lower()) if w not in _STOP and len(w) > 1]


def _load() -> dict:
    try:
        with open(_PATH, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {"version": 1, "techniques": []}


def _save(doc: dict) -> None:
    os.makedirs("data", exist_ok=True)
    with open(_PATH, "w", encoding="utf-8") as f:
        json.dump(doc, f, indent=2, ensure_ascii=False)


def _sig(vuln_class: str, technique: str) -> str:
    """Dedup signature: class + the meaningful tokens of the technique, sorted."""
    toks = sorted(set(_tok(vuln_class) + _tok(technique)))
    return " ".join(toks)


def _overlap(a: set, b: set) -> float:
    if not a or not b:
        return 0.0
    return len(a & b) / len(a | b)            # Jaccard


def add(vuln_class: str, technique: str, stack: str = "", payload: str = "",
        tell: str = "", source: str = "manual", ref: str = "",
        validated: bool = False, difficulty: str = "", verify: bool = False,
        dedup: bool = True) -> dict:
    """Add a technique. With dedup (default) skip near-duplicates in the same class
    (>0.7 token-Jaccard) — that's the runtime auto-capture path. dedup=False appends
    directly (canonical seeding, where each entry is a distinct known technique)."""
    technique = (technique or "").strip()
    if not technique:
        return {"added": False, "reason": "empty technique"}
    doc = _load()
    new_sig = set(_tok(vuln_class) + _tok(technique) + _tok(payload))
    for e in (doc["techniques"] if dedup else []):
        if e.get("class") == vuln_class:
            ex_sig = set(_tok(e.get("class", "")) + _tok(e.get("technique", "")) + _tok(e.get("payload", "")))
            if _overlap(new_sig, ex_sig) >= 0.7:
                # if the new one is PROVEN and the old wasn't, upgrade it
                if validated and not e.get("validated"):
                    e["validated"] = True
                    if payload: e["payload"] = payload
                    if tell:    e["tell"] = tell
                    _save(doc)
                    return {"added": False, "reason": "upgraded existing to validated", "id": e["id"]}
                return {"added": False, "reason": "duplicate", "id": e["id"]}
    tid = f"pb{len(doc['techniques']) + 1:04d}"
    doc["techniques"].append({
        "id": tid, "class": vuln_class, "stack": stack, "difficulty": difficulty,
        "technique": technique, "payload": payload, "tell": tell,
        "source": source, "ref": ref, "validated": bool(validated),
        "verify": bool(verify), "added": datetime.datetime.now().isoformat(timespec="seconds"),
    })
    _save(doc)
    return {"added": True, "reason": "new", "id": tid}


def recall(query: str = "", stack: str = "", vuln_class: str = "", top_k: int = 8) -> list:
    """Return the most relevant techniques for a query / stack / class, ranked.
    Proven (validated) entries get a confidence boost so they surface first."""
    doc = _load()
    terms = Counter(_tok(query) + _tok(stack) * 2 + _tok(vuln_class) * 3)
    out = []
    for e in doc["techniques"]:
        if vuln_class and e.get("class") != vuln_class:
            continue
        hay = Counter(_tok(e.get("class", "")) + _tok(e.get("stack", "")) +
                      _tok(e.get("technique", "")) + _tok(e.get("payload", "")))
        score = sum(min(terms[t], hay[t]) for t in terms) if terms else 0
        if not terms and not vuln_class:
            continue
        if vuln_class and not terms:
            score = 1            # class filter alone still returns the class
        if score <= 0 and not (vuln_class and not query and not stack):
            continue
        if e.get("validated"):
            score += 3           # proven beats reference
        out.append((score, e))
    out.sort(key=lambda x: (-x[0], not x[1].get("validated")))
    return [e for _, e in out[:top_k]]


def classes() -> dict:
    """Count techniques per class."""
    doc = _load()
    c = Counter(e.get("class", "?") for e in doc["techniques"])
    return dict(c.most_common())


def stats() -> dict:
    doc = _load()
    t = doc["techniques"]
    return {"total": len(t),
            "validated": sum(1 for e in t if e.get("validated")),
            "verify_needed": sum(1 for e in t if e.get("verify")),
            "classes": len(set(e.get("class") for e in t))}


def needs_verify() -> list:
    """Entries whose distillation is uncertain — the human screenshot list."""
    return [e for e in _load()["techniques"] if e.get("verify")]
