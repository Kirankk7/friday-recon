"""
Phase 62 — Ultron Knowledge Pack.

A built-in, RAG-indexed bug-bounty/OSINT methodology knowledge base for Ultron.
Vendored notes live in agents/ultron/knowledge/notes/ (bug-bounty playbooks,
OSINT resources, tool catalog). This indexes them with the project's TF-IDF
primitives (reused from vector_memory) so Ultron can cite real methodology —
"how do I test for subdomain takeover?" — fully local, no cloud, no embeddings.

Separate index from the user-doc RAG (core.rag) so the KB never mixes with the
user's own documents. The index ships prebuilt (data/security_kb.json) so it
works on clone; rebuild with build_index() after editing the notes.

Drop SnailSploit/Claude-Red's Skills/*.md into notes/ then rebuild to fold in
its 58 methodology skills.
"""

import os
import json
import math

from core.vector_memory import _tokenize, _tfidf_vec, _cosine

_NOTES_DIR = os.path.join("agents", "ultron", "knowledge", "notes")
_WORDLIST_DIR = os.path.join("agents", "ultron", "knowledge", "wordlists")
_INDEX_FILE = os.path.join("data", "security_kb.json")
_CHUNK_CHARS = 700

# Private notes = 3rd-party personal-use-only licensed content (e.g. PentestingChecklist
# by m14r41). Both the notes dir AND this index are gitignored — they index LOCALLY and
# merge into search results at query time, but never enter a committed/shipped artifact,
# so nothing licensed gets redistributed via the public repo.
_PRIVATE_NOTES_DIR = os.path.join("agents", "ultron", "knowledge", "notes_private")
_PRIVATE_INDEX_FILE = os.path.join("data", "security_kb_private.json")


def _chunk(text: str) -> list:
    paras = [p.strip() for p in text.split("\n") if p.strip()]
    chunks, buf = [], ""
    for p in paras:
        if len(buf) + len(p) + 1 <= _CHUNK_CHARS:
            buf = f"{buf} {p}".strip()
        else:
            if buf:
                chunks.append(buf)
            while len(p) > _CHUNK_CHARS:
                chunks.append(p[:_CHUNK_CHARS]); p = p[_CHUNK_CHARS:]
            buf = p
    if buf:
        chunks.append(buf)
    return chunks


_CACHE = None        # in-memory public index (built/loaded once; read-only at runtime)
_PRIV_CACHE = None   # in-memory private index (None = not loaded yet)


def build_index() -> dict:
    """(Re)build the KB index from notes/. Run after adding/editing notes."""
    global _CACHE
    chunks = []
    if not os.path.isdir(_NOTES_DIR):
        return {"success": False, "message": "knowledge/notes dir missing", "passages": 0}
    for name in sorted(os.listdir(_NOTES_DIR)):
        path = os.path.join(_NOTES_DIR, name)
        if not os.path.isfile(path):
            continue
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as f:
                text = f.read()
        except Exception:
            continue
        topic = os.path.splitext(name)[0]
        if topic.startswith("claudered_"):     # claudered_web_offensive-ssrf -> web / ssrf
            topic = topic[len("claudered_"):].replace("offensive-", "").replace("_", " / ")
        topic = topic.replace("_", " ")
        for piece in _chunk(text):
            chunks.append({"name": name, "topic": topic,
                           "chunk": piece, "tokens": _tokenize(topic + " " + piece)})
    _CACHE = chunks                     # use in-memory copy directly (avoid read race)
    os.makedirs(os.path.dirname(_INDEX_FILE), exist_ok=True)
    try:
        with open(_INDEX_FILE, "w", encoding="utf-8") as f:
            json.dump(chunks, f)
    except Exception as e:
        print(f"[security_kb] index write failed (using in-memory): {e}")
    return {"success": True, "passages": len(chunks),
            "docs": len({c["name"] for c in chunks}),
            "message": f"Indexed {len({c['name'] for c in chunks})} notes, {len(chunks)} passages."}


def _load() -> list:
    global _CACHE
    if _CACHE is not None:
        return _CACHE
    try:
        if os.path.exists(_INDEX_FILE):
            with open(_INDEX_FILE, "r", encoding="utf-8") as f:
                _CACHE = json.load(f)
                return _CACHE
    except Exception as e:
        print(f"[security_kb] index read failed, rebuilding: {e}")
    return []


def _ensure_index() -> list:
    chunks = _load()
    if not chunks:                      # first run on a fresh clone
        build_index()                   # populates _CACHE in-memory
        chunks = _CACHE or []
    return chunks


def build_private_index() -> dict:
    """(Re)build the PRIVATE index from notes_private/. Local-only, never committed.
    Returns {passages: 0} gracefully when the dir is absent (e.g. a fresh clone)."""
    global _PRIV_CACHE
    chunks = []
    if os.path.isdir(_PRIVATE_NOTES_DIR):
        for name in sorted(os.listdir(_PRIVATE_NOTES_DIR)):
            path = os.path.join(_PRIVATE_NOTES_DIR, name)
            if not os.path.isfile(path):
                continue
            try:
                with open(path, "r", encoding="utf-8", errors="replace") as f:
                    text = f.read()
            except Exception:
                continue
            topic = os.path.splitext(name)[0]
            if topic.startswith("pc_"):          # pc_api -> api, pc_active-directory -> active directory
                topic = topic[len("pc_"):]
            topic = topic.replace("-", " ").replace("_", " ")
            for piece in _chunk(text):
                chunks.append({"name": name, "topic": topic,
                               "chunk": piece, "tokens": _tokenize(topic + " " + piece)})
    _PRIV_CACHE = chunks
    if chunks:
        os.makedirs(os.path.dirname(_PRIVATE_INDEX_FILE), exist_ok=True)
        try:
            with open(_PRIVATE_INDEX_FILE, "w", encoding="utf-8") as f:
                json.dump(chunks, f)
        except Exception as e:
            print(f"[security_kb] private index write failed (using in-memory): {e}")
    return {"success": True, "passages": len(chunks),
            "docs": len({c["name"] for c in chunks})}


def _ensure_private() -> list:
    """Load (or first-time build) the private index. Empty list when no private notes."""
    global _PRIV_CACHE
    if _PRIV_CACHE is not None:
        return _PRIV_CACHE
    try:
        if os.path.exists(_PRIVATE_INDEX_FILE):
            with open(_PRIVATE_INDEX_FILE, "r", encoding="utf-8") as f:
                _PRIV_CACHE = json.load(f)
                return _PRIV_CACHE
    except Exception as e:
        print(f"[security_kb] private index read failed, rebuilding: {e}")
    if os.path.isdir(_PRIVATE_NOTES_DIR):     # notes present but no index yet -> build
        build_private_index()
        return _PRIV_CACHE or []
    _PRIV_CACHE = []
    return _PRIV_CACHE


def _all_chunks() -> list:
    """Public (shipped) + private (local-only) passages merged for retrieval."""
    return _ensure_index() + _ensure_private()


def search(query: str, top_k: int = 4) -> list:
    chunks = _all_chunks()
    if not chunks or not query.strip():
        return []
    doc_freq = {}
    for c in chunks:
        for t in set(c.get("tokens", [])):
            doc_freq[t] = doc_freq.get(t, 0) + 1
    N = len(chunks)
    idf = {t: math.log((N + 1) / (df + 1)) + 1 for t, df in doc_freq.items()}
    q_vec = _tfidf_vec(_tokenize(query), idf)
    if not q_vec:
        return []
    scored = []
    for c in chunks:
        s = _cosine(q_vec, _tfidf_vec(c.get("tokens", []), idf))
        if s > 0.05:
            scored.append((s, c))
    scored.sort(key=lambda x: x[0], reverse=True)
    return [{"name": c["name"], "topic": c["topic"], "chunk": c["chunk"], "score": round(s, 3)}
            for s, c in scored[:top_k]]


def methodology(query: str) -> dict:
    """Answer a methodology question grounded in the vendored notes, with sources."""
    hits = search(query, top_k=4)
    if not hits:
        return {"success": True,
                "message": "Nothing in my bug-bounty notes on that yet, boss.",
                "data": {"sources": []}}
    from core.llm import ask_llm
    context = "\n\n".join(f"[{h['topic']}] {h['chunk']}" for h in hits)
    prompt = (
        "You are Ultron, a security mentor. Using ONLY the methodology notes below, "
        "explain how to approach this in plain, practical English — concise, steps where "
        "useful, no markdown headers. If the notes don't cover it, say so.\n\n"
        f"Question: {query}\n\nNotes:\n{context}\n\nAnswer:"
    )
    ans = ask_llm(prompt, agent="ultron", autotune_on=False,
                  params={"temperature": 0.3, "num_predict": 320})
    srcs = []
    for h in hits:
        if h["topic"] not in srcs:
            srcs.append(h["topic"])
    if ans and srcs:
        ans = ans.strip() + f"  (from notes: {', '.join(srcs[:3])})"
    return {"success": True, "message": ans or "Couldn't form an answer.",
            "data": {"sources": srcs}}


def wordlist_path(kind: str = "") -> dict:
    """Resolve a bundled wordlist/payload file by keyword (for ffuf/nuclei/dorking)."""
    if not os.path.isdir(_WORDLIST_DIR):
        return {"success": False, "message": "no wordlists bundled", "data": {}}
    files = sorted(os.listdir(_WORDLIST_DIR))
    if not kind:
        return {"success": True, "message": "Bundled wordlists: " + ", ".join(files),
                "data": {"files": files, "dir": os.path.abspath(_WORDLIST_DIR)}}
    k = kind.lower()
    match = next((f for f in files if k in f.lower()), None)
    if not match:
        return {"success": False, "message": f"No wordlist matching '{kind}'. Have: {', '.join(files)}",
                "data": {"files": files}}
    return {"success": True, "message": f"{match} -> {os.path.abspath(os.path.join(_WORDLIST_DIR, match))}",
            "data": {"path": os.path.abspath(os.path.join(_WORDLIST_DIR, match))}}


def stats() -> dict:
    chunks = _load()
    priv = _ensure_private()
    wl = sorted(os.listdir(_WORDLIST_DIR)) if os.path.isdir(_WORDLIST_DIR) else []
    return {"notes": len({c["name"] for c in chunks}), "passages": len(chunks),
            "private_notes": len({c["name"] for c in priv}), "private_passages": len(priv),
            "wordlists": len(wl)}
