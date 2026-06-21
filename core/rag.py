"""
Phase 58 - RAG: chat with your documents (local, offline).

Index a file or folder, then ask questions and get answers grounded in the
content with source citations. Reuses the project's TF-IDF retrieval
(core.vector_memory primitives) + MarkItDown reader (file_agent) - no new deps,
no cloud, no embeddings model. Separate index from conversation memory so docs
don't pollute chat recall.

    from core import rag
    rag.index_folder("~/Documents/contracts")
    rag.ask("what's the termination notice period?")
"""

import os
import json
import math

from core.vector_memory import _tokenize, _tfidf_vec, _cosine

INDEX_FILE = "data/rag_index.json"
_CHUNK_CHARS = 600          # ~target passage size
_MAX_CHARS_PER_DOC = 40000  # cap how much of a huge doc we ingest


def _load() -> list:
    try:
        if os.path.exists(INDEX_FILE):
            with open(INDEX_FILE, "r", encoding="utf-8") as f:
                return json.load(f)
    except Exception:
        pass
    return []


def _save(chunks: list) -> None:
    try:
        os.makedirs(os.path.dirname(INDEX_FILE), exist_ok=True)
        with open(INDEX_FILE, "w", encoding="utf-8") as f:
            json.dump(chunks, f)
    except Exception as e:
        print(f"[rag] save error: {e}")


def _chunk(text: str) -> list:
    """Split text into ~_CHUNK_CHARS passages on paragraph/sentence boundaries."""
    text = text[:_MAX_CHARS_PER_DOC]
    paras = [p.strip() for p in text.split("\n") if p.strip()]
    chunks, buf = [], ""
    for p in paras:
        if len(buf) + len(p) + 1 <= _CHUNK_CHARS:
            buf = f"{buf} {p}".strip()
        else:
            if buf:
                chunks.append(buf)
            # paragraph itself too big → hard-split
            while len(p) > _CHUNK_CHARS:
                chunks.append(p[:_CHUNK_CHARS])
                p = p[_CHUNK_CHARS:]
            buf = p
    if buf:
        chunks.append(buf)
    return chunks


def index_file(path: str) -> dict:
    """Read + chunk + index one document. Re-indexing replaces its old chunks."""
    path = os.path.expanduser(path)
    if not os.path.exists(path):
        return {"success": False, "message": "I couldn't find that file, boss.", "added": 0}

    from agents.file.file_agent import file_agent, _friendly_name
    read = file_agent.read_document(path, max_chars=_MAX_CHARS_PER_DOC)
    if not read.get("success"):
        return {"success": False, "message": read.get("message", "Couldn't read it."), "added": 0}

    text = read.get("message", "")
    pieces = _chunk(text)
    if not pieces:
        return {"success": False, "message": f"Nothing readable in {_friendly_name(path)}.", "added": 0}

    src = os.path.abspath(path)
    chunks = [c for c in _load() if c.get("source") != src]   # drop old version
    for piece in pieces:
        chunks.append({"source": src, "name": os.path.basename(path),
                       "chunk": piece, "tokens": _tokenize(piece)})
    _save(chunks)
    return {"success": True, "added": len(pieces),
            "message": f"Indexed {_friendly_name(path)} - {len(pieces)} passages."}


def index_folder(path: str) -> dict:
    """Index every readable document in a folder (non-recursive top level + 1 deep)."""
    path = os.path.expanduser(path)
    if not os.path.isdir(path):
        return {"success": False, "message": "That folder doesn't exist, boss.", "added": 0}

    from agents.file.file_agent import _READABLE_EXTS
    total, files = 0, 0
    for root, _dirs, names in os.walk(path):
        # limit depth to 1 below the given folder
        if root[len(path):].count(os.sep) > 1:
            continue
        for n in names:
            if os.path.splitext(n)[1].lower() in _READABLE_EXTS:
                r = index_file(os.path.join(root, n))
                if r.get("success"):
                    total += r["added"]
                    files += 1
    if not files:
        return {"success": False, "message": "No readable documents in that folder.", "added": 0}
    return {"success": True, "added": total, "files": files,
            "message": f"Indexed {files} document(s) - {total} passages ready."}


def search(query: str, top_k: int = 4) -> list:
    """Return top matching passages: [{source, name, chunk, score}]."""
    chunks = _load()
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
        score = _cosine(q_vec, _tfidf_vec(c.get("tokens", []), idf))
        if score > 0.05:
            scored.append((score, c))
    scored.sort(key=lambda x: x[0], reverse=True)
    return [{"source": c["source"], "name": c.get("name", ""),
             "chunk": c["chunk"], "score": round(s, 3)} for s, c in scored[:top_k]]


def ask(query: str) -> dict:
    """Answer a question grounded in the indexed docs, with sources."""
    if not _load():
        return {"success": False,
                "message": "No documents indexed yet, boss. Say 'index <folder>' first.",
                "data": {}}
    hits = search(query, top_k=4)
    if not hits:
        return {"success": True,
                "message": "I couldn't find anything about that in your documents, boss.",
                "data": {"sources": []}}

    from core.llm import ask_llm
    context = "\n\n".join(f"[from {h['name']}] {h['chunk']}" for h in hits)
    prompt = (
        "Answer the question using ONLY the document excerpts below. Speak in plain, "
        "natural English - 2-4 sentences, no markdown, no bullet points. If the answer "
        "isn't in the excerpts, say you couldn't find it.\n\n"
        f"Question: {query}\n\nExcerpts:\n{context}\n\nAnswer:"
    )
    answer = ask_llm(prompt, agent="file", autotune_on=False,
                     params={"temperature": 0.3, "num_predict": 280})
    names = []
    for h in hits:
        if h["name"] not in names:
            names.append(h["name"])
    if answer and names:
        answer = answer.strip() + f"  (from {', '.join(names[:3])})"
    return {"success": True, "message": answer or "Couldn't form an answer.",
            "data": {"sources": names, "hits": len(hits)}}


def stats() -> dict:
    chunks = _load()
    sources = sorted({c.get("name", c.get("source", "")) for c in chunks})
    return {"documents": len(sources), "passages": len(chunks), "names": sources}


def clear() -> dict:
    _save([])
    return {"success": True, "message": "Cleared the document index, boss."}
