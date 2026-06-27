"""
Vector memory — keyword-based similarity search.
Replaced neural embeddings (sentence_transformers/PyTorch) with TF-IDF-style
keyword overlap to avoid PyTorch+CTranslate2 CUDA conflict that caused segfaults.
Semantic quality slightly lower but stable on all hardware.
"""

import json
import math
import os
import re

VECTOR_FILE = "vector_memory.json"
MAX_ENTRIES = 500

_STOPWORDS = {
    "a", "an", "the", "is", "it", "in", "on", "at", "to", "for",
    "of", "and", "or", "but", "with", "this", "that", "what", "how",
    "do", "did", "are", "was", "be", "been", "have", "has", "had",
    "i", "you", "we", "they", "he", "she", "my", "your", "me", "us"
}


def _tokenize(text: str) -> list[str]:
    tokens = re.findall(r"[a-z0-9]+", text.lower())
    return [t for t in tokens if t not in _STOPWORDS and len(t) > 1]


def _tfidf_vec(tokens: list[str], idf: dict) -> dict:
    """Compute TF-IDF-style vector (term -> weight)."""
    tf = {}
    for t in tokens:
        tf[t] = tf.get(t, 0) + 1
    total = len(tokens) or 1
    return {t: (c / total) * idf.get(t, 1.0) for t, c in tf.items()}


def _cosine(a: dict, b: dict) -> float:
    common = set(a) & set(b)
    if not common:
        return 0.0
    dot = sum(a[t] * b[t] for t in common)
    mag_a = math.sqrt(sum(v * v for v in a.values()))
    mag_b = math.sqrt(sum(v * v for v in b.values()))
    if mag_a == 0 or mag_b == 0:
        return 0.0
    return dot / (mag_a * mag_b)


def load_vector() -> list:
    if not os.path.exists(VECTOR_FILE):
        return []
    try:
        with open(VECTOR_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return []


def save_vector(data: list):
    try:
        with open(VECTOR_FILE, "w", encoding="utf-8") as f:
            json.dump(data, f)
    except Exception as e:
        print(f"[vector] Save error: {e}")


def add_to_vector(text: str):
    if not text or not text.strip():
        return
    data = load_vector()
    tokens = _tokenize(text.strip())
    if not tokens:
        return
    data.append({"text": text.strip(), "tokens": tokens})
    if len(data) > MAX_ENTRIES:
        data = data[-MAX_ENTRIES:]
    save_vector(data)


def search_similar(query: str, top_k: int = 5) -> list:
    data = load_vector()
    if not data:
        return []
    try:
        # Build IDF from corpus
        doc_freq = {}
        for item in data:
            for t in set(item.get("tokens", [])):
                doc_freq[t] = doc_freq.get(t, 0) + 1
        N = len(data)
        idf = {t: math.log((N + 1) / (df + 1)) + 1 for t, df in doc_freq.items()}

        q_tokens = _tokenize(query)
        if not q_tokens:
            return []
        q_vec = _tfidf_vec(q_tokens, idf)

        scored = []
        for item in data:
            tokens = item.get("tokens")
            if not tokens:
                # Legacy entries with embeddings — skip
                continue
            d_vec = _tfidf_vec(tokens, idf)
            score = _cosine(q_vec, d_vec)
            if score > 0.15:
                scored.append((item["text"], score))

        scored.sort(key=lambda x: x[1], reverse=True)
        return [text for text, _ in scored[:top_k]]

    except Exception as e:
        print(f"[vector] Search error: {e}")
        return []
