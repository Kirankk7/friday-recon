"""
Phase 61 — notification hub.

One push channel for proactive alerts. push(text) fans out to every enabled
sink; the HUD is always a sink (polls /notifications). Telegram/email can plug
in later as extra sinks without touching callers.

    from core.notify import push
    push("New listening port 4444 on your machine.", kind="security")
"""

import time
import threading
from collections import deque

_lock = threading.Lock()
_seq = 0
_queue = deque(maxlen=50)   # recent notifications for the HUD to poll

_KINDS = {"info", "digest", "reminder", "security"}


def push(text: str, kind: str = "info") -> dict:
    """Queue a notification for delivery. Returns the stored item."""
    global _seq
    text = (text or "").strip()
    if not text:
        return {}
    if kind not in _KINDS:
        kind = "info"
    with _lock:
        _seq += 1
        item = {"id": _seq, "text": text, "kind": kind, "ts": time.time()}
        _queue.append(item)
    # extra sinks (Telegram, etc.) register here later
    for sink in list(_SINKS):
        try:
            sink(item)
        except Exception as e:
            print(f"[notify] sink error: {e}")
    print(f"[notify] {kind}: {text}")
    return item


def poll(since_id: int = 0) -> list:
    """Return notifications newer than since_id (for the HUD)."""
    with _lock:
        return [dict(i) for i in _queue if i["id"] > since_id]


def latest_id() -> int:
    with _lock:
        return _seq


# ── extra delivery sinks (Telegram/email plug in here) ──
_SINKS = []


def register_sink(fn) -> None:
    """fn(item:dict) is called for every push. Used by the Telegram bridge later."""
    if fn not in _SINKS:
        _SINKS.append(fn)
