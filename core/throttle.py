"""
Phase 52 #1 — Shared API throttle.

Min-interval rate limiter per external API, mirroring the Ollama circuit breaker
pattern. Prevents 429s on the free-tier APIs (NVD, VirusTotal, Football, GitHub)
by spacing calls to each host. Thread-safe, dependency-free.

Usage:
    from core.throttle import throttle
    throttle("virustotal")          # blocks until this call is allowed
    ... make the request ...

The interval auto-relaxes when an API key is present (higher quota).
"""

import time
import threading

# Per-API minimum seconds between calls. (limit headroom baked in.)
#   nvd:        50 req/30s w/ key (->0.6s)   · 5 req/30s without (->6s)
#   virustotal: 4 req/min  (->15s)
#   football:   10 req/min (->6s)
#   github:     5000/hr w/ token (->0.72s)   · 60/hr without (->60s)
_LIMITS = {
    "nvd":        {"with_key": 0.7,  "no_key": 6.5},
    "virustotal": {"with_key": 15.5, "no_key": 15.5},
    "football":   {"with_key": 6.2,  "no_key": 6.2},
    "github":     {"with_key": 0.8,  "no_key": 60.0},
}

_DEFAULT_INTERVAL = 1.0
_MAX_BLOCK = 20.0   # never block longer than this (safety against UI hang)

_lock = threading.Lock()
_last_call = {}     # api name -> last allowed timestamp


def _interval(api: str) -> float:
    """Resolve the min interval for an API, accounting for whether a key is set."""
    spec = _LIMITS.get(api)
    if not spec:
        return _DEFAULT_INTERVAL
    try:
        import config
        keyed = {
            "nvd":        bool(getattr(config, "NVD_API_KEY", "")),
            "virustotal": bool(getattr(config, "VIRUSTOTAL_API_KEY", "")),
            "football":   bool(getattr(config, "FOOTBALL_API_KEY", "")),
            "github":     bool(getattr(config, "GITHUB_TOKEN", "")),
        }.get(api, False)
    except Exception:
        keyed = False
    return spec["with_key"] if keyed else spec["no_key"]


def throttle(api: str) -> float:
    """
    Block until the next call to `api` is allowed under its rate limit.
    Returns the number of seconds slept (0 if no wait was needed).
    """
    interval = _interval(api)
    with _lock:
        now = time.monotonic()
        last = _last_call.get(api, 0.0)
        wait = (last + interval) - now
        if wait > _MAX_BLOCK:
            wait = _MAX_BLOCK
        if wait > 0:
            # release lock while sleeping so other APIs aren't blocked
            target = now + wait
        else:
            target = now
            wait = 0.0
        _last_call[api] = max(target, now)

    if wait > 0:
        print(f"[throttle] {api}: waiting {wait:.1f}s (limit spacing)")
        time.sleep(wait)
    return wait


def reset(api: str = None) -> None:
    """Clear throttle state (for tests)."""
    with _lock:
        if api:
            _last_call.pop(api, None)
        else:
            _last_call.clear()
