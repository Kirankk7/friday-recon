"""
Phase 56 — AutoTune: context-adaptive sampling parameters + EMA learning.

Ported from elder-plinius/G0DM0D3 (HF/src/lib/autotune.ts + autotune-feedback.ts),
adapted for local Ollama. Pure heuristic classifier (no LLM, no deps).

Idea: a single fixed temperature is wrong for half of all queries. Classify the
prompt (code / analytical / creative / conversational / chaotic) BEFORE generation
and apply the matching sampling profile in one call. An EMA feedback loop nudges
profiles toward what the user upvotes over time.

Param keys are Ollama option names (repeat_penalty, not repetition_penalty).
"""

import os
import re
import json
import threading

_FEEDBACK_FILE = "data/autotune_feedback.json"
_lock = threading.Lock()

# ── Per-context sampling profiles (Ollama option names) ────────────────────────
_PROFILES = {
    "code": {
        "temperature": 0.15, "top_p": 0.80, "top_k": 25,
        "repeat_penalty": 1.05, "frequency_penalty": 0.2, "presence_penalty": 0.0,
    },
    "analytical": {
        "temperature": 0.40, "top_p": 0.88, "top_k": 40,
        "repeat_penalty": 1.08, "frequency_penalty": 0.2, "presence_penalty": 0.15,
    },
    "conversational": {
        "temperature": 0.75, "top_p": 0.90, "top_k": 50,
        "repeat_penalty": 1.0, "frequency_penalty": 0.1, "presence_penalty": 0.1,
    },
    "creative": {
        "temperature": 1.15, "top_p": 0.95, "top_k": 85,
        "repeat_penalty": 1.2, "frequency_penalty": 0.5, "presence_penalty": 0.7,
    },
    "chaotic": {
        "temperature": 1.7, "top_p": 0.99, "top_k": 100,
        "repeat_penalty": 1.3, "frequency_penalty": 0.8, "presence_penalty": 0.9,
    },
}

_BOUNDS = {
    "temperature": (0.0, 2.0), "top_p": (0.0, 1.0), "top_k": (1, 100),
    "repeat_penalty": (0.0, 2.0), "frequency_penalty": (-2.0, 2.0),
    "presence_penalty": (-2.0, 2.0),
}

# ── Context detection patterns (ported) ────────────────────────────────────────
_PATTERNS = {
    "code": [
        re.compile(r"\b(code|function|class|variable|bug|error|debug|compile|syntax|api|endpoint|regex|algorithm|refactor|typescript|javascript|python|rust|html|css|sql|json|xml|import|export|return|async|await|interface|const|let|var)\b", re.I),
        re.compile(r"```[\s\S]*```"),
        re.compile(r"\b(fix|implement|write|create|build|deploy|test|lint|npm|pip|cargo|git)\b.*\b(code|function|app|service|component|module|script)\b", re.I),
        re.compile(r"[{}();=><]"),
        re.compile(r"\b(stack overflow|github|repo|pull request|commit|merge)\b", re.I),
    ],
    "creative": [
        re.compile(r"\b(story|poem|creative|imagine|fiction|narrative|character|plot|scene|dialogue|metaphor|lyrics|song|artistic|fantasy|dream|inspire|prose|verse|haiku)\b", re.I),
        re.compile(r"\b(describe|paint|envision|portray|illustrate|craft)\b.*\b(world|scene|character|feeling|emotion|atmosphere)\b", re.I),
        re.compile(r"\b(roleplay|role-play|pretend|act as|you are a)\b", re.I),
        re.compile(r"\b(brainstorm|ideate|come up with|think of|generate ideas)\b", re.I),
    ],
    "analytical": [
        re.compile(r"\b(analyze|analysis|compare|contrast|evaluate|assess|examine|investigate|research|study|review|critique|breakdown|statistics|metrics|benchmark)\b", re.I),
        re.compile(r"\b(pros and cons|advantages|disadvantages|trade-?offs|implications|consequences)\b", re.I),
        re.compile(r"\b(why|how does|what causes|explain|elaborate|clarify|define|summarize|overview)\b", re.I),
        re.compile(r"\b(report|document|technical|specification|architecture|whitepaper)\b", re.I),
    ],
    "conversational": [
        re.compile(r"\b(hey|hi|hello|sup|how are you|thanks|thank you|cool|nice|awesome|great|lol|haha)\b", re.I),
        re.compile(r"\b(chat|talk|tell me about|what do you think|opinion|feel|believe)\b", re.I),
        re.compile(r"^.{0,30}$"),
    ],
    "chaotic": [
        re.compile(r"\b(chaos|random|wild|crazy|absurd|surreal|glitch|corrupt|unleash|madness|void|entropy)\b", re.I),
        re.compile(r"\b(gl1tch|h4ck|pwn|1337|l33t)\b", re.I),
        re.compile(r"(!{3,}|\?{3,}|\.{4,})"),
    ],
}

_EMA_ALPHA = 0.3            # weight for new feedback observation
_MIN_SAMPLES = 3           # samples before learned adjustments kick in
_MAX_LEARN_WEIGHT = 0.5    # learned adjustments cap at 50% influence

# remembers the last autotuned call so a 👍/👎 hook can attribute feedback
_LAST = {"context": None, "params": None}


def _clamp(key, val):
    lo, hi = _BOUNDS[key]
    val = max(lo, min(hi, val))
    return int(round(val)) if key == "top_k" else round(val, 3)


def classify(prompt: str, history: list | None = None) -> tuple:
    """Return (context, confidence, scores). Current prompt weighted 3x, history 1x."""
    scores = {k: 0 for k in _PATTERNS}
    for ctx, pats in _PATTERNS.items():
        for p in pats:
            if p.search(prompt or ""):
                scores[ctx] += 3
    for msg in (history or [])[-4:]:
        content = msg.get("content", "") if isinstance(msg, dict) else str(msg)
        for ctx, pats in _PATTERNS.items():
            for p in pats:
                if p.search(content):
                    scores[ctx] += 1
    total = sum(scores.values())
    if total == 0:
        return "conversational", 0.5, scores
    best = max(scores, key=scores.get)
    return best, min(scores[best] / total, 1.0), scores


def _load_feedback() -> dict:
    try:
        if os.path.exists(_FEEDBACK_FILE):
            with open(_FEEDBACK_FILE, "r", encoding="utf-8") as f:
                return json.load(f)
    except Exception:
        pass
    return {}


def _save_feedback(state: dict) -> None:
    try:
        os.makedirs(os.path.dirname(_FEEDBACK_FILE), exist_ok=True)
        with open(_FEEDBACK_FILE, "w", encoding="utf-8") as f:
            json.dump(state, f, indent=2)
    except Exception as e:
        print(f"[autotune] feedback save error: {e}")


def _learned_adjustments(context: str) -> dict:
    """Delta per param learned from feedback: direction from downvoted->upvoted EMA."""
    prof = _load_feedback().get(context)
    if not prof:
        return {}
    samples = prof.get("pos_n", 0) + prof.get("neg_n", 0)
    if samples < _MIN_SAMPLES:
        return {}
    pos, neg = prof.get("pos", {}), prof.get("neg", {})
    base = _PROFILES[context]
    weight = min(samples / 10.0, 1.0) * _MAX_LEARN_WEIGHT
    adj = {}
    for k in base:
        if k in pos and k in neg:
            # nudge toward upvoted, away from downvoted
            adj[k] = (pos[k] - neg[k]) * 0.5 * weight
    return adj


def tune(prompt: str, history: list | None = None, context: str | None = None) -> dict:
    """Compute Ollama sampling options for this prompt. Records context for feedback."""
    ctx = context or classify(prompt, history)[0]
    params = dict(_PROFILES.get(ctx, _PROFILES["conversational"]))
    for k, delta in _learned_adjustments(ctx).items():
        params[k] = params[k] + delta
    params = {k: _clamp(k, v) for k, v in params.items()}
    # long conversation -> bump repeat penalty slightly
    if history and len(history) > 10:
        params["repeat_penalty"] = _clamp("repeat_penalty", params["repeat_penalty"] + 0.05)
    with _lock:
        _LAST["context"], _LAST["params"] = ctx, dict(params)
    return params


def record_feedback(rating: int, context: str | None = None,
                    params: dict | None = None) -> dict:
    """
    Update per-context EMA from a 👍 (+1) / 👎 (-1) rating on the last response.
    Returns the updated profile summary.
    """
    with _lock:
        ctx = context or _LAST["context"]
        prm = params or _LAST["params"]
    if not ctx or not prm or rating == 0:
        return {"ok": False, "message": "no recent autotuned call to rate"}

    state = _load_feedback()
    prof = state.setdefault(ctx, {"pos": {}, "neg": {}, "pos_n": 0, "neg_n": 0})
    side = "pos" if rating > 0 else "neg"
    n_key = "pos_n" if rating > 0 else "neg_n"
    cur = prof[side]
    inv = 1 - _EMA_ALPHA
    for k, v in prm.items():
        cur[k] = (cur[k] * inv + v * _EMA_ALPHA) if k in cur else v
    prof[n_key] = prof.get(n_key, 0) + 1
    _save_feedback(state)
    return {"ok": True, "context": ctx, "rating": rating,
            "samples": prof["pos_n"] + prof["neg_n"]}


def last_context() -> str | None:
    with _lock:
        return _LAST["context"]
