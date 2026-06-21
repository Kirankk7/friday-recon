import requests
import json
import time
import threading
from config import OLLAMA_HOST, OLLAMA_MODEL, AUTOTUNE_ENABLED, model_for
from core import autotune


def _resolve_options(prompt, agent, autotune_on, params, base):
    """
    Build the Ollama `options` dict. Precedence: explicit params > AutoTune > base.
    NOTE: Ollama reads sampling params from `options`, not top-level payload keys —
    the old top-level temperature/top_p were silently ignored.
    """
    opts = dict(base)
    if autotune_on and AUTOTUNE_ENABLED and params is None:
        try:
            opts.update(autotune.tune(prompt))
        except Exception as e:
            print(f"[llm] autotune skipped: {e}")
    if params:
        opts.update(params)
    return opts

# ─── Circuit breaker (Phase 51 #3) ────────────────────────────────────────────
# After N consecutive connection/timeout failures, trip the breaker and fail fast
# for a cooldown window instead of blocking on 120s timeouts repeatedly.
_cb_lock          = threading.Lock()
_cb_failures      = 0
_cb_tripped_until = 0.0
_CB_THRESHOLD     = 3      # consecutive failures to trip
_CB_COOLDOWN      = 30     # seconds to stay open
_CB_MSG           = "Brain's not responding, boss — Ollama looks down. Give it a moment."


def _cb_is_open() -> bool:
    """True while the breaker is tripped (skip network entirely)."""
    with _cb_lock:
        return bool(_cb_tripped_until and time.time() < _cb_tripped_until)


def _cb_record_success():
    global _cb_failures, _cb_tripped_until
    with _cb_lock:
        _cb_failures = 0
        _cb_tripped_until = 0.0


def _cb_record_failure():
    global _cb_failures, _cb_tripped_until
    with _cb_lock:
        _cb_failures += 1
        if _cb_failures >= _CB_THRESHOLD:
            _cb_tripped_until = time.time() + _CB_COOLDOWN
            print(f"[llm] circuit breaker OPEN — {_cb_failures} consecutive fails, "
                  f"failing fast for {_CB_COOLDOWN}s")


def ask_llm_stream(prompt: str, agent: str = None, autotune_on: bool = True,
                   params: dict = None):
    """Generator — yields tokens from Ollama as they arrive."""
    if _cb_is_open():
        yield _CB_MSG
        return
    try:
        url = f"{OLLAMA_HOST}/api/generate"
        options = _resolve_options(
            prompt, agent, autotune_on, params,
            {"temperature": 0.7, "top_p": 0.9, "num_predict": 500},
        )
        payload = {
            "model": model_for(agent),
            "prompt": prompt,
            "stream": True,
            "options": options,
        }
        with requests.post(url, json=payload, stream=True, timeout=120) as response:
            for line in response.iter_lines():
                if line:
                    data = json.loads(line)
                    token = data.get("response", "")
                    if token:
                        yield token
                    if data.get("done"):
                        break
        _cb_record_success()
    except (requests.exceptions.ConnectionError, requests.exceptions.Timeout):
        _cb_record_failure()
        yield "I'm offline. Is Ollama running?"
    except Exception as e:
        yield f"Brain hiccup: {str(e)[:40]}"


def ask_llm_fast(prompt: str, max_tokens: int = 80) -> str:
    """
    Low-latency Ollama call for routing/classification.
    temperature=0, low num_predict — returns quickly with short output.
    """
    if _cb_is_open():
        return ""   # fail fast — router falls through to clarification/fallback
    try:
        url = f"{OLLAMA_HOST}/api/generate"
        payload = {
            "model": OLLAMA_MODEL,
            "prompt": prompt,
            "stream": False,
            # Routing must be deterministic — fixed temp 0, no AutoTune.
            "options": {"temperature": 0, "top_p": 1.0, "num_predict": max_tokens},
        }
        response = requests.post(url, json=payload, timeout=30)
        if response.status_code == 200:
            _cb_record_success()
            return response.json().get("response", "").strip()
        return ""
    except (requests.exceptions.ConnectionError, requests.exceptions.Timeout):
        _cb_record_failure()
        return ""
    except Exception:
        return ""


def ask_llm(prompt: str, agent: str = None, autotune_on: bool = True,
            params: dict = None) -> str:
    """
    Query local Ollama LLM.

    - No cloud APIs / keys — all inference local.
    - agent: routes to a per-agent model (config.AGENT_MODELS), else default.
    - autotune_on: pick sampling params by query context (Phase 56).
    - params: explicit Ollama options override (skips AutoTune).
    """
    if _cb_is_open():
        return _CB_MSG
    try:
        url = f"{OLLAMA_HOST}/api/generate"
        model = model_for(agent)
        options = _resolve_options(
            prompt, agent, autotune_on, params,
            {"temperature": 0.7, "top_p": 0.9, "num_predict": 500},
        )
        payload = {
            "model": model,
            "prompt": prompt,
            "stream": False,
            "options": options,
        }

        # Longer timeout for local LLM thinking
        response = requests.post(url, json=payload, timeout=120)

        if response.status_code == 200:
            data = response.json()
            answer = data.get("response", "").strip()

            if answer and len(answer) > 0:
                _cb_record_success()
                print(f"[llm] {len(answer)} chars from {model} "
                      f"(ctx={autotune.last_context()})")
                return answer
            else:
                return "I'm thinking about that, boss. Give me a moment."
        else:
            print(f"[llm] Ollama error: {response.status_code}")
            return f"I'm having trouble thinking right now (Ollama: {response.status_code})"

    except requests.exceptions.ConnectionError:
        _cb_record_failure()
        return "I'm offline. Is Ollama running? (http://localhost:11434)"
    except requests.exceptions.Timeout:
        _cb_record_failure()
        return "That took too long to think about. Can you try again?"
    except Exception as e:
        print(f"[llm] error: {str(e)}")
        return f"Brain hiccup: {str(e)[:40]}"