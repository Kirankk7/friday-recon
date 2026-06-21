"""
Phase 57 — Critic pass (local, gated).

A self-review loop for high-stakes, NON-streaming answers: critique the draft for
hallucinations / missing steps / unsupported claims / errors, then revise only if
the critic flags something. One extra LLM round; never touches the token-streaming
chat path (that's why it's a standalone helper, not baked into ask_llm's stream).

Used by Ultron's security-report synthesis. Off by default → set CRITIC_ENABLED.
"""

# Agents whose long-form output is worth a review pass.
_HIGH_STAKES = {"ultron", "athena"}
_MIN_LEN = 200   # don't bother reviewing short replies


def _enabled() -> bool:
    try:
        import config
        return bool(getattr(config, "CRITIC_ENABLED", False))
    except Exception:
        return False


def should_refine(agent: str, draft: str) -> bool:
    return (_enabled()
            and (agent or "").lower() in _HIGH_STAKES
            and isinstance(draft, str) and len(draft) >= _MIN_LEN)


def refine(question: str, draft: str, agent: str = None) -> str:
    """
    Critique `draft`; revise only if issues are found. Returns the (possibly
    improved) text. Falls back to the original draft on any error.
    """
    if not should_refine(agent, draft):
        return draft

    from core.llm import ask_llm
    try:
        critique_prompt = (
            "You are a strict reviewer of a technical/security answer. "
            "List concrete problems ONLY: hallucinations, unsupported claims, "
            "missing steps, factual or logical errors. Be terse, one per line. "
            "If the answer is solid, reply with exactly: PASS\n\n"
            f"QUESTION:\n{question}\n\nANSWER:\n{draft}\n\nIssues:"
        )
        critique = ask_llm(critique_prompt, autotune_on=False,
                           params={"temperature": 0.2, "num_predict": 200}) or ""
        if "PASS" in critique[:12].upper() or not critique.strip():
            return draft

        revise_prompt = (
            "Revise the answer to fix the listed issues. Keep what was correct, "
            "stay concise and factual, do not invent details. Output only the "
            "revised answer.\n\n"
            f"QUESTION:\n{question}\n\nORIGINAL:\n{draft}\n\nISSUES:\n{critique}\n\nRevised answer:"
        )
        revised = ask_llm(revise_prompt, autotune_on=False,
                          params={"temperature": 0.3, "num_predict": 700})
        return revised.strip() if revised and revised.strip() else draft
    except Exception as e:
        print(f"[critic] refine skipped: {e}")
        return draft
