"""
F4 — Replay (rerun a recorded run from its timeline).

Separate concern from the Timeline recorder: the timeline is the immutable record;
replay READS it and reruns work. A full replay reruns the hunt from the recorded target;
a per-step replay reruns one stage against the artifacts that stage's inputs were captured
from (e.g. probe reruns against the exact endpoints recon crawled — no re-crawl).

Replay launches ACTIVE scans against the recorded target. It is exposed only through
authorized entry points (the recon CLI), never an unauthenticated endpoint.
"""
import os
import json

from core import timeline


def _artifact(run_id: str, name: str):
    """Load a persisted stage artifact (endpoints.json, findings.json, …). None if absent."""
    try:
        with open(os.path.join(timeline._RUNS_DIR, run_id, name), "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return None


def replay(run_id: str, step: str = None) -> dict:
    """Rerun a recorded run. No step (or 'full') reruns the whole hunt; a step name reruns
    that stage from recorded inputs/artifacts. Returns a {success, message, data} result."""
    tl = timeline.load(run_id)
    if not tl:
        return {"success": False, "message": f"No run '{run_id}' recorded.", "data": {}}
    target = tl.get("target", "")
    if not target:
        return {"success": False, "message": f"Run '{run_id}' has no target to replay.", "data": {}}

    from agents.ultron.ultron_agent import ultron_agent as U
    step = (step or "").strip().lower()

    if step in ("", "full", "all", "hunt"):
        r = U.bug_bounty(target, force=True)
        return {"success": r.get("success", False),
                "message": f"Replayed full hunt on {target}.",
                "data": {"new_run_id": r.get("data", {}).get("run_id"),
                         "report": r.get("data", {}).get("report", "")}}

    if step == "recon":
        r = U.full_pipeline(target)
        return {"success": r.get("success", False),
                "message": f"Replayed recon on {target}.",
                "data": r.get("data", {})}

    if step == "probe":
        urls = _artifact(run_id, "endpoints.json") or []
        posts = _artifact(run_id, "post_endpoints.json") or []
        findings = []
        for fn, arg in ((U._probe_injection, urls), (U._probe_path_params, urls),
                        (U._probe_stored_xss, urls), (U._probe_post, posts)):
            try:
                findings += fn(arg)
            except Exception:
                pass
        return {"success": True,
                "message": (f"Replayed probe over {len(urls)} endpoint(s) / {len(posts)} "
                            f"POST endpoint(s) -> {len(findings)} candidate finding(s)."),
                "data": {"findings": findings}}

    return {"success": False,
            "message": f"Step '{step}' is not replayable. Options: full | recon | probe.",
            "data": {}}
