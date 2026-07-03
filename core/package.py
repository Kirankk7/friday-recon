"""
F4 — Submission package (the Phase-2 deliverable).

Zip one recorded run into a single bounty submission: the immutable timeline, the raw
stage artifacts (endpoints/findings), the human report, and the F3 evidence bundle.
Everything reads from what the pipeline already persisted — this adds no new data, it
just assembles the deliverable.
"""
import os
import zipfile

from core import timeline


def _report_path(tl: dict) -> str:
    """The report.md recorded on the evidence event (saved outside the run dir)."""
    for e in tl.get("events", []):
        if e.get("step") == "evidence":
            for a in e.get("artifacts", []):
                if a.get("kind") == "report" and a.get("path"):
                    return a["path"]
    return ""


def build_package(run_id: str, dest: str = None) -> dict:
    """Assemble runs/<run_id> + its report + evidence/ into one zip. Returns
    {success, message, data:{path, files}}. Never raises."""
    tl = timeline.load(run_id)
    if not tl:
        return {"success": False, "message": f"No run '{run_id}' recorded.", "data": {}}

    run_dir = os.path.join(timeline._RUNS_DIR, run_id)
    files = []  # (abs_path, arcname)

    # 1) the run dir: timeline.json + persisted stage artifacts (skip prior zips)
    if os.path.isdir(run_dir):
        for root, _, names in os.walk(run_dir):
            for n in names:
                if n.endswith(".zip"):
                    continue
                fp = os.path.join(root, n)
                files.append((fp, os.path.relpath(fp, run_dir)))

    # 2) the human report + its F3 evidence bundle (saved in the reports folder)
    report = _report_path(tl)
    if report and os.path.exists(report):
        files.append((report, os.path.basename(report)))
        ev_dir = os.path.join(os.path.dirname(report), "evidence")
        if os.path.isdir(ev_dir):
            for root, _, names in os.walk(ev_dir):
                for n in names:
                    fp = os.path.join(root, n)
                    files.append((fp, os.path.join("evidence", os.path.relpath(fp, ev_dir))))

    if not files:
        return {"success": False, "message": f"Run '{run_id}' has nothing to package.", "data": {}}

    dest = dest or os.path.join(run_dir, f"submission_{run_id[:8]}.zip")
    try:
        os.makedirs(os.path.dirname(dest), exist_ok=True)
        with zipfile.ZipFile(dest, "w", zipfile.ZIP_DEFLATED) as z:
            for fp, arc in files:
                z.write(fp, arc)
    except Exception as e:
        return {"success": False, "message": f"Package failed: {e}", "data": {}}

    return {"success": True,
            "message": f"Submission package: {dest} ({len(files)} file(s)).",
            "data": {"path": dest, "files": len(files)}}
