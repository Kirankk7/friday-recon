"""
F4 — Execution Timeline (pure recorder).

Every pipeline stage is independently inspectable: record not just *that* a step ran,
but *what it produced*. The timeline is IMMUTABLE + versioned (same discipline as the
Evidence Object): written once, everything downstream (viewer, replay, package) reads it.

This module is a PURE RECORDER — no pipeline coupling. It builds one canonical
ExecutionTimeline object and persists it to data/runs/<run_id>/timeline.json. Read side
(viewer), replay, and packaging are separate modules that consume this file.

Guardrail: the recorder must NEVER break the pipeline. Persistence is wrapped in
try/except and degrades silently. The `step()` context manager times a stage and records
its outcome, then re-raises so pipeline behaviour is unchanged.
"""
import os
import json
import uuid
import datetime
from contextlib import contextmanager

SCHEMA_VERSION = 1
_RUNS_DIR = os.path.join("data", "runs")


def _now() -> str:
    return datetime.datetime.now().isoformat(timespec="seconds")


class Timeline:
    """One run's immutable execution record. Build via start_run()."""

    def __init__(self, target: str = "", run_id: str = None, persist: bool = True):
        self.schema_version = SCHEMA_VERSION
        self.run_id = run_id or uuid.uuid4().hex
        self.target = target or ""
        self.started_at = _now()
        self.finished_at = None
        self.status = "running"          # running | ok | partial | failed
        self.events = []
        self._persist = persist

    # ── paths ──
    @property
    def run_dir(self) -> str:
        return os.path.join(_RUNS_DIR, self.run_id)

    def artifact_path(self, name: str) -> str:
        """Absolute-ish path under this run's dir; ensures the dir exists."""
        try:
            os.makedirs(self.run_dir, exist_ok=True)
        except Exception:
            pass
        return os.path.join(self.run_dir, name)

    def write_artifact(self, name: str, data, kind: str = "json") -> dict:
        """Persist a stage's output under the run dir so replay/debugging can read exactly
        what it emitted (not just counts). Returns the artifact ref for an event's
        artifacts[], or {} on failure. Never raises."""
        try:
            path = self.artifact_path(name)
            with open(path, "w", encoding="utf-8") as f:
                if kind == "json":
                    json.dump(data, f, indent=2, default=str)
                else:
                    f.write(data if isinstance(data, str) else str(data))
            return {"name": name, "path": path, "kind": kind}
        except Exception:
            return {}

    # ── recording ──
    def record_event(self, step: str, tool: str = "", inputs=None, outputs=None,
                     artifacts=None, exit_code=None, status: str = "ok",
                     error: str = None, started_at: str = None, finished_at: str = None,
                     duration_ms=None, parent_event: str = None) -> str:
        """Append one event; persist. Returns the event_id. Never raises."""
        event_id = uuid.uuid4().hex
        try:
            started_at = started_at or _now()
            finished_at = finished_at or started_at
            event = {
                "event_id": event_id,
                "step": step,
                "tool": tool or "",
                "started_at": started_at,
                "finished_at": finished_at,
                "duration_ms": duration_ms,
                "inputs": inputs or {},
                "outputs": outputs or {},
                "artifacts": artifacts or [],
                "exit_code": exit_code,
                "status": status,              # ok | skipped | failed
                "error": error,
                "parent_event": parent_event,
            }
            self.events.append(event)
            self._save()
        except Exception:
            pass
        return event_id

    @contextmanager
    def step(self, step: str, tool: str = "", inputs=None, parent_event: str = None):
        """Time a pipeline stage and record its outcome. Re-raises on failure so
        pipeline behaviour is unchanged. Yields a mutable dict the caller fills with
        outputs/artifacts before the block exits:

            with tl.step("subfinder", inputs={"target": t}) as ev:
                domains = run_subfinder(t)
                ev["outputs"] = {"domains": len(domains)}
                ev["artifacts"] = [{"name": "subdomains.txt", "path": p, "kind": "text"}]
        """
        t0 = datetime.datetime.now()
        ev = {"outputs": {}, "artifacts": [], "exit_code": None}
        error = None
        status = "ok"
        try:
            yield ev
        except Exception as e:
            status = "failed"
            error = f"{type(e).__name__}: {e}"
            raise
        finally:
            t1 = datetime.datetime.now()
            self.record_event(
                step, tool=tool, inputs=inputs,
                outputs=ev.get("outputs"), artifacts=ev.get("artifacts"),
                exit_code=ev.get("exit_code"), status=status, error=error,
                started_at=t0.isoformat(timespec="seconds"),
                finished_at=t1.isoformat(timespec="seconds"),
                duration_ms=int((t1 - t0).total_seconds() * 1000),
                parent_event=parent_event,
            )

    def finish(self, status: str = None) -> str:
        """Seal the run. Status defaults from event outcomes. Returns timeline.json path."""
        self.finished_at = _now()
        if status:
            self.status = status
        elif any(e.get("status") == "failed" for e in self.events):
            self.status = "partial" if any(e.get("status") == "ok" for e in self.events) else "failed"
        else:
            self.status = "ok"
        self._save()
        return os.path.join(self.run_dir, "timeline.json")

    # ── serialize / persist ──
    def to_dict(self) -> dict:
        return {
            "schema_version": self.schema_version,
            "run_id": self.run_id,
            "target": self.target,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "status": self.status,
            "events": self.events,
        }

    def _save(self):
        if not self._persist:
            return
        try:
            os.makedirs(self.run_dir, exist_ok=True)
            path = os.path.join(self.run_dir, "timeline.json")
            with open(path, "w", encoding="utf-8") as f:
                json.dump(self.to_dict(), f, indent=2)
        except Exception:
            pass


# ── module API ──
def start_run(target: str = "", run_id: str = None, persist: bool = True) -> Timeline:
    """Begin recording a run."""
    return Timeline(target=target, run_id=run_id, persist=persist)


def load(run_id: str) -> dict:
    """Read a persisted timeline back (for the viewer/replay). None if absent."""
    try:
        path = os.path.join(_RUNS_DIR, run_id, "timeline.json")
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return None


def list_runs() -> list:
    """Run ids present under data/runs/, newest first."""
    try:
        ids = [d for d in os.listdir(_RUNS_DIR)
               if os.path.isfile(os.path.join(_RUNS_DIR, d, "timeline.json"))]
        ids.sort(key=lambda d: os.path.getmtime(os.path.join(_RUNS_DIR, d, "timeline.json")),
                 reverse=True)
        return ids
    except Exception:
        return []


# ── viewer (read side) ──
_MARK = {"ok": "✓", "skipped": "○", "failed": "✗", "running": "…"}


def _summary(outputs: dict) -> str:
    """One-line 'k v, k v' from an event's outputs (skip zero/empty)."""
    if not outputs:
        return ""
    return ", ".join(f"{v} {k}" for k, v in outputs.items() if v not in (0, "", None))


def render(run_id: str) -> str:
    """Platform-feel view of one run (the design's viewer target). '' if absent."""
    tl = load(run_id)
    if not tl:
        return ""
    head = f"Run {tl.get('started_at','')}  ({run_id[:8]}…)  [{tl.get('status','')}]"
    lines = [head, f"  Target: {tl.get('target','')}"]
    for e in tl.get("events", []):
        mark = _MARK.get(e.get("status"), " ")
        dur = e.get("duration_ms")
        dur_s = f"{dur/1000:.1f}s" if isinstance(dur, (int, float)) else ""
        summary = _summary(e.get("outputs")) or (e.get("error") or "")
        lines.append(f"  {mark} {e.get('step',''):<10} {summary:<28} {dur_s}".rstrip())
    return "\n".join(lines)


def render_list(limit: int = 20) -> str:
    """One line per recent run: id · status · target · #events."""
    out = []
    for rid in list_runs()[:limit]:
        tl = load(rid) or {}
        out.append(f"{rid[:8]}…  {tl.get('status',''):<8} {tl.get('target',''):<24} "
                   f"{len(tl.get('events', []))} events  {tl.get('started_at','')}")
    return "\n".join(out) or "No runs recorded yet."
