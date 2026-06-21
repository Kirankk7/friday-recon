#!/usr/bin/env python3
"""
ht_search.py — Query tools.json.

Emits a compact JSON list of matching tools. Intended to be grepped/piped
by Claude to pick a tool before calling ht_run.py.

Filters are ANDed:
  --q TEXT          substring match on title + description + tags + id
  --category NAME   exact category match (e.g. information_gathering)
  --tag TAG         tag match (exact, lowercase)
  --capability K    key in capabilities that must be true
                    (runnable_by_claude, interactive, requires_sudo, ...)
  --no-capability K key must be false/absent
  --os OS           supported_os must include this (linux, macos)
  --installed-only  hide archived tools
  --limit N         cap results (default 50)

Output: JSON array of minimal records {id, title, category, description, tags, capabilities, run_commands, project_url}.
"""

import argparse
import json
import sys
from pathlib import Path

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")


DATA_PATH = Path(__file__).resolve().parent.parent / "data" / "tools.json"


def load() -> list[dict]:
    if not DATA_PATH.exists():
        sys.exit(json.dumps({"error": f"tools.json missing at {DATA_PATH}. Run ht_index.py."}))
    return json.loads(DATA_PATH.read_text(encoding="utf-8"))["tools"]


def match(t: dict, q: str | None, category: str | None, tag: str | None,
          capability: list[str], no_capability: list[str],
          os_filter: str | None, installed_only: bool) -> bool:
    if installed_only and t.get("archived"):
        return False
    if q:
        q_low = q.lower()
        blob = " ".join([
            t.get("id", ""), t.get("title", ""), t.get("description", ""),
            " ".join(t.get("tags") or []),
        ]).lower()
        if q_low not in blob:
            return False
    if category and t.get("category") != category:
        return False
    if tag and tag.lower() not in [x.lower() for x in (t.get("tags") or [])]:
        return False
    caps = t.get("capabilities") or {}
    for k in capability:
        if not caps.get(k):
            return False
    for k in no_capability:
        if caps.get(k):
            return False
    if os_filter and os_filter not in (t.get("supported_os") or []):
        return False
    return True


def compact(t: dict) -> dict:
    return {
        "id": t["id"],
        "title": t["title"],
        "category": t["category"],
        "description": t["description"],
        "tags": t.get("tags") or [],
        "capabilities": t.get("capabilities") or {},
        "run_commands": t.get("run_commands") or [],
        "project_url": t.get("project_url") or "",
    }


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--q", default=None)
    ap.add_argument("--category", default=None)
    ap.add_argument("--tag", default=None)
    ap.add_argument("--capability", action="append", default=[])
    ap.add_argument("--no-capability", action="append", default=[], dest="no_capability")
    ap.add_argument("--os", dest="os_filter", default=None, choices=["linux", "macos"])
    ap.add_argument("--installed-only", action="store_true")
    ap.add_argument("--limit", type=int, default=50)
    args = ap.parse_args()

    tools = load()
    matches = [
        compact(t) for t in tools
        if match(t, args.q, args.category, args.tag,
                 args.capability, args.no_capability,
                 args.os_filter, args.installed_only)
    ]
    matches = matches[: args.limit]
    print(json.dumps({"count": len(matches), "tools": matches}, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
