#!/usr/bin/env python3
"""Pre-push disclosure guard — refuse to publish target-identifying or credential material.

Both repos are PUBLIC and the bug-bounty programs behind the hunts forbid disclosure ("full, partial or
otherwise"). The engine is publishable; the hunt is not. A near-miss earned this: `git add <file>` on a
file that ALREADY carried unrelated uncommitted changes swept a detailed hunt log — program name, how
their authz resolved, real test-account ids — into a commit that was three deep in local history and one
`git push` from being permanent.

Fail-closed by design: exit 1 on any hit. The cost is asymmetric — a false alarm costs a re-read, a miss
is an irreversible public disclosure against a program that explicitly forbids it.

This does NOT replace reading `git diff` yourself. Grep cannot see an architecture note, a TODO holding
confidential context, or a program's name spelled in prose. It catches the mechanical mistakes so the
human review can spend its attention on the things only a human can catch.

    python scripts/prepush_scan.py [<base-ref>]      # default: origin/<current-branch>

Target names deliberately live OUTSIDE this file, in `.hunt_targets` (gitignored, one name per line):
listing the programs you hunt inside a public repo would itself be the disclosure this guard exists to
prevent. No file, no name-checking — the credential patterns still run.
"""
import os
import re
import subprocess
import sys

# Credential / operator-identifying shapes. Generic on purpose: these are patterns, not secrets, so they
# are safe to publish. Anything target-SPECIFIC belongs in .hunt_targets.
PATTERNS = [
    ("JWT",                 re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}")),
    ("Bearer token",        re.compile(r"Bearer\s+[A-Za-z0-9._~+/-]{20,}", re.I)),
    # quotes and hyphens are the normal shapes in captured traffic ("Authorization": ..., SESSID-FOO=...)
    ("Authorization header", re.compile(r"authorization[\"']?\s*[:=]\s*[\"']?\S", re.I)),
    ("Cookie header",       re.compile(r"\bcookie[\"']?\s*[:=]\s*[\"']?[\w.-]+=", re.I)),
    ("session id",          re.compile(r"\b(?:PHPSESSID|JSESSIONID|SESSID[\w-]*|sessionid)\s*=\s*[A-Za-z0-9]{8,}", re.I)),
    ("api key / secret",    re.compile(r"\b(?:api[_-]?key|client[_-]?secret|access[_-]?token|"
                                       r"secret[_-]?key|private[_-]?key)\b\s*[:=]\s*[\"']?[A-Za-z0-9_\-]{16,}", re.I)),
    ("AWS key id",          re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("OOB listener URL",    re.compile(r"\b(?:webhook\.site|burpcollaborator\.net|oastify\.com|"
                                       r"interact\.sh|requestbin|pipedream\.net)\b", re.I)),
    ("email address",       re.compile(r"\b[A-Za-z0-9._%+-]+@(?!example\.(?:com|org)\b)"
                                       r"[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")),
    ("researcher handle",   re.compile(r"\byeswehack\.ninja\b|\bywh[-_]?alias\b", re.I)),
]


def _git(*args) -> str:
    """Decode UTF-8 explicitly. Under the Windows locale (cp1252) an em-dash in a diff raised
    UnicodeDecodeError and killed the scan — fail-closed kept it safe, but a guard that dies on
    ordinary prose is a guard that gets bypassed."""
    out = subprocess.run(["git", *args], capture_output=True).stdout
    return out.decode("utf-8", "replace") if out else ""


def _base_ref(explicit: str = "") -> str:
    if explicit:
        return explicit
    branch = _git("rev-parse", "--abbrev-ref", "HEAD").strip() or "main"
    for ref in (f"origin/{branch}", "origin/main", "origin/master"):
        if _git("rev-parse", "--verify", "--quiet", ref).strip():
            return ref
    return ""        # nothing pushed yet -> scan the whole history


def _target_names() -> list:
    """Program/host names from the gitignored .hunt_targets (never hardcoded — see module docstring)."""
    root = _git("rev-parse", "--show-toplevel").strip() or "."
    path = os.path.join(root, ".hunt_targets")
    if not os.path.exists(path):
        return []
    with open(path, encoding="utf-8", errors="replace") as f:
        return [ln.strip() for ln in f
                if ln.strip() and not ln.lstrip().startswith("#") and len(ln.strip()) >= 3]


_SELF = "scripts/prepush_scan.py"     # its own pattern definitions are patterns, not secrets
_ALLOW = "prepush: allow"             # inline escape hatch for a line that is genuinely generic


def scan(diff: str, names: list) -> list:
    """-> [(label, file, line)]. Only ADDED lines matter; removals cannot leak.

    Path-aware so a hit names its file, and so this guard does not flag its own regex table (it caught
    itself on the first run — correct behaviour, wrong target)."""
    checks = [(lbl, rx) for lbl, rx in PATTERNS]
    checks += [(f"target name '{n}'", re.compile(re.escape(n), re.I)) for n in names]

    hits, path = [], ""
    for line in diff.splitlines():
        if line.startswith("+++ b/"):
            path = line[6:].strip()
            continue
        if not line.startswith("+") or line.startswith("+++"):
            continue
        if path == _SELF or _ALLOW in line:
            continue
        for label, rx in checks:
            if rx.search(line):
                hits.append((label, path, line.strip()[:150]))

    seen, uniq = set(), []
    for h in hits:
        if h not in seen:
            seen.add(h)
            uniq.append(h)
    return uniq


def main() -> int:
    base = _base_ref(sys.argv[1] if len(sys.argv) > 1 else "")
    diff = _git("diff", f"{base}..HEAD") if base else _git("diff", "--cached")
    if not diff.strip():
        print("pre-push scan: nothing outgoing.")
        return 0

    names = _target_names()
    hits = scan(diff, names)
    scope = f"{base}..HEAD" if base else "staged changes"
    if not hits:
        print(f"pre-push scan: clean ({scope}"
              + (f", {len(names)} target name(s) checked)." if names else
                 ", no .hunt_targets file — credential patterns only)."))
        print("  Still read the diff: grep cannot see prose, notes, or context only a human recognises.")
        return 0

    print(f"\n  PUSH BLOCKED — {len(hits)} disclosure risk(s) in {scope}:\n")
    for label, path, line in hits[:25]:
        print(f"    [{label}]  {path}\n      {line}")
    if len(hits) > 25:
        print(f"    ... and {len(hits) - 25} more")
    print("\n  Nothing is published yet, so history is still safe to rewrite:")
    print("    git reset --soft <base>   # unwind, keep the work")
    print("    # sanitize, then recommit code only — the engine is public, the hunt is not")
    print("  Override only if every hit above is genuinely generic: git push --no-verify\n")
    return 1


if __name__ == "__main__":
    sys.exit(main())
