#!/usr/bin/env python
"""
friday-recon CLI CHAIN dogfood (40-day plan, Days 21-40). Tests the seams UNIQUE to the
CLI: CROSS-PROCESS state (each verb is a fresh process — does state written by one persist
and read correctly by the next?), verb pipelines, and concurrent-write races on data/*.json.

Each verb runs as a subprocess with a forced cp1252 console. Asserts: no crash, cp1252-clean
output, sane exit, AND state flows process->process. Needs probe_lab on :7000.
"""
import os, sys, subprocess, json, time

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
L = "http://127.0.0.1:7000"
results = []


def cli(*args, timeout=120):
    env = dict(os.environ, PYTHONIOENCODING="cp1252", JARVIS_CI="1")
    p = subprocess.run([sys.executable, "cli.py", *args], cwd=HERE, env=env,
                       capture_output=True, timeout=timeout)
    out = (p.stdout or b"").decode("cp1252", "replace")
    err = (p.stderr or b"").decode("utf-8", "replace")
    crashed = "Traceback" in err or "UnicodeEncodeError" in err
    return out, err, p.returncode, crashed


def check(name, fn):
    try:
        fn()
        results.append((name, "PASS", ""))
    except AssertionError as e:
        results.append((name, "FAIL", str(e)[:60]))
    except Exception as e:
        results.append((name, "CRASH", f"{type(e).__name__}: {str(e)[:45]}"))


# ---- D22: cross-process session state: set in one process, used in another ----
def c_session_xprocess():
    cli("session-set", "userA", "uid=1")
    cli("session-set", "userB", "uid=2")
    out, err, rc, crashed = cli("sessions")            # fresh process must SEE both
    assert not crashed, f"sessions crashed: {err[-60:]}"
    assert "userA" in out and "userB" in out, "sessions not persisted cross-process"
    out, err, rc, crashed = cli("idor", f"{L}/account?id=1")  # fresh process reads sessions.json
    assert not crashed, f"idor crashed: {err[-60:]}"
    assert "candidate" in out.lower() or "cross-principal" in out.lower(), f"idor didn't run off persisted sessions: {out[:60]}"


# ---- D23: knowledge persists: playbook recall in a fresh process ----
def c_playbook_xprocess():
    out, err, rc, crashed = cli("playbook", "jwt bypass")
    assert not crashed and "technique" in out.lower(), f"playbook recall broke: {out[:50]}"


# ---- D24: scope chain: scope-setup -> scope (fresh process reads scope.json) ----
def c_scope_xprocess():
    pol = os.path.join(HERE, "_chain_policy.txt")
    open(pol, "w", encoding="utf-8").write("In scope: *.example.com. Out of scope: tls, missing headers. 5 req/s.")
    try:
        cli("scope-setup", pol)
        out, err, rc, crashed = cli("scope")           # fresh process must read the saved scope
        assert not crashed, f"scope crashed: {err[-60:]}"
        assert "example.com" in out, f"scope not persisted: {out[:60]}"
    finally:
        os.remove(pol)


# ---- D30: corrupt data/*.json mid-chain -> next verb recovers, no crash ----
def c_corrupt_state_recover():
    for fn in ("sessions.json", "target_profiles.json"):
        p = os.path.join(HERE, "data", fn)
        bak = open(p, encoding="utf-8").read() if os.path.exists(p) else None
        try:
            os.makedirs(os.path.dirname(p), exist_ok=True)
            open(p, "w", encoding="utf-8").write("{corrupt ][ json")
            verb = "sessions" if fn == "sessions.json" else "targets"
            out, err, rc, crashed = cli(verb)
            assert not crashed, f"{verb} crashed on corrupt {fn}: {err[-50:]}"
        finally:
            if bak is not None: open(p, "w", encoding="utf-8").write(bak)
            elif os.path.exists(p): os.remove(p)


# ---- D36: concurrent writers to the same store -> no crash / corruption ----
def c_concurrent_write_race():
    env = dict(os.environ, PYTHONIOENCODING="cp1252", JARVIS_CI="1")
    procs = [subprocess.Popen([sys.executable, "cli.py", "session-set", f"u{i}", f"uid={i}"],
                              cwd=HERE, env=env, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
             for i in range(6)]
    for pr in procs: pr.wait(timeout=60)
    # the store must still be VALID json after concurrent writes (last-writer-wins is OK; corruption isn't)
    p = os.path.join(HERE, "data", "sessions.json")
    try:
        json.load(open(p, encoding="utf-8"))            # must parse = not corrupted
    except Exception as e:
        raise AssertionError(f"concurrent writes corrupted sessions.json: {e}")


# ---- D21: full hunt pipeline contract (graceful, exit codes) on a fast target ----
def c_hunt_pipeline_contract():
    out, err, rc, crashed = cli("crawl", L)
    assert not crashed and rc in (0, 1), f"crawl pipeline broke rc={rc}"
    out, err, rc, crashed = cli("graphql", f"{L}/render?tpl=x")  # not gql -> graceful exit
    assert not crashed, f"graphql crashed: {err[-50:]}"


for nm, fn in [("D22 cross-process session->idor", c_session_xprocess),
               ("D23 playbook recall (fresh process)", c_playbook_xprocess),
               ("D24 scope-setup->scope (cross-process)", c_scope_xprocess),
               ("D30 corrupt-state recovery (CLI)", c_corrupt_state_recover),
               ("D36 concurrent-write race (no corruption)", c_concurrent_write_race),
               ("D21 hunt pipeline contract", c_hunt_pipeline_contract)]:
    check(nm, fn)

print(f"{'chain':44} status note")
print("-" * 78)
for name, status, note in results:
    print(f"{name:44} {status:6} {note}")
print("-" * 78)
fails = sum(1 for _, s, _ in results if s != "PASS")
print(f"{len(results)-fails}/{len(results)} PASS" + ("" if not fails else f"  — {fails} need attention"))
sys.exit(1 if fails else 0)
