#!/usr/bin/env python
"""
Dogfood harness (Tier 0): drive every Ultron probe against the probe_lab TP/FP bench,
assert TP is flagged and FP-trap stays silent. Prints a PASS/FAIL table; exits non-zero
on any FAIL (a FAIL row = a bug in OUR probe to chase by hand).

Prereq:  python labs/probe_lab/app.py   (running on :7000)
Run:     python scripts/dogfood.py
"""
import os, sys, time
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

L = "http://127.0.0.1:7000"


def _reachable():
    import urllib.request
    try:
        urllib.request.urlopen(L + "/", timeout=4)
        return True
    except Exception:
        return False


def main():
    if not _reachable():
        print("probe_lab not reachable on :7000 — run `python labs/probe_lab/app.py` first.")
        sys.exit(2)
    import agents.ultron.ultron_agent as _ult
    U = _ult.ultron_agent

    def tps(res):                      # set of templates flagged
        return {r["template"] for r in (res or [])}

    # each check: (name, want_template, TP-call, FP-call)
    checks = []

    def add(name, tmpl, tp, fp):
        checks.append((name, tmpl, tp, fp))

    add("path-param SQLi", "sqli-error-based",
        lambda: U._probe_path_params([f"{L}/api/user/1"]),
        lambda: U._probe_path_params([f"{L}/api/safe/1"]))
    add("SSTI", "ssti",
        lambda: U._probe_injection([f"{L}/render?tpl=hi"]),
        lambda: U._probe_injection([f"{L}/render_safe?tpl=hi"]))
    add("cmd-injection", "command-injection",
        lambda: U._probe_injection([f"{L}/ping?host=127.0.0.1"]),
        lambda: U._probe_injection([f"{L}/ping_safe?host=127.0.0.1"]))
    add("time-blind SQLi", "sqli-blind-time",
        lambda: U._probe_injection([f"{L}/q?id=1"], max_params=1),
        lambda: U._probe_injection([f"{L}/slow?id=1"], max_params=1))   # always-slow must NOT flag
    add("stored-XSS", "xss-stored",
        lambda: U._probe_stored_xss([f"{L}/post?c=x", f"{L}/wall"]),
        lambda: U._probe_stored_xss([f"{L}/post_safe?c=x", f"{L}/wall_safe"]))
    add("host-header", "host-header-injection",
        lambda: U._probe_injection([f"{L}/reset?email=x"]),
        lambda: U._probe_injection([f"{L}/reset_safe?email=x"]))
    add("NoSQL auth-bypass", "nosqli-operator",
        lambda: U._probe_post([{"url": f"{L}/login", "method": "POST",
                                "body": '{"username":"x","password":"y"}', "ctype": "application/json"}]),
        lambda: U._probe_post([{"url": f"{L}/login_safe", "method": "POST",
                                "body": '{"username":"x","password":"y"}', "ctype": "application/json"}]))
    add("XXE", "xxe",
        lambda: U._probe_post([{"url": f"{L}/xml", "method": "POST",
                                "body": "<?xml version='1.0'?><d><n>x</n></d>", "ctype": "application/xml"}]),
        lambda: U._probe_post([{"url": f"{L}/xml_safe", "method": "POST",
                                "body": "<?xml version='1.0'?><d><n>x</n></d>", "ctype": "application/xml"}]))

    print(f"{'class':20} {'TP(catch)':12} {'FP(silent)':12} verdict")
    print("-" * 58)
    fails = 0
    for name, tmpl, tp, fp in checks:
        t0 = time.time()
        try:
            tp_hit = tmpl in tps(tp())
        except Exception as e:
            tp_hit = f"ERR:{str(e)[:20]}"
        try:
            fp_clean = tmpl not in tps(fp())
        except Exception as e:
            fp_clean = f"ERR:{str(e)[:20]}"
        ok = (tp_hit is True) and (fp_clean is True)
        if not ok:
            fails += 1
        dt = time.time() - t0
        print(f"{name:20} {str(tp_hit):12} {str(fp_clean):12} {'PASS' if ok else 'FAIL'}  ({dt:.0f}s)")

    print("-" * 58)
    print(f"{len(checks) - fails}/{len(checks)} PASS" + ("" if not fails else f"  — {fails} FAIL (chase by hand)"))
    sys.exit(1 if fails else 0)


if __name__ == "__main__":
    main()
