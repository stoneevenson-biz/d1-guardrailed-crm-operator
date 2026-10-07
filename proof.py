#!/usr/bin/env python3
"""Red -> green proof: plant a real defect, watch the acceptance suite fail, remove it, watch it pass.

Synthetic scenario — not a client deployment. The defect is planted in a throwaway copy of the
code in a temp directory; the real files are never edited, so an interrupted run leaves nothing behind.

    python3 proof.py                           # recording flow: green -> plant 'scope-contact' -> red -> removed -> green
    python3 proof.py --mutation send-with-approval   # same flow with another defect
    python3 proof.py --all                     # every defect must turn the suite red (exit 1 if one survives)
    python3 proof.py --list                    # show the defects
"""

import argparse
import difflib
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent
P = "guardrail/policy.py"
G = "guardrail/gateway.py"
A = "guardrail/audit.py"
T = "guardrail/approvals.py"
R = "guardrail/runner.py"
C = "guardrail/crm.py"
DEFAULT = "scope-contact"

# name -> (what breaks, [(file, exact original text, defective text), ...]). Each original must occur once.
MUTATIONS = {
    "read-sql-injection": (
        "Search builds its SQL from the agent's text, so a crafted query rewrites the read (SQL injection)",
        [(C, '''"SELECT id, name, stage FROM contacts WHERE name LIKE ? OR notes LIKE ? OR stage LIKE ? ORDER BY id",
        (like, like, like),''',
             '''f"SELECT id, name, stage FROM contacts WHERE name LIKE '{like}' OR notes LIKE '{like}' OR stage LIKE '{like}' ORDER BY id",''')],
    ),
    "write-no-token": (
        "A write with no approval token is treated as approved",
        [(P, 'return needs_approval("approval-required")', 'return allow("approval-required")')],
    ),
    "scope-contact": (
        "The approval's contact scope is not checked: approving one contact unlocks every contact",
        [(P, '    if args["contact_id"] not in grant["contact_ids"]:\n        return deny("out-of-scope:contact")\n', "")],
    ),
    "scope-action": (
        "The approval's action is not checked: an approval to add a tag also changes stages and removes tags",
        [(P, '    if grant["action"] != tool:\n        return deny("out-of-scope:action")\n', "")],
    ),
    "scope-value": (
        "The approval's value is not checked: approving stage 'qualified' also allows 'won'",
        [(P, 'if spec.value_arg and args[spec.value_arg] not in grant["values"]:',
             'if spec.value_arg and args[spec.value_arg] is None:')],
    ),
    "expiry-units": (
        "Expiry compared in mixed units (seconds vs milliseconds), so approvals never expire",
        [(P, 'if now_ts >= grant["exp"]:', 'if now_ts >= grant["exp"] * 1000:')],
    ),
    "expiry-boundary": (
        "Off by one at the expiry instant: a 10-minute approval still works at exactly 10 minutes",
        [(P, 'if now_ts >= grant["exp"]:', 'if now_ts > grant["exp"]:')],
    ),
    "ttl-cap": (
        "No cap on approval lifetime: a human can issue a day-long (or never-ending) approval",
        [(P, 'if not (type(ttl_seconds) is int and 0 < ttl_seconds <= policy["max_ttl_seconds"]):',
             'if not (type(ttl_seconds) is int and 0 < ttl_seconds):')],
    ),
    "replay": (
        "Off by one on the use count: a single-use approval can be replayed once more",
        [(P, 'if uses >= grant["max_uses"]:', 'if uses > grant["max_uses"]:')],
    ),
    "token-signature": (
        "Token signature only checked for presence, so an altered (widened, extended) token is accepted",
        [(T, "if not hmac.compare_digest(_sig(key, body), sig):", "if not sig:")],
    ),
    "self-approve": (
        "Approver list not checked, so the agent's own identity can issue approvals",
        [(P, '    if approver not in policy["approvers"]:\n        return "not-an-approver"\n', "")],
    ),
    "grant-send": (
        "Sends, deletes and unknown tools can be approved like any write",
        [(P, '    if classify(policy, action) != WRITE:\n        return "not-grantable"',
             '    if classify(policy, action) == READ:\n        return "not-grantable"')],
    ),
    "send-with-approval": (
        "The never-list only applies when no token is presented, so a token naming sms.send sends the text",
        [(P, "if cls == NEVER or spec is None:", "if (cls == NEVER and not presented) or spec is None:")],
    ),
    "default-allow": (
        "A tool nobody classified defaults to read, so a newly added export tool runs unchecked",
        [(P, "return NEVER  # default deny: a tool nobody classified never runs", "return READ")],
    ),
    "stage-validation": (
        "Stage not checked against the pipeline, so a (mis)approved value writes a stage that does not exist",
        [(P, '    if "stage" in args and args["stage"] not in policy["stages"]:\n        return "invalid-stage"\n', "")],
    ),
    "control-chars": (
        "Hidden characters allowed in text: a tag 'hot-lead' plus a newline, or a terminal escape, gets through",
        [(P, "0 < len(value) <= MAX_TEXT and value.isprintable() and _utf8(value)", "0 < len(value) <= MAX_TEXT")],
    ),
    "id-range": (
        "Contact ids not range-checked: an id larger than the database's integer crashes the check",
        [(P, "if kind is int and not 0 < value <= MAX_ID:", "if kind is int and not 0 < value:")],
    ),
    "grant-scope": (
        "An approval's contact list is not validated, so a malformed scope is signed and issued",
        [(P, "if not (isinstance(contact_ids, list) and contact_ids and all(type(c) is int and 0 < c <= MAX_ID for c in contact_ids)):",
             "if not isinstance(contact_ids, list):")],
    ),
    "audit-fail-open": (
        "An audit-log failure is swallowed and the action runs anyway (fail open)",
        [(G, '            return {"status": "denied", "reason": "audit-unavailable"}', "            pass")],
    ),
    "audit-denials": (
        "Only allowed calls are logged; refusals and approval requests leave no trace",
        [(G, '        try:\n            self.audit.append(\n                iso(now), actor, "decision",',
             '        try:\n            if d.decision == "allow": self.audit.append(\n                iso(now), actor, "decision",')],
    ),
    "audit-append-only": (
        "Audit log can be silently edited (append-only triggers removed)",
        [(A, "BEGIN SELECT RAISE(ABORT, 'audit_log is append-only'); END;\nCREATE TRIGGER IF NOT EXISTS audit_log_no_delete",
             "BEGIN SELECT 1; END;\nCREATE TRIGGER IF NOT EXISTS audit_log_no_delete"),
         (A, "BEFORE DELETE ON audit_log\nBEGIN SELECT RAISE(ABORT, 'audit_log is append-only'); END;",
             "BEFORE DELETE ON audit_log\nBEGIN SELECT 1; END;")],
    ),
    "audit-chain": (
        "The hash chain leaves out the detail column, so an edited entry still verifies",
        [(A, "content = json.dumps({k: row[k] for k in FIELDS}, sort_keys=True)",
             'content = json.dumps({k: row[k] for k in FIELDS if k != "detail"}, sort_keys=True)')],
    ),
    "audit-unicode": (
        "Text that is not valid UTF-8 is written to the log as is, so the write fails and the refusal is lost",
        [(A, '    return str(value).encode("utf-8", "backslashreplace").decode("utf-8")', "    return value")],
    ),
    "audit-size": (
        "The agent's arguments are logged whole, so one call can bloat the log by megabytes",
        [(G, "    return args if len(text) <= MAX_LOGGED_ARGS else", "    return args if True else")],
    ),
    "pipe-limit": (
        "No per-message size limit on the pipe: an oversized message is read in pieces and misparsed",
        [(R, "        if len(line) > MAX_LINE:", "        if False:")],
    ),
    "demo-escape": (
        "The demo prints the agent's tool name raw in the audit listing, so a crafted name forges an approval row",
        [("demo.py", "{clean(r['tool'] or '', 60):<20}", "{r['tool'] or '':<20}")],
    ),
    "agent-env-leak": (
        "The agent process inherits the parent's environment, API keys included",
        [(R, "    return {}\n", "    return None  # inherit\n")],
    ),
    "agent-sys-path": (
        "The agent process is started without isolated mode, so it can import the gateway's own code",
        [(R, 'return [sys.executable, "-I", "-B", str(AGENT)]', 'return [sys.executable, "-B", str(AGENT)]')],
    ),
}

GREEN, RED, BOLD, DIM, OFF = ("\033[32m", "\033[31m", "\033[1m", "\033[2m", "\033[0m") if sys.stdout.isatty() else ("",) * 5


def run_suite(where, verbose):
    cmd = [sys.executable, "-m", "unittest", "discover", "-s", "tests", "-t", "."] + (["-v"] if verbose else [])
    env = dict(os.environ, PYTHONDONTWRITEBYTECODE="1")
    return subprocess.run(cmd, cwd=where, capture_output=True, text=True, env=env)


def planted_copy(name):
    tmp = Path(tempfile.mkdtemp(prefix=f"d1-mutant-{name}-"))
    for part in ("guardrail", "tests", "fixtures"):
        shutil.copytree(ROOT / part, tmp / part, ignore=shutil.ignore_patterns("__pycache__"))
    for part in ("demo.py", "README.md", "ACCEPTANCE.md", "LICENSE"):
        shutil.copy2(ROOT / part, tmp / part)
    diffs = []
    for rel, old, new in MUTATIONS[name][1]:
        path = tmp / rel
        src = path.read_text()
        if src.count(old) != 1:
            shutil.rmtree(tmp)
            raise SystemExit(f"mutation {name!r}: expected exactly one match in {rel}; the code moved, update MUTATIONS")
        path.write_text(src.replace(old, new))
        diffs += difflib.unified_diff(old.splitlines(), new.splitlines(), f"a/{rel}", f"b/{rel}", lineterm="", n=0)
    return tmp, diffs


def summary_line(proc):
    lines = [l for l in proc.stderr.strip().splitlines() if l.startswith(("Ran ", "OK", "FAILED"))]
    return "  ".join(lines)


def failing_tests(proc):
    return [l.split(" ... ")[0] for l in proc.stderr.splitlines() if l.endswith((" ... FAIL", " ... ERROR"))]


def step(title):
    print(f"\n{BOLD}== {title}{OFF}")


def show(proc, ok_expected):
    colour = GREEN if proc.returncode == 0 else RED
    verdict = "GREEN (all acceptance tests pass)" if proc.returncode == 0 else "RED (acceptance tests fail)"
    print(f"{colour}{BOLD}{verdict}{OFF}  {DIM}{summary_line(proc)}{OFF}")
    return (proc.returncode == 0) == ok_expected


def recording_flow(name):
    print("Illustrative synthetic scenario. Not a real client, result, or testimonial. Runs on sample data.")
    print("Command: python3 -m unittest discover -s tests -t .")

    step("1. Acceptance suite on the real code")
    ok = show(run_suite(ROOT, verbose=False), ok_expected=True)

    step(f"2. Plant a real defect: {name} — {MUTATIONS[name][0]}")
    tmp, diffs = planted_copy(name)
    try:
        for d in diffs:
            print(f"  {RED if d.startswith('+') and not d.startswith('+++') else DIM}{d}{OFF}")
        step("3. Same suite against the defective code")
        proc = run_suite(tmp, verbose=True)
        ok &= show(proc, ok_expected=False)
        for t in failing_tests(proc):
            print(f"  {RED}x{OFF} {t}")
    finally:
        shutil.rmtree(tmp)

    step("4. Defect removed (real code again)")
    ok &= show(run_suite(ROOT, verbose=False), ok_expected=True)
    print(f"\n{BOLD}{'PROOF OK: red with the defect, green without it.' if ok else 'PROOF FAILED'}{OFF}")
    return 0 if ok else 1


def all_flow():
    print("Illustrative synthetic scenario. Not a real client, result, or testimonial. Runs on sample data.")
    base = run_suite(ROOT, verbose=False)
    print(f"baseline: {'GREEN' if base.returncode == 0 else 'RED'}  {summary_line(base)}")
    survivors = [] if base.returncode == 0 else ["<baseline>"]
    for name, (why, _) in MUTATIONS.items():
        tmp, _ = planted_copy(name)
        try:
            proc = run_suite(tmp, verbose=True)
        finally:
            shutil.rmtree(tmp)
        # Caught means a real assertion failed; a crash (ERROR) alone does not prove the tests check behaviour.
        caught = " ... FAIL" in proc.stderr
        survivors += [] if caught else [name]
        mark = f"{GREEN}caught{OFF}" if caught else f"{RED}SURVIVED{OFF}"
        print(f"  {name:<18} {mark}  by {len(failing_tests(proc))} test(s)  — {why}")
    print("ALL MUTATIONS CAUGHT" if not survivors else f"NOT PROVEN: {', '.join(survivors)}")
    return 0 if not survivors else 1


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--mutation", default=DEFAULT, choices=sorted(MUTATIONS))
    parser.add_argument("--all", action="store_true")
    parser.add_argument("--list", action="store_true")
    args = parser.parse_args()
    if args.list:
        for name, (why, _) in MUTATIONS.items():
            print(f"{name:<18} {why}")
        sys.exit(0)
    sys.exit(all_flow() if args.all else recording_flow(args.mutation))
