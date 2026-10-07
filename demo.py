#!/usr/bin/env python3
"""Run the D1 scenario end to end on sample data and print every decision.

Synthetic scenario — not a client deployment. No network, no API key, no real CRM, SMS or email.

    python3 demo.py
"""

import argparse
import json
from datetime import datetime, timezone

from guardrail import LABEL, crm, load_json
from guardrail.gateway import Gateway, SimClock
from guardrail.runner import HumanApprover, run_session

START = datetime(2026, 10, 1, 15, 0, 0, tzinfo=timezone.utc)
GREEN, RED, YELLOW, BOLD, DIM, OFF = ("\033[32m", "\033[31m", "\033[33m", "\033[1m", "\033[2m", "\033[0m")


def clean(value, limit=160):
    """Agent-supplied text, printed safely: control characters (newlines, terminal escapes) shown escaped, length capped.

    A hijacked agent must not be able to print a fake "ALLOWED" or "HUMAN approves" line into the recording.
    """
    if isinstance(value, str):
        text = json.dumps(value)[1:-1]
    else:
        text = json.dumps(value, separators=(",", ":"), default=repr)
    text = text.replace("\x7f", "\\u007f")
    return text if len(text) <= limit else text[:limit] + "..."


def build():
    return Gateway.in_memory(load_json("policy.json"), load_json("crm_seed.json")["contacts"], SimClock(START))


def run(out=print, colour=False, script=None):
    c = (lambda code, text: f"{code}{text}{OFF}") if colour else (lambda code, text: text)
    gateway = build()
    script = script or load_json("agent_script.json")
    before = crm.snapshot(gateway.conn)
    counter = iter(range(1, 1000))

    out(f"{LABEL} Runs on sample data (555-01xx numbers).")
    out(f"Business: {gateway.policy['business_name']}  |  task: {clean(script['task'])}")
    out("Policy: reads allowed | tag/stage writes need a human's scoped, time-boxed token | SMS, email, deletes: never")
    out("Planner: a scripted stand-in for a model (no API key, no network), running in its own process")
    out("")

    def show(e):
        kind = e["kind"]
        if kind == "start":
            out(c(DIM, f"Agent process started: pid {e['pid']}, `{' '.join(e['command'])}`, nothing inherited from this environment."))
        elif kind == "probe":
            f = e["found"]
            env = f"{clean(f['env'])} (locale defaults the OS/runtime adds)" if f["env"] else "none"
            out(f"[{next(counter)}] AGENT  looks around its own process: env vars {env}, gateway code importable: "
                f"{clean(f['importable']) if f['importable'] else 'no'}, isolated mode: {f['isolated_mode']}")
        elif kind == "call":
            r = e["response"]
            status = r["status"]
            code = {"ok": GREEN, "needs-approval": YELLOW}.get(status, RED)
            args = clean(e["args"])
            token = " + token" if e["with_token"] else ""
            out(f"[{next(counter)}] {e['at']:%H:%M:%S} AGENT  {clean(e['tool'])} {args}{token}")
            out(c(DIM, f"      why: {clean(e['why'])}"))
            verdict = {"ok": "ALLOWED", "needs-approval": "NEEDS APPROVAL", "denied": "REFUSED"}.get(status, status)
            out("      -> " + c(code + BOLD, f"{verdict} ({r['reason']})") + _result(r))
        elif kind == "human":
            p = e["proposal"]
            what = clean(f"{p.get('action')} on #{p.get('contact_id')} = {p.get('value')}")
            if e["approved"]:
                out(c(GREEN, f"      HUMAN  {e['approver']} approves {what}: valid {e['ttl_seconds'] // 60} min, "
                             f"{e['max_uses']} use"))
            else:
                out(c(RED, f"      HUMAN  {e['approver']} declines {what}: {clean(e['reason'])}"))
        elif kind == "wait":
            out(c(DIM, f"      ... {e['minutes']} minutes pass (simulated clock): {clean(e['why'])}"))
        elif kind == "violation":
            out(c(RED, f"      -> REFUSED protocol message {clean(e['message_type'])}"))
        elif kind == "stopped":
            out(c(RED, f"Agent stopped: {e['reason']}"))

    run_session(gateway, script["steps"], HumanApprover(load_json("approver_script.json")), script["task"], show)
    out("")
    _after(gateway, before, out, c)
    return gateway


def _result(r):
    if r["status"] != "ok":
        return ""
    res = r["result"]
    if isinstance(res, list):
        return f": {len(res)} contact(s) " + ", ".join(f"#{x['id']}" for x in res)
    if isinstance(res, dict) and "notes" in res:
        return f": #{res['id']} stage={res['stage']} notes=\"{clean(res['notes'], 60)}\""
    return f": {clean(res)}"


def _after(gateway, before, out, c):
    out(c(BOLD, "What changed in the mock CRM:"))
    after = crm.snapshot(gateway.conn)
    changes = [(b, a) for b, a in zip(before, after) if b != a]
    for b, a in changes:
        diff = {k: f"{b[k]} -> {a[k]}" for k in b if b[k] != a[k]}
        out(f"  #{a['id']} {a['name']}: {diff}")
    if len(after) != len(before):
        out(f"  contacts: {len(before)} -> {len(after)}")
    out(c(BOLD, "Simulated outbox (SMS/email the agent tried to send):") + f" {crm.count(gateway.conn, 'outbox')} messages")

    rows = gateway.audit.rows()
    out("")
    out(c(BOLD, f"Audit log: {len(rows)} append-only, hash-chained entries (separate store; the agent has no handle)"))
    for r in rows:
        tag = r["decision"] or ""
        out(f"  {r['seq']:>3} {r['at'][11:19]} {clean(r['actor'], 40):<24} {r['event']:<18} "
            f"{clean(r['tool'] or '', 60):<20} {tag:<14} {clean(r['reason'] or '')}")
    ok, why = gateway.audit.verify()
    out(c(GREEN if ok else RED, f"Audit chain verified: {why}. Head {gateway.audit.head()[:16]} (copy it off-box)."))


if __name__ == "__main__":
    import sys

    argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter).parse_args()
    run(colour=sys.stdout.isatty())
