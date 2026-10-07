"""Run the agent in its own process and relay its requests to the gateway.

Synthetic scenario — not a client deployment.

The agent process is started with Python's isolated mode (-I: no user site-packages, no PYTHON* variables,
the gateway's code not on its import path) and an empty environment, so it inherits no keys or tokens.
The CRM and the audit log live in this process's memory; the agent has no handle to either. The only
things it can send are: a tool call, a request for human approval, a wait, a probe report, done.
Anything else is logged as a protocol violation and refused.
"""

import json
import queue
import subprocess
import sys
import threading
from pathlib import Path

from .gateway import Refused

AGENT = Path(__file__).resolve().parent / "agent_proc.py"
SECONDS_PER_MESSAGE = 2  # simulated time each exchange takes
MAX_MESSAGES = 200  # budget: a looping agent is stopped, not waited on
MAX_LINE = 64 * 1024  # bytes per message; a longer line is refused without being kept
REPLY_TIMEOUT = 10
OVERSIZED = object()


def read_lines(stream, lines):
    """Reader thread: one bounded line at a time into the queue, then None at end of stream."""
    while True:
        line = stream.readline(MAX_LINE + 1)
        if not line:
            break
        if len(line) > MAX_LINE:
            while line and not line.endswith(b"\n"):  # drain the rest of the oversized line
                line = stream.readline(MAX_LINE + 1)
            lines.put(OVERSIZED)
            continue
        lines.put(line)
    lines.put(None)


def parse(line):
    """(message, None) for a JSON line, else (None, why it was refused)."""
    if line is OVERSIZED:
        return None, "oversized-message"
    try:
        return json.loads(line.decode("utf-8")), None
    except (ValueError, RecursionError):  # bad UTF-8, bad JSON, or nesting deep enough to exhaust the parser
        return None, "unparseable-message"


def child_env():
    """Nothing inherited from the parent: no API keys, tokens or paths reach the agent."""
    return {}


def agent_command():
    return [sys.executable, "-I", "-B", str(AGENT)]


class HumanApprover:
    """A scripted stand-in for a person reviewing each approval request. Unknown requests are declined."""

    def __init__(self, script):
        self.rules, self.default = script["rules"], script["default"]

    def review(self, proposal):
        for rule in self.rules:
            if rule["match"] == proposal:
                return rule
        return self.default


def run_session(gateway, steps, approver, task="", on_event=None):
    """Run one agent session to completion. Returns the list of events (also passed to on_event as they happen)."""
    events = []
    agent_id = gateway.policy["agent_id"]

    def emit(event):
        events.append(event)
        if on_event:
            on_event(event)

    proc = subprocess.Popen(
        agent_command(), stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
        env=child_env(), cwd=AGENT.parent,
    )
    lines = queue.Queue()
    threading.Thread(target=read_lines, args=(proc.stdout, lines), daemon=True).start()

    def reply(message):
        """False if the agent is gone (it exited or closed its end of the pipe)."""
        try:
            proc.stdin.write((json.dumps(message) + "\n").encode())
            proc.stdin.flush()
        except (BrokenPipeError, OSError):
            return False
        return True

    def stop(reason):
        gateway.session_stopped(agent_id, reason)
        emit({"kind": "stopped", "reason": reason})

    try:
        emit({"kind": "start", "pid": proc.pid, "command": ["python3", "-I", "-B", AGENT.name], "task": task})
        if not reply({"type": "start", "agent_id": agent_id, "task": task, "tools": gateway.menu(), "steps": steps}):
            stop("agent-exited")
            return events
        for _ in range(MAX_MESSAGES):
            try:
                line = lines.get(timeout=REPLY_TIMEOUT)
            except queue.Empty:
                stop("agent-timeout")
                break
            if line is None:
                stop("agent-exited")
                break
            gateway.clock.advance(SECONDS_PER_MESSAGE)
            msg, refused = parse(line)
            if refused:
                emit({"kind": "violation", "message_type": refused})
                response = gateway.protocol_violation(agent_id, None, refused)
            else:
                kind = msg.get("type") if isinstance(msg, dict) else None
                if kind == "done":
                    emit({"kind": "done"})
                    break
                response = _dispatch(gateway, approver, agent_id, kind, msg, emit)
            if not reply(response):
                stop("agent-exited")
                break
        else:
            stop("message-budget-exhausted")
    finally:
        proc.kill()
        proc.wait()
        for pipe in (proc.stdin, proc.stdout):
            try:
                pipe.close()
            except OSError:
                pass
    return events


def _dispatch(gateway, approver, agent_id, kind, msg, emit):
    if kind == "call":
        response = gateway.handle(agent_id, msg.get("tool"), msg.get("args"), msg.get("approval"))
        emit({"kind": "call", "at": gateway.clock(), "tool": msg.get("tool"), "args": msg.get("args"),
              "with_token": msg.get("approval") is not None, "why": msg.get("why", ""), "response": response})
        return response
    if kind == "request_approval":
        return _human_review(gateway, approver, msg.get("proposal"), emit)
    if kind == "wait":
        minutes = msg.get("minutes")
        if type(minutes) is int and 0 < minutes <= 120:
            gateway.clock.advance(minutes * 60)
            emit({"kind": "wait", "minutes": minutes, "why": msg.get("why", "")})
            return {"type": "ok"}
    if kind == "probe" and _valid_probe(msg.get("found")):
        emit({"kind": "probe", "found": msg["found"]})
        return {"type": "ok"}
    emit({"kind": "violation", "message_type": str(kind)[:100]})
    return gateway.protocol_violation(agent_id, msg)


def _valid_probe(found):
    return (isinstance(found, dict) and set(found) == {"env", "importable", "isolated_mode"}
            and all(isinstance(found[k], list) and all(isinstance(x, str) for x in found[k]) for k in ("env", "importable"))
            and isinstance(found["isolated_mode"], bool))


def _human_review(gateway, approver, proposal, emit):
    if not isinstance(proposal, dict):
        emit({"kind": "violation", "message_type": "request_approval"})
        return gateway.protocol_violation(gateway.policy["agent_id"], {"type": "request_approval"})
    rule = approver.review(proposal)
    who = rule.get("approver", "Demo Approver: Ops Lead")
    if not rule["approve"]:
        gateway.decline(who, proposal, rule["reason"])
        emit({"kind": "human", "approver": who, "approved": False, "proposal": proposal, "reason": rule["reason"]})
        return {"type": "approval", "token": None, "reason": rule["reason"]}
    try:
        token = gateway.grant(who, proposal["action"], [proposal["contact_id"]], [proposal["value"]],
                              rule["ttl_seconds"], rule["max_uses"])
    except Refused as exc:
        emit({"kind": "human", "approver": who, "approved": False, "proposal": proposal, "reason": str(exc)})
        return {"type": "approval", "token": None, "reason": str(exc)}
    emit({"kind": "human", "approver": who, "approved": True, "proposal": proposal,
          "ttl_seconds": rule["ttl_seconds"], "max_uses": rule["max_uses"]})
    return {"type": "approval", "token": token}
