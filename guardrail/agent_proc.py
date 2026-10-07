"""The agent's side. Runs in its own process, started by runner.py, and speaks JSON lines on stdin/stdout.

Synthetic scenario — not a client deployment.

Standard library only (json, os, sys, importlib.util), on purpose: this process holds no CRM connection, no audit
log, no signing key and no credentials. All it can do is send a message to the gateway and read the answer.

The planner here is scripted: it stands in for a language model, so the demo runs with no API key and no
network. A model-backed planner would implement the same run(io) and would be trusted exactly as little:
the gateway decides every call the same way whoever produced it.
"""

import importlib.util
import json
import os
import sys


class PipeIO:
    """The only channel to the outside world: one JSON message out, one JSON reply in."""

    def __init__(self, inp, out):
        self.inp, self.out = inp, out

    def send(self, message):
        self.out.write(json.dumps(message) + "\n")
        self.out.flush()
        line = self.inp.readline()
        return json.loads(line) if line else {"type": "closed"}

    def send_bytes(self, data):
        self.out.flush()
        self.out.buffer.write(data)
        self.out.buffer.flush()
        line = self.inp.readline()
        return json.loads(line) if line else {"type": "closed"}

    def call(self, tool, args, approval, why):
        return self.send({"type": "call", "tool": tool, "args": args, "approval": approval, "why": why})

    def request_approval(self, proposal, why):
        return self.send({"type": "request_approval", "proposal": proposal, "why": why})

    def wait(self, minutes, why):
        return self.send({"type": "wait", "minutes": minutes, "why": why})


def probe():
    """What this process can see: environment variable names, and whether the gateway's code is importable."""
    reachable = [m for m in ("guardrail", "gateway", "audit", "approvals", "crm") if importlib.util.find_spec(m)]
    return {"env": sorted(os.environ), "importable": reachable, "isolated_mode": bool(sys.flags.isolated)}


class ScriptedPlanner:
    """Stands in for a model: emits the scripted tool calls in order and reacts to the gateway's answers.

    A step that gets `needs-approval` and says ask_human asks a human, then retries with the token it was given.
    use_token: present the latest token on this call (to show what a token does and does not cover).
    """

    def __init__(self, steps):
        self.steps = steps
        self.token = None

    def run(self, io):
        for step in self.steps:
            do, why = step["do"], step.get("why", "")
            if do == "probe":
                io.send({"type": "probe", "found": probe(), "why": why})
            elif do == "raw":  # a hijacked agent sending whatever it likes
                io.send(step["message"])
            elif do == "raw_line":  # ... or not even JSON: a text line, or bytes given as hex
                data = bytes.fromhex(step["hex"]) if "hex" in step else step["text"].encode()
                io.send_bytes(data + b"\n")
            elif do == "exit":  # ... or vanishing mid-conversation, without reading the answer
                io.out.write(json.dumps({"type": "call", "tool": "crm.list_pipeline", "args": {}}) + "\n")
                io.out.flush()
                os._exit(0)
            elif do == "wait":
                io.wait(step["minutes"], why)
            elif do == "call":
                self.call(io, step, why)
        io.send({"type": "done"})

    def call(self, io, step, why):
        tool, args = step["tool"], step.get("args", {})
        reply = io.call(tool, args, self.token if step.get("use_token") else None, why)
        if reply.get("status") != "needs-approval" or not step.get("ask_human"):
            return
        answer = io.request_approval(reply["proposal"], why)
        if not answer.get("token"):
            return
        self.token = answer["token"]
        if step.get("wait_minutes_before_use"):
            io.wait(step["wait_minutes_before_use"], "busy elsewhere before using the approval")
        io.call(tool, args, self.token, "retry with the human's approval")


def main():
    io = PipeIO(sys.stdin, sys.stdout)
    start = json.loads(sys.stdin.readline())
    ScriptedPlanner(start["steps"]).run(io)


if __name__ == "__main__":
    main()
