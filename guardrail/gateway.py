"""The gateway: the only door between the agent and the CRM.

Synthetic scenario — not a client deployment.

    agent request -> policy decision -> decision written to the audit log -> (only if allowed) execute -> result logged

If the decision cannot be written to the audit log, nothing runs (fail closed). Approvals are minted here, for
humans only, through grant(); the agent's side of the pipe (runner.py) can reach handle() and nothing else.
"""

import json
import secrets
from datetime import datetime, timedelta, timezone

from . import approvals, crm, policy
from .audit import AuditLog

MAX_LOGGED_ARGS = 2000  # characters of the agent's arguments kept in the log; the rest is cut, not stored


def loggable(args):
    text = json.dumps(args, sort_keys=True, default=repr)
    return args if len(text) <= MAX_LOGGED_ARGS else {"_truncated": text[:MAX_LOGGED_ARGS]}


def iso(dt):
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


class SimClock:
    """A controllable clock, so a 10-minute approval can expire inside a 90-second demo."""

    def __init__(self, start):
        self.now = start

    def __call__(self):
        return self.now

    def advance(self, seconds):
        self.now += timedelta(seconds=seconds)


class Refused(Exception):
    """A human's approval request that the policy does not allow."""


class Gateway:
    def __init__(self, crm_conn, audit_log, policy_config, clock, tools=None):
        self.conn = crm_conn
        self.audit = audit_log
        self.policy = policy.check_policy(policy_config)
        self.clock = clock
        self.tools = dict(crm.TOOLS if tools is None else tools)
        self._key = secrets.token_bytes(32)  # approval signing key: in memory, this process only, never logged

    @classmethod
    def in_memory(cls, policy_config, contacts, clock):
        conn = crm.connect()
        crm.seed(conn, contacts)
        return cls(conn, AuditLog(), policy_config, clock)

    def menu(self):
        """What the agent is told it can ask for. Never-class tools are not advertised (and refused if tried)."""
        return {name: policy.classify(self.policy, name) for name in self.tools
                if policy.classify(self.policy, name) != policy.NEVER}

    # --- agent-facing -------------------------------------------------------------------------------------

    def handle(self, actor, tool, args, approval=None):
        """Decide and (maybe) run one tool call from the agent. Returns a JSON-able response for the agent."""
        now = self.clock()
        presented = approval is not None
        grant = approvals.verify(self._key, approval) if presented else None
        uses = self.audit.uses(grant["id"]) if grant else 0
        spec = self.tools.get(tool) if isinstance(tool, str) else None
        try:
            d = policy.decide(
                self.policy, tool, spec, args, lambda cid: crm.exists(self.conn, cid), presented, grant, uses,
                int(now.timestamp()),
            )
        except Exception as exc:  # a check that cannot complete is a refusal, and it is still logged below
            d = policy.deny(f"policy-error:{type(exc).__name__}")
        try:
            self.audit.append(
                iso(now), actor, "decision", tool=str(tool), decision=d.decision, reason=d.reason,
                token_id=grant["id"] if grant else None, args=loggable(args), token_presented=presented,
            )
        except Exception:  # fail closed: a decision that cannot be recorded is not carried out
            return {"status": "denied", "reason": "audit-unavailable"}

        if d.decision == "needs-approval":
            value = args[spec.value_arg] if spec.value_arg else None
            proposal = {"action": tool, "contact_id": args["contact_id"], "value": value}
            return {"status": "needs-approval", "reason": d.reason, "proposal": proposal}
        if d.decision != "allow":
            return {"status": "denied", "reason": d.reason}

        self.conn.execute("BEGIN")
        try:
            result = spec.fn(self.conn, **args)
        except Exception as exc:
            self.conn.execute("ROLLBACK")
            self.audit.append(iso(self.clock()), actor, "execution-failed", tool=tool, reason=type(exc).__name__)
            return {"status": "error", "reason": type(exc).__name__}
        self.conn.execute("COMMIT")
        if policy.classify(self.policy, tool) != policy.READ:
            self.audit.append(iso(self.clock()), actor, "executed", tool=tool, token_id=grant and grant["id"],
                              result=result)
        return {"status": "ok", "reason": d.reason, "result": result}

    def protocol_violation(self, actor, message, reason="unsupported-message"):
        """The agent sent something that is not a valid tool call or approval request. Logged, never obeyed."""
        kind = message.get("type") if isinstance(message, dict) else None
        self.audit.append(iso(self.clock()), actor, "protocol-violation", decision="deny",
                          reason=reason, message_type=str(kind)[:100])
        return {"status": "denied", "reason": reason}

    def session_stopped(self, actor, reason):
        """The agent's session ended other than by saying done (timeout, exit, budget). Logged."""
        self.audit.append(iso(self.clock()), actor, "session-stopped", decision="deny", reason=reason)

    # --- human-facing (never reachable from the agent's pipe) ----------------------------------------------

    def grant(self, approver, action, contact_ids, values, ttl_seconds, max_uses=1):
        """A human approves a scoped, time-boxed write. Returns the token; raises Refused if not allowed."""
        now = self.clock()
        problem = policy.check_grant(self.policy, approver, action, contact_ids, values, ttl_seconds, max_uses)
        if problem:
            self.audit.append(iso(now), str(approver), "approval-refused", tool=str(action), decision="deny",
                              reason=problem, contact_ids=contact_ids, values=values, ttl_seconds=ttl_seconds)
            raise Refused(problem)
        iat = int(now.timestamp())
        grant = {"id": secrets.token_hex(4), "approver": approver, "action": action, "contact_ids": contact_ids,
                 "values": values, "iat": iat, "exp": iat + ttl_seconds, "max_uses": max_uses}
        self.audit.append(iso(now), approver, "approval-granted", tool=action, decision="grant",
                          token_id=grant["id"], contact_ids=contact_ids, values=values,
                          expires_at=iso(datetime.fromtimestamp(grant["exp"], timezone.utc)), max_uses=max_uses)
        return approvals.mint(self._key, grant)

    def decline(self, approver, proposal, reason):
        self.audit.append(iso(self.clock()), str(approver), "approval-declined", tool=str(proposal.get("action")),
                          decision="deny", reason=reason, proposal=loggable(proposal))
