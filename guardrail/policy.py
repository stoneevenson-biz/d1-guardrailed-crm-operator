"""Deterministic policy engine: the only thing that decides whether an agent's tool call runs.

Synthetic scenario — not a client deployment. No model, no network, no randomness: the same request,
approval, clock and CRM state always get the same decision. The policy itself is data (fixtures/policy.json).

    read   -> allowed, logged
    write  -> needs a human's approval token scoped to this action, contact and value, unexpired, not used up
    never  -> refused, even with a token (outbound SMS/email, deletes, and any tool nobody classified)
"""

import re
from collections import namedtuple

READ, WRITE, NEVER = "read", "write", "never"
TAG = re.compile(r"^[a-z0-9][a-z0-9-]{0,39}$")
MAX_TEXT = 500
MAX_ID = 2**31 - 1

Decision = namedtuple("Decision", "decision reason")


def allow(reason):
    return Decision("allow", reason)


def deny(reason):
    return Decision("deny", reason)


def needs_approval(reason):
    return Decision("needs-approval", reason)


def check_policy(policy):
    """Refuse a policy file that could let the agent approve itself or that uses an unknown class."""
    if policy["agent_id"] in policy["approvers"]:
        raise ValueError("the agent can never be an approver")
    for name, rule in policy["tools"].items():
        if rule.get("class") not in (READ, WRITE, NEVER):
            raise ValueError(f"tool {name}: unknown class {rule.get('class')!r}")
    return policy


def rule_for(policy, tool):
    return policy["tools"].get(tool) if isinstance(tool, str) else None


def classify(policy, tool):
    rule = rule_for(policy, tool)
    if rule is None:
        return NEVER  # default deny: a tool nobody classified never runs
    return rule["class"]


def never_reason(policy, tool):
    return "never:" + (rule_for(policy, tool) or {}).get("kind", "unlisted-tool")


def _utf8(text):
    try:
        text.encode("utf-8")
    except UnicodeEncodeError:  # lone surrogates
        return False
    return True


def check_args(policy, spec, args):
    """None if the arguments are exactly what the tool takes, else the reason they are not."""
    if not isinstance(args, dict) or set(args) != set(spec.args):
        return "invalid-args"
    for name, kind in spec.args.items():
        value = args[name]
        if type(value) is not kind:  # exact type: True is not a contact id
            return "invalid-args"
        if kind is str and not (0 < len(value) <= MAX_TEXT and value.isprintable() and _utf8(value)):
            return "invalid-args"
        if kind is int and not 0 < value <= MAX_ID:
            return "invalid-args"
    if "tag" in args and not TAG.fullmatch(args["tag"]):
        return "invalid-tag"
    if "stage" in args and args["stage"] not in policy["stages"]:
        return "invalid-stage"
    return None


def decide(policy, tool, spec, args, contact_exists, presented, grant, uses, now_ts):
    """Decide one tool call.

    spec: the tool's implementation record (None if no such tool exists); contact_exists(id) -> bool;
    presented: whether the caller attached an approval token; grant: the verified grant (None if the token
    was absent, forged or malformed); uses: calls this grant already let through; now_ts: epoch seconds.
    """
    cls = classify(policy, tool)
    if cls == NEVER or spec is None:
        return deny(never_reason(policy, tool))
    problem = check_args(policy, spec, args)
    if problem:
        return deny(problem)
    if "contact_id" in args and not contact_exists(args["contact_id"]):
        return deny("unknown-contact")
    if cls == READ:
        return allow("read")

    if not presented:
        return needs_approval("approval-required")
    if grant is None:
        return deny("bad-token")
    if now_ts >= grant["exp"]:
        return deny("approval-expired")
    if grant["action"] != tool:
        return deny("out-of-scope:action")
    if args["contact_id"] not in grant["contact_ids"]:
        return deny("out-of-scope:contact")
    if spec.value_arg and args[spec.value_arg] not in grant["values"]:
        return deny("out-of-scope:value")
    if uses >= grant["max_uses"]:
        return deny("approval-used-up")
    return allow("approved")


def check_grant(policy, approver, action, contact_ids, values, ttl_seconds, max_uses):
    """None if a human may issue this approval, else the reason it is refused."""
    if approver not in policy["approvers"]:
        return "not-an-approver"
    if classify(policy, action) != WRITE:
        return "not-grantable"  # sends, deletes and unclassified tools can never be approved
    if not (isinstance(contact_ids, list) and contact_ids and all(type(c) is int and 0 < c <= MAX_ID for c in contact_ids)):
        return "bad-scope"
    if not (isinstance(values, list) and values and all(isinstance(v, str) and v for v in values)):
        return "bad-scope"
    if not (type(ttl_seconds) is int and 0 < ttl_seconds <= policy["max_ttl_seconds"]):
        return "ttl-out-of-range"
    if not (type(max_uses) is int and 0 < max_uses <= policy["max_uses"]):
        return "max-uses-out-of-range"
    return None
