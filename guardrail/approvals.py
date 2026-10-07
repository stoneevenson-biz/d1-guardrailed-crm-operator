"""Scoped, time-boxed approval tokens, minted only for a human approver.

Synthetic scenario — not a client deployment.

A token is `<base64url JSON grant>.<HMAC-SHA256 hex>`. The grant names one action, the contacts and values it
covers, when it expires and how many calls it may let through. The signing key is generated in memory by the
gateway on every run and never leaves it, so the agent can carry a token but cannot fake or widen one.
"""

import base64
import hashlib
import hmac
import json

GRANT_FIELDS = {"id": str, "approver": str, "action": str, "contact_ids": list, "values": list,
                "iat": int, "exp": int, "max_uses": int}


def _sig(key, body):
    return hmac.new(key, body.encode(), hashlib.sha256).hexdigest()


def mint(key, grant):
    body = base64.urlsafe_b64encode(json.dumps(grant, sort_keys=True).encode()).decode().rstrip("=")
    return f"{body}.{_sig(key, body)}"


def verify(key, token):
    """The grant inside a genuine token, or None for anything forged, altered or malformed."""
    if not isinstance(token, str) or not token.isascii() or token.count(".") != 1:
        return None
    body, sig = token.split(".")
    if not hmac.compare_digest(_sig(key, body), sig):
        return None
    try:
        grant = json.loads(base64.urlsafe_b64decode(body + "=" * (-len(body) % 4)))
    except ValueError:
        return None
    if not isinstance(grant, dict) or set(grant) != set(GRANT_FIELDS):
        return None
    if any(type(grant[k]) is not t for k, t in GRANT_FIELDS.items()):
        return None
    return grant
