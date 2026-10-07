"""Append-only, hash-chained audit log, kept out of the agent's reach.

Synthetic scenario — not a client deployment.

- Its own SQLite database, separate from the CRM. Only the gateway holds the connection; the agent runs
  in another process and has no handle to it (see runner.py).
- Triggers make the table reject UPDATE and DELETE.
- Every row carries the SHA-256 of the previous row's hash plus its own content, so an edit, a deleted
  row or a reordering is detected by verify() even by someone who dropped the triggers. Checking the
  latest hash (head) against a copy kept elsewhere also detects a truncated or fully rewritten log.
"""

import hashlib
import json
import sqlite3

GENESIS = "0" * 64

SCHEMA = """
CREATE TABLE IF NOT EXISTS audit_log (
    seq       INTEGER PRIMARY KEY,
    at        TEXT NOT NULL,
    actor     TEXT NOT NULL,
    event     TEXT NOT NULL,
    tool      TEXT,
    decision  TEXT,
    reason    TEXT,
    token_id  TEXT,
    detail    TEXT NOT NULL,
    prev_hash TEXT NOT NULL,
    hash      TEXT NOT NULL
);
CREATE TRIGGER IF NOT EXISTS audit_log_no_update BEFORE UPDATE ON audit_log
BEGIN SELECT RAISE(ABORT, 'audit_log is append-only'); END;
CREATE TRIGGER IF NOT EXISTS audit_log_no_delete BEFORE DELETE ON audit_log
BEGIN SELECT RAISE(ABORT, 'audit_log is append-only'); END;
"""

FIELDS = ("seq", "at", "actor", "event", "tool", "decision", "reason", "token_id", "detail")


def safe_text(value):
    """Text as stored: anything that is not valid UTF-8 (lone surrogates) is escaped, never dropped or crashed on."""
    if value is None:
        return None
    return str(value).encode("utf-8", "backslashreplace").decode("utf-8")


def entry_hash(prev_hash, row):
    content = json.dumps({k: row[k] for k in FIELDS}, sort_keys=True)
    return hashlib.sha256(f"{prev_hash}|{content}".encode()).hexdigest()


class AuditLog:
    def __init__(self, path=":memory:"):
        self.conn = sqlite3.connect(path, isolation_level=None)
        self.conn.row_factory = sqlite3.Row
        self.conn.executescript(SCHEMA)

    def append(self, at, actor, event, tool=None, decision=None, reason=None, token_id=None, **detail):
        last = self.conn.execute("SELECT seq, hash FROM audit_log ORDER BY seq DESC LIMIT 1").fetchone()
        prev_hash = last["hash"] if last else GENESIS
        row = {
            "seq": (last["seq"] + 1) if last else 1,
            "at": at, "actor": safe_text(actor), "event": event, "tool": safe_text(tool), "decision": decision,
            "reason": safe_text(reason), "token_id": safe_text(token_id), "detail": json.dumps(detail, sort_keys=True),
        }
        row["prev_hash"], row["hash"] = prev_hash, entry_hash(prev_hash, row)
        self.conn.execute(
            f"INSERT INTO audit_log ({', '.join(row)}) VALUES ({', '.join('?' * len(row))})", tuple(row.values())
        )
        return row["hash"]

    def head(self):
        last = self.conn.execute("SELECT hash FROM audit_log ORDER BY seq DESC LIMIT 1").fetchone()
        return last["hash"] if last else GENESIS

    def rows(self):
        return [dict(r) for r in self.conn.execute("SELECT * FROM audit_log ORDER BY seq")]

    def uses(self, token_id):
        """How many calls this approval has already let through (the log is the source of truth)."""
        return self.conn.execute(
            "SELECT COUNT(*) AS n FROM audit_log WHERE event = 'decision' AND decision = 'allow' AND token_id = ?",
            (token_id,),
        ).fetchone()["n"]

    def verify(self, expected_head=None):
        """Recompute the chain. Returns (ok, message).

        expected_head: a head() copied somewhere else earlier; it must still be in the chain (later appends are fine).
        """
        prev, seen = GENESIS, {GENESIS}
        for i, row in enumerate(self.rows(), 1):
            if row["seq"] != i:
                return False, f"sequence gap at {i} (row deleted or reordered)"
            if row["prev_hash"] != prev or entry_hash(prev, row) != row["hash"]:
                return False, f"hash mismatch at seq {row['seq']} (row edited)"
            prev = row["hash"]
            seen.add(prev)
        if expected_head is not None and expected_head not in seen:
            return False, "recorded head is no longer in the chain (log truncated or rewritten)"
        return True, "chain intact"
