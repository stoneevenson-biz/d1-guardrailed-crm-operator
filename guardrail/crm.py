"""Mock CRM (SQLite) and the tool implementations an agent could ask for.

Synthetic scenario — not a client deployment. Nothing here talks to a real CRM, carrier or mail server.
The send and delete tools are implemented on purpose, the way a real integration would have them: an
"sent" message becomes a row in the simulated outbox. Only the policy engine stands between a request
and these functions, so an empty outbox proves the policy held.
"""

import sqlite3
from collections import namedtuple

SCHEMA = """
CREATE TABLE IF NOT EXISTS contacts (
    id        INTEGER PRIMARY KEY,
    name      TEXT NOT NULL,
    phone     TEXT NOT NULL UNIQUE,
    stage     TEXT NOT NULL,
    owner     TEXT,
    notes     TEXT NOT NULL DEFAULT ''
);
CREATE TABLE IF NOT EXISTS contact_tags (
    contact_id INTEGER NOT NULL REFERENCES contacts(id) ON DELETE CASCADE,
    tag        TEXT NOT NULL,
    PRIMARY KEY (contact_id, tag)
);
CREATE TABLE IF NOT EXISTS outbox (
    id         INTEGER PRIMARY KEY,
    channel    TEXT NOT NULL,
    contact_id INTEGER NOT NULL,
    subject    TEXT,
    body       TEXT NOT NULL,
    status     TEXT NOT NULL DEFAULT 'simulated, never sent'
);
"""

# fn(conn, **args) -> JSON-able result; args: {name: type}; value_arg: the argument an approval scopes by value.
Tool = namedtuple("Tool", "fn args value_arg")


def connect(path=":memory:"):
    conn = sqlite3.connect(path, isolation_level=None)  # explicit BEGIN/COMMIT in the gateway
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    conn.executescript(SCHEMA)
    return conn


def seed(conn, contacts):
    """Load the synthetic contacts (fixtures only)."""
    for c in contacts:
        cur = conn.execute(
            "INSERT INTO contacts (name, phone, stage, owner, notes) VALUES (?, ?, ?, ?, ?)",
            (c["name"], c["phone"], c["stage"], c.get("owner"), c.get("notes", "")),
        )
        for tag in c.get("tags", []):
            conn.execute("INSERT INTO contact_tags (contact_id, tag) VALUES (?, ?)", (cur.lastrowid, tag))


def tags_for(conn, contact_id):
    rows = conn.execute("SELECT tag FROM contact_tags WHERE contact_id = ? ORDER BY tag", (contact_id,))
    return [r["tag"] for r in rows]


def exists(conn, contact_id):
    return conn.execute("SELECT 1 FROM contacts WHERE id = ?", (contact_id,)).fetchone() is not None


def count(conn, table):
    return conn.execute(f"SELECT COUNT(*) AS n FROM {table}").fetchone()["n"]


def snapshot(conn):
    """Every contact with its tags, for before/after comparisons."""
    return [dict(r) | {"tags": tags_for(conn, r["id"])} for r in conn.execute("SELECT * FROM contacts ORDER BY id")]


# --- read tools -------------------------------------------------------------------------------------------

def search_contacts(conn, query):
    like = f"%{query}%"
    rows = conn.execute(
        "SELECT id, name, stage FROM contacts WHERE name LIKE ? OR notes LIKE ? OR stage LIKE ? ORDER BY id",
        (like, like, like),
    )
    return [dict(r) | {"tags": tags_for(conn, r["id"])} for r in rows]


def get_contact(conn, contact_id):
    row = conn.execute("SELECT * FROM contacts WHERE id = ?", (contact_id,)).fetchone()
    return dict(row) | {"tags": tags_for(conn, contact_id)}


def list_pipeline(conn):
    rows = conn.execute("SELECT stage, COUNT(*) AS n FROM contacts GROUP BY stage ORDER BY stage")
    return {r["stage"]: r["n"] for r in rows}


# --- write tools (need a scoped, time-boxed approval) -------------------------------------------------------

def add_tag(conn, contact_id, tag):
    conn.execute("INSERT OR IGNORE INTO contact_tags (contact_id, tag) VALUES (?, ?)", (contact_id, tag))
    return {"contact_id": contact_id, "tags": tags_for(conn, contact_id)}


def remove_tag(conn, contact_id, tag):
    conn.execute("DELETE FROM contact_tags WHERE contact_id = ? AND tag = ?", (contact_id, tag))
    return {"contact_id": contact_id, "tags": tags_for(conn, contact_id)}


def set_stage(conn, contact_id, stage):
    old = conn.execute("SELECT stage FROM contacts WHERE id = ?", (contact_id,)).fetchone()["stage"]
    conn.execute("UPDATE contacts SET stage = ? WHERE id = ?", (stage, contact_id))
    return {"contact_id": contact_id, "stage": {"from": old, "to": stage}}


# --- never tools (the policy refuses them; they exist so a policy bug would really fire) --------------------

def send_sms(conn, contact_id, body):
    cur = conn.execute("INSERT INTO outbox (channel, contact_id, body) VALUES ('sms', ?, ?)", (contact_id, body))
    return {"outbox_id": cur.lastrowid}


def send_email(conn, contact_id, subject, body):
    cur = conn.execute(
        "INSERT INTO outbox (channel, contact_id, subject, body) VALUES ('email', ?, ?, ?)", (contact_id, subject, body)
    )
    return {"outbox_id": cur.lastrowid}


def delete_contact(conn, contact_id):
    conn.execute("DELETE FROM contacts WHERE id = ?", (contact_id,))
    return {"deleted": contact_id}


TOOLS = {
    "crm.search_contacts": Tool(search_contacts, {"query": str}, None),
    "crm.get_contact": Tool(get_contact, {"contact_id": int}, None),
    "crm.list_pipeline": Tool(list_pipeline, {}, None),
    "crm.add_tag": Tool(add_tag, {"contact_id": int, "tag": str}, "tag"),
    "crm.remove_tag": Tool(remove_tag, {"contact_id": int, "tag": str}, "tag"),
    "crm.set_stage": Tool(set_stage, {"contact_id": int, "stage": str}, "stage"),
    "sms.send": Tool(send_sms, {"contact_id": int, "body": str}, None),
    "email.send": Tool(send_email, {"contact_id": int, "subject": str, "body": str}, None),
    "crm.delete_contact": Tool(delete_contact, {"contact_id": int}, None),
}
