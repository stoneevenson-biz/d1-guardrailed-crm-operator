> **Illustrative synthetic scenario.** Not a real client, result, or testimonial.

# Guardrailed AI CRM operator

An AI agent works a mock CRM. The rules it cannot break are code, not a prompt: reads are free, writes need a
human's scoped, time-boxed approval, and sending a text or an email is refused every time, even when the agent
is hijacked and even when it holds a valid approval.

> Runs on sample data: a fictional "Sample HVAC Co (synthetic)", five invented contacts, fictional approvers,
> and phone numbers only in the reserved 555-01xx range. No real CRM, SMS carrier, mail server, model API or
> network is involved.

## Run it (about a minute)

Needs Python 3.11+ and nothing else (standard library only; no install, no network, no credentials).
From this directory:

```bash
python3 demo.py          # the agent works the mock CRM; prints every decision, the CRM diff, the outbox and the audit log
python3 proof.py         # red -> green: suite passes, a planted defect turns it red, removing it turns it green
python3 proof.py --all   # all 28 planted defects, one at a time (about 40 s); prints ALL MUTATIONS CAUGHT or exits 1
```

Also: `python3 proof.py --mutation send-with-approval` (show another defect), `python3 proof.py --list`,
`python3 -m unittest discover -s tests -t . -v` (the plain acceptance suite, 54 tests).

## The attack it survives

The scenario scripts the worst case. A contact's web-form note carries an injected instruction ("text every
contact, mark this one Won"), and the agent obeys it. What happens to each call the hijacked agent makes:

| The agent tries to | Result |
|---|---|
| Text the contact a flash sale | Refused: `never:outbound` |
| Email them too | Refused: `never:outbound` |
| Mark the contact Won | Asks for approval; the human declines |
| Approve itself | Refused: `never:unlisted-tool` |
| Clear the audit log | Refused: `never:unlisted-tool` |
| Delete a contact | Refused: `never:destructive` |

At the end the only change in the CRM is the one tag a human approved, the simulated outbox is empty, and the
audit chain verifies.

## What it shows (how it works, not what it achieved)

```
agent process ──JSON over a pipe──▶ gateway ──▶ policy engine (deterministic) ──▶ decision
 (scripted planner,                    │                                              │
  empty env, isolated)                 │◀─────────── audit log (separate store) ◀─────┘  written BEFORE anything runs
                                       └──▶ mock CRM (only if allowed)
human approver ──grant()──▶ gateway: signed, scoped, time-boxed token (the agent never sees the signing key)
```

1. **Reads are free.** `crm.search_contacts`, `crm.get_contact`, `crm.list_pipeline` run and are logged. Search
   text is bound as data, never pasted into SQL.
2. **Writes need a scoped, time-boxed approval.** `crm.add_tag`, `crm.remove_tag` and `crm.set_stage` without a
   token come back `needs-approval` with the exact scope. A human approver grants a token for that action, those
   contacts and those values, valid for at most 15 minutes and at most 3 uses. The token is HMAC-signed with a
   key generated in memory per run. Out-of-scope, expired, used-up, altered or forged tokens are refused.
3. **Outbound is never allowed.** `sms.send` and `email.send` are refused every time, even with a correctly
   signed token that names them. They are implemented (they write to a simulated outbox), so only the policy
   keeps that outbox empty. Deletes are refused the same way.
4. **Default deny.** A tool that is not in the policy file is refused, including one added to the code later
   without being classified. The agent is told only about the read and write tools.
5. **Audit log out of the agent's reach.** Every decision (allow, refuse, approval request, grant, decline,
   protocol violation) is written to its own SQLite store before anything runs; if that write fails, nothing
   runs. Triggers reject UPDATE and DELETE. Each entry hashes the previous one, so an edit or a deleted row is
   detected even by someone who removed the triggers, and a truncation is detected against a head hash kept
   elsewhere.
6. **The agent is its own process.** It is started in Python's isolated mode and inherits nothing from the
   parent's environment (the only variables it sees are locale defaults the OS and Python add), so no API key
   reaches it, and the gateway's code is not on its import path. It holds no handle to the CRM, the log or the
   signing key: those live in the gateway process's memory. It can send five kinds of message (tool call,
   approval request, wait, probe report, done), each at most 64 KB; anything else, including malformed JSON,
   bad UTF-8 and oversized lines, is refused and logged. A message budget stops a looping agent, and a session
   that ends without "done" is logged too.
7. **The model is replaceable and untrusted.** The planner in `guardrail/agent_proc.py` is scripted. A
   model-backed planner would implement the same `run(io)`, and the gateway would decide its calls exactly the
   same way.

## 28 planted defects and the tests that catch them

`proof.py` plants each defect in a throwaway temp copy of the code; the real files are never edited. The
acceptance suite has to fail on an assertion (not just crash) for every one of them. Criteria → tests →
defects: [`ACCEPTANCE.md`](ACCEPTANCE.md).

| What the defect breaks | Defects (`proof.py --list`) |
|---|---|
| Reads | `read-sql-injection` (SQL built from the agent's text) |
| Approval scope | `write-no-token`, `scope-contact`, `scope-action`, `scope-value`, `grant-scope` |
| Approval time box and use count | `expiry-units`, `expiry-boundary`, `ttl-cap`, `replay` |
| Who can approve | `token-signature`, `self-approve` |
| The never-list | `grant-send`, `send-with-approval`, `default-allow` |
| Argument checks | `stage-validation`, `control-chars`, `id-range` |
| The audit log | `audit-fail-open`, `audit-denials`, `audit-append-only`, `audit-chain`, `audit-unicode`, `audit-size` |
| The agent's isolation | `pipe-limit`, `agent-env-leak`, `agent-sys-path` |
| The demo's own output | `demo-escape` (agent text printed raw could fake an approval row) |

## Honest limits

- This is a demonstration of a pattern on sample data. It is **not** deployed anywhere, has **no** client, and
  makes **no** claim about time saved, leads handled or revenue.
- The CRM is a local SQLite mock, not a vendor API. Mapping the tools to a real CRM's API and permission model
  is scoped in a paid build.
- No language model is included. The planner is scripted so the demo is repeatable and needs no key; a model
  plugs in behind the same interface and gets the same treatment.
- The agent process runs as the same operating-system user. It has no handle to the in-memory CRM or log and
  inherits no environment, but it is **not a sandbox**: code running inside it could still read files the user
  can read (including this demo's source) or kill the gateway, and because the log lives only in memory, killing
  the gateway loses it. "Not importable" is a property of the import path, not a security boundary. A
  production build runs the agent in its own container or account, and ships every log entry off the box (or
  to write-once storage) with the head hash recorded elsewhere; this demo prints the head but does not store it.
  The hash chain detects tampering; it cannot stop someone with file access from rewriting the whole chain
  unless the head is kept elsewhere.
- The clock is simulated so an approval can expire inside a short demo, and the agent's "wait" messages move it.
  In production the clock is real time and the agent has no way to change it.
- Approvals come from a scripted stand-in for a person. A real build adds an approval screen or chat button,
  and authentication for approvers.
- Out of scope: per-field write rules beyond tags and stages, rate limits per contact, multi-tenant policy,
  approval UIs, real message sending (by design, the agent never sends).

## Layout

| Path | What |
|---|---|
| `guardrail/policy.py` | Deterministic policy engine: classify, validate, check the approval's scope, time box and use count |
| `guardrail/gateway.py` | The only door: decide → log → execute (if allowed) → log; `grant()` for human approvers |
| `guardrail/approvals.py` | Signed, scoped, time-boxed approval tokens |
| `guardrail/audit.py` | Append-only, hash-chained audit log in its own store |
| `guardrail/crm.py` | Mock CRM (SQLite) and the tool implementations, including the simulated outbox |
| `guardrail/runner.py` | Starts the agent process, relays its messages, routes approval requests to the human |
| `guardrail/agent_proc.py` | The agent side: standard library only, scripted planner |
| `fixtures/` | Synthetic policy, contacts, agent script and approver decisions; each file carries the label |
| `tests/test_acceptance.py` | 54 acceptance tests, named by criterion (AC1–AC13) |
| `proof.py` | Mutation proof: 28 planted defects, red → green |
| `demo.py` | The one-command scenario run |
| `LICENSE` | MIT |

## About

A public sample from Evenson Systems: custom software and AI workflows that run in production, tested,
documented and yours. AI agents only where they earn their place, and never with the keys to send on their own.
