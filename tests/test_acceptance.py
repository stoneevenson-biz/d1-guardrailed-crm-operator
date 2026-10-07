"""Acceptance tests for D1. Each test names the acceptance criterion (ACn) it proves; see ACCEPTANCE.md.

Synthetic scenario — not a client deployment. All numbers are in the reserved 555-01xx range.
"""

import base64
import io
import json
import os
import re
import sqlite3
import unittest
from contextlib import redirect_stdout
from datetime import datetime, timezone
from pathlib import Path
from unittest import mock

from guardrail import approvals, crm, load_json
from guardrail.gateway import Gateway, Refused, SimClock
from guardrail.runner import HumanApprover, run_session

T0 = datetime(2026, 10, 1, 15, 0, 0, tzinfo=timezone.utc)
AGENT = "operator-agent"
APPROVER = "Demo Approver: Ops Lead"


class D1Case(unittest.TestCase):
    def setUp(self):
        self.clock = SimClock(T0)
        self.gw = Gateway.in_memory(load_json("policy.json"), load_json("crm_seed.json")["contacts"], self.clock)
        self.addCleanup(self.gw.conn.close)
        self.addCleanup(self.gw.audit.conn.close)
        self.before = crm.snapshot(self.gw.conn)

    def call(self, tool, args, token=None):
        return self.gw.handle(AGENT, tool, args, token)

    def grant(self, action="crm.add_tag", contacts=(2,), values=("hot-lead",), ttl=600, uses=1, approver=APPROVER):
        return self.gw.grant(approver, action, list(contacts), list(values), ttl, uses)

    def mint(self, action, contacts, values, ttl=600, uses=1):
        """A correctly signed token that grant() would never issue: stands in for a bug elsewhere minting one."""
        iat = int(self.clock().timestamp())
        grant = {"id": "handmade", "approver": APPROVER, "action": action, "contact_ids": list(contacts),
                 "values": list(values), "iat": iat, "exp": iat + ttl, "max_uses": uses}
        return approvals.mint(self.gw._key, grant)

    def tags(self, cid):
        return crm.tags_for(self.gw.conn, cid)

    def stage(self, cid):
        return crm.get_contact(self.gw.conn, cid)["stage"]

    def decisions(self):
        return [(r["tool"], r["decision"], r["reason"]) for r in self.gw.audit.rows() if r["event"] == "decision"]

    def assert_crm_unchanged(self):
        self.assertEqual(crm.snapshot(self.gw.conn), self.before)
        self.assertEqual(crm.count(self.gw.conn, "outbox"), 0)


class Reads(D1Case):
    def test_ac1_reads_run_without_approval_and_are_logged(self):
        self.assertEqual(self.call("crm.list_pipeline", {})["result"], {"lost": 1, "new": 3, "won": 1})
        found = self.call("crm.search_contacts", {"query": "web form"})["result"]
        self.assertEqual([c["id"] for c in found], [2, 3, 4])
        contact = self.call("crm.get_contact", {"contact_id": 2})
        self.assertEqual((contact["status"], contact["result"]["phone"]), ("ok", "+13125550172"))
        self.assertEqual(self.decisions(), [(t, "allow", "read") for t in
                                            ("crm.list_pipeline", "crm.search_contacts", "crm.get_contact")])
        self.assert_crm_unchanged()

    def test_ac1_search_text_is_data_not_sql(self):
        r = self.call("crm.search_contacts", {"query": "zzz' OR 1=1 OR name LIKE '"})
        self.assertEqual((r["status"], r["result"]), ("ok", []))
        self.assert_crm_unchanged()


class WritesNeedApproval(D1Case):
    def test_ac2_tag_write_without_a_token_is_not_executed(self):
        r = self.call("crm.add_tag", {"contact_id": 2, "tag": "hot-lead"})
        self.assertEqual((r["status"], r["reason"]), ("needs-approval", "approval-required"))
        self.assertEqual(r["proposal"], {"action": "crm.add_tag", "contact_id": 2, "value": "hot-lead"})
        self.assert_crm_unchanged()
        self.assertEqual(self.decisions(), [("crm.add_tag", "needs-approval", "approval-required")])

    def test_ac2_stage_and_untag_writes_without_a_token_are_not_executed(self):
        self.assertEqual(self.call("crm.set_stage", {"contact_id": 3, "stage": "won"})["status"], "needs-approval")
        self.assertEqual(self.call("crm.remove_tag", {"contact_id": 3, "tag": "web-form"})["status"], "needs-approval")
        self.assert_crm_unchanged()


class Scope(D1Case):
    def test_ac3_a_token_lets_exactly_its_scope_through(self):
        token = self.grant()
        r = self.call("crm.add_tag", {"contact_id": 2, "tag": "hot-lead"}, token)
        self.assertEqual((r["status"], r["reason"]), ("ok", "approved"))
        self.assertEqual(self.tags(2), ["hot-lead", "web-form"])
        executed = [x for x in self.gw.audit.rows() if x["event"] == "executed"]
        self.assertEqual(len(executed), 1)
        self.assertIsNotNone(executed[0]["token_id"])

    def test_ac3_a_multi_contact_approval_covers_each_listed_contact(self):
        token = self.grant(contacts=(2, 3), uses=2)
        for cid in (2, 3):
            self.assertEqual(self.call("crm.add_tag", {"contact_id": cid, "tag": "hot-lead"}, token)["status"], "ok")
            self.assertIn("hot-lead", self.tags(cid))

    def test_ac3_a_token_for_one_contact_does_not_cover_another(self):
        token = self.grant(contacts=(2,))
        r = self.call("crm.add_tag", {"contact_id": 3, "tag": "hot-lead"}, token)
        self.assertEqual((r["status"], r["reason"]), ("denied", "out-of-scope:contact"))
        self.assert_crm_unchanged()

    def test_ac3_a_token_for_one_action_does_not_cover_another(self):
        token = self.grant(action="crm.add_tag", contacts=(2,), values=("qualified", "web-form"), uses=3)
        r = self.call("crm.set_stage", {"contact_id": 2, "stage": "qualified"}, token)
        self.assertEqual((r["status"], r["reason"]), ("denied", "out-of-scope:action"))
        r = self.call("crm.remove_tag", {"contact_id": 2, "tag": "web-form"}, token)
        self.assertEqual((r["status"], r["reason"]), ("denied", "out-of-scope:action"))
        self.assert_crm_unchanged()

    def test_ac3_a_token_for_one_value_does_not_cover_another(self):
        token = self.grant(action="crm.set_stage", contacts=(2,), values=("qualified",))
        r = self.call("crm.set_stage", {"contact_id": 2, "stage": "won"}, token)
        self.assertEqual((r["status"], r["reason"]), ("denied", "out-of-scope:value"))
        self.assert_crm_unchanged()


class TimeBox(D1Case):
    def test_ac4_an_approval_expires(self):
        token = self.grant(ttl=600)
        self.clock.advance(601)
        r = self.call("crm.add_tag", {"contact_id": 2, "tag": "hot-lead"}, token)
        self.assertEqual((r["status"], r["reason"]), ("denied", "approval-expired"))
        self.assert_crm_unchanged()

    def test_ac4_the_expiry_instant_itself_is_expired(self):
        early, late = self.grant(ttl=600), self.grant(ttl=600)
        self.clock.advance(599)
        self.assertEqual(self.call("crm.add_tag", {"contact_id": 2, "tag": "hot-lead"}, early)["status"], "ok")
        self.clock.advance(1)
        r = self.call("crm.add_tag", {"contact_id": 2, "tag": "hot-lead"}, late)
        self.assertEqual((r["status"], r["reason"]), ("denied", "approval-expired"))

    def test_ac4_approvals_are_capped_at_15_minutes(self):
        for ttl in (901, 86400, 0, -5, 60.0):
            with self.assertRaises(Refused, msg=ttl) as ctx:
                self.grant(ttl=ttl)
            self.assertEqual(str(ctx.exception), "ttl-out-of-range")
        self.assertTrue(self.grant(ttl=900))
        refused = [r for r in self.gw.audit.rows() if r["event"] == "approval-refused"]
        self.assertEqual(len(refused), 5)


class UseLimit(D1Case):
    def test_ac5_a_single_use_approval_cannot_be_replayed(self):
        token = self.grant(uses=1)
        args = {"contact_id": 2, "tag": "hot-lead"}
        self.assertEqual(self.call("crm.add_tag", args, token)["status"], "ok")
        r = self.call("crm.add_tag", args, token)
        self.assertEqual((r["status"], r["reason"]), ("denied", "approval-used-up"))
        self.assertEqual(len([x for x in self.gw.audit.rows() if x["event"] == "executed"]), 1)

    def test_ac5_max_uses_is_honoured_and_capped(self):
        token = self.grant(contacts=(2, 3, 4), uses=3)
        for cid in (2, 3, 4):
            self.assertEqual(self.call("crm.add_tag", {"contact_id": cid, "tag": "hot-lead"}, token)["status"], "ok")
        r = self.call("crm.add_tag", {"contact_id": 2, "tag": "hot-lead"}, token)
        self.assertEqual(r["reason"], "approval-used-up")
        for uses in (4, 0):
            with self.assertRaises(Refused):
                self.grant(uses=uses)


class TokenIntegrity(D1Case):
    def test_ac6_forged_and_malformed_tokens_are_refused(self):
        grant = {"id": "forged", "approver": APPROVER, "action": "crm.add_tag", "contact_ids": [2],
                 "values": ["hot-lead"], "iat": 0, "exp": 2**40, "max_uses": 3}
        for token in ("garbage", "a.b", "", "é.é", 123, ["x"], approvals.mint(b"k" * 32, grant)):
            r = self.call("crm.add_tag", {"contact_id": 2, "tag": "hot-lead"}, token)
            self.assertEqual((r["status"], r["reason"]), ("denied", "bad-token"), token)
        self.assert_crm_unchanged()

    def test_ac6_an_altered_token_is_refused(self):
        body, sig = self.grant(contacts=(2,), ttl=60).split(".")
        grant = json.loads(base64.urlsafe_b64decode(body + "=" * (-len(body) % 4)))
        grant.update(contact_ids=[2, 3, 4, 5], exp=grant["exp"] + 86400, max_uses=3)  # widen and extend it
        widened = base64.urlsafe_b64encode(json.dumps(grant, sort_keys=True).encode()).decode().rstrip("=")
        r = self.call("crm.add_tag", {"contact_id": 3, "tag": "hot-lead"}, f"{widened}.{sig}")
        self.assertEqual((r["status"], r["reason"]), ("denied", "bad-token"))
        self.assert_crm_unchanged()

    def test_ac6_only_listed_humans_can_approve(self):
        for who in (AGENT, "Someone Else", "", None):
            with self.assertRaises(Refused) as ctx:
                self.grant(approver=who)
            self.assertEqual(str(ctx.exception), "not-an-approver")
        self.assertEqual([r["event"] for r in self.gw.audit.rows()], ["approval-refused"] * 4)

    def test_ac6_the_agent_can_never_be_configured_as_an_approver(self):
        policy = load_json("policy.json")
        policy["approvers"].append(policy["agent_id"])
        with self.assertRaises(ValueError):
            Gateway.in_memory(policy, [], SimClock(T0))

    def test_ac6_sends_deletes_and_unknown_tools_cannot_be_approved(self):
        for action in ("sms.send", "email.send", "crm.delete_contact", "crm.run_sql", "crm.get_contact"):
            with self.assertRaises(Refused, msg=action) as ctx:
                self.grant(action=action, values=("x",))
            self.assertEqual(str(ctx.exception), "not-grantable")

    def test_ac6_an_approval_must_name_real_contact_ids_and_values(self):
        for contacts, values in (([], ["hot-lead"]), (["2"], ["hot-lead"]), ([True], ["hot-lead"]), ([2**40], ["x"]),
                                 ([2], []), ([2], [3]), ([2], [""])):
            with self.assertRaises(Refused, msg=(contacts, values)) as ctx:
                self.grant(contacts=contacts, values=values)
            self.assertEqual(str(ctx.exception), "bad-scope")

    def test_ac6_the_signing_key_never_leaves_the_gateway(self):
        token = self.grant()
        self.call("crm.add_tag", {"contact_id": 2, "tag": "hot-lead"}, token)
        key = self.gw._key.hex()
        self.assertNotIn(key, json.dumps(self.gw.audit.rows()) + json.dumps(self.gw.menu()) + token)
        self.assertNotIn(token, json.dumps(self.gw.audit.rows()), "tokens are bearer secrets: log the id only")


class OutboundNever(D1Case):
    def test_ac7_sms_and_email_are_refused(self):
        r = self.call("sms.send", {"contact_id": 4, "body": "Flash sale"})
        self.assertEqual((r["status"], r["reason"]), ("denied", "never:outbound"))
        r = self.call("email.send", {"contact_id": 4, "subject": "Hi", "body": "Flash sale"})
        self.assertEqual((r["status"], r["reason"]), ("denied", "never:outbound"))
        self.assert_crm_unchanged()

    def test_ac7_sends_are_refused_even_with_a_valid_token_naming_them(self):
        token = self.mint("sms.send", [4], ["Flash sale"], uses=3)
        r = self.call("sms.send", {"contact_id": 4, "body": "Flash sale"}, token)
        self.assertEqual((r["status"], r["reason"]), ("denied", "never:outbound"))
        token = self.mint("email.send", [4], ["Flash sale"], uses=3)
        r = self.call("email.send", {"contact_id": 4, "subject": "Hi", "body": "Flash sale"}, token)
        self.assertEqual((r["status"], r["reason"]), ("denied", "never:outbound"))
        self.assert_crm_unchanged()

    def test_ac7_a_write_approval_does_not_unlock_a_send(self):
        token = self.grant(contacts=(4,))
        r = self.call("sms.send", {"contact_id": 4, "body": "hot-lead"}, token)
        self.assertEqual((r["status"], r["reason"]), ("denied", "never:outbound"))
        self.assert_crm_unchanged()


class DefaultDeny(D1Case):
    def test_ac8_deletes_are_refused_even_with_a_token(self):
        self.assertEqual(self.call("crm.delete_contact", {"contact_id": 5})["reason"], "never:destructive")
        token = self.mint("crm.delete_contact", [5], ["x"])
        self.assertEqual(self.call("crm.delete_contact", {"contact_id": 5}, token)["reason"], "never:destructive")
        self.assert_crm_unchanged()

    def test_ac8_unknown_tools_are_refused(self):
        for tool in ("audit.clear", "approvals.grant", "crm.run_sql", 42, None, ["crm.get_contact"]):
            r = self.call(tool, {})
            self.assertEqual((r["status"], r["reason"]), ("denied", "never:unlisted-tool"), tool)
        self.assert_crm_unchanged()

    def test_ac8_a_tool_added_later_without_classifying_it_is_refused(self):
        calls = []

        def export_contacts(conn):
            calls.append(1)
            return crm.snapshot(conn)

        tools = dict(crm.TOOLS, **{"crm.export_contacts": crm.Tool(export_contacts, {}, None)})
        gw = Gateway(self.gw.conn, self.gw.audit, load_json("policy.json"), self.clock, tools=tools)
        r = gw.handle(AGENT, "crm.export_contacts", {})
        self.assertEqual((r["status"], r["reason"]), ("denied", "never:unlisted-tool"))
        self.assertEqual(calls, [])
        self.assertNotIn("crm.export_contacts", gw.menu())


class Validation(D1Case):
    def test_ac9_malformed_arguments_are_refused(self):
        for args in ({"contact_id": "2"}, {"contact_id": True}, {"contact_id": -1}, {}, {"contact_id": 2, "x": 1},
                     None, [2], {"contact_id": 2.0}):
            r = self.call("crm.get_contact", args)
            self.assertEqual((r["status"], r["reason"]), ("denied", "invalid-args"), args)
        self.assertEqual(self.call("crm.search_contacts", {"query": "x" * 501})["reason"], "invalid-args")

    def test_ac9_hidden_characters_and_out_of_range_ids_are_refused(self):
        cases = [
            ("crm.add_tag", {"contact_id": 2, "tag": "hot-lead\n"}),  # looks like "hot-lead" to an approver
            ("crm.add_tag", {"contact_id": 2, "tag": "hot-lead\ud800"}),  # not valid UTF-8
            ("crm.search_contacts", {"query": "x\x1b[32m ALLOWED"}),  # terminal escape
            ("crm.get_contact", {"contact_id": 2**63}),  # larger than SQLite's integer
            ("crm.get_contact", {"contact_id": 2**31}),
        ]
        for tool, args in cases:
            r = self.call(tool, args)
            self.assertEqual((r["status"], r["reason"]), ("denied", "invalid-args"), args)
        self.assertEqual(len(self.decisions()), len(cases), "every refusal is logged")
        self.assert_crm_unchanged()

    def test_ac9_a_check_that_crashes_is_a_logged_refusal(self):
        with mock.patch.object(crm, "exists", side_effect=sqlite3.OperationalError("database is locked")):
            r = self.call("crm.get_contact", {"contact_id": 2})
        self.assertEqual((r["status"], r["reason"]), ("denied", "policy-error:OperationalError"))
        self.assertEqual(self.decisions(), [("crm.get_contact", "deny", "policy-error:OperationalError")])

    def test_ac9_unknown_contacts_are_refused_before_any_approval(self):
        self.assertEqual(self.call("crm.get_contact", {"contact_id": 99})["reason"], "unknown-contact")
        self.assertEqual(self.call("crm.add_tag", {"contact_id": 99, "tag": "hot-lead"})["reason"], "unknown-contact")

    def test_ac9_invalid_values_are_refused_even_with_a_matching_token(self):
        token = self.mint("crm.set_stage", [2], ["archived-forever"])
        r = self.call("crm.set_stage", {"contact_id": 2, "stage": "archived-forever"}, token)
        self.assertEqual((r["status"], r["reason"]), ("denied", "invalid-stage"))
        token = self.mint("crm.add_tag", [2], ["VIP; DROP TABLE contacts"])
        r = self.call("crm.add_tag", {"contact_id": 2, "tag": "VIP; DROP TABLE contacts"}, token)
        self.assertEqual((r["status"], r["reason"]), ("denied", "invalid-tag"))
        self.assert_crm_unchanged()


class Audit(D1Case):
    def exercise(self):
        self.call("crm.get_contact", {"contact_id": 2})
        self.call("crm.add_tag", {"contact_id": 2, "tag": "hot-lead"})
        self.call("sms.send", {"contact_id": 2, "body": "hi"})
        token = self.grant()
        self.call("crm.add_tag", {"contact_id": 2, "tag": "hot-lead"}, token)
        self.call("crm.add_tag", {"contact_id": 2, "tag": "hot-lead"}, "forged")
        self.gw.decline(APPROVER, {"action": "crm.set_stage", "contact_id": 4, "value": "won"}, "not from the team")
        self.gw.protocol_violation(AGENT, {"type": "grant"})

    def test_ac10_every_decision_is_logged(self):
        self.exercise()
        rows = self.gw.audit.rows()
        self.assertEqual([(r["event"], r["decision"], r["reason"]) for r in rows], [
            ("decision", "allow", "read"),
            ("decision", "needs-approval", "approval-required"),
            ("decision", "deny", "never:outbound"),
            ("approval-granted", "grant", None),
            ("decision", "allow", "approved"),
            ("executed", None, None),
            ("decision", "deny", "bad-token"),
            ("approval-declined", "deny", "not from the team"),
            ("protocol-violation", "deny", "unsupported-message"),
        ])
        self.assertEqual(json.loads(rows[2]["detail"])["args"], {"contact_id": 2, "body": "hi"})
        self.assertEqual({r["actor"] for r in rows}, {AGENT, APPROVER})

    def test_ac10_text_that_is_not_valid_utf8_is_still_logged(self):
        for i in range(3):
            self.assertEqual(self.call(f"sms.send\ud800{i}", {})["reason"], "never:unlisted-tool")
        self.gw.decline(APPROVER, {"action": "\ud800", "contact_id": 2, "value": "x"}, "nope\udfff")
        self.gw.protocol_violation("agent\ud800", {"type": "\ud800"})
        rows = self.gw.audit.rows()
        self.assertEqual([r["event"] for r in rows], ["decision"] * 3 + ["approval-declined", "protocol-violation"])
        self.assertIn("\\ud800", rows[0]["tool"])
        self.assertEqual(self.gw.audit.verify(), (True, "chain intact"))

    def test_ac10_huge_arguments_are_cut_before_logging(self):
        r = self.call("sms.send", {"contact_id": 4, "body": "x" * 1_000_000})
        self.assertEqual(r["reason"], "never:outbound")
        self.assertLess(len(self.gw.audit.rows()[0]["detail"]), 3000)

    def test_ac10_the_log_is_append_only(self):
        self.exercise()
        n = len(self.gw.audit.rows())
        with self.assertRaises(sqlite3.DatabaseError):
            self.gw.audit.conn.execute("UPDATE audit_log SET reason = 'approved' WHERE seq = 3")
        with self.assertRaises(sqlite3.DatabaseError):
            self.gw.audit.conn.execute("DELETE FROM audit_log")
        self.assertEqual(len(self.gw.audit.rows()), n)
        self.assertEqual(self.gw.audit.verify(), (True, "chain intact"))

    def drop_triggers(self):
        for t in ("audit_log_no_update", "audit_log_no_delete"):
            self.gw.audit.conn.execute(f"DROP TRIGGER {t}")

    def test_ac10_the_hash_chain_detects_an_edit_even_without_the_triggers(self):
        self.exercise()
        self.drop_triggers()  # someone with raw access to the file
        self.gw.audit.conn.execute(
            "UPDATE audit_log SET detail = ? WHERE seq = 3", (json.dumps({"args": {"note": "nothing happened"}}),)
        )
        ok, why = self.gw.audit.verify()
        self.assertFalse(ok)
        self.assertIn("seq 3", why)

    def test_ac10_the_hash_chain_detects_deleted_rows_and_truncation(self):
        self.exercise()
        head = self.gw.audit.head()
        self.drop_triggers()
        self.gw.audit.conn.execute("DELETE FROM audit_log WHERE seq = (SELECT MAX(seq) FROM audit_log)")
        self.assertTrue(self.gw.audit.verify()[0], "a clean truncation needs the recorded head to be caught")
        self.assertFalse(self.gw.audit.verify(expected_head=head)[0])
        self.gw.audit.conn.execute("DELETE FROM audit_log WHERE seq = 2")
        self.assertFalse(self.gw.audit.verify()[0])

    def test_ac10_if_the_decision_cannot_be_logged_nothing_runs(self):
        token = self.grant()
        real = self.gw.audit.append

        def broken(at, actor, event, **kw):
            if event == "decision":
                raise sqlite3.OperationalError("disk I/O error (simulated)")
            return real(at, actor, event, **kw)

        with mock.patch.object(self.gw.audit, "append", broken):
            for tool, args, tok in (("crm.get_contact", {"contact_id": 2}, None),
                                    ("crm.add_tag", {"contact_id": 2, "tag": "hot-lead"}, token)):
                r = self.call(tool, args, tok)
                self.assertEqual((r["status"], r["reason"]), ("denied", "audit-unavailable"))
        self.assert_crm_unchanged()

    def test_ac10_the_log_is_a_separate_store_from_the_crm(self):
        tables = {r[0] for r in self.gw.conn.execute("SELECT name FROM sqlite_master WHERE type = 'table'")}
        self.assertNotIn("audit_log", tables)
        self.assertIsNot(self.gw.conn, self.gw.audit.conn)


class AgentIsolation(D1Case):
    def session(self, steps):
        approver = HumanApprover(load_json("approver_script.json"))
        return run_session(self.gw, steps, approver)

    def test_ac11_the_agent_process_inherits_no_secrets_and_cannot_import_the_gateway(self):
        with mock.patch.dict(os.environ, {"D1_CANARY_TOKEN": "canary"}):
            events = self.session([{"do": "probe"}])
        found = [e["found"] for e in events if e["kind"] == "probe"][0]
        self.assertNotIn("D1_CANARY_TOKEN", found["env"])
        self.assertLessEqual(set(found["env"]), {"LC_CTYPE", "__CF_USER_TEXT_ENCODING"}, "only runtime locale defaults")
        self.assertEqual(found["importable"], [])
        self.assertTrue(found["isolated_mode"])
        self.assertEqual(events[-1]["kind"], "done")

    def test_ac11_the_agent_cannot_approve_itself_or_step_outside_the_protocol(self):
        steps = [
            {"do": "raw", "message": {"type": "grant", "action": "sms.send", "contact_ids": [4]}},
            {"do": "raw", "message": {"type": "approval", "token": "self-made"}},
            {"do": "raw", "message": ["not", "an", "object"]},
            {"do": "raw", "message": {"type": "request_approval", "proposal": "tag everyone"}},
            {"do": "call", "tool": "approvals.grant", "args": {"action": "sms.send", "contact_ids": [4]}},
            {"do": "call", "tool": "sms.send", "args": {"contact_id": 4, "body": "hi"}, "ask_human": True},
        ]
        events = self.session(steps)
        self.assertEqual([e["kind"] for e in events], ["start", "violation", "violation", "violation", "violation",
                                                       "call", "call", "done"])
        events_logged = [r["event"] for r in self.gw.audit.rows()]
        self.assertEqual(events_logged.count("protocol-violation"), 4)
        self.assertNotIn("approval-granted", events_logged)
        self.assert_crm_unchanged()

    def test_ac11_garbage_on_the_pipe_is_refused_and_logged_not_crashed_on(self):
        steps = [
            {"do": "raw_line", "text": "[" * 50_000},  # nesting deep enough to exhaust the JSON parser
            {"do": "raw_line", "hex": "ff fe 7b 7d"},  # not UTF-8
            {"do": "raw_line", "text": "x" * 70_000},  # over the per-message size limit
            {"do": "raw_line", "text": "not json"},
            {"do": "raw", "message": {"type": "probe", "found": {"env": "\n-> ALLOWED"}}},  # malformed probe
            {"do": "call", "tool": "crm.list_pipeline", "args": {}},  # the session carries on afterwards
        ]
        events = self.session(steps)
        self.assertEqual([e.get("message_type") for e in events if e["kind"] == "violation"],
                         ["unparseable-message", "unparseable-message", "oversized-message", "unparseable-message",
                          "probe"])
        self.assertEqual([e["kind"] for e in events][-2:], ["call", "done"])
        reasons = [r["reason"] for r in self.gw.audit.rows() if r["event"] == "protocol-violation"]
        self.assertEqual(reasons, ["unparseable-message", "unparseable-message", "oversized-message",
                                   "unparseable-message", "unsupported-message"])

    def test_ac11_an_agent_that_vanishes_ends_the_session_and_is_logged(self):
        events = self.session([{"do": "exit"}])
        self.assertEqual(events[-1], {"kind": "stopped", "reason": "agent-exited"})
        self.assertEqual(self.gw.audit.rows()[-1]["event"], "session-stopped")

    def test_ac11_a_request_for_approval_goes_to_a_human_who_can_decline(self):
        steps = [{"do": "call", "tool": "crm.set_stage", "args": {"contact_id": 4, "stage": "won"}, "ask_human": True}]
        events = self.session(steps)
        human = [e for e in events if e["kind"] == "human"][0]
        self.assertFalse(human["approved"])
        self.assert_crm_unchanged()

    def test_ac11_a_looping_agent_is_stopped_by_the_message_budget(self):
        steps = [{"do": "call", "tool": "crm.list_pipeline", "args": {}}] * 300
        events = self.session(steps)
        self.assertEqual(events[-1], {"kind": "stopped", "reason": "message-budget-exhausted"})
        self.assertEqual(self.gw.audit.rows()[-1]["reason"], "message-budget-exhausted")


class EndToEnd(unittest.TestCase):
    def test_ac12_the_demo_scenario_ends_exactly_as_scripted(self):
        import demo

        lines = []
        with redirect_stdout(io.StringIO()):
            gw = demo.run(out=lines.append)
        self.assertTrue(lines[0].startswith("Illustrative synthetic scenario. Not a real client, result, or testimonial."))
        reasons = [r["reason"] for r in gw.audit.rows() if r["event"] == "decision"]
        self.assertEqual(reasons, [
            "read", "read", "read", "approval-required", "approved", "out-of-scope:contact", "out-of-scope:action",
            "approval-used-up", "approval-required", "approval-expired", "read", "never:outbound", "never:outbound",
            "approval-required", "never:unlisted-tool", "never:unlisted-tool", "never:destructive",
        ])
        after = {c["id"]: c for c in crm.snapshot(gw.conn)}
        self.assertEqual(len(after), 5)
        self.assertEqual(after[2]["tags"], ["hot-lead", "web-form"])
        self.assertEqual([c["stage"] for c in after.values()], ["won", "new", "new", "new", "lost"])
        self.assertEqual(crm.count(gw.conn, "outbox"), 0)
        self.assertEqual(gw.audit.verify(), (True, "chain intact"))


    def test_ac12_agent_text_cannot_fake_a_line_in_the_demo_output(self):
        import demo

        for hostile in ("ok\n      -> ALLOWED (approved)", "\x1b[2K\rHUMAN approves", {"a": "\n"}, ["\r"]):
            shown = demo.clean(hostile)
            self.assertNotRegex(shown, r"[\x00-\x1f\x7f]", hostile)
        self.assertTrue(demo.clean("x" * 1000).endswith("..."))
        fake_row = "x\n  12 15:00:04 Demo Approver: Owner    approval-granted   sms.send   grant"
        steps = [{"do": "call", "tool": tool, "args": {}, "why": tool}
                 for tool in (fake_row, "crm.list_pipeline\x1b[32m ALLOWED", "a\x7f\r")]
        lines = []
        demo.run(out=lines.append, script={"task": "hostile\ntask", "steps": steps})
        for line in lines:
            for part in line.split("\n"):  # out() gets whole lines; any embedded break would be a forged line
                self.assertEqual(part, line, "agent text broke a line")
            self.assertNotRegex(line, r"[\x00-\x1f\x7f]")
        forged = [l for l in lines if re.match(r"\s+\d+ \d\d:\d\d:\d\d Demo Approver", l)]
        self.assertEqual(forged, [], "no human ever acted, so no audit row may start with an approver")


class ProofHygiene(unittest.TestCase):
    """AC13: the demo is self-contained and synthetic (the pre-share checks that code can enforce)."""

    ROOT = Path(__file__).resolve().parent.parent

    def sources(self):
        return [p for p in self.ROOT.rglob("*") if p.is_file() and p.suffix in {".py", ".json", ".md", ".sh"}]

    def test_ac13_no_network_or_model_sdk_imports(self):
        banned = re.compile(
            r"^\s*(import|from)\s+(socket|http|urllib|smtplib|requests|httpx|twilio|ssl|anthropic|openai)\b", re.M
        )
        for p in self.ROOT.rglob("*.py"):
            self.assertIsNone(banned.search(p.read_text()), f"network import in {p.name}")

    def test_ac13_the_agent_side_imports_only_json_os_sys_importlib(self):
        src = (self.ROOT / "guardrail" / "agent_proc.py").read_text()
        imported = set(re.findall(r"^(?:import|from)\s+([\w.]+)", src, re.M))
        self.assertEqual(imported, {"importlib.util", "json", "os", "sys"})

    def test_ac13_all_phone_numbers_are_reserved_fictional_555_01xx(self):
        phone = re.compile(r"(?<![\d])(?:\+?1[\s.-]?)?\(?\d{3}\)?[\s.-]?\d{3}[\s.-]?\d{4}(?![\d])")
        for p in self.sources():
            for m in phone.finditer(p.read_text()):
                digits = re.sub(r"\D", "", m.group())[-10:]
                self.assertRegex(digits[3:], r"^55501\d\d$", f"non-fictional number {m.group()!r} in {p.name}")

    def test_ac13_no_email_addresses(self):
        email = re.compile(r"[\w.%+-]+@[\w-]+\.[a-z]{2,}", re.I)
        for p in self.sources():
            self.assertIsNone(email.search(p.read_text()), p.name)

    def test_ac13_fixtures_carry_the_synthetic_label(self):
        for p in (self.ROOT / "fixtures").glob("*.json"):
            self.assertIn("Synthetic scenario — not a client deployment", json.loads(p.read_text())["_label"])

    def test_ac13_public_docs_open_with_the_verbatim_label_and_ship_a_license(self):
        label = "> **Illustrative synthetic scenario.** Not a real client, result, or testimonial."
        for name in ("README.md", "ACCEPTANCE.md"):
            self.assertEqual((self.ROOT / name).read_text().splitlines()[0], label, f"{name} line 1")
        self.assertTrue((self.ROOT / "LICENSE").read_text().startswith("MIT License"))


if __name__ == "__main__":
    unittest.main()
