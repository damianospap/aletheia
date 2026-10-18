import hashlib
import json
import os
import sqlite3
import threading
import unittest

from aletheia import errors, vault
from aletheia.indexing import index_evidence
from aletheia.models import Exposure, Purpose
from aletheia.vault import GENESIS, Vault, canonical_json, entry_hash

from helpers import FakeClock, VaultTestCase

TEXT = "Pay IBAN GR16 0110 1250 0000 0001 2300 695 or +30 694 123 4567 via https://evil.top/pay"


def codes(report):
    return sorted(i.code for i in report.issues)


class LifecycleTests(VaultTestCase):
    def test_create_requires_aup_and_valid_title(self):
        with self.assertRaises(errors.AupNotAcceptedError):
            self.vault.create_case("x", Purpose.JOURNALISM, accept_aup=False)
        for bad in ("", "   ", "x" * 201):
            with self.assertRaises(errors.ValidationError):
                self.vault.create_case(bad, Purpose.JOURNALISM, accept_aup=True)
        self.assertEqual(self.vault.list_cases(), [])

    def test_create_open_list_delete(self):
        case = self.new_case("Δοκιμή | υπόθεση")
        cid = case.case_id
        self.assertRegex(cid, r"^\d{8}-\d{6}-[0-9a-f]{6}$")
        self.assertEqual(case.title, "Δοκιμή | υπόθεση")
        self.assertEqual(case.purpose, "victim-report")
        case.close()
        summaries = self.vault.list_cases()
        self.assertEqual([(s.case_id, s.title, s.evidence_count) for s in summaries], [(cid, "Δοκιμή | υπόθεση", 0)])
        with self.vault.open_case(cid) as again:
            again.add_evidence(b"x", kind="text", source="s", method="manual_import")
        self.assertEqual(self.vault.list_cases()[0].evidence_count, 1)
        self.vault.delete_case(cid)
        self.assertEqual(self.vault.list_cases(), [])
        with self.assertRaises(errors.CaseNotFoundError):
            self.vault.delete_case(cid)

    def test_case_ids_are_validated_against_path_traversal(self):
        for bad in ("../x", "..", "20261014-090000-ZZZZZZ", "", "20261014-090000-abcdef/../../etc", "a" * 40):
            with self.assertRaises(errors.InvalidCaseIdError, msg=bad):
                self.vault.open_case(bad)
            with self.assertRaises(errors.InvalidCaseIdError, msg=bad):
                self.vault.delete_case(bad)
        with self.assertRaises(errors.CaseNotFoundError):
            self.vault.open_case("20200101-000000-abcdef")

    def test_control_characters_in_title_are_neutralised(self):
        case = self.new_case("line1\nline2\x00end")
        self.assertEqual(case.title, "line1 line2 end")

    def test_private_permissions(self):
        case = self.new_case()
        if os.name == "posix":
            self.assertEqual(case.dir.stat().st_mode & 0o077, 0)
            self.assertEqual((case.dir / "blobs").stat().st_mode & 0o077, 0)

    def test_database_corruption_and_future_schema(self):
        case = self.new_case()
        cid, path = case.case_id, case.dir / "case.db"
        case.close()
        conn = sqlite3.connect(path)
        conn.execute("PRAGMA user_version = 99")
        conn.close()
        with self.assertRaises(errors.VaultTooNewError):
            self.vault.open_case(cid)
        path.write_bytes(b"this is not a database" * 100)
        with self.assertRaises(errors.VaultIntegrityError):
            self.vault.open_case(cid)


class EvidenceTests(VaultTestCase):
    def test_sequential_ids_dedupe_and_read_back(self):
        case = self.new_case()
        a = case.add_evidence(b"same bytes", kind="text", source="one", method="manual_import")
        b = case.add_evidence(b"same bytes", kind="text", source="two", method="manual_import")
        c = case.add_evidence("Καλημέρα".encode(), kind="text", source="three", method="manual_import", media_type="text/plain")
        self.assertEqual([a.id, b.id, c.id], ["E0001", "E0002", "E0003"])
        self.assertEqual(a.sha256, b.sha256)
        self.assertEqual(len([p for p in (case.dir / "blobs").rglob("*") if p.is_file()]), 2)  # deduplicated blob
        self.assertEqual(case.read_blob(a.sha256), b"same bytes")
        self.assertEqual(case.get_evidence("E0003").media_type, "text/plain")
        self.assertEqual([e.id for e in case.list_evidence()], ["E0001", "E0002", "E0003"])
        audit = [e for e in case.audit_entries() if e.action == "evidence.add"]
        self.assertEqual([e.payload["deduplicated"] for e in audit], [False, True, False])
        self.assertTrue(case.verify().ok)

    def test_blobs_are_read_only(self):
        case = self.new_case()
        ev = case.add_evidence(b"x", kind="text", source="s", method="manual_import")
        if os.name == "posix":
            self.assertEqual(case.blob_path(ev.sha256).stat().st_mode & 0o222, 0)

    def test_add_file_streams_and_enforces_limit(self):
        case = self.new_case()
        big = self.tmp_path("big.bin")
        big.write_bytes(os.urandom(3 * 1024 * 1024 + 17))
        ev = case.add_evidence_file(big, kind="file", source="big.bin", method="manual_import")
        self.assertEqual(ev.sha256, hashlib.sha256(big.read_bytes()).hexdigest())
        self.assertEqual(ev.size, big.stat().st_size)
        before = len(case.list_evidence())
        with self.assertRaises(errors.InputTooLargeError):
            case.add_evidence_file(big, kind="file", source="big.bin", method="manual_import", max_bytes=1024)
        self.assertEqual(len(case.list_evidence()), before)
        self.assertFalse([p for p in (case.dir / "blobs").iterdir() if p.name.startswith(".tmp-")])

    def test_read_blob_detects_tampering(self):
        case = self.new_case()
        ev = case.add_evidence(b"original", kind="text", source="s", method="manual_import")
        path = case.blob_path(ev.sha256)
        os.chmod(path, 0o600)
        path.write_bytes(b"forged!!")
        with self.assertRaises(errors.VaultIntegrityError):
            case.read_blob(ev.sha256)
        path.unlink()
        with self.assertRaises(errors.VaultIntegrityError):
            case.read_blob(ev.sha256)

    def test_unknown_evidence_is_a_localizable_error(self):
        case = self.new_case()
        with self.assertRaises(errors.ValidationError) as cm:
            case.get_evidence("E9999")
        self.assertEqual(cm.exception.key, "error.validation.unknown_evidence")

    def test_sql_injection_is_inert(self):
        case = self.new_case("'); DROP TABLE evidence;--")
        ev = case.add_evidence(b"x", kind="text", source="'; DELETE FROM audit;--", method="manual_import",
                               note="\" OR 1=1 --")
        self.assertEqual(case.title, "'); DROP TABLE evidence;--")
        self.assertEqual(case.get_evidence(ev.id).source, "'; DELETE FROM audit;--")
        self.assertTrue(case.verify().ok)

    def test_exposure_is_stored(self):
        case = self.new_case()
        ev = case.add_evidence(b"x", kind="http_body", source="u", method="http_get", exposure=Exposure.ACTIVE)
        self.assertEqual(case.get_evidence(ev.id).exposure, "active_target")


class AuditTests(VaultTestCase):
    def test_chain_formula_is_reproducible_independently(self):
        case = self.new_case()
        case.add_evidence(b"x", kind="text", source="s", method="manual_import")
        case.log("custom.note", {"why": "Δοκιμή"})
        prev = GENESIS
        for e in case.audit_entries():
            body = {"seq": e.seq, "ts": e.ts, "actor": e.actor, "action": e.action, "payload": e.payload}
            expected = hashlib.sha256(prev.encode() + b"\n" + json.dumps(
                body, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()).hexdigest()
            self.assertEqual(e.entry_hash, expected)
            self.assertEqual(e.prev_hash, prev)
            prev = e.entry_hash
        self.assertEqual(case.anchor()["entry_hash"], prev)
        self.assertEqual([e.action for e in case.audit_entries()],
                         ["case.create", "policy.aup_accepted", "evidence.add", "custom.note"])

    def test_canonical_json_is_order_independent_and_ascii(self):
        self.assertEqual(canonical_json({"b": 1, "a": [2, {"d": 1, "c": 2}]}), canonical_json({"a": [2, {"c": 2, "d": 1}], "b": 1}))
        self.assertEqual(canonical_json({"k": "δ"}), b'{"k":"\\u03b4"}')
        self.assertNotEqual(entry_hash(GENESIS, {"a": 1}), entry_hash("1" * 64, {"a": 1}))

    def test_invalid_audit_action_rejected(self):
        case = self.new_case()
        for bad in ("", "Has Space", "UPPER", "a" * 65, "x;y"):
            with self.assertRaises(errors.ValidationError, msg=bad):
                case.log(bad)

    def test_actor_defaults_to_operator_not_the_os_user(self):
        case = self.new_case()
        self.assertEqual({e.actor for e in case.audit_entries()}, {"operator"})
        other = self.vault.create_case("n", Purpose.JOURNALISM, accept_aup=True, actor="Μαρία")
        self.addCleanup(other.close)
        self.assertEqual({e.actor for e in other.audit_entries()}, {"Μαρία"})


class TamperDetectionTests(VaultTestCase):
    def make(self):
        case = self.new_case()
        ev = case.add_evidence(TEXT.encode(), kind="text", source="s", method="manual_import", media_type="text/plain")
        index_evidence(case, ev.id)
        case.save_analysis("triage", ev.id, {"level": "high", "score": 9})
        self.assertTrue(case.verify().ok)
        return case, ev

    def db(self, case):
        conn = sqlite3.connect(case.dir / "case.db", isolation_level=None)
        self.addCleanup(conn.close)
        return conn

    def test_clean_case_has_no_issues(self):
        case, _ = self.make()
        report = case.verify()
        self.assertEqual((report.ok, report.issues), (True, []))
        self.assertGreater(report.entries_checked, 4)

    def test_modified_blob(self):
        case, ev = self.make()
        path = case.blob_path(ev.sha256)
        os.chmod(path, 0o600)
        path.write_bytes(path.read_bytes() + b"x")
        report = case.verify()
        self.assertFalse(report.ok)
        self.assertEqual(codes(report), ["BLOB_CORRUPT"])

    def test_deleted_blob(self):
        case, ev = self.make()
        case.blob_path(ev.sha256).unlink()
        self.assertEqual(codes(case.verify()), ["BLOB_MISSING"])

    def test_modified_audit_payload(self):
        case, _ = self.make()
        self.db(case).execute("UPDATE audit SET payload = ? WHERE seq = 3", ('{"id":"E0001","tampered":true}',))
        self.assertIn("AUDIT_HASH_MISMATCH", codes(case.verify()))

    def test_deleted_audit_entry(self):
        case, _ = self.make()
        self.db(case).execute("DELETE FROM audit WHERE seq = 3")
        found = codes(case.verify())
        self.assertIn("AUDIT_SEQ_GAP", found)
        self.assertIn("AUDIT_CHAIN_BROKEN", found)
        self.assertIn("EVIDENCE_NOT_IN_AUDIT", found)

    def test_truncated_audit_tail_is_visible_through_evidence(self):
        case, _ = self.make()
        self.db(case).execute("DELETE FROM audit WHERE seq = (SELECT MAX(seq) FROM audit)")
        self.assertIn("ANALYSIS_NOT_IN_AUDIT", codes(case.verify()))

    def test_modified_and_deleted_evidence_rows(self):
        case, ev = self.make()
        self.db(case).execute("UPDATE evidence SET source = 'forged' WHERE id = ?", (ev.id,))
        self.assertIn("EVIDENCE_AUDIT_MISMATCH", codes(case.verify()))
        self.db(case).execute("PRAGMA foreign_keys=OFF")
        self.db(case).execute("DELETE FROM evidence WHERE id = ?", (ev.id,))
        self.assertIn("EVIDENCE_MISSING_FROM_DB", codes(case.verify()))

    def test_modified_analysis(self):
        case, _ = self.make()
        self.db(case).execute("UPDATE analysis SET result = ?", ('{"level":"none","score":0}',))
        self.assertEqual(codes(case.verify()), ["ANALYSIS_MODIFIED"])

    def test_orphan_blob_and_leftover_tmp_are_warnings_only(self):
        case, _ = self.make()
        (case.dir / "blobs" / "ab").mkdir(exist_ok=True)
        (case.dir / "blobs" / "ab" / ("ab" + "0" * 62)).write_bytes(b"stray")
        (case.dir / "blobs" / ".tmp-leftover").write_bytes(b"x")
        report = case.verify()
        self.assertTrue(report.ok)
        self.assertEqual(codes(report), ["BLOB_ORPHAN", "BLOB_TMP_LEFTOVER"])
        self.assertTrue(all(i.severity == "warning" for i in report.issues))

    def test_all_problems_are_reported_not_just_the_first(self):
        case, ev = self.make()
        os.chmod(case.blob_path(ev.sha256), 0o600)
        case.blob_path(ev.sha256).write_bytes(b"x")
        self.db(case).execute("UPDATE audit SET actor = 'mallory' WHERE seq = 1")
        self.assertGreaterEqual(len(codes(case.verify())), 2)


class IndicatorStorageTests(VaultTestCase):
    def test_observations_are_idempotent(self):
        case = self.new_case()
        ev = case.add_evidence(TEXT.encode(), kind="text", source="s", method="manual_import", media_type="text/plain")
        first = index_evidence(case, ev.id)
        second = index_evidence(case, ev.id)
        self.assertGreater(first, 0)
        self.assertEqual(second, 0)
        rows = case.list_indicators()
        self.assertEqual({r.type for r in rows}, {"iban", "phone", "url", "domain"})
        self.assertTrue(all(r.evidence_ids == [ev.id] for r in rows))
        self.assertTrue(case.verify().ok)

    def test_binary_evidence_is_not_indexed(self):
        case = self.new_case()
        ev = case.add_evidence(b"\x89PNG" + bytes(50), kind="file", source="a.png", method="manual_import",
                               media_type="image/png")
        self.assertEqual(index_evidence(case, ev.id), 0)

    def test_record_for_unknown_evidence_fails(self):
        case = self.new_case()
        with self.assertRaises(errors.ValidationError):
            case.record_observations("E0042", [], "1")

    def test_analysis_roundtrip(self):
        case = self.new_case()
        aid = case.save_analysis("domain", None, {"domain": "evil.top", "n": 1, "greek": "δ"})
        (row,) = case.list_analyses("domain")
        self.assertEqual((row["id"], row["result"]["greek"]), (aid, "δ"))
        self.assertEqual(case.list_analyses("triage"), [])


class ConcurrencyTests(VaultTestCase):
    def test_parallel_writers_keep_a_consistent_chain(self):
        case = self.new_case()
        cid = case.case_id
        errs: list[Exception] = []

        def worker(n: int) -> None:
            try:
                with Vault(self.home, clock=FakeClock()).open_case(cid) as c:
                    for i in range(8):
                        c.add_evidence(f"w{n}-{i}".encode(), kind="text", source=f"w{n}", method="manual_import")
            except Exception as exc:  # noqa: BLE001
                errs.append(exc)

        threads = [threading.Thread(target=worker, args=(n,)) for n in range(5)]
        [t.start() for t in threads]
        [t.join() for t in threads]
        self.assertEqual(errs, [])
        evidence = case.list_evidence()
        self.assertEqual(len(evidence), 40)
        self.assertEqual([e.seq for e in evidence], list(range(1, 41)))
        report = case.verify()
        self.assertTrue(report.ok, report.issues)

    def test_failed_write_rolls_back_cleanly(self):
        case = self.new_case()
        before = len(case.audit_entries())
        with self.assertRaises(errors.ValidationError):
            case.log("Bad Action")
        self.assertEqual(len(case.audit_entries()), before)
        self.assertTrue(case.verify().ok)


class HelperTests(unittest.TestCase):
    def test_new_case_id_is_time_ordered(self):
        from datetime import datetime, timezone

        a = vault.new_case_id(datetime(2026, 1, 1, tzinfo=timezone.utc), lambda n: "aaaaaa")
        b = vault.new_case_id(datetime(2026, 1, 2, tzinfo=timezone.utc), lambda n: "000000")
        self.assertLess(a, b)
        self.assertEqual(vault.validate_case_id(a), a)


if __name__ == "__main__":
    unittest.main()
