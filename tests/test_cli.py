import io
import json
import os
import re
import subprocess
import sys
import tempfile
import unittest
import zipapp
import zipfile
from pathlib import Path
from unittest import mock

from aletheia import cli, errors, platform_info
from aletheia.cli import main
from aletheia.http import HttpResult

from helpers import FakeClock, TestSite, VaultTestCase, build_export_zip, env_for, make_client, thread_json

SRC = Path(__file__).resolve().parent.parent / "src"

SCAM = ("Επείγον! Ο λογαριασμός σας θα κλειδωθεί. Στείλτε τον κωδικό OTP. IBAN GR16 0110 1250 0000 0001 2300 695, "
        "τηλ 694 123 4567, hxxps://elta-gr-delivery[.]top/pay και @scam_acc")


class CliTestCase(VaultTestCase):
    def run_cli(self, *argv, stdin=b"", lang=None, client_factory=None, **env_extra):
        out, err = io.StringIO(), io.StringIO()
        env = env_for(self.home, **env_extra)
        if lang:
            env["ALETHEIA_LANG"] = lang
        stdin_obj = mock.Mock()
        stdin_obj.buffer = io.BytesIO(stdin)
        code = main(list(argv), stdin=stdin_obj, stdout=out, stderr=err, env=env, now=FakeClock(),
                    client_factory=client_factory)
        return code, out.getvalue(), err.getvalue()

    def new_case_id(self, **kw):
        code, out, err = self.run_cli("--json", "case", "new", "--title", "Δοκιμή", "--purpose", "victim-report",
                                      "--accept-aup", **kw)
        self.assertEqual(code, 0, err)
        return json.loads(out)["case_id"]


class CaseCommandTests(CliTestCase):
    def test_case_new_requires_aup_and_shows_it(self):
        code, out, err = self.run_cli("case", "new", "--title", "T", "--purpose", "journalism")
        self.assertEqual(code, 77)
        self.assertIn("Acceptable Use Policy", out)
        self.assertIn("1.", out)
        self.assertIn("E_AUP_REQUIRED", err)
        self.assertIn("--accept-aup", err)
        self.assertEqual(self.run_cli("case", "list")[1].strip(), "No cases yet.")

    def test_greek_aup_error(self):
        code, out, err = self.run_cli("case", "new", "--title", "T", "--purpose", "journalism", lang="el")
        self.assertEqual(code, 77)
        self.assertIn("Πολιτική Αποδεκτής Χρήσης", out)
        self.assertIn("Σφάλμα [E_AUP_REQUIRED]", err)

    def test_create_list_show_verify_delete(self):
        cid = self.new_case_id()
        code, out, _ = self.run_cli("case", "list")
        self.assertIn(cid, out)
        self.assertIn("Fraud victim report", out)
        code, out, _ = self.run_cli("--json", "case", "show", cid)
        data = json.loads(out)
        self.assertEqual((data["case"]["title"], data["evidence"]), ("Δοκιμή", 0))
        code, out, _ = self.run_cli("--lang", "el", "case", "verify", cid)
        self.assertEqual(code, 0)
        self.assertIn("Η ακεραιότητα επαληθεύτηκε", out)
        code, _, err = self.run_cli("case", "delete", cid)
        self.assertEqual((code, "--yes" in err), (2, True))
        self.assertEqual(self.run_cli("case", "delete", cid, "--yes")[0], 0)
        code, _, err = self.run_cli("case", "show", cid)
        self.assertEqual(code, 4)
        self.assertIn("E_CASE_NOT_FOUND", err)

    def test_bad_case_id_is_a_usage_error(self):
        code, _, err = self.run_cli("case", "show", "../../etc")
        self.assertEqual(code, 2)
        self.assertIn("E_BAD_CASE_ID", err)

    def test_verify_fails_with_exit_4_after_tampering(self):
        cid = self.new_case_id()
        self.run_cli("add", cid, "--text", "hello")
        with self.vault.open_case(cid) as case:
            blob = case.blob_path(case.list_evidence()[0].sha256)
        os.chmod(blob, 0o600)
        blob.write_bytes(b"forged")
        code, out, _ = self.run_cli("case", "verify", cid)
        self.assertEqual(code, 4)
        self.assertIn("BLOB_CORRUPT", out)
        code, out, _ = self.run_cli("--json", "case", "verify", cid)
        self.assertEqual((code, json.loads(out)["ok"]), (4, False))


class EvidenceCommandTests(CliTestCase):
    def test_add_text_stdin_and_file(self):
        cid = self.new_case_id()
        code, out, _ = self.run_cli("add", cid, "--text", SCAM, "--source", "dm")
        self.assertEqual(code, 0)
        self.assertIn("E0001", out)
        self.assertRegex(out, r"\d+ indicators recorded")
        code, out, _ = self.run_cli("--lang", "el", "add", cid, "--stdin", stdin="Στείλε στο +30 694 123 4567".encode())
        self.assertIn("Προστέθηκε το E0002", out)
        self.assertIn("Καταγράφηκε 1 δείκτης.", out)  # singular form for exactly one indicator
        f = self.tmp_path("note.txt")
        f.write_text("IBAN DE89 3704 0044 0532 0130 00", encoding="utf-8")
        code, out, _ = self.run_cli("--json", "add", cid, "--file", str(f), "--note", "ν")
        data = json.loads(out)
        self.assertEqual((data["evidence"]["source"], data["evidence"]["media_type"], data["indicators_recorded"]),
                         ("note.txt", "text/plain", 1))
        with self.vault.open_case(cid) as case:
            self.assertEqual(len(case.list_evidence()), 3)
            self.assertTrue(case.verify().ok)

    def test_input_validation(self):
        cid = self.new_case_id()
        for argv in (("add", cid), ("add", cid, "--text", "a", "--stdin"), ("extract",), ("triage",)):
            code, _, err = self.run_cli(*argv)
            self.assertEqual(code, 2, argv)
            self.assertIn("--text", err)
        self.assertEqual(self.run_cli("add", cid, "--stdin", stdin=b"")[0], 2)
        code, _, err = self.run_cli("add", cid, "--file", "/no/such/file")
        self.assertEqual((code, "E_USAGE" in err, "/no/such/file" in err), (2, True, True))

    def test_extract_is_stateless_and_machine_readable(self):
        code, out, _ = self.run_cli("--json", "extract", "--text", SCAM)
        data = json.loads(out)
        kinds = {(i["type"], i["value"]) for i in data["indicators"]}
        self.assertIn(("iban", "GR1601101250000000012300695"), kinds)
        self.assertIn(("domain", "elta-gr-delivery.top"), kinds)
        self.assertEqual(self.run_cli("case", "list")[1].strip(), "No cases yet.")  # nothing was stored
        human = self.run_cli("extract", "--text", SCAM)[1]
        self.assertIn("iban", human)
        self.assertIn("(derived)", human)
        self.assertIn("No indicators found.", self.run_cli("extract", "--text", "nothing here")[1])
        self.assertIn("Δεν βρέθηκαν δείκτες.", self.run_cli("--lang", "el", "extract", "--text", "nothing")[1])
        self.assertIn("GR1601101250000000012300695", self.run_cli("extract", "--stdin", stdin=SCAM.encode())[1])

    def test_triage_stateless_and_in_case(self):
        code, out, _ = self.run_cli("--lang", "el", "triage", "--text", SCAM)
        self.assertIn("υψηλό", out)
        self.assertIn("Πίεση για άμεση ενέργεια", out)
        cid = self.new_case_id()
        self.run_cli("add", cid, "--text", SCAM)
        code, out, _ = self.run_cli("--json", "triage", "--case", cid)
        res = json.loads(out)["results"]
        self.assertEqual((res[0]["evidence_id"], res[0]["level"]), ("E0001", "high"))
        with self.vault.open_case(cid) as case:
            self.assertEqual(len(case.list_analyses("triage")), 1)
            self.assertTrue(case.verify().ok)
        pack = self.tmp_path("mine.toml")
        pack.write_text('pack = {id="m", lang="en"}\n[[rule]]\nid="x"\ncategory="c"\nweight=3\npattern=\'\'\'otp\'\'\'\n')
        code, out, _ = self.run_cli("--json", "triage", "--text", "send otp", "--pack", str(pack))
        self.assertIn("c", json.loads(out)["results"][0]["categories"])
        bad = self.tmp_path("bad.toml")
        bad.write_text("not = = toml")
        code, _, err = self.run_cli("triage", "--text", "x", "--pack", str(bad))
        self.assertEqual((code, "E_PACK" in err), (3, True))
        self.assertIn("No text evidence", self.run_cli("triage", "--case", self.new_case_id())[1])


class InstagramCommandTests(CliTestCase):
    MSGS = [{"sender_name": "scam_acc", "timestamp_ms": 1_700_000_300_000,
             "content": "Στείλε στο IBAN GR16 0110 1250 0000 0001 2300 695", "share": {"link": "https://wa.me/306941234567"}},
            {"sender_name": "Victim", "timestamp_ms": 1_700_000_100_000, "content": "Τι χρειάζεσαι;"}]

    def export_zip(self):
        return build_export_zip(self.tmp_path("ig.zip"), {"message_requests/scam_1": [thread_json(self.MSGS)]})

    def test_ig_export_import(self):
        cid = self.new_case_id()
        code, out, err = self.run_cli("--lang", "el", "ig-export", cid, str(self.export_zip()))
        self.assertEqual(code, 0, err)
        self.assertIn("Εισήχθησαν 1 συζητήσεις (2 μηνύματα)", out)
        with self.vault.open_case(cid) as case:
            kinds = [e.kind for e in case.list_evidence()]
            self.assertEqual(kinds, ["ig_export_json", "ig_thread"])
            transcript = case.read_blob(case.list_evidence()[1].sha256).decode("utf-8")
            self.assertIn("Στείλε στο IBAN", transcript)  # mojibake repaired, Greek intact
            self.assertTrue(case.get_evidence("E0002").meta["derived_from"] == ["E0001"])
            self.assertIn("GR1601101250000000012300695", {i.value for i in case.list_indicators()})
            self.assertIn("+306941234567", {i.value for i in case.list_indicators()})
            (timeline,) = case.list_analyses("timeline")
            events = timeline["result"]["events"]
            self.assertEqual(len(events), 1)
            self.assertIn("iban:GR1601101250000000012300695", events[0]["indicators"])
            self.assertTrue(case.verify().ok)

    def test_ig_export_errors(self):
        cid = self.new_case_id()
        code, _, err = self.run_cli("ig-export", cid, str(self.tmp_path("missing.zip")))
        self.assertEqual((code, "E_PARSE" in err), (3, True))
        evil = self.tmp_path("evil.zip")
        with zipfile.ZipFile(evil, "w") as zf:
            zf.writestr("../evil.json", "{}")
        code, _, err = self.run_cli("--lang", "el", "ig-export", cid, str(evil))
        self.assertEqual(code, 3)
        self.assertIn("μη ασφαλές", err)

    def test_ig_id(self):
        code, out, _ = self.run_cli("--json", "ig-id", "https://www.instagram.com/p/Bk7e3P4gDAV/?igsh=1")
        data = json.loads(out)
        self.assertEqual((data["shortcode"], data["method"]), ("Bk7e3P4gDAV", "heuristic"))
        self.assertTrue(data["created_at"].endswith("Z"))
        self.assertIn("heuristic", self.run_cli("ig-id", "Bk7e3P4gDAV")[1])
        code, out, _ = self.run_cli("ig-id", "A")
        self.assertIn("Warning", out)
        code, _, err = self.run_cli("--lang", "el", "ig-id", "bad!code")
        self.assertEqual(code, 3)
        self.assertIn("Μη έγκυρος χαρακτήρας", err)
        code, _, err = self.run_cli("--lang", "el", "ig-id", "https://www.instagram.com/someone/")
        self.assertIn("Δεν βρέθηκε shortcode", err)


class ExportCommandTests(CliTestCase):
    def setUp(self):
        super().setUp()
        self.cid = self.new_case_id()
        self.run_cli("add", self.cid, "--text", SCAM)

    def test_export_both_languages_and_verify(self):
        out_dir = self.tmp_path("pack")
        code, out, err = self.run_cli("case", "export", self.cid, "--out", str(out_dir))
        self.assertEqual(code, 0, err)
        self.assertTrue((out_dir / "report.el.html").is_file() and (out_dir / "report.en.html").is_file())
        proc = subprocess.run([sys.executable, str(out_dir / "verify.py"), str(out_dir)], capture_output=True, text=True)
        self.assertEqual(proc.returncode, 0, proc.stdout)
        code, out, err = self.run_cli("case", "export", self.cid, "--out", str(out_dir))
        self.assertEqual((code, "E_OUT_EXISTS" in err), (2, True))
        self.assertEqual(self.run_cli("case", "export", self.cid, "--out", str(out_dir), "--force")[0], 0)

    def test_single_language_zip(self):
        z = self.tmp_path("pack.zip")
        code, out, _ = self.run_cli("--json", "case", "export", self.cid, "--out", str(z), "--zip", "--report-lang", "el")
        self.assertEqual(code, 0)
        self.assertTrue(json.loads(out)["integrity_ok"])
        with zipfile.ZipFile(z) as zf:
            names = zf.namelist()
        self.assertIn("report.el.md", names)
        self.assertNotIn("report.en.md", names)

    def test_publication_profile_and_audited_reveal(self):
        out_dir = self.tmp_path("pub")
        code, out, _ = self.run_cli("case", "export", self.cid, "--out", str(out_dir), "--profile", "publication",
                                    "--reveal", "phone, email")
        self.assertEqual(code, 0)
        self.assertIn("recorded in the audit log", out)
        ind = (out_dir / "indicators.json").read_text(encoding="utf-8")
        self.assertIn("+306941234567", ind)
        self.assertNotIn("GR1601101250000000012300695", ind)
        with self.vault.open_case(self.cid) as case:
            reveals = [e for e in case.audit_entries() if e.action == "report.reveal"]
            self.assertEqual(reveals[0].payload["types"], ["email", "phone"])

    def test_reveal_validation(self):
        out_dir = str(self.tmp_path("x"))
        code, _, err = self.run_cli("case", "export", self.cid, "--out", out_dir, "--reveal", "phone")
        self.assertEqual((code, "publication" in err), (2, True))
        code, _, err = self.run_cli("case", "export", self.cid, "--out", out_dir, "--profile", "publication", "--reveal", "wallet,foo")
        self.assertEqual(code, 2)
        self.assertIn("wallet", err)


class NetworkCommandTests(CliTestCase):
    def setUp(self):
        super().setUp()
        self.site = TestSite()
        self.site.__enter__()
        self.addCleanup(self.site.__exit__, None, None, None)
        self.cid = self.new_case_id()

    def test_capture_workflow(self):
        factory = lambda: make_client()  # noqa: E731
        code, _, err = self.run_cli("capture", self.cid, self.site.base + "/ok", "--ignore-robots", client_factory=factory)
        self.assertEqual((code, "E_ACTIVE_CONFIRM" in err, self.site.hits), (77, True, []))
        code, out, err = self.run_cli("--lang", "el", "capture", self.cid, self.site.base + "/ok", "--confirm-active",
                                      "--ignore-robots", client_factory=factory)
        self.assertEqual(code, 0, err)
        self.assertIn("η διεύθυνση IP σας θα είναι ορατή", out)
        self.assertIn("Καταγράφηκε", out)
        code, out, _ = self.run_cli("--json", "capture", self.cid, self.site.base + "/ok", "--confirm-active", "--ignore-robots",
                                    client_factory=factory)
        data = json.loads(out)
        self.assertEqual((data["status"], data["tls_verified"]), (200, True))
        self.assertGreater(data["indicators_recorded"], 0)
        code, _, err = self.run_cli("capture", self.cid, self.site.base + "/private", "--confirm-active",
                                    client_factory=lambda: make_client(respect_robots=True))
        self.assertEqual((code, "E_ROBOTS" in err), (77, True))

    def test_capture_blocks_internal_targets_by_default(self):
        code, _, err = self.run_cli("capture", self.cid, self.site.base + "/ok", "--confirm-active", "--ignore-robots")
        self.assertEqual((code, "E_NET_BLOCKED" in err), (5, True))
        self.assertEqual(self.site.hits, [])

    def test_domain_offline_and_online(self):
        code, out, _ = self.run_cli("--json", "domain", self.cid, "elta-gr-delivery.top", "--offline")
        data = json.loads(out)
        self.assertEqual(data["lookalikes"][0]["official"], "elta.gr")
        self.assertIsNone(data["rdap"])
        bootstrap = json.dumps({"services": [[["top"], ["https://rdap.top.example/"]]]}).encode()
        record = json.dumps({"events": [{"eventAction": "registration", "eventDate": "2026-10-01T00:00:00Z"}],
                             "entities": [{"roles": ["registrar"], "vcardArray": ["vcard", [["fn", {}, "text", "Reg Inc"]]]}]}).encode()

        class Stub:
            def get(self, url, **kw):
                body = bootstrap if url.endswith("dns.json") else record
                return HttpResult(requested_url=url, final_url=url, status=200, reason="", headers=[], body=body)

        code, out, err = self.run_cli("domain", self.cid, "elta-gr-delivery.top", client_factory=lambda: Stub())
        self.assertEqual(code, 0, err)
        self.assertIn("Reg Inc", out)
        self.assertIn("ELTA (Hellenic Post)", out)
        self.assertIn("days old", out)
        with self.vault.open_case(self.cid) as case:
            self.assertEqual([e.kind for e in case.list_evidence()], ["rdap"])
            self.assertEqual(case.get_evidence("E0001").exposure, "passive_third_party")
            self.assertEqual(len(case.list_analyses("domain")), 2)
            self.assertTrue(case.verify().ok)
        code, _, err = self.run_cli("domain", self.cid, "not a domain", "--offline")
        self.assertEqual((code, "E_VALIDATION" in err), (3, True))

    def test_correlate_command(self):
        a = self.tmp_path("a.txt")
        a.write_text("pay GR16 0110 1250 0000 0001 2300 695", encoding="utf-8")
        self.run_cli("add", self.cid, "--file", str(a))
        self.run_cli("add", self.cid, "--text", "IBAN GR1601101250000000012300695 again")
        code, out, _ = self.run_cli("correlate", self.cid)
        self.assertIn("iban: GR1601101250000000012300695 (2)", out)
        csv_out = self.run_cli("correlate", self.cid, "--format", "csv")[1]
        self.assertTrue(csv_out.startswith("source,source_type"))
        self.assertEqual(len(json.loads(self.run_cli("correlate", self.cid, "--format", "json")[1])["clusters"]), 1)
        self.assertIn("No links", self.run_cli("correlate", self.new_case_id())[1])


class RobustnessTests(CliTestCase):
    def test_doctor(self):
        code, out, err = self.run_cli("doctor")
        self.assertEqual(code, 0, err)
        self.assertIn("Atomic file replacement", out)
        self.assertIn("Everything Aletheia needs is available.", out)
        code, out, _ = self.run_cli("--json", "doctor")
        self.assertTrue(json.loads(out)["ok"])
        self.assertIn("Έλεγχοι συστήματος αρχείων", self.run_cli("--lang", "el", "doctor")[1])

    def test_unsafe_storage_is_refused_with_guidance(self):
        with mock.patch.object(platform_info.os.path, "realpath", return_value="/storage/emulated/0/Aletheia"), \
                mock.patch.object(platform_info, "detect_system", return_value="termux"), \
                mock.patch.object(cli, "get_platform_info", return_value=platform_info.PlatformInfo("termux", "5", "aarch64", "3.12", True, "utf-8")):
            code, _, err = self.run_cli("--lang", "el", "case", "new", "--title", "x", "--purpose", "journalism", "--accept-aup")
            self.assertEqual((code, "E_STORAGE_UNSAFE" in err, "Termux" in err), (4, True, True))
            code, out, _ = self.run_cli("doctor")
            self.assertEqual(code, 1)
            self.assertIn("shared storage", out)

    def test_no_command_unknown_command_and_help(self):
        code, out, _ = self.run_cli()
        self.assertEqual(code, 2)
        self.assertIn("usage:", out)
        code, _, err = self.run_cli("--lang", "el", "frobnicate")
        self.assertEqual(code, 2)
        self.assertIn("Σφάλμα:", err)
        self.assertIn("aletheia --help", err)

    def test_internal_errors_are_summarised_not_dumped(self):
        with mock.patch.object(cli, "cmd_doctor", side_effect=RuntimeError("secret internals")):
            code, _, err = self.run_cli("doctor")
        self.assertEqual(code, 70)
        self.assertIn("E_INTERNAL", err)
        self.assertIn("RuntimeError", err)
        self.assertNotIn("secret internals", err)
        self.assertNotIn("Traceback", err)
        with mock.patch.object(cli, "cmd_doctor", side_effect=RuntimeError("secret internals")):
            code, _, err = self.run_cli("--debug", "doctor")
        self.assertIn("Traceback", err)

    def test_json_errors_are_json(self):
        code, _, err = self.run_cli("--json", "case", "show", "20200101-000000-abcdef")
        payload = json.loads(err)
        self.assertEqual(payload["error"]["code"], "E_CASE_NOT_FOUND")
        self.assertEqual(code, 4)

    def test_keyboard_interrupt_and_broken_pipe(self):
        with mock.patch.object(cli, "cmd_aup", side_effect=KeyboardInterrupt):
            self.assertEqual(self.run_cli("aup")[0], 130)
        with mock.patch.object(cli, "cmd_aup", side_effect=BrokenPipeError):
            self.assertEqual(self.run_cli("aup")[0], 0)

    def test_language_selection(self):
        self.assertIn("Πολιτική Αποδεκτής Χρήσης", self.run_cli("aup", lang="el")[1])
        self.assertIn("Acceptable Use Policy", self.run_cli("aup", lang="en")[1])
        self.assertIn("Acceptable Use Policy", self.run_cli("aup", LANG="de_DE.UTF-8")[1])
        self.assertIn("Πολιτική", self.run_cli("aup", LANG="el_GR.UTF-8")[1])
        self.assertIn("Acceptable", self.run_cli("--lang", "en", "aup", lang="el")[1])

    def test_actor_comes_from_environment(self):
        cid = self.new_case_id(ALETHEIA_ACTOR="Μαρία Κ.")
        with self.vault.open_case(cid) as case:
            self.assertEqual({e.actor for e in case.audit_entries()}, {"Μαρία Κ."})

    def test_configure_stdio_forces_utf8_for_pipes(self):
        raw = io.BytesIO()
        fake = io.TextIOWrapper(raw, encoding="cp1253", errors="strict")
        with mock.patch.object(sys, "stdout", fake), mock.patch.object(sys, "stderr", fake):
            cli.configure_stdio()
            print("Ελληνικά ✓ 😀")
            fake.flush()
        self.assertEqual(raw.getvalue().decode("utf-8"), "Ελληνικά ✓ 😀\n")


class SubprocessAndPackagingTests(unittest.TestCase):
    def run_module(self, *args, env_extra=None, python=None, cwd=None):
        env = {**os.environ, "PYTHONPATH": str(SRC), "PYTHONIOENCODING": ""}
        env.update(env_extra or {})
        return subprocess.run([python or sys.executable, *args], capture_output=True, env=env, timeout=120, cwd=cwd)

    def test_python_dash_m_greek_output_is_utf8_when_piped(self):
        with tempfile.TemporaryDirectory() as home:
            proc = self.run_module("-m", "aletheia", "--lang", "el", "aup", env_extra={"ALETHEIA_HOME": home})
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertIn("Πολιτική Αποδεκτής Χρήσης", proc.stdout.decode("utf-8"))

    def test_version(self):
        proc = self.run_module("-m", "aletheia", "--version")
        self.assertEqual((proc.returncode, proc.stdout.decode().strip()), (0, "aletheia 0.1.0"))

    def test_zipapp_runs_with_bundled_catalogs_and_rule_packs(self):
        with tempfile.TemporaryDirectory() as tmp:
            staging = Path(tmp) / "app"
            import shutil

            shutil.copytree(SRC / "aletheia", staging / "aletheia", ignore=shutil.ignore_patterns("__pycache__"))
            target = Path(tmp) / "aletheia.pyz"
            zipapp.create_archive(staging, target, main="aletheia.cli:main", compressed=True)
            home = Path(tmp) / "home"
            env = {"ALETHEIA_HOME": str(home), "PYTHONPATH": ""}
            proc = self.run_module(str(target), "--lang", "el", "triage", "--text", SCAM, env_extra=env)
            self.assertEqual(proc.returncode, 0, proc.stderr.decode())
            out = proc.stdout.decode("utf-8")
            self.assertIn("υψηλό", out)
            self.assertIn("Πίεση για άμεση ενέργεια", out)
            proc = self.run_module(str(target), "--json", "extract", "--text", SCAM, env_extra=env)
            self.assertIn("GR1601101250000000012300695", proc.stdout.decode())
            proc = self.run_module(str(target), "doctor", env_extra=env)
            self.assertEqual(proc.returncode, 0, proc.stdout.decode())
            cid = json.loads(self.run_module(str(target), "--json", "case", "new", "--title", "z", "--purpose", "journalism",
                                             "--accept-aup", env_extra=env).stdout)["case_id"]
            pack = Path(tmp) / "pack"
            proc = self.run_module(str(target), "case", "export", cid, "--out", str(pack), env_extra=env)
            self.assertEqual(proc.returncode, 0, proc.stderr.decode())
            verify = subprocess.run([sys.executable, str(pack / "verify.py"), str(pack)], capture_output=True, timeout=60)
            self.assertEqual(verify.returncode, 0, verify.stdout.decode())

    def test_runs_from_a_directory_with_non_ascii_name(self):
        with tempfile.TemporaryDirectory() as tmp:
            weird = Path(tmp) / "Φάκελος δεδομένων ✓"
            proc = self.run_module("-m", "aletheia", "--home", str(weird), "--json", "case", "new", "--title", "Τίτλος",
                                   "--purpose", "journalism", "--accept-aup")
            self.assertEqual(proc.returncode, 0, proc.stderr.decode())
            self.assertTrue(any((weird / "cases").iterdir()))


if __name__ == "__main__":
    unittest.main()
