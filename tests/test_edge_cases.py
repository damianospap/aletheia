import io
import json
import sqlite3
import socket
import unittest
from unittest import mock

from aletheia import cli, errors, http, i18n, report, textnorm, vault
from aletheia.indicators import accounts, crypto, extract_indicators, urls
from aletheia.i18n import Translator
from aletheia.indexing import index_evidence
from aletheia.models import IndicatorType
from aletheia.policy import ReportProfile

from helpers import START, FakeClock, TestSite, VaultTestCase, env_for, make_client


def types(matches, derived=None):
    return {(m.type.value, m.value) for m in matches if derived is None or m.derived == derived}


class ExtractionEdgeCases(unittest.TestCase):
    def test_ip_hosts_and_social_handles_from_urls(self):
        found = extract_indicators("see http://8.8.8.8/x and http://10.0.0.5/admin and https://t.me/scambot and wa.me/x")
        by_value = {m.value: m for m in found if m.type == IndicatorType.IP}
        self.assertTrue(by_value["8.8.8.8"].attrs["global"])
        self.assertFalse(by_value["10.0.0.5"].attrs["global"])
        self.assertIn(("handle", "telegram:scambot"), types(found, derived=True))

    def test_unparseable_candidates_are_skipped_silently(self):
        text = "http://-bad-.com/x icon@2x.png -bad-[.]top 1:2:3:4 hxxp://[::1 bad@exa_mple"
        self.assertEqual([m for m in extract_indicators(text) if m.type != IndicatorType.IP], [])

    def test_ipv6_text_is_extracted_and_validated(self):
        found = extract_indicators("server at 2001:db8:0:0:0:0:0:1 and fake 12:34:56:78 and ok 2606:4700:4700::1111")
        self.assertEqual(sorted(m.value for m in found if m.type == IndicatorType.IP), ["2001:db8::1", "2606:4700:4700::1111"])

    def test_invalid_internationalised_label_is_rejected(self):
        for bad in ("http://xn--@@@.com/", "http://xn--zzzzzzzzzzzzzzzzzzzzz-.com/"):
            with self.assertRaises(errors.ValidationError):
                urls.parse_url(bad)

    def test_shim_with_unparseable_target_is_ignored(self):
        info = urls.parse_url("https://l.instagram.com/?u=https%3A%2F%2F-bad-.com%2F")
        self.assertIsNone(info.unwrapped)

    def test_handle_stop_words_and_digits(self):
        found = {raw for _s, _e, raw, _p in accounts.find_handles("@ig @me @12345 ig: 12345 insta: instagram @real_user")}
        self.assertEqual(found, {"@real_user"})


class CryptoEdgeCases(unittest.TestCase):
    def enc(self, witver, nbytes, variant, hrp="bc"):
        return crypto.bech32_encode(hrp, [witver] + crypto._convertbits(list(range(nbytes)), 8, 5, True), variant)

    def test_invalid_witness_programs(self):
        invalid = {
            "version 17": self.enc(17, 20, "bech32m"),
            "v0 with bech32m checksum": self.enc(0, 20, "bech32m"),
            "v1 with bech32 checksum": self.enc(1, 32, "bech32"),
            "v0 wrong program length": self.enc(0, 25, "bech32"),
            "testnet hrp": self.enc(0, 20, "bech32", hrp="tb"),
            "program too short": self.enc(1, 1, "bech32m"),
            "program too long": self.enc(1, 41, "bech32m"),
        }
        for name, addr in invalid.items():
            self.assertIsNone(crypto.validate_wallet(addr), name)
        self.assertIsNone(crypto.validate_wallet(crypto.bech32_encode("bc", [], "bech32")))
        self.assertIsNotNone(crypto.validate_wallet(self.enc(0, 20, "bech32")))
        self.assertIsNotNone(crypto.validate_wallet(self.enc(2, 40, "bech32m")))

    def test_bech32_structural_rejections(self):
        for bad in ("bc1", "bc1q", "1qqqqqq", "bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq" + "q" * 60,
                    "bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdb", "bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5md\x01"):
            self.assertIsNone(crypto.bech32_decode(bad), repr(bad))
        self.assertIsNone(crypto._convertbits([32], 5, 8, False))
        self.assertIsNone(crypto._convertbits([1, 1], 5, 8, False))  # non-zero padding

    def test_base58_edge_cases(self):
        self.assertIsNone(crypto.b58check_decode("1111"))
        self.assertIsNone(crypto.b58check_decode("0abc"))
        self.assertEqual(crypto.b58decode(""), b"")
        self.assertIsNone(crypto.validate_wallet("1" * 30))
        self.assertIsNone(crypto.validate_wallet("T" + "1" * 33))


class TextNormEdgeCases(unittest.TestCase):
    def test_gamma_clusters(self):
        self.assertEqual(textnorm.greek_to_latin("Σύγχρονος"), "Synchronos")
        self.assertEqual(textnorm.greek_to_latin("Λύγξ"), "Lynx")
        self.assertEqual(textnorm.greek_to_latin("ΜΠΑΡ"), "BAR")

    def test_broken_utf16_is_lossy_not_fatal(self):
        text, enc, lossy = textnorm.decode_text(b"\xff\xfe\x00\xd8")
        self.assertEqual((enc, lossy), ("utf-16", True))

    def test_script_of_unnamed_letters(self):
        with mock.patch.object(textnorm.unicodedata, "name", side_effect=ValueError):
            self.assertEqual(textnorm.scripts_in("a"), {"UNKNOWN"})


class I18nEdgeCases(unittest.TestCase):
    def test_unsupported_language_catalog(self):
        with self.assertRaises(ValueError):
            i18n.load_catalog("xx")

    def test_plural_fallbacks_and_malformed_templates(self):
        t = Translator("en-US")
        self.assertEqual(t.plural("msg.case_created", 3, case_id="X"), "Case created: X")  # no .one/.other variants
        t._cat = {**t._cat, "broken": "oops {unclosed"}
        self.assertEqual(t("broken"), "oops {unclosed")
        self.assertTrue(t.has("msg.case_created") and not t.has("nope"))

    def test_nested_tables_are_flattened(self):
        self.assertEqual(i18n._flatten({"a": {"b": {"c": "x"}, "d": "y"}, "e": "z"}), {"a.b.c": "x", "a.d": "y", "e": "z"})


class ResolverTests(unittest.TestCase):
    def test_default_resolver(self):
        self.assertEqual(http.default_resolver("192.0.2.9", 80), ["192.0.2.9"])
        self.assertIn("127.0.0.1", http.default_resolver("localhost", 80) + ["127.0.0.1"])
        with self.assertRaises(errors.TransportError) as cm:
            http.default_resolver("definitely-not-a-real-host.invalid", 80)
        self.assertIn("DNS", cm.exception.detail)
        with mock.patch.object(socket, "getaddrinfo", return_value=[]):
            with self.assertRaises(errors.TransportError):
                http.default_resolver("empty.example", 80)

    def test_tls_info_of_plain_socket_is_none(self):
        with socket.socket() as plain:
            self.assertIsNone(http.tls_info(plain))
        self.assertIsNone(http.tls_info(None))

    def test_invalid_gzip_body_is_a_transport_error(self):
        from helpers import _Handler

        orig = _Handler.do_GET

        def patched(self):
            if self.path == "/badgzip":
                self._send(200, b"this is not gzip data", {"Content-Encoding": "gzip"})
            else:
                orig(self)

        with mock.patch.object(_Handler, "do_GET", patched), TestSite() as site:
            client = make_client(max_attempts=2)
            with self.assertRaises(errors.TransportError) as cm:
                client.get(site.base + "/badgzip", check_robots=False)
            self.assertIn("invalid gzip", cm.exception.detail)


class VaultEdgeCases(VaultTestCase):
    def test_nested_locking_does_not_deadlock(self):
        case = self.new_case()
        with case._locked():
            with case._locked():
                case.log("custom.nested", {"ok": True})
        self.assertIn("custom.nested", [e.action for e in case.audit_entries()])

    def test_database_locked_by_another_connection_maps_to_vault_locked(self):
        case = self.new_case()
        cid, db = case.case_id, self.home / "cases" / case.case_id / "case.db"
        case.close()
        # (a) another process holds an exclusive lock: even opening the case must report "in use", not "corrupt"
        blocker = sqlite3.connect(db, isolation_level=None)
        self.addCleanup(blocker.close)
        blocker.execute("BEGIN EXCLUSIVE")
        with self.assertRaises(errors.VaultLockedError) as cm:
            vault.Case(self.home / "cases" / cid, clock=FakeClock(), lock_timeout=0.2)
        self.assertTrue(cm.exception.retryable)
        blocker.execute("ROLLBACK")
        # (b) another writer holds the write lock: reads work, writes report "in use"
        blocker.execute("BEGIN IMMEDIATE")
        short = vault.Case(self.home / "cases" / cid, clock=FakeClock(), lock_timeout=0.2)
        self.addCleanup(short.close)
        self.assertEqual(short.title, "Test case")
        with self.assertRaises(errors.VaultLockedError):
            short.log("custom.blocked")
        blocker.execute("ROLLBACK")
        short.log("custom.free")  # works again once the other writer is gone
        self.assertTrue(short.verify().ok)

    def test_verify_survives_missing_tables_and_garbage_payloads(self):
        case = self.new_case()
        case.log("custom.note", {"a": 1})
        conn = sqlite3.connect(case.dir / "case.db", isolation_level=None)
        self.addCleanup(conn.close)
        conn.execute("UPDATE audit SET payload = '{not json' WHERE seq = 3")
        found = {i.code for i in case.verify().issues}
        self.assertIn("AUDIT_PAYLOAD_INVALID", found)
        conn.execute("DROP TABLE audit")
        report_ = case.verify()
        self.assertFalse(report_.ok)
        self.assertIn("DB_UNREADABLE", {i.code for i in report_.issues})

    def test_list_cases_skips_junk_and_unreadable_cases(self):
        good = self.new_case("good")
        bad = self.new_case("bad")
        bad_id = bad.case_id
        bad.close()
        (self.home / "cases" / bad_id / "case.db").write_bytes(b"garbage" * 50)
        (self.home / "cases" / "not-a-case").mkdir()
        (self.home / "cases" / "20260101-000000-abcdef").mkdir()  # no database inside
        (self.home / "cases" / "stray.txt").write_text("x")
        self.assertEqual([c.case_id for c in self.vault.list_cases()], [good.case_id])

    def test_case_without_database_is_not_found(self):
        (self.home / "cases" / "20260101-000000-abcdef").mkdir(parents=True)
        with self.assertRaises(errors.CaseNotFoundError):
            self.vault.open_case("20260101-000000-abcdef")


class ReportClusterRendering(VaultTestCase):
    def test_clusters_render_in_markdown_and_html(self):
        case = self.new_case()
        for text in ("pay GR16 0110 1250 0000 0001 2300 695", "again GR1601101250000000012300695 ok"):
            ev = case.add_evidence(text.encode(), kind="text", source="s", method="manual_import", media_type="text/plain")
            index_evidence(case, ev.id)
        model = report.build_model(case, ReportProfile.HANDOVER, now=START)
        for lang, label in (("en-US", "Group 1"), ("el", "Ομάδα 1")):
            t = Translator(lang)
            self.assertIn(f"**{label}**", report.render_markdown(model, t))
            self.assertIn(f"<strong>{label}</strong>", report.render_html(model, t))
        self.assertIn("iban: `GR1601101250000000012300695` (2)", report.render_markdown(model, Translator("en-US")))

    def test_malformed_shortcode_never_breaks_a_report(self):
        case = self.new_case()
        ev = case.add_evidence(b"https://instagram.com/p/%%%%%/", kind="text", source="s", method="manual_import",
                               media_type="text/plain")
        index_evidence(case, ev.id)
        with mock.patch.object(report, "decode_ig", side_effect=errors.ValidationError("bad")):
            report.build_model(case, ReportProfile.HANDOVER, now=START)


class CliInputLimits(VaultTestCase):
    def run_cli(self, *argv, stdin=b""):
        out, err = io.StringIO(), io.StringIO()
        stdin_obj = mock.Mock()
        stdin_obj.buffer = io.BytesIO(stdin)
        code = cli.main(list(argv), stdin=stdin_obj, stdout=out, stderr=err, env=env_for(self.home), now=FakeClock())
        return code, out.getvalue(), err.getvalue()

    def test_file_inputs_and_size_limits(self):
        f = self.tmp_path("in.txt")
        f.write_text("IBAN DE89 3704 0044 0532 0130 00 and +44 20 7946 0958", encoding="utf-8")
        code, out, _ = self.run_cli("--json", "extract", "--file", str(f))
        self.assertEqual(code, 0)
        self.assertEqual({i["type"] for i in json.loads(out)["indicators"]}, {"iban", "phone"})
        code, out, _ = self.run_cli("--json", "triage", "--file", str(f))
        self.assertEqual(code, 0)
        with mock.patch.object(cli, "MAX_TEXT_BYTES", 10):
            code, _, err = self.run_cli("extract", "--file", str(f))
            self.assertEqual((code, "E_INPUT_TOO_LARGE" in err), (3, True))
            code, _, err = self.run_cli("extract", "--stdin", stdin=b"x" * 50)
            self.assertEqual((code, "E_INPUT_TOO_LARGE" in err), (3, True))
        code, _, err = self.run_cli("extract", "--file", str(self.tmp_path("missing.txt")))
        self.assertEqual((code, "E_USAGE" in err), (2, True))
        code, _, err = self.run_cli("triage", "--file", str(self.tmp_path("missing.txt")))
        self.assertEqual(code, 2)

    @unittest.skipIf(__import__("os").name != "posix" or __import__("os").geteuid() == 0, "needs POSIX permissions, non-root")
    def test_unreadable_file(self):
        f = self.tmp_path("secret.txt")
        f.write_text("x")
        f.chmod(0)
        code, _, err = self.run_cli("extract", "--file", str(f))
        self.assertEqual((code, "E_USAGE" in err), (2, True))


if __name__ == "__main__":
    unittest.main()
