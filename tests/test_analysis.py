import io
import json
import os
import random
import time
import unittest
import zipfile
from datetime import datetime, timedelta, timezone
from unittest import mock

from aletheia import domains, errors, ig_ids, meta_export, policy, triage
from aletheia.correlate import correlate, edges_csv
from aletheia.indexing import index_evidence
from aletheia.models import IndicatorType

from helpers import VaultTestCase, build_export_zip, thread_json, to_mojibake


class IgIdTests(unittest.TestCase):
    def test_alphabet_and_roundtrip(self):
        self.assertEqual(ig_ids.shortcode_to_media_id("B"), 1)
        self.assertEqual(ig_ids.shortcode_to_media_id("BA"), 64)
        self.assertEqual(ig_ids.shortcode_to_media_id("_"), 63)
        self.assertEqual(ig_ids.media_id_to_shortcode(0), "A")
        rng = random.Random(7)
        for _ in range(200):
            media_id = rng.getrandbits(62)
            self.assertEqual(ig_ids.shortcode_to_media_id(ig_ids.media_id_to_shortcode(media_id)), media_id)

    def test_decode_constructed_id(self):
        created = datetime(2023, 5, 17, 12, 30, 45, 123000, tzinfo=timezone.utc)
        media_id = ig_ids.make_media_id(created, shard=5, sequence=7)
        res = ig_ids.decode(ig_ids.media_id_to_shortcode(media_id), now=datetime(2026, 10, 14, tzinfo=timezone.utc))
        self.assertEqual(res.created_at, created)
        self.assertEqual((res.shard, res.sequence, res.media_id), (5, 7, media_id))
        self.assertTrue(res.plausible)

    def test_epoch_matches_documented_constant(self):
        self.assertEqual(ig_ids.INSTAGRAM_EPOCH_MS, 1314220021721)
        res = ig_ids.decode("B", now=datetime(2026, 1, 1, tzinfo=timezone.utc))
        self.assertEqual(res.created_at, datetime(2011, 8, 24, 21, 7, 1, 721000, tzinfo=timezone.utc))

    def test_plausibility_window(self):
        sc = ig_ids.media_id_to_shortcode(ig_ids.make_media_id(datetime(2023, 1, 1, tzinfo=timezone.utc)))
        self.assertFalse(ig_ids.decode(sc, now=datetime(2012, 1, 1, tzinfo=timezone.utc)).plausible)  # from the future
        self.assertFalse(ig_ids.decode("A").plausible)  # before Instagram existed

    def test_invalid_shortcodes(self):
        for bad, key in (("", "error.validation.shortcode_length"), ("A" * 12, "error.validation.shortcode_length"),
                         ("ab!cd", "error.validation.shortcode_char"), ("ab cd", "error.validation.shortcode_char"),
                         ("_" * 11, "error.validation.shortcode_range")):
            with self.assertRaises(errors.ValidationError, msg=bad) as cm:
                ig_ids.decode(bad)
            self.assertEqual(cm.exception.key, key)
        with self.assertRaises(errors.ValidationError):
            ig_ids.media_id_to_shortcode(-1)


class MojibakeTests(unittest.TestCase):
    def test_greek_roundtrip(self):
        for original in ("Καλημέρα", "Επείγον! Ο λογαριασμός σας θα κλειδωθεί", "ΕΛΤΑ δέμα 😀", "naïve café"):
            broken = original.encode("utf-8").decode("latin-1")
            self.assertNotEqual(broken, original)
            self.assertEqual(meta_export.fix_mojibake(broken), original)

    def test_already_correct_text_is_untouched(self):
        for s in ("Καλημέρα", "plain ascii", "café", "é", "ÃƒÂ", "", "日本語"):
            self.assertEqual(meta_export.fix_mojibake(s), s)

    def test_fix_is_idempotent_on_fixed_text(self):
        s = meta_export.fix_mojibake("Καλημέρα".encode().decode("latin-1"))
        self.assertEqual(meta_export.fix_mojibake(s), s)

    def test_fix_tree(self):
        tree = to_mojibake({"κλειδί": ["Γειά", {"n": 5, "t": "ναι"}], "ok": True, "none": None})
        self.assertEqual(meta_export.fix_tree(tree), {"κλειδί": ["Γειά", {"n": 5, "t": "ναι"}], "ok": True, "none": None})


MSGS_1 = [
    {"sender_name": "scam_acc", "timestamp_ms": 1_700_000_300_000, "content": "Στείλε χρήματα στο IBAN GR16 0110 1250 0000 0001 2300 695"},
    {"sender_name": "Victim", "timestamp_ms": 1_700_000_200_000, "content": "Τι χρειάζεσαι;"},
]
MSGS_2 = [
    {"sender_name": "scam_acc", "timestamp_ms": 1_700_000_100_000, "content": "Γεια σου! 😀",
     "share": {"link": "https://wa.me/306941234567"}, "photos": [{"uri": "photos/a.jpg"}]},
    {"sender_name": "scam_acc", "timestamp_ms": 1_700_000_050_000},
]


class ExportReaderTests(VaultTestCase):
    def zip(self, threads=None, name="export.zip", **kw):
        return build_export_zip(self.tmp_path(name), threads or {"message_requests/scam_123": [thread_json(MSGS_1), thread_json(MSGS_2)]}, **kw)

    def test_threads_are_merged_sorted_and_repaired(self):
        path = self.zip()
        with meta_export.ExportSource(path) as src:
            (thread,) = list(meta_export.iter_threads(src))
            self.assertEqual(src.sha256_of_container(), __import__("hashlib").sha256(path.read_bytes()).hexdigest())
        self.assertEqual(thread.folder, "message_requests/scam_123")
        self.assertEqual(thread.participants, ["Victim", "scam_acc"])
        stamps = [m.ts_ms for m in thread.messages]
        self.assertEqual(stamps, sorted(stamps))
        self.assertEqual(len(thread.messages), 4)
        text = thread.transcript()
        self.assertIn("Στείλε χρήματα στο IBAN", text)  # mojibake repaired
        self.assertIn("😀", text)
        self.assertIn("<link: https://wa.me/306941234567>", text)
        self.assertIn("<attachment: photos/a.jpg>", text)
        self.assertIn("<no text>", text)
        self.assertTrue(text.splitlines()[0].startswith("[2023-11-14T22:14:10Z] scam_acc:"))
        self.assertEqual([n for n, _ in thread.members], [n for n, _ in thread.raw_members])
        self.assertEqual(len(thread.members), 2)

    def test_all_thread_folders_are_read(self):
        path = self.zip({f"{kind}/t_{i}": [thread_json(MSGS_1)] for i, kind in
                         enumerate(("inbox", "message_requests", "filtered_threads", "archived_threads"))})
        with meta_export.ExportSource(path) as src:
            self.assertEqual(len(list(meta_export.iter_threads(src))), 4)

    def test_directory_source(self):
        root = self.tmp_path("extracted")
        (root / "your_instagram_activity" / "messages" / "inbox" / "t_1").mkdir(parents=True)
        (root / "your_instagram_activity" / "messages" / "inbox" / "t_1" / "message_1.json").write_text(
            json.dumps(to_mojibake(thread_json(MSGS_1))), encoding="utf-8")
        with meta_export.ExportSource(root) as src:
            (thread,) = list(meta_export.iter_threads(src))
        self.assertIn("Τι χρειάζεσαι;", thread.transcript())

    def test_unmangled_export_also_works(self):
        path = self.zip(mojibake=False)
        with meta_export.ExportSource(path) as src:
            (thread,) = list(meta_export.iter_threads(src))
        self.assertIn("Στείλε χρήματα", thread.transcript())

    def test_zip_slip_names_are_rejected(self):
        for evil in ("../evil.json", "/abs/evil.json", "C:\\evil.json", "a/../../evil.json", "a\\..\\evil.json"):
            path = self.tmp_path("slip.zip")
            with zipfile.ZipFile(path, "w") as zf:
                zf.writestr(evil, "{}")
            with meta_export.ExportSource(path) as src:
                with self.assertRaises(errors.UnsafeArchiveError, msg=evil):
                    list(src.members())
            os.unlink(path)

    def test_decompression_bomb_is_rejected(self):
        path = self.tmp_path("bomb.zip")
        with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as zf:
            zf.writestr("your_instagram_activity/messages/inbox/t/message_1.json", b"\x00" * 11_000_000)
        with mock.patch.object(meta_export, "MAX_RATIO", 50):
            with meta_export.ExportSource(path) as src:
                with self.assertRaises(errors.UnsafeArchiveError):
                    list(meta_export.iter_threads(src))

    def test_oversized_member_is_rejected(self):
        path = self.zip()
        with mock.patch.object(meta_export, "MAX_JSON_BYTES", 100):
            with meta_export.ExportSource(path) as src:
                with self.assertRaises(errors.UnsafeArchiveError):
                    list(meta_export.iter_threads(src))

    def test_symlinks_cannot_escape_a_directory_export(self):
        if os.name != "posix":
            self.skipTest("symlinks")
        outside = self.tmp_path("secret.json")
        outside.write_text(json.dumps(thread_json(MSGS_1)))
        root = self.tmp_path("exp")
        d = root / "messages" / "inbox" / "t"
        d.mkdir(parents=True)
        os.symlink(outside, d / "message_1.json")
        os.symlink(self.tmp_path(""), root / "linkdir")
        with meta_export.ExportSource(root) as src:
            self.assertEqual([m for m in src.members()], [])
            with self.assertRaises(errors.ParseError):
                list(meta_export.iter_threads(src))

    def test_directory_read_rejects_traversal(self):
        root = self.tmp_path("exp2")
        root.mkdir()
        (self.tmp_path("outside.txt")).write_text("x")
        with meta_export.ExportSource(root) as src:
            with self.assertRaises(errors.UnsafeArchiveError):
                src.read("../outside.txt")

    def test_malformed_inputs_raise_parse_errors(self):
        with self.assertRaises(errors.ParseError):
            meta_export.ExportSource(self.tmp_path("missing.zip"))
        bad = self.tmp_path("bad.zip")
        bad.write_bytes(b"not a zip")
        with self.assertRaises(errors.ParseError):
            with meta_export.ExportSource(bad):
                pass
        empty = self.tmp_path("empty.zip")
        with zipfile.ZipFile(empty, "w") as zf:
            zf.writestr("readme.txt", "hi")
        with meta_export.ExportSource(empty) as src:
            with self.assertRaises(errors.ParseError):
                list(meta_export.iter_threads(src))
        for payload in (b"{not json", json.dumps({"no": "messages"}).encode(), b"\xff\xfe\x00"):
            p = self.tmp_path("junk.zip")
            with zipfile.ZipFile(p, "w") as zf:
                zf.writestr("messages/inbox/t/message_1.json", payload)
            with meta_export.ExportSource(p) as src:
                with self.assertRaises(errors.ParseError):
                    list(meta_export.iter_threads(src))
            os.unlink(p)

    def test_tolerates_odd_but_valid_messages(self):
        weird = thread_json([{"sender_name": 5, "timestamp_ms": "soon", "content": ["x"]}, "junk", {"photos": [None, {"uri": 3}]}])
        p = self.zip({"inbox/t": [weird]})
        with meta_export.ExportSource(p) as src:
            (thread,) = list(meta_export.iter_threads(src))
        self.assertEqual(len(thread.messages), 2)
        self.assertEqual(thread.messages[0].iso, "unknown")


class PolicyTests(unittest.TestCase):
    def test_masking(self):
        m = policy.mask_value
        self.assertEqual(m(IndicatorType.EMAIL, "boss@evil.top"), "b***@evil.top")
        self.assertEqual(m("phone", "+306941234567"), "+30••••••••67")
        self.assertEqual(m("iban", "GR1601101250000000012300695"), "GR16" + "•" * 21 + "95")
        self.assertEqual(m("handle", "instagram:scam_acc"), "instagram:sc" + "•" * 6)
        for kept in ("wallet", "domain", "url", "ip"):
            self.assertEqual(m(kept, "value-stays"), "value-stays")
        self.assertEqual(m("phone", "+1"), "••")
        self.assertEqual(m("email", "x@y.z"), "x***@y.z")

    def test_gates(self):
        policy.require_aup(True)
        with self.assertRaises(errors.AupNotAcceptedError):
            policy.require_aup(False)
        policy.require_active_confirmation("https://x", True)
        with self.assertRaises(errors.ActiveConfirmationRequired) as cm:
            policy.require_active_confirmation("https://x", False)
        self.assertEqual(cm.exception.params["url"], "https://x")


class TriageTests(unittest.TestCase):
    EN = ("URGENT: your account will be suspended. Verify your password within 2 hours and pay the processing fee "
          "in USDT to this wallet. Do not tell your bank.")
    EL = ("Επείγον! Ο λογαριασμός σας θα κλειδωθεί. Στείλτε μας τον κωδικό OTP. Το δέμα ΕΛΤΑ περιμένει, "
          "πατήστε το link και πληρώστε τέλη αποστολής.")

    def test_english_scam_is_high(self):
        r = triage.triage(self.EN)
        self.assertEqual(r.level, "high")
        self.assertEqual({"urgency", "account_threat", "credential", "advance_fee", "payment", "secrecy"}, set(r.categories))

    def test_greek_scam_matches_through_accent_and_sigma_folding(self):
        r = triage.triage(self.EL)
        self.assertEqual(r.level, "high")
        self.assertIn("credential", r.categories)
        for h in r.hits:  # offsets refer to the ORIGINAL (accented) text
            self.assertEqual(self.EL[h.start:h.end].split()[0][:2].lower().replace("ί", "ι").replace("έ", "ε")[:1] != "", True)
        snippets = [h.snippet for h in r.hits]
        self.assertIn("Επείγον", snippets)
        self.assertTrue(any("λογαριασμός σας θα κλειδωθεί" in s for s in snippets))

    def test_greek_uppercase_and_greeklike_variants(self):
        self.assertEqual(triage.triage("ΕΠΕΙΓΟΝ: Ο ΛΟΓΑΡΙΑΣΜΟΣ ΣΑΣ ΘΑ ΑΠΕΝΕΡΓΟΠΟΙΗΘΕΙ").level, "medium")

    def test_benign_text_is_none(self):
        for text in ("Hi, are we still on for lunch tomorrow?", "Καλημέρα, θα τα πούμε αύριο στο γραφείο.", ""):
            self.assertEqual(triage.triage(text).level, "none", text)

    def test_category_score_is_capped_and_deduplicated(self):
        text = " ".join(["gift card"] * 50 + ["send bitcoin payment"] * 50)
        r = triage.triage(text)
        self.assertLessEqual(r.categories["payment"], 5)
        self.assertLessEqual(len([h for h in r.hits if h.rule_id == "payment.giftcard"]), triage.MAX_HITS_PER_RULE)

    def test_explanations_exist_in_both_languages(self):
        for pack in triage.load_default_packs():
            for rule in pack.rules:
                self.assertTrue(rule.explain.get("en") and rule.explain.get("el"), rule.id)
        r = triage.triage(self.EN)
        self.assertTrue(all(h.explain.get("el") for h in r.hits))

    def test_to_dict_is_json_serialisable(self):
        json.dumps(triage.triage(self.EL).to_dict())

    def test_truncation_flag(self):
        with mock.patch.object(triage, "MAX_TRIAGE_CHARS", 50):
            r = triage.triage("x" * 100)
        self.assertTrue(r.truncated)

    def test_pack_validation(self):
        good = 'pack = {id="p", lang="en"}\n[[rule]]\nid="r"\ncategory="c"\nweight=2\npattern=\'\'\'foo\\d+\'\'\'\n'
        self.assertEqual(len(triage.parse_pack(good).rules), 1)
        bad_cases = {
            "toml": "this is = = not toml", "no pack": '[[rule]]\nid="r"\ncategory="c"\nweight=1\npattern="x"',
            "weight": good.replace("weight=2", "weight=9"), "weight type": good.replace("weight=2", 'weight="2"'),
            "regex": good.replace("foo\\d+", "(unclosed"), "nested": good.replace("foo\\d+", "(a+)+b"),
            "missing field": 'pack = {id="p", lang="en"}\n[[rule]]\nid="r"\nweight=1\npattern="x"',
            "duplicate": good + '[[rule]]\nid="r"\ncategory="c"\nweight=1\npattern="y"\n',
        }
        for name, text in bad_cases.items():
            with self.assertRaises(errors.PackError, msg=name):
                triage.parse_pack(text)

    def test_custom_pack_file_extends_detection(self):
        pack = triage.parse_pack('pack = {id="mine", lang="en"}\n[[rule]]\nid="x"\ncategory="custom"\nweight=4\n'
                                 'pattern=\'\'\'pig\\s+butchering\'\'\'\nexplain_en="custom rule"\n')
        r = triage.triage("this is pig butchering", [pack])
        self.assertEqual((r.level, r.categories), ("medium", {"custom": 4}))

    def test_lint(self):
        self.assertEqual(triage.lint_pattern("(a+)+"), "nested quantifier")
        self.assertEqual(triage.lint_pattern(r"(\w*)*x"), "nested quantifier")
        self.assertIsNone(triage.lint_pattern(r"(?:ab)?c+"))
        self.assertEqual(triage.lint_pattern("x" * 2001), "pattern too long")

    def test_builtin_packs_are_fast_on_adversarial_text(self):
        for text in ("a " * 300_000, "account " * 100_000, "bitcoin " * 100_000 + "x" * 100_000, "α" * 400_000):
            started = time.perf_counter()
            triage.triage(text)
            self.assertLess(time.perf_counter() - started, 8.0)


class DomainTests(unittest.TestCase):
    def kinds(self, domain):
        return {(x["brand"], x["kind"]) for x in domains.analyze_domain(domain).lookalikes}

    def test_lookalikes(self):
        self.assertIn(("PayPal", "homoglyph_or_typo"), self.kinds("paypa1.com"))
        self.assertIn(("PayPal", "homoglyph_or_typo"), self.kinds("p\u0430ypal.com"))
        self.assertIn(("PayPal", "homoglyph_or_typo"), self.kinds("rnicrosoft.com") | self.kinds("paypaI.com"))
        self.assertIn(("ELTA (Hellenic Post)", "brand_in_domain"), self.kinds("elta-gr-delivery.top"))
        self.assertIn(("ELTA (Hellenic Post)", "homoglyph_or_typo"), self.kinds("ΕLΤΑ.gr"))
        self.assertIn(("PayPal", "brand_in_subdomain"), self.kinds("secure.paypal.com.evil.top"))
        self.assertIn(("ELTA (Hellenic Post)", "same_name_other_tld"), self.kinds("elta.com"))
        self.assertIn(("Revolut", "near_typo"), self.kinds("revolutt.com"))

    def test_official_domains_and_innocent_names_are_not_flagged(self):
        for d in ("paypal.com", "www.paypal.com", "elta.gr", "tracking.elta.gr", "example.org", "revolut.com", "examp1e.org",
                  "canvas.com", "ordinary-shop.gr"):
            self.assertEqual(self.kinds(d), set(), d)

    def test_flags(self):
        s = domains.analyze_domain("p\u0430ypal.com")
        self.assertTrue(s.idn and s.mixed_script)
        g = domains.analyze_domain("παράδειγμα.gr")
        self.assertTrue(g.idn)
        self.assertFalse(g.mixed_script)  # Greek label under a Latin TLD is normal
        self.assertEqual(domains.analyze_domain("192.0.2.1").lookalikes, [])
        with self.assertRaises(errors.ValidationError):
            domains.analyze_domain("not a domain")

    def test_levenshtein(self):
        self.assertEqual(domains.levenshtein("kitten", "sitting"), 3)
        self.assertEqual(domains.levenshtein("", "abc"), 3)
        self.assertEqual(domains.levenshtein("same", "same"), 0)

    def test_seed_data_is_sane(self):
        brands, stop = domains.load_brands()
        self.assertGreater(len(brands), 15)
        self.assertIn("instagram.com", stop)
        for b in brands:
            self.assertTrue(b.name and b.domains)
            for d in b.domains:
                host, _, kind = __import__("aletheia.indicators.urls", fromlist=["x"]).normalize_host(d)
                self.assertEqual((host, kind), (d, "domain"))
        self.assertEqual(len({d for b in brands for d in b.domains}), sum(len(b.domains) for b in brands))


class CorrelationTests(VaultTestCase):
    def add(self, case, text):
        ev = case.add_evidence(text.encode(), kind="text", source="s", method="manual_import", media_type="text/plain")
        index_evidence(case, ev.id)
        return ev.id

    def test_shared_strong_indicator_links_evidence(self):
        case = self.new_case()
        a = self.add(case, "pay GR16 0110 1250 0000 0001 2300 695 at https://instagram.com/x/")
        b = self.add(case, "again IBAN GR1601101250000000012300695, see https://instagram.com/y/")
        c = self.add(case, "unrelated https://instagram.com/z/ and a.b@gmail.com")
        res = correlate(case)
        (cluster,) = res["clusters"]
        self.assertEqual(cluster["evidence_ids"], sorted([a, b]))
        self.assertEqual(cluster["confidence"], "high")
        self.assertEqual([(s["type"], s["evidence_count"]) for s in cluster["shared"]], [("iban", 2)])
        self.assertNotIn(c, cluster["evidence_ids"])

    def test_stoplisted_domains_never_link(self):
        case = self.new_case()
        self.add(case, "see https://instagram.com/a/ and wa.me/306941234567")
        self.add(case, "see https://instagram.com/b/ and https://www.google.com/x")
        self.assertEqual(correlate(case)["clusters"], [])

    def test_medium_confidence_for_shared_domain_and_transitive_grouping(self):
        case = self.add_three = self.new_case()
        a = self.add(case, "visit https://evil-shop.top/a")
        b = self.add(case, "visit https://evil-shop.top/b and +30 694 123 4567")
        c = self.add(case, "call +306941234567")
        res = correlate(case)
        (cluster,) = res["clusters"]
        self.assertEqual(cluster["evidence_ids"], sorted([a, b, c]))
        self.assertEqual(cluster["confidence"], "high")  # the phone link is strong
        kinds = {s["type"] for s in cluster["shared"]}
        self.assertEqual(kinds, {"domain", "phone"})

    def test_domain_only_link_is_medium(self):
        case = self.new_case()
        self.add(case, "https://evil-shop.top/a")
        self.add(case, "https://evil-shop.top/b")
        (cluster,) = correlate(case)["clusters"]
        self.assertEqual(cluster["confidence"], "medium")

    def test_cooccurrence_and_csv(self):
        case = self.new_case()
        far = "x" * 400
        ev = self.add(case, f"send to GR16 0110 1250 0000 0001 2300 695 call +30 694 123 4567 {far} mail boss@evil.top")
        res = correlate(case)
        pairs = {(p["a"]["type"], p["b"]["type"]) for p in res["cooccurrence"]}
        self.assertIn(("iban", "phone"), pairs)
        self.assertFalse(any({p["a"]["type"], p["b"]["type"]} == {"iban", "email"} for p in res["cooccurrence"]))
        csv_text = edges_csv(case, res)
        self.assertTrue(csv_text.startswith("source,source_type,target,target_type,relation\n"))
        self.assertIn(f",{ev},evidence,observed_in", csv_text)
        self.assertIn("co_occurs", csv_text)

    def test_nothing_to_correlate(self):
        case = self.new_case()
        self.assertEqual(correlate(case), {"clusters": [], "cooccurrence": []})


if __name__ == "__main__":
    unittest.main()
