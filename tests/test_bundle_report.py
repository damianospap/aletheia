import hashlib
import json
import os
import re
import subprocess
import sys
import zipfile
from pathlib import Path
from unittest import mock

from aletheia import bundle, errors, report
from aletheia.i18n import Translator
from aletheia.indexing import index_evidence
from aletheia.models import Purpose
from aletheia.policy import ReportProfile
from aletheia.triage import triage

from helpers import START, VaultTestCase

SECRET_TEXT = (
    "Επείγον! Ο λογαριασμός σας θα κλειδωθεί. Στείλε στο IBAN GR16 0110 1250 0000 0001 2300 695, "
    "τηλ +30 694 123 4567, email boss@evil-shop.top, insta: scam_acc, "
    "wallet 0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed, https://instagram.com/p/Bk7e3P4gDAV/ και hxxps://elta-gr-delivery[.]top/pay"
)
RAW_PERSONAL = ["GR1601101250000000012300695", "GR16 0110", "+306941234567", "694 123 4567", "boss@evil-shop.top", "scam_acc"]


class BundleTestCase(VaultTestCase):
    def setUp(self):
        super().setUp()
        self.case = self.new_case("Υπόθεση <b>απάτης</b> | δοκιμή")
        ev = self.case.add_evidence(SECRET_TEXT.encode(), kind="text", source="<script>alert(1)</script>.txt",
                                    method="manual_import", media_type="text/plain")
        index_evidence(self.case, ev.id)
        self.case.save_analysis("triage", ev.id, triage(SECRET_TEXT).to_dict())
        self.case.save_analysis("domain", None, {"domain": "elta-gr-delivery.top", "unicode": "elta-gr-delivery.top",
                                                 "idn": False, "mixed_script": False, "skeleton": "x",
                                                 "lookalikes": [{"brand": "ELTA (Hellenic Post)", "official": "elta.gr",
                                                                 "kind": "brand_in_domain"}],
                                                 "rdap": {"found": True, "registrar": "Example Registrar", "registered": "2026-10-10T08:00:00Z"},
                                                 "age_days": 4})
        self.case.save_analysis("timeline", ev.id, {"thread": "t", "events": [
            {"ts": "2026-10-01T10:00:00Z", "sender": "scam_acc", "snippet": "send to GR16 0110 ...", "indicators": ["iban:GR16"]}]})
        self.now = START

    def export(self, name="bundle", profile=ReportProfile.HANDOVER, langs=("en-US", "el"), **kw):
        dest = self.tmp_path(name)
        path, manifest = bundle.export_bundle(self.case, dest, profile=profile, langs=list(langs), now=self.now, **kw)
        return path, manifest

    def run_verify(self, target: Path):
        script = Path(target) / "verify.py" if Path(target).is_dir() else None
        if script is None:  # zip: extract the script to run it from a neutral place
            with zipfile.ZipFile(target) as zf:
                script = self.tmp_path("verify_extracted.py")
                script.write_bytes(zf.read("verify.py"))
        proc = subprocess.run([sys.executable, str(script), str(target)], capture_output=True, text=True, timeout=120)
        return proc.returncode, proc.stdout


class HandoverBundleTests(BundleTestCase):
    def test_structure_and_manifest(self):
        path, manifest = self.export()
        names = {p.relative_to(path).as_posix() for p in path.rglob("*") if p.is_file()}
        for expected in ("manifest.json", "audit.jsonl", "report.json", "indicators.json", "report.en.md", "report.en.html",
                         "report.el.md", "report.el.html", "VERIFY.txt", "verify.py"):
            self.assertIn(expected, names)
        (ev,) = self.case.list_evidence()
        self.assertIn(f"evidence/{ev.sha256}", names)
        self.assertEqual(manifest["profile"], "handover")
        self.assertTrue(manifest["audit_included"] and manifest["integrity_ok"])
        for name, digest in manifest["files"].items():
            self.assertEqual(hashlib.sha256((path / name).read_bytes()).hexdigest(), digest, name)
        self.assertEqual(json.loads((path / "manifest.json").read_text(encoding="utf-8")), manifest)
        self.assertEqual(manifest["audit_head"], {k: self.case.anchor()[k] for k in ("seq", "entry_hash")})
        self.assertEqual((path / "evidence" / ev.sha256).read_bytes(), SECRET_TEXT.encode())

    def test_independent_verifier_accepts_a_good_bundle(self):
        path, _ = self.export()
        code, out = self.run_verify(path)
        self.assertEqual(code, 0, out)
        self.assertIn("VERIFICATION OK", out)

    def test_independent_verifier_detects_every_kind_of_tampering(self):
        for victim, mutate in {
            "evidence": lambda p: self.writable(p / "evidence" / self.case.list_evidence()[0].sha256).write_bytes(b"forged"),
            "audit": lambda p: (p / "audit.jsonl").write_text((p / "audit.jsonl").read_text().replace("evidence.add", "evidence.xxx")),
            "report": lambda p: (p / "report.en.md").write_text("tampered"),
            "missing": lambda p: (p / "indicators.json").unlink(),
            "audit_truncated": lambda p: (p / "audit.jsonl").write_text("\n".join((p / "audit.jsonl").read_text().splitlines()[:-1]) + "\n"),
        }.items():
            path, _ = self.export(name=f"b_{victim}")
            mutate(path)
            code, out = self.run_verify(path)
            self.assertEqual(code, 1, f"{victim}: {out}")
            self.assertIn("VERIFICATION FAILED", out)

    @staticmethod
    def writable(p):
        os.chmod(p, 0o644)
        return p

    def test_zip_export_verifies_and_is_deterministic(self):
        a, _ = self.export("one.zip", as_zip=True)
        b, _ = self.export("two.zip", as_zip=True)
        self.assertEqual(hashlib.sha256(a.read_bytes()).hexdigest(), hashlib.sha256(b.read_bytes()).hexdigest())
        with zipfile.ZipFile(a) as zf:
            self.assertIsNone(zf.testzip())
            self.assertTrue(all(i.date_time == (1980, 1, 1, 0, 0, 0) for i in zf.infolist()))
        code, out = self.run_verify(a)
        self.assertEqual(code, 0, out)

    def test_existing_output_requires_force_and_no_staging_leftovers(self):
        path, _ = self.export("keep")
        with self.assertRaises(errors.OutputExistsError):
            self.export("keep")
        (path / "marker").write_text("x")
        self.export("keep", force=True)
        self.assertFalse((path / "marker").exists())
        self.assertEqual([p.name for p in path.parent.iterdir() if p.name.startswith(".aletheia-export")], [])

    def test_failed_export_leaves_nothing_behind_and_keeps_old_output(self):
        dest = self.tmp_path("fail")
        with mock.patch.object(bundle, "render_html", side_effect=RuntimeError("boom")):
            with self.assertRaises(RuntimeError):
                bundle.export_bundle(self.case, dest, profile=ReportProfile.HANDOVER, langs=["en-US"], now=self.now)
        self.assertFalse(dest.exists())
        self.assertEqual([p.name for p in dest.parent.iterdir() if p.name.startswith(".aletheia-export")], [])

    def test_export_refuses_a_corrupted_evidence_file(self):
        (ev,) = self.case.list_evidence()
        self.writable(self.case.blob_path(ev.sha256)).write_bytes(b"corrupted")
        with self.assertRaises(errors.VaultIntegrityError):
            self.export("corrupt")
        self.assertFalse(self.tmp_path("corrupt").exists())

    def test_report_states_integrity_problems_instead_of_hiding_them(self):
        (ev,) = self.case.list_evidence()
        self.writable(self.case.blob_path(ev.sha256)).write_bytes(b"corrupted")
        model = report.build_model(self.case, ReportProfile.HANDOVER, now=self.now)
        self.assertFalse(model["integrity"]["ok"])
        self.assertIn("BLOB_CORRUPT", model["integrity"]["issues"])
        self.assertIn("ΑΝΙΧΝΕΥΤΗΚΑΝ ΠΡΟΒΛΗΜΑΤΑ", report.render_markdown(model, Translator("el")))


class ReportContentTests(BundleTestCase):
    def model(self, profile=ReportProfile.HANDOVER, **kw):
        return report.build_model(self.case, profile, now=self.now, **kw)

    def test_both_languages_render_complete_reports(self):
        model = self.model()
        en, el = report.render_markdown(model, Translator("en-US")), report.render_markdown(model, Translator("el"))
        self.assertIn("# Evidence report", en)
        self.assertIn("# Αναφορά τεκμηρίων", el)
        for text, needles in ((en, ["Integrity", "Indicators", "Scam signals", "Timeline of messages", "Possible look-alike of ELTA"]),
                              (el, ["Ακεραιότητα", "Δείκτες", "Ενδείξεις απάτης", "Χρονολόγιο μηνυμάτων", "Πιθανή απομίμηση του ELTA"])):
            for n in needles:
                self.assertIn(n, text)
        for text in (en, el, report.render_html(model, Translator("el")), report.render_html(model, Translator("en-US"))):
            self.assertIsNone(re.search(r"\{[a-z_]+\}", text), "unresolved placeholder")
        self.assertIn("2026-10-10T08:00:00Z", en)
        self.assertIn("4 days old", en)
        self.assertIn("4 ημερών", el)

    def test_instagram_post_time_is_labelled_heuristic(self):
        model = self.model()
        urls = [i for i in model["indicators"] if i["type"] == "url" and "ig_post_time" in i]
        self.assertEqual(len(urls), 1)
        self.assertEqual(urls[0]["ig_post_time"]["method"], "heuristic")
        self.assertIn("post time, heuristic", report.render_markdown(model, Translator("en-US")))
        self.assertIn("ώρα δημοσίευσης, ευρετική εκτίμηση", report.render_markdown(model, Translator("el")))

    def test_html_escapes_hostile_content(self):
        model = self.model()
        for lang in ("en-US", "el"):
            html_doc = report.render_html(model, Translator(lang))
            self.assertNotIn("<script", html_doc.lower())
            self.assertNotIn("<b>", html_doc)
            self.assertIn("&lt;script&gt;alert(1)&lt;/script&gt;.txt", html_doc)
            self.assertIn("Υπόθεση &lt;b&gt;απάτης&lt;/b&gt;", html_doc)
            self.assertTrue(html_doc.startswith("<!doctype html>"))
            self.assertIn(f'lang="{"el" if lang == "el" else "en"}"', html_doc)
            self.assertIn("prefers-color-scheme:dark", html_doc)

    def test_markdown_pipes_do_not_break_tables(self):
        md = report.render_markdown(self.model(), Translator("en-US"))
        self.assertIn("Υπόθεση <b>απάτης</b> \\| δοκιμή", md)
        for line in md.splitlines():
            if line.startswith("| E0001"):
                self.assertEqual(line.replace("\\|", "").count("|"), 8)

    def test_labels_are_translated_but_codes_fall_back(self):
        el = report.render_markdown(self.model(), Translator("el"))
        self.assertIn("Κείμενο", el)
        self.assertIn("Εισαγωγή από τον χειριστή", el)
        self.assertEqual(report._lab(Translator("el"), "kind.", "unknown_kind"), "unknown_kind")

    def test_model_is_json_serialisable_and_stable(self):
        a, b = report.model_json(self.model()), report.model_json(self.model())
        self.assertEqual(a, b)
        data = json.loads(a)
        self.assertEqual(data["schema"], "aletheia-report/1")
        self.assertEqual(data["case"]["purpose"], "victim-report")


class PublicationProfileTests(BundleTestCase):
    def test_personal_data_is_absent_from_every_file(self):
        path, manifest = self.export("pub", profile=ReportProfile.PUBLICATION)
        self.assertFalse(manifest["audit_included"])
        self.assertFalse((path / "audit.jsonl").exists())
        self.assertFalse((path / "evidence").exists())
        self.assertTrue(all(e["included"] is False and e["source"] is None for e in manifest["evidence"]))
        for f in path.rglob("*"):
            if f.is_file():
                content = f.read_text(encoding="utf-8", errors="replace")
                for raw in RAW_PERSONAL:
                    self.assertNotIn(raw, content, f"{raw!r} leaked into {f.name}")
        self.assertNotIn("Στείλε στο IBAN", (path / "report.json").read_text(encoding="utf-8"))

    def test_masked_values_and_non_personal_indicators_are_kept(self):
        model = report.build_model(self.case, ReportProfile.PUBLICATION, now=self.now)
        by_type = {}
        for i in model["indicators"]:
            by_type.setdefault(i["type"], []).append(i["value"])
        self.assertEqual(by_type["email"], ["b***@evil-shop.top"])
        self.assertTrue(by_type["phone"][0].startswith("+30•") and by_type["phone"][0].endswith("67"))
        self.assertTrue(by_type["iban"][0].startswith("GR16•"))
        self.assertIn("eth:0x5aaeb6053f3e94c9b9a09f33669435e7ef1beaed", by_type["wallet"])
        self.assertIn("elta-gr-delivery.top", by_type["domain"])
        self.assertEqual(model["timeline"], [])
        self.assertEqual(model["evidence"][0]["source"], "(withheld)")
        for tr in model["triage"]:
            self.assertTrue(all(h["snippet"] == "" for h in tr["hits"]))

    def test_publication_bundle_still_verifies(self):
        path, _ = self.export("pub2", profile=ReportProfile.PUBLICATION)
        code, out = self.run_verify(path)
        self.assertEqual(code, 0, out)
        self.assertIn("Audit head:", out)

    def test_reveal_unmasks_only_the_requested_types(self):
        model = report.build_model(self.case, ReportProfile.PUBLICATION, reveal=frozenset({"phone"}), now=self.now)
        values = {i["type"]: i["value"] for i in model["indicators"] if i["type"] in ("phone", "email", "iban")}
        self.assertEqual(values["phone"], "+306941234567")
        self.assertTrue(values["email"].startswith("b***"))
        self.assertTrue("•" in values["iban"])
        self.assertEqual(model["revealed_types"], ["phone"])

    def test_cluster_values_are_masked_too(self):
        ev2 = self.case.add_evidence(b"again GR1601101250000000012300695", kind="text", source="b", method="manual_import",
                                     media_type="text/plain")
        index_evidence(self.case, ev2.id)
        model = report.build_model(self.case, ReportProfile.PUBLICATION, now=self.now)
        shared = [s for c in model["correlation"]["clusters"] for s in c["shared"]]
        self.assertTrue(shared)
        self.assertTrue(all("GR1601101250000000012300695" not in s["value"] for s in shared))
        raw = report.model_json(model)
        self.assertNotIn("GR1601101250000000012300695", raw)
        handover = report.build_model(self.case, ReportProfile.HANDOVER, now=self.now)
        self.assertIn("GR1601101250000000012300695", report.model_json(handover))
