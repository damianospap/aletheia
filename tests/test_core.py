import ast
import os
import re
import stat
import sys
import threading
import unittest
from pathlib import Path
from unittest import mock

from aletheia import errors, fsutil, i18n, platform_info, textnorm
from aletheia.errors import AletheiaError

from helpers import VaultTestCase

SRC = Path(__file__).resolve().parent.parent / "src" / "aletheia"


class CatalogTests(unittest.TestCase):
    def setUp(self):
        self.en, self.el = i18n.load_catalog("en-US"), i18n.load_catalog("el")

    def test_same_keys(self):
        self.assertEqual(sorted(set(self.en) - set(self.el)), [])
        self.assertEqual(sorted(set(self.el) - set(self.en)), [])

    def test_same_placeholders(self):
        for key in self.en:
            self.assertEqual(i18n.placeholders(self.en[key]), i18n.placeholders(self.el[key]), key)

    def test_greek_is_really_translated(self):
        same = {k for k in self.en if self.en[k] == self.el[k]}
        self.assertLessEqual(same, {"doctor.python", "doctor.feature.fsync", "error.usage"}, same)
        for key in ("aup.item1", "report.disclaimer", "error.vault.locked", "help.description"):
            self.assertTrue(re.search(r"[\u0370-\u03ff]", self.el[key]), key)

    def test_every_key_used_in_source_exists(self):
        used = set()
        for path in list(SRC.glob("*.py")) + list((SRC / "indicators").glob("*.py")):
            text = path.read_text(encoding="utf-8")
            for pat in (r"""\bt\(\s*["']([a-z0-9_.\-]+)["']""", r"""\bplural\(\s*["']([a-z0-9_.\-]+)["']""",
                        r"""\bkey\s*=\s*["']([a-z0-9_.\-]+)["']"""):
                used |= set(re.findall(pat, text))
        used = {k for k in used if "." in k and not k.endswith(".")}
        missing = [k for k in used if k not in self.en and f"{k}.one" not in self.en]
        self.assertEqual(missing, [])

    def test_every_error_class_key_exists(self):
        def walk(cls):
            for sub in cls.__subclasses__():
                yield sub
                yield from walk(sub)

        for cls in [AletheiaError, *walk(AletheiaError)]:
            self.assertIn(cls.key, self.en, cls.__name__)

    def test_dynamic_enum_keys_exist(self):
        for prefix, values in {
            "purpose.": ["journalism", "victim-report"], "profile.": ["handover", "publication"],
            "exposure.": ["none", "passive_third_party", "active_target"],
            "confidence.": ["high", "medium", "low"], "level.": ["none", "low", "medium", "high"],
            "flag.": ["idn", "mixed_script"],
            "lookalike.": ["same_name_other_tld", "homoglyph_or_typo", "near_typo", "brand_in_domain", "brand_in_subdomain"],
            "kind.": ["text", "file", "ig_thread", "ig_export_json", "http_body", "http_capture_meta", "rdap"],
            "method.": ["manual_import", "http_get", "rdap"],
            "doctor.feature.": ["atomic_replace", "fsync", "locking", "private_mode", "symlinks", "exec_bit",
                                "case_sensitive", "unicode_names", "long_paths"],
        }.items():
            for v in values:
                self.assertIn(prefix + v, self.en)

    def test_templates_are_well_formed(self):
        for lang, cat in (("en-US", self.en), ("el", self.el)):
            t = i18n.Translator(lang)
            for key, template in cat.items():
                params = {p: "X" for p in i18n.placeholders(template)}
                rendered = t(key, **params)
                self.assertNotIn("{", rendered, key)


class TranslatorTests(unittest.TestCase):
    def test_plural_and_fallback(self):
        for lang, one, other in (("en-US", "1 indicator recorded.", "2 indicators recorded."),
                                 ("el", "Καταγράφηκε 1 δείκτης.", "Καταγράφηκαν 2 δείκτες.")):
            t = i18n.Translator(lang)
            self.assertEqual(t.plural("msg.indicators_found", 1), one)
            self.assertEqual(t.plural("msg.indicators_found", 2), other)
            self.assertEqual(t.plural("msg.indicators_found", 0), t.plural("msg.indicators_found", 5).replace("5", "0"))

    def test_missing_key_and_placeholder_never_raise(self):
        t = i18n.Translator("el")
        self.assertEqual(t("no.such.key"), "no.such.key")
        self.assertIn("{case_id}", t("msg.case_created"))
        self.assertEqual(t("msg.case_created", case_id="{x}"), "Δημιουργήθηκε η υπόθεση: {x}")

    def test_normalize_lang(self):
        cases = {"el_GR.UTF-8": "el", "el-GR": "el", "el": "el", "Greek_Greece": "el", "en_GB.UTF-8": "en-US",
                 "English_United States": "en-US", "en": "en-US", "de_DE": None, "C": None, "POSIX": None,
                 "": None, None: None}
        for raw, expected in cases.items():
            self.assertEqual(i18n.normalize_lang(raw), expected, raw)

    def test_detect_lang_priority(self):
        self.assertEqual(i18n.detect_lang("el", {"LANG": "en_US"}), "el")
        self.assertEqual(i18n.detect_lang(None, {"ALETHEIA_LANG": "el", "LANG": "en_US"}), "el")
        self.assertEqual(i18n.detect_lang(None, {"LANG": "el_GR.UTF-8"}), "el")
        self.assertEqual(i18n.detect_lang(None, {"LANGUAGE": "el:en"}), "el")
        self.assertEqual(i18n.detect_lang("zz", {"LANG": "el_GR"}), "el")
        with mock.patch.object(i18n, "_windows_ui_locale", return_value=None):
            self.assertEqual(i18n.detect_lang(None, {}), "en-US")


class ErrorTests(unittest.TestCase):
    def test_exit_codes_and_codes_are_unique_and_stable(self):
        self.assertEqual(errors.UsageError().exit_code, 2)
        self.assertEqual(errors.ValidationError().exit_code, 3)
        self.assertEqual(errors.VaultIntegrityError().exit_code, 4)
        self.assertEqual(errors.TransportError().exit_code, 5)
        self.assertEqual(errors.AupNotAcceptedError().exit_code, 77)
        self.assertEqual(errors.InternalError().exit_code, 70)
        codes = []

        def walk(cls):
            for sub in cls.__subclasses__():
                codes.append(sub.code)
                walk(sub)

        walk(AletheiaError)
        self.assertEqual(len(codes), len(set(codes)))

    def test_localized_message_uses_params(self):
        exc = errors.CaseNotFoundError(case_id="abc", home="/h")
        self.assertIn("abc", exc.localized(i18n.Translator("en-US")))
        self.assertIn("«abc»", exc.localized(i18n.Translator("el")))
        self.assertTrue(errors.VaultLockedError().retryable)
        self.assertTrue(errors.TransportError().retryable)
        self.assertFalse(errors.TlsError().retryable)


class TextNormTests(unittest.TestCase):
    SAMPLES = ["Καλημέρα κόσμε", "ΣΑΣ ΕΥΧΑΡΙΣΤΟΥΜΕ", "ΐΰ ς Σ ά", "Hello 😀 wörld", "İstanbul ß", ""]

    def test_fold_keep_length_preserves_offsets(self):
        for s in self.SAMPLES:
            self.assertEqual(len(textnorm.fold_keep_length(s)), len(s), s)
        folded = textnorm.fold_keep_length("Επείγον! Ο ΛΟΓΑΡΙΑΣΜΟΣ σας")
        self.assertEqual(folded, "επειγον! ο λογαριασμοσ σασ")

    def test_fold_greek_key(self):
        self.assertEqual(textnorm.fold_greek("Δίωξη ΗΛΕΚΤΡΟΝΙΚΟΥ Εγκλήματος"), "διωξη ηλεκτρονικου εγκληματοσ")
        self.assertEqual(textnorm.fold_greek("ΆΈΉ"), textnorm.fold_greek("άέή"))

    def test_elot743(self):
        cases = {"Καλημέρα": "Kalimera", "Παπαδόπουλος": "Papadopoulos", "Γιώργος": "Giorgos", "Μπάμπης": "Bampis",
                 "Ντίνος": "Dinos", "Αθήνα": "Athina", "Θεσσαλονίκη": "Thessaloniki", "ΕΛΤΑ": "ELTA",
                 "Ευαγγελία": "Evangelia", "Αυγούστου": "Avgoustou", "Ευχαριστώ": "Efcharisto", "Άγγελος": "Angelos",
                 "Γκρέκο": "Greko", "Ψυχή": "Psychi", "abc 123": "abc 123"}
        for greek, latin in cases.items():
            self.assertEqual(textnorm.greek_to_latin(greek), latin, greek)

    def test_scripts_and_mixed(self):
        self.assertEqual(textnorm.scripts_in("paypal"), {"LATIN"})
        self.assertEqual(textnorm.scripts_in("ΕΛΤΑ"), {"GREEK"})
        self.assertTrue(textnorm.is_mixed_script("p\u0430ypal"))  # Cyrillic a
        self.assertTrue(textnorm.is_mixed_script("ΕLΤΑ"))
        self.assertFalse(textnorm.is_mixed_script("ΕΛΤΑ"))
        self.assertFalse(textnorm.is_mixed_script("abc123-"))

    def test_confusable_skeleton(self):
        sk = textnorm.confusable_skeleton
        self.assertEqual(sk("ΕLΤΑ"), sk("elta"))
        self.assertEqual(sk("p\u0430ypal"), sk("paypal"))
        self.assertEqual(sk("paypa1"), sk("paypal"))
        self.assertEqual(sk("rnicrosoft"), sk("microsoft"))
        self.assertNotEqual(sk("paypal"), sk("paypol"))

    def test_decode_text(self):
        self.assertEqual(textnorm.decode_text("Καλημέρα".encode())[0:3:2], ("Καλημέρα", False))
        self.assertEqual(textnorm.decode_text(b"\xef\xbb\xbfhi")[:2], ("hi", "utf-8-sig"))
        self.assertEqual(textnorm.decode_text("Γειά".encode("utf-16"))[:2], ("Γειά", "utf-16"))
        text, enc, lossy = textnorm.decode_text(b"abc\xff\xfe\xfd")
        self.assertTrue(lossy)
        self.assertIn("abc", text)
        with self.assertRaises(errors.InputTooLargeError):
            textnorm.decode_text(b"x" * 11, limit=10)


class FsUtilTests(VaultTestCase):
    def test_atomic_write_replaces_and_leaves_no_temp(self):
        target = self.tmp_path("a.bin")
        fsutil.atomic_write_bytes(target, b"one")
        fsutil.atomic_write_bytes(target, b"two")
        self.assertEqual(target.read_bytes(), b"two")
        self.assertFalse([p for p in target.parent.iterdir() if p.name.startswith(".tmp-")])
        if os.name == "posix":
            self.assertEqual(stat.S_IMODE(target.stat().st_mode), 0o600)

    def test_atomic_write_failure_keeps_old_content_and_cleans_up(self):
        target = self.tmp_path("keep.bin")
        fsutil.atomic_write_bytes(target, b"old")
        with mock.patch.object(fsutil, "replace_with_retry", side_effect=OSError("boom")):
            with self.assertRaises(OSError):
                fsutil.atomic_write_bytes(target, b"new")
        self.assertEqual(target.read_bytes(), b"old")
        self.assertFalse([p for p in target.parent.iterdir() if p.name.startswith(".tmp-")])

    def test_replace_with_retry_recovers_from_transient_permission_error(self):
        calls = {"n": 0}
        real = os.replace

        def flaky(src, dst):
            calls["n"] += 1
            if calls["n"] < 3:
                raise PermissionError("locked by antivirus")
            return real(src, dst)

        src, dst = self.tmp_path("s"), self.tmp_path("d")
        src.write_bytes(b"x")
        with mock.patch.object(fsutil.os, "replace", flaky), mock.patch.object(fsutil.time, "sleep"):
            fsutil.replace_with_retry(src, dst)
        self.assertEqual(dst.read_bytes(), b"x")
        self.assertEqual(calls["n"], 3)

    @unittest.skipIf(fsutil.fcntl is None and fsutil.msvcrt is None, "no locking primitive")
    def test_file_lock_is_exclusive_and_releasable(self):
        path = self.tmp_path("x.lock")
        a = fsutil.FileLock(path, timeout=1)
        a.acquire()
        with self.assertRaises(errors.VaultLockedError):
            fsutil.FileLock(path, timeout=0.2).acquire()
        a.release()
        with fsutil.FileLock(path, timeout=1):
            pass

    @unittest.skipIf(fsutil.fcntl is None and fsutil.msvcrt is None, "no locking primitive")
    def test_file_lock_serialises_threads(self):
        path, counter, errs = self.tmp_path("t.lock"), {"v": 0}, []

        def work():
            try:
                for _ in range(20):
                    with fsutil.FileLock(path, timeout=10):
                        v = counter["v"]
                        counter["v"] = v + 1
            except Exception as exc:  # noqa: BLE001
                errs.append(exc)

        threads = [threading.Thread(target=work) for _ in range(4)]
        [t.start() for t in threads]
        [t.join() for t in threads]
        self.assertEqual(errs, [])
        self.assertEqual(counter["v"], 80)

    def test_safe_filename(self):
        f = fsutil.safe_filename
        self.assertEqual(f("CON"), "_CON")
        self.assertEqual(f("com1.txt"), "_com1.txt")
        self.assertEqual(f("nul"), "_nul")
        self.assertEqual(f('a<b>c:d"e/f\\g|h?i*j'), "a_b_c_d_e_f_g_h_i_j")
        self.assertEqual(f("name. . "), "name")
        self.assertEqual(f(""), "file")
        self.assertEqual(f("..."), "file")
        self.assertEqual(f("αρχείο-Δοκιμή.txt"), "αρχείο-Δοκιμή.txt")
        nfd = "α\u0301.txt"  # decomposed alpha + tonos
        self.assertEqual(f(nfd), "\u03ac.txt")
        long = f("δ" * 200 + ".txt")
        self.assertLessEqual(len(long.encode("utf-8")), 120)
        self.assertNotEqual(f("δ" * 200 + "1"), f("δ" * 200 + "2"))

    def test_win_long_path_logic(self):
        short = "C:\\Users\\me\\a.txt"
        self.assertEqual(fsutil.win_long_path(short, force=True), short)
        long = "C:\\" + "\\".join(["d" * 50] * 6) + "\\f.txt"
        self.assertEqual(fsutil.win_long_path(long, force=True), "\\\\?\\" + long)
        unc = "\\\\server\\share\\" + "\\".join(["d" * 50] * 6)
        self.assertTrue(fsutil.win_long_path(unc, force=True).startswith("\\\\?\\UNC\\server\\share"))
        already = "\\\\?\\C:\\x"
        self.assertEqual(fsutil.win_long_path(already, force=True), already)
        self.assertEqual(fsutil.win_long_path(long), long if sys.platform != "win32" else fsutil.win_long_path(long))

    def test_rmtree_force_removes_readonly_files(self):
        root = self.tmp_path("tree")
        (root / "a" / "b").mkdir(parents=True)
        f = root / "a" / "b" / "ro.bin"
        f.write_bytes(b"x")
        os.chmod(f, 0o400)
        fsutil.rmtree_force(root)
        self.assertFalse(root.exists())

    def test_sha256_helpers(self):
        p = self.tmp_path("h.bin")
        p.write_bytes(b"abc")
        digest = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        self.assertEqual(fsutil.sha256_file(p), (digest, 3))
        self.assertEqual(fsutil.sha256_chunks([b"a", b"bc"]), (digest, 3))


class PlatformTests(VaultTestCase):
    def test_detect_system(self):
        d = platform_info.detect_system
        no = lambda p: False  # noqa: E731
        self.assertEqual(d({}, "win32", no), "windows")
        self.assertEqual(d({}, "darwin", no), "macos")
        self.assertEqual(d({}, "linux", no), "linux")
        self.assertEqual(d({"TERMUX_VERSION": "0.118.3"}, "linux", no), "termux")
        self.assertEqual(d({"PREFIX": "/data/data/com.termux/files/usr"}, "linux", no), "termux")
        self.assertEqual(d({}, "linux", lambda p: p == "/data/data/com.termux/files/usr"), "termux")
        self.assertEqual(d({}, "android", no), "android")
        self.assertEqual(d({}, "freebsd14", no), "other")

    def test_default_home(self):
        h = Path("/home/u")
        env = {"LOCALAPPDATA": "C:\\Users\\u\\AppData\\Local", "XDG_DATA_HOME": "/x/share"}
        self.assertEqual(platform_info.default_home(env, "windows", h), Path("C:\\Users\\u\\AppData\\Local") / "Aletheia")
        self.assertEqual(platform_info.default_home({}, "windows", h), h / "AppData" / "Local" / "Aletheia")
        self.assertEqual(platform_info.default_home({}, "macos", h), h / "Library" / "Application Support" / "Aletheia")
        self.assertEqual(platform_info.default_home(env, "linux", h), Path("/x/share/aletheia"))
        self.assertEqual(platform_info.default_home({}, "linux", h), h / ".local" / "share" / "aletheia")
        self.assertEqual(platform_info.default_home({}, "termux", Path("/data/data/com.termux/files/home")),
                         Path("/data/data/com.termux/files/home/.local/share/aletheia"))

    def test_resolve_home_precedence(self):
        self.assertEqual(platform_info.resolve_home("/a", {"ALETHEIA_HOME": "/b"}), Path("/a"))
        self.assertEqual(platform_info.resolve_home(None, {"ALETHEIA_HOME": "/b"}), Path("/b"))
        self.assertTrue(str(platform_info.resolve_home(None, {})).lower().endswith("aletheia"))

    def test_shared_storage_detection(self):
        shared = ["/sdcard/x", "/sdcard", "/storage/emulated/0/Download", "/storage/1234-ABCD/a", "/mnt/sdcard/x",
                  "/mnt/media_rw/ABCD"]
        for p in shared:
            with mock.patch.object(platform_info.os.path, "realpath", return_value=p):
                self.assertTrue(platform_info.is_shared_storage(Path(p), "termux"), p)
        with mock.patch.object(platform_info.os.path, "realpath", return_value="/data/data/com.termux/files/home/x"):
            self.assertFalse(platform_info.is_shared_storage(Path("/x"), "termux"))
        with mock.patch.object(platform_info.os.path, "realpath", return_value="/storage/emulated/0/x"):
            self.assertFalse(platform_info.is_shared_storage(Path("/x"), "linux"))  # only Android is special

    def test_symlink_into_shared_storage_is_detected(self):
        with mock.patch.object(platform_info.os.path, "realpath", return_value="/storage/emulated/0/Aletheia"):
            with self.assertRaises(errors.UnsafeStorageError) as cm:
                platform_info.ensure_home(self.home, "termux")
        self.assertIn("Termux", cm.exception.localized(i18n.Translator("en-US")))

    def test_ensure_home_creates_private_dir(self):
        platform_info.ensure_home(self.home, "linux")
        self.assertTrue(self.home.is_dir())
        if os.name == "posix":
            self.assertEqual(stat.S_IMODE(self.home.stat().st_mode), 0o700)

    def test_probe_filesystem_on_this_machine(self):
        self.home.mkdir(parents=True)
        caps = platform_info.probe_filesystem(self.home, "linux")
        self.assertTrue(caps.atomic_replace and caps.locking and caps.fsync)
        self.assertTrue(caps.unicode_names and caps.long_paths)
        self.assertEqual(caps.problems, [])
        self.assertEqual(list(self.home.iterdir()), [])  # probe cleaned up after itself
        self.assertIn("atomic_replace", caps.to_dict())

    def test_probe_reports_problems(self):
        self.home.mkdir(parents=True)
        with mock.patch.object(platform_info, "atomic_write_bytes", side_effect=OSError("no")):
            caps = platform_info.probe_filesystem(self.home, "linux")
        self.assertFalse(caps.atomic_replace)
        self.assertIn("doctor.problem.atomic", caps.problems)
        shared = platform_info.probe_filesystem
        with mock.patch.object(platform_info, "is_shared_storage", return_value=True):
            caps = shared(self.home, "termux")
        self.assertIn("doctor.problem.shared_storage", caps.problems)


class ArchitectureTests(unittest.TestCase):
    """Guarantees about the code base itself (no hidden network, no third-party dependencies)."""

    def _imports(self, path: Path) -> set[str]:
        tree = ast.parse(path.read_text(encoding="utf-8"))
        found = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                found |= {a.name.split(".")[0] for a in node.names}
            elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
                found.add(node.module.split(".")[0])
        return found

    def test_only_stdlib_dependencies(self):
        allowed = set(sys.stdlib_module_names) | {"aletheia"}
        for path in SRC.rglob("*.py"):
            self.assertLessEqual(self._imports(path), allowed, path.name)

    def test_only_http_module_touches_the_network(self):
        network = {"socket", "ssl", "http", "urllib", "ftplib", "smtplib", "xmlrpc", "telnetlib", "imaplib", "poplib"}
        for path in SRC.rglob("*.py"):
            if path.name == "http.py":
                continue
            names = self._imports(path)
            tree = ast.parse(path.read_text(encoding="utf-8"))
            for node in ast.walk(tree):  # urllib.parse (pure string handling) is fine
                if isinstance(node, ast.ImportFrom) and node.module and node.module.startswith("urllib.parse"):
                    names.discard("urllib")
                if isinstance(node, ast.ImportFrom) and node.module == "urllib.robotparser":
                    names.discard("urllib")
            self.assertEqual(names & network, set(), path.name)


if __name__ == "__main__":
    unittest.main()
