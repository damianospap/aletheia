import re
import tomllib
import unittest
from pathlib import Path

import aletheia
from aletheia import cli, errors, i18n

ROOT = Path(__file__).resolve().parent.parent


class DocsConsistencyTests(unittest.TestCase):
    def test_aup_document_matches_the_catalogs_the_cli_shows(self):
        text = (ROOT / "ACCEPTABLE_USE.md").read_text(encoding="utf-8")
        self.assertIn(f"version {aletheia.AUP_VERSION}", text.splitlines()[0])
        english, greek = text.split("## Ελληνικά")
        for section, lang in ((english, "en-US"), (greek, "el")):
            items = re.findall(r"^\d+\. (.+)$", section, re.M)
            catalog = i18n.load_catalog(lang)
            self.assertEqual(items, [catalog[f"aup.item{i}"] for i in range(1, 7)], lang)

    def test_version_numbers_agree(self):
        meta = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
        self.assertEqual(meta["project"]["version"], aletheia.__version__)
        self.assertEqual(meta["project"]["dependencies"], [])
        self.assertEqual(meta["project"]["requires-python"], ">=3.11")
        self.assertIn("locales/*.toml", meta["tool"]["setuptools"]["package-data"]["aletheia"])
        self.assertTrue(list((ROOT / "src" / "aletheia" / "packs").glob("*.toml")))

    def test_every_exit_code_is_documented(self):
        documented = {0, 1, 2, 3, 4, 5, 70, 77}
        seen = set()

        def walk(cls):
            for sub in cls.__subclasses__():
                seen.add(sub.exit_code)
                walk(sub)

        walk(errors.AletheiaError)
        self.assertLessEqual(seen, documented)
        for readme in ("README.md", "README.el.md"):
            text = (ROOT / readme).read_text(encoding="utf-8")
            for code in (0, 2, 3, 4, 5, 70, 77):
                self.assertIn(f"`{code}`", text, f"{readme}: exit code {code}")

    def test_readme_commands_exist(self):
        parser = cli.build_parser(i18n.Translator("en-US"))
        sub = next(a for a in parser._actions if a.dest == "command")
        known = set(sub.choices)
        case_actions = set(next(a for a in sub.choices["case"]._actions if a.dest == "case_command").choices)
        for readme in ("README.md", "README.el.md"):
            text = (ROOT / readme).read_text(encoding="utf-8")
            used = set(re.findall(r"^aletheia (?!--)([a-z][a-z-]*)", text, re.M))
            self.assertTrue(used, readme)
            self.assertLessEqual(used, known, readme)
            for action in re.findall(r"^aletheia case ([a-z]+)", text, re.M):
                self.assertIn(action, case_actions)

    def test_readmes_are_in_sync_on_commands(self):
        def commands(name):
            return re.findall(r"^aletheia (?:case )?[a-z][a-z-]*", (ROOT / name).read_text(encoding="utf-8"), re.M)

        self.assertEqual(commands("README.md"), commands("README.el.md"))


if __name__ == "__main__":
    unittest.main()
