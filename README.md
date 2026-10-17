# Aletheia

**Evidence-grade, passive OSINT toolkit for journalists and fraud victims** — English / Ελληνικά.
Runs on Windows, macOS, Linux and Android (Termux). Python 3.11+, **no third-party dependencies**.

> Greek version: [README.el.md](README.el.md) · Policy: [ACCEPTABLE_USE.md](ACCEPTABLE_USE.md) ·
> Security: [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md)

## What problem does it solve?

Existing tools either scrape social networks (fragile, often against the platform's terms and the law) or are
hard to use and don't run everywhere. Aletheia takes a different route: it is a **case and evidence engine**
that works on material you are entitled to hold, and produces something authorities can actually use.

| Real problem | What Aletheia does |
|---|---|
| Evidence that cannot be trusted later | Tamper-evident vault: content-addressed files, hash-chained audit log, **standalone `verify.py`** in every bundle |
| Instagram "Download your information" exports are corrupted for non-English text (Greek shows as `Î•Î»...`) | Lossless repair of Meta's double-encoded UTF-8; safe reading of huge ZIPs (zip-slip, bombs) |
| "When was this post made?" when the page is gone or hides dates | Offline decoding of the post shortcode → creation time (*heuristic*, clearly labelled) |
| Scam links hidden behind `l.instagram.com`, `hxxp://`, look-alike letters | Unwraps redirect shims, refangs, flags mixed-alphabet/IDN domains and brand look-alikes (Greek + Latin aware) |
| Payment details scattered in chat | Validates and extracts IBANs (mod-97), Bitcoin (Base58Check/Bech32), Ethereum (EIP-55), TRON, phone numbers (E.164, Greek rules), emails, handles |
| "Is this message a scam?" | Transparent, explainable signals (EN + EL rule packs you can extend) — hints, not verdicts |
| Handing a case to the Cyber Crime Division, lawyers or editors | Bilingual bundle (EN + EL reports), *handover* profile (complete) and *publication* profile (personal data masked) |
| Tools that break on Windows, Android or Greek file names | `aletheia doctor` probes the real filesystem; Termux shared storage is refused with an explanation |

## What it deliberately does *not* do

No logging in to or scraping Instagram or any platform, no face recognition, no breach-dump lookups, no
"hack-back". Contacting a target's server requires an explicit flag. See the Acceptable Use Policy.

## Install and run

```bash
# Option 1: single file (build once, copy anywhere that has Python 3.11+)
mkdir -p dist/app && cp -r src/aletheia dist/app/
python -m zipapp dist/app -m aletheia.cli:main -c -o aletheia.pyz
python aletheia.pyz doctor

# Option 2: run from source
PYTHONPATH=src python -m aletheia doctor

# Option 3: pip (installs the `aletheia` command)
pip install .
```

**Termux (Android):** `pkg install python`, then run as above. Keep the data folder in Termux's private home
(the default). Never point it at `/sdcard` — `doctor` and `case new` refuse shared storage.

Language: `--lang el|en`, or `ALETHEIA_LANG=el`, otherwise taken from your system locale.

## Quick start

```bash
aletheia aup                                   # read the policy
aletheia case new --title "Fake courier SMS" --purpose victim-report --accept-aup
aletheia add CASE --file messages.txt          # or --text "..." / --stdin
aletheia ig-export CASE instagram-export.zip   # your own Meta data export (JSON)
aletheia triage --case CASE                    # explainable scam signals
aletheia domain CASE evil-shop.top             # look-alike check + RDAP registration data
aletheia capture CASE https://evil-shop.top --confirm-active   # contacts the server: your IP is visible
aletheia correlate CASE                        # links between evidence items
aletheia case export CASE --out handover.zip --zip             # EN + EL reports, evidence, audit log
aletheia case export CASE --out publish --profile publication  # personal data masked
```

Stateless helpers: `aletheia extract --text "..."`, `aletheia ig-id <shortcode-or-URL>`.
Add `--json` for machine-readable output. Exit codes: `0` ok, `2` usage, `3` invalid input, `4` vault/integrity,
`5` network, `70` internal, `77` policy refusal.

## Verifying a bundle (recipients)

Extract `verify.py` from the bundle and run `python verify.py handover.zip` — it needs only Python 3.6+ and
checks every file hash and the whole audit chain. **Keep the "audit head" hash somewhere independent**
(email, publish, timestamp): that is what proves the bundle existed in this form at that time.

## Development

```bash
PYTHONPATH=src:tests python -m unittest discover -s tests -v     # 250+ tests
python tools/coverage_report.py --show-missing                   # stdlib-only coverage
```

Rule packs (`src/aletheia/packs/*.toml`) and the brand list are plain data: contributions welcome — especially
new countries. Greek packs run on accent/sigma-folded text, so write them without accents.

## Limitations (v0.1)

* No encryption at rest yet — use full-disk encryption. No built-in RFC 3161 timestamping.
* Tested on Linux; Windows/macOS/Termux are covered by simulation tests and a CI matrix that still has to be run.
* Instagram export layout is not a public contract; parsing is tolerant but may need updates.
* Phone validation is strict only for Greece; BIC/bank lookup for IBANs is intentionally absent.
* `argparse` usage lines remain English (all other messages are translated).

## License

To be chosen by the maintainer before publication (Apache-2.0 is recommended for enterprise adoption).
