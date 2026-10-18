# Threat model

Aletheia stores evidence, journalists' material and victims' messages on a single machine. This
document states what it protects against, how, and — just as important — what it does **not** do.

## Assets and actors

* **Assets:** evidence files, extracted indicators, the audit log, report bundles, the identity of sources.
* **Actors:** the operator (journalist, victim), a recipient (police, lawyer, editor), a curious or hostile
  local user, an attacker who controls *input* (a scam page, a crafted export ZIP, a scam message), a network
  attacker, and the operator themselves (mistakes, over-sharing, misidentification).

## Threats and mitigations

| # | Threat | Mitigation in the code | Residual risk / limits |
|---|--------|------------------------|------------------------|
| 1 | Evidence is altered after collection | SHA-256 content-addressed blobs (read-only), hash-chained audit log, evidence/analysis rows cross-checked against the chain, `case verify`, and a **standalone `verify.py`** shipped in every bundle | Someone with full write access to the vault can rebuild the whole chain. **Anchor the audit head** outside the vault (email it, publish it, timestamp it). RFC 3161 timestamping is not built in yet |
| 2 | Source or victim identity leaks | Local-only; no telemetry; no network unless a command explicitly needs it; audit actor defaults to `operator` (not your OS user name); one directory per case; owner-only permissions | **No encryption at rest in this version** — use full-disk encryption (BitLocker, FileVault, LUKS, Android file-based encryption). `case delete` is not a secure wipe on SSDs/journaling filesystems. OS traces (shell history, swap, backups, thumbnails) are out of scope |
| 3 | Misidentifying or doxxing a person (scammers use stolen photos and identities) | AUP acceptance and a purpose are mandatory; findings carry confidence labels; no automatic linking of a profile to a natural person; *publication* profile masks emails, phones, IBANs, handles, withholds sources and message text; every `--reveal` is audited | Human judgement. The tool cannot stop an operator from accusing someone |
| 4 | Unlawful access or ToS-breaking collection | No login automation, no credentials/cookies, no scraping of Instagram: it ingests *your own* data export and public URLs you choose; contacting a target requires `--confirm-active`; robots.txt respected by default (overrides audited) | Legality depends on jurisdiction and use. See "Compliance notes". This is not legal advice |
| 5 | Malicious input: ZIP slip / decompression bomb | Archives are never extracted; names with `..`, absolute paths or drive letters rejected; size, member-count and compression-ratio limits; directory exports never follow symlinks | Limits are heuristics; very large legitimate exports may need the constants raised |
| 6 | Malicious input: ReDoS, huge inputs | Own patterns are linear and tested on adversarial strings; community rule packs are linted for nested quantifiers; global input caps | A pattern that passes the lint can still be slow; review packs like code |
| 7 | Malicious input: HTML/Markdown injection in reports | Everything dynamic is escaped for its output format; tested with hostile titles/sources | Opening evidence *files* in other programs is the operator's risk |
| 8 | SSRF / DNS rebinding through `capture`, `domain` | Resolve once, require **global** addresses, connect to the pinned IP while verifying TLS for the original host; every redirect hop re-validated; size/time/redirect limits | Proxies are not supported (see 9) |
| 9 | The target learns who is looking | Each collection step is labelled *offline / passive / active*; active steps need confirmation and warn that the IP is visible; honest default User-Agent | For anonymity route the **whole machine** through a VPN/Tor — the client deliberately has no proxy settings |
| 10 | Path traversal / injection in the vault | Case ids are validated by regex; SQL is parameterised; file names are never taken from evidence (content-addressed) | — |
| 11 | Supply-chain compromise | **Zero third-party dependencies** (enforced by a test); CI on Windows/macOS/Linux | Releases should be signed and ship an SBOM (not done yet) |
| 12 | Platform pitfalls | Termux/Android shared storage is refused; atomic replace with retry (Windows AV locks); advisory locking per platform; Unicode (Greek) file names probed; UTF-8 output forced for pipes; `aletheia doctor` reports what the filesystem supports | Development testing so far ran on Linux only; Windows/macOS/Termux paths are exercised by platform-simulating unit tests and a ready-made CI matrix (`.github/workflows/ci.yml`) that has **not been run yet**. Run `aletheia doctor` on your device |

## Deliberately not included

* Face recognition or any biometric matching; image scraping.
* Breach-dump / credential lookups.
* Logging in to, or scraping, Instagram or any platform; "hack-back" of any kind.
* A GUI / web UI (planned separately).

## Compliance notes (not legal advice — have a lawyer review before relying on them)

* **GDPR principles → features.** Purpose limitation → mandatory purpose + AUP; data minimisation → default
  actor, no telemetry, masked publication profile; integrity and confidentiality (Art. 5(1)(f), Art. 32) →
  hash chain, permissions, and the FDE recommendation; accountability → audit log.
* **Journalism.** Greek Law 4624/2019 art. 28 (implementing GDPR art. 85) gives conditional room for
  journalistic processing, but security-of-processing duties (GDPR art. 32) still apply; the exemption is not
  a blanket permission. Victims acting privately cannot assume the journalistic exemption.
* **EU AI Act.** Untargeted scraping of facial images to build recognition databases is prohibited; Aletheia
  contains no such feature.
* **Greek criminal law.** Unauthorised access to information systems or data is an offence (Penal Code
  arts. 370B/370C). Aletheia never accesses anything that requires credentials.
* **Platform terms.** Automated collection from a platform's servers may breach its terms; Aletheia does not
  perform it.
