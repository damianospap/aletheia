import random
import time
import unittest

from aletheia.errors import ValidationError
from aletheia.indicators import accounts, crypto, extract_indicators, iban, phones, urls
from aletheia.models import Confidence, IndicatorType


def values(matches, itype=None, derived=None):
    return [m.value for m in matches if (itype is None or m.type == itype) and (derived is None or m.derived == derived)]


class UrlTests(unittest.TestCase):
    def test_refang(self):
        self.assertEqual(urls.refang("hxxps://evil[.]com/a"), "https://evil.com/a")
        self.assertEqual(urls.refang("hXXp[:]//a(.)b{.}c"), "http://a.b.c")
        self.assertEqual(urls.refang("user[at]example[dot]com"), "user@example.com")

    def test_canonicalisation(self):
        info = urls.parse_url("HTTPS://Example.COM:443/Path?b=2&utm_source=x&a=1&fbclid=zzz#frag")
        self.assertEqual(info.canonical, "https://example.com/Path?a=1&b=2")
        self.assertEqual(urls.parse_url("http://example.com:8080").canonical, "http://example.com:8080/")
        self.assertEqual(urls.parse_url("http://example.com:80/x").canonical, "http://example.com/x")

    def test_idn_and_mixed_script(self):
        info = urls.parse_url("https://παράδειγμα.gr/login")
        self.assertTrue(info.is_idn)
        self.assertTrue(info.host.startswith("xn--"))
        self.assertFalse(info.mixed_script)
        spoof = urls.parse_url("https://p\u0430ypal.com/")  # Cyrillic а
        self.assertTrue(spoof.is_idn and spoof.mixed_script)
        self.assertEqual(urls.parse_url("https://" + spoof.host).host_unicode, "p\u0430ypal.com")
        self.assertFalse(urls.parse_url("https://paypal.com").is_idn)

    def test_userinfo_trick(self):
        info = urls.parse_url("https://paypal.com@evil.top/login")
        self.assertEqual(info.host, "evil.top")
        self.assertTrue(info.has_userinfo)

    def test_ip_hosts(self):
        self.assertEqual(urls.parse_url("http://192.0.2.7/x").host_kind, "ip")
        v6 = urls.parse_url("http://[2001:db8::1]:8080/x")
        self.assertEqual((v6.host, v6.port, v6.host_kind), ("2001:db8::1", 8080, "ip"))
        self.assertEqual(v6.canonical, "http://[2001:db8::1]:8080/x")

    def test_redirect_shims_are_unwrapped(self):
        ig = urls.parse_url("https://l.instagram.com/?u=https%3A%2F%2Fevil.top%2Fpay%3Fx%3D1&e=AT0abc")
        self.assertEqual(ig.unwrapped.canonical, "https://evil.top/pay?x=1")
        fb = urls.parse_url("https://l.facebook.com/l.php?u=https%3A%2F%2Fevil.top%2F")
        self.assertEqual(fb.unwrapped.host, "evil.top")
        g = urls.parse_url("https://www.google.com/url?q=https://evil.top/a&sa=D")
        self.assertEqual(g.unwrapped.host, "evil.top")
        self.assertIsNone(urls.parse_url("https://l.instagram.com/?u=javascript%3Aalert(1)").unwrapped)
        self.assertIsNone(urls.parse_url("https://example.com/?u=https://evil.top").unwrapped)

    def test_invalid_urls_raise_localizable_errors(self):
        for bad in ("example.com", "http://", "mailto:a@b.c", "http://exa mple.com", "javascript:alert(1)",
                    "http://-bad-.com", "http://a..b/", "http://[::1"):
            with self.assertRaises(ValidationError, msg=bad) as cm:
                urls.parse_url(bad)
            self.assertTrue(cm.exception.key.startswith("error.validation"))

    def test_find_urls_trims_punctuation_but_keeps_balanced_brackets(self):
        text = "see (https://a.com/x), and https://en.wikipedia.org/wiki/Foo_(bar). Also <https://b.org/y>; done"
        found = [raw for _s, _e, raw in urls.find_urls(text)]
        self.assertEqual(found, ["https://a.com/x", "https://en.wikipedia.org/wiki/Foo_(bar)", "https://b.org/y"])

    def test_find_urls_defanged_and_offsets(self):
        text = "go to hxxps://evil[.]com/a now"
        (start, end, raw), = urls.find_urls(text)
        self.assertEqual(text[start:end], raw)
        self.assertEqual(raw, "hxxps://evil[.]com/a")

    def test_bare_domains(self):
        found = {raw: defanged for _s, _e, raw, defanged in urls.find_bare_domains(
            "visit evil[.]top and example.com or shop.example.co.uk; ignore script.py README.md photo.jpg "
            "version 1.2.3 user@example.com")}
        self.assertEqual(found, {"evil[.]top": True, "example.com": False, "shop.example.co.uk": False})

    def test_registrable_domain(self):
        r = urls.registrable_domain
        self.assertEqual(r("a.b.example.co.uk"), "example.co.uk")
        self.assertEqual(r("www.elta.com.gr"), "elta.com.gr")
        self.assertEqual(r("sub.evil.top"), "evil.top")
        self.assertEqual(r("example.com"), "example.com")

    def test_instagram_classification(self):
        def c(u):
            return urls.classify_instagram(urls.parse_url(u))

        self.assertEqual(c("https://www.instagram.com/John.Doe/"), urls.IgRef("profile", handle="john.doe"))
        self.assertEqual(c("https://instagram.com/p/Bk7e3P4gDAV/?igsh=abc").shortcode, "Bk7e3P4gDAV")
        self.assertEqual(c("https://instagram.com/reel/Bk7e3P4gDAV/").kind, "reel")
        self.assertEqual(c("https://instagram.com/reels/Bk7e3P4gDAV/").kind, "reel")
        self.assertEqual(c("https://instagram.com/john/p/Bk7e3P4gDAV/"), urls.IgRef("post", "john", "Bk7e3P4gDAV"))
        self.assertEqual(c("https://instagram.com/stories/john/3000000000000000000/").kind, "story")
        self.assertEqual(c("https://instagram.com/stories/highlights/1789/").kind, "highlight")
        self.assertEqual(c("https://instagram.com/explore/tags/scam/").kind, "tag")
        self.assertEqual(c("https://instagram.com/explore/").kind, "other")
        self.assertEqual(c("https://instagram.com/accounts/login/").kind, "other")
        self.assertEqual(c("https://instagram.com/_u/someone").handle, "someone")
        self.assertEqual(c("https://ig.me/m/someone").handle, "someone")
        self.assertEqual(c("https://instagram.com/").kind, "home")
        self.assertIsNone(c("https://example.com/john"))
        self.assertIsNone(c("https://instagram.com/bad name!/"))

    def test_social_refs(self):
        def s(u):
            return urls.social_ref(urls.parse_url(u))

        self.assertEqual(s("https://t.me/ScamBot"), urls.SocialRef("telegram", "handle", "scambot"))
        self.assertIsNone(s("https://t.me/joinchat/abcdef"))
        self.assertEqual(s("https://wa.me/306941234567"), urls.SocialRef("whatsapp", "phone", "+306941234567"))
        self.assertEqual(s("https://api.whatsapp.com/send?phone=306941234567&text=hi").value, "+306941234567")
        self.assertEqual(s("https://www.tiktok.com/@some.user").value, "some.user")
        self.assertEqual(s("https://x.com/someone").platform, "x")
        self.assertIsNone(s("https://x.com/i/status/1"))
        self.assertIsNone(s("https://facebook.com/groups/123"))
        self.assertEqual(s("https://facebook.com/some.page").value, "some.page")
        self.assertEqual(s("https://snapchat.com/add/buddy99").value, "buddy99")
        self.assertIsNone(s("https://example.com/x"))


class PhoneTests(unittest.TestCase):
    def test_greek_numbers(self):
        n = phones.normalize_phone
        p = n("+30 694 123 4567")
        self.assertEqual((p.e164, p.line_type, p.region, p.confidence), ("+306941234567", "mobile", "GR", Confidence.HIGH))
        self.assertEqual(n("0030 694-123-4567").e164, "+306941234567")
        self.assertEqual(n("(+30) 694 123 4567").e164, "+306941234567")
        nat = n("694 123 4567")
        self.assertEqual((nat.e164, nat.confidence), ("+306941234567", Confidence.MEDIUM))
        land = n("210 1234567")
        self.assertEqual((land.line_type, land.confidence), ("landline", Confidence.LOW))
        self.assertEqual(n("+30 210 123 4567").confidence, Confidence.HIGH)
        self.assertEqual(n("+30 800 123 4567").line_type, "toll_free")
        self.assertEqual(n("+30 901 123 4567").line_type, "premium_rate")
        self.assertIsNone(n("+30 123"))
        self.assertIsNone(n("+30 694 123 456"))  # too short for Greece

    def test_international_and_invalid(self):
        n = phones.normalize_phone
        self.assertEqual(n("+1 (415) 555-2671").region, "NANP")
        self.assertEqual(n("+44 20 7946 0958").region, "GB")
        self.assertEqual(n("+370 612 34567").region, "LT")
        self.assertEqual(n("+999 1234567").confidence, Confidence.LOW)
        for bad in ("12345", "", "abc", "+1234567890123456", "0694 123 4567 89", "6941234567890"):
            self.assertIsNone(n(bad), bad)
        self.assertIsNone(n("694 123 4567", default_region=None))

    def test_find_phones(self):
        text = "call +30 694 123 4567 or 694 123 4567 or 210 1234567, order 12345678901 ref 2024-10-14"
        found = [raw for _s, _e, raw in phones.find_phones(text)]
        self.assertIn("+30 694 123 4567", found)
        self.assertTrue(any(r.strip() == "694 123 4567" for r in found))
        self.assertFalse(any("12345678901" in r for r in found))


class IbanTests(unittest.TestCase):
    VALID = ["GR16 0110 1250 0000 0001 2300 695", "GB82 WEST 1234 5698 7654 32", "DE89 3704 0044 0532 0130 00",
             "FR14 2004 1010 0505 0001 3M02 606", "IT60 X054 2811 1010 0000 0123 456", "ES91 2100 0418 4502 0005 1332",
             "NL91 ABNA 0417 1643 00", "LT12 1000 0111 0100 1000", "CY17 0020 0128 0000 0012 0052 7600"]

    def test_valid_ibans(self):
        for s in self.VALID:
            info = iban.validate_iban(s)
            self.assertIsNotNone(info, s)
            self.assertEqual(info.confidence, Confidence.HIGH)
        gr = iban.validate_iban("gr16 0110 1250 0000 0001 2300 695")
        self.assertEqual((gr.iban, gr.country, gr.bank_code), ("GR1601101250000000012300695", "GR", "0110125"))

    def test_invalid_ibans(self):
        self.assertIsNone(iban.validate_iban("GR16 0110 1250 0000 0001 2300 696"))  # checksum
        self.assertIsNone(iban.validate_iban("GR16 0110 1250 0000 0001 2300 69"))  # length
        self.assertIsNone(iban.validate_iban("XX00 1234"))
        self.assertIsNone(iban.validate_iban("hello world"))

    def test_unknown_country_is_medium(self):
        # build a mod-97-valid IBAN for a country missing from the length table
        body = "00001234567890"
        check = 98 - int("".join(str(int(c, 36)) for c in body + "ZZ00")) % 97
        candidate = f"ZZ{check:02d}{body}"
        info = iban.validate_iban(candidate)
        self.assertIsNotNone(info)
        self.assertEqual(info.confidence, Confidence.MEDIUM)

    def test_find_ibans_trims_swallowed_words_and_offsets(self):
        text = "IBAN: GR16 0110 1250 0000 0001 2300 695 and then DE89370400440532013000, thanks"
        found = iban.find_ibans(text)
        self.assertEqual([i.iban for _s, _e, i in found], ["GR1601101250000000012300695", "DE89370400440532013000"])
        for s, e, info in found:
            self.assertEqual(text[s:e].replace(" ", ""), info.iban)
        self.assertEqual(iban.find_ibans("GR16 0110 1250 0000 0001 2300 696"), [])


class CryptoTests(unittest.TestCase):
    def test_keccak_vectors(self):
        self.assertEqual(crypto.keccak256(b"").hex(), "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470")
        self.assertEqual(crypto.keccak256(b"abc").hex(), "4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45")
        long = crypto.keccak256(b"a" * 1000)  # multi-block input (rate = 136)
        self.assertEqual(len(long), 32)
        self.assertEqual(crypto.keccak256(b"a" * 135).hex(), crypto.keccak256(b"a" * 135).hex())
        self.assertNotEqual(crypto.keccak256(b"a" * 135), crypto.keccak256(b"a" * 136))

    def test_eip55(self):
        for addr in ("0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed", "0xfB6916095ca1df60bB79Ce92cE3Ea74c37c5d359",
                     "0xdbF03B407c01E7cD3CBea99509d93f8DDDC8C6FB", "0xD1220A0cf47c7B9Be7A2E6BA89F429762e7b9aDb"):
            w = crypto.validate_wallet(addr)
            self.assertEqual((w.chain, w.confidence, w.note), ("eth", Confidence.HIGH, "eip55_ok"), addr)
            self.assertEqual(w.address, addr.lower())
        self.assertIsNone(crypto.validate_wallet("0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAEd"))  # wrong case on one letter
        lower = crypto.validate_wallet("0x5aaeb6053f3e94c9b9a09f33669435e7ef1beaed")
        self.assertEqual((lower.confidence, lower.note), (Confidence.MEDIUM, "no_checksum_case"))
        self.assertIsNone(crypto.validate_wallet("0x123"))

    def test_bitcoin_legacy(self):
        for addr, kind in (("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa", "p2pkh"), ("3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy", "p2sh")):
            w = crypto.validate_wallet(addr)
            self.assertEqual((w.chain, w.kind), ("btc", kind))
        self.assertIsNone(crypto.validate_wallet("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNb"))

    def test_bitcoin_bech32(self):
        self.assertEqual(crypto.validate_wallet("bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq").kind, "segwit_v0")
        self.assertEqual(crypto.validate_wallet("BC1QW508D6QEJXTDG4Y5R3ZARVARY0C5XW7KV8F3T4").address,
                         "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4")
        self.assertEqual(crypto.validate_wallet("bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqzk5jj0").kind, "taproot")
        self.assertIsNone(crypto.validate_wallet("bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdp"))  # bad checksum
        self.assertIsNone(crypto.validate_wallet("Bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq"))  # mixed case
        self.assertIsNone(crypto.validate_wallet("tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx"))  # testnet not supported

    def test_bech32_roundtrip(self):
        data = [0] + crypto._convertbits(list(range(20)), 8, 5, True)
        enc = crypto.bech32_encode("bc", data)
        self.assertEqual(crypto.bech32_decode(enc)[:2], ("bc", data))
        enc_m = crypto.bech32_encode("bc", [1] + crypto._convertbits(list(range(32)), 8, 5, True), "bech32m")
        self.assertEqual(crypto.bech32_decode(enc_m)[2], "bech32m")
        self.assertEqual(crypto.validate_wallet(enc_m).kind, "taproot")

    def test_base58_roundtrip(self):
        rng = random.Random(1)
        for _ in range(50):
            raw = bytes(rng.randrange(256) for _ in range(rng.randrange(1, 40)))
            self.assertEqual(crypto.b58decode(crypto.b58encode(raw)), raw)
        zeros = b"\x00\x00\x01\x02"
        self.assertEqual(crypto.b58decode(crypto.b58encode(zeros)), zeros)
        self.assertIsNone(crypto.b58decode("0OIl"))  # characters outside the alphabet

    def test_tron(self):
        addr = crypto.b58check_encode(bytes([0x41]) + bytes(range(20)))
        self.assertTrue(addr.startswith("T") and len(addr) == 34)
        w = crypto.validate_wallet(addr)
        self.assertEqual((w.chain, w.kind), ("trx", "tron"))
        self.assertIsNone(crypto.validate_wallet(addr[:-1] + ("A" if addr[-1] != "A" else "B")))

    def test_find_wallets_in_text(self):
        text = ("send USDT to TXYZ... no; real: 0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed, "
                "or 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa. Not: 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNb")
        self.assertEqual([w.chain for _s, _e, w in crypto.find_wallets(text)], ["eth", "btc"])


class AccountTests(unittest.TestCase):
    def test_emails(self):
        e = accounts.parse_email("John.Doe+tag@Example.COM")
        self.assertEqual((e.address, e.domain, e.alias_key), ("john.doe+tag@example.com", "example.com", None))
        g = accounts.parse_email("J.o.h.n+spam@gmail.com")
        self.assertEqual(g.alias_key, "john@gmail.com")
        self.assertEqual(accounts.parse_email("user[at]example[.]com").address, "user@example.com")
        for bad in ("icon@2x.png", "a..b@x.com", ".a@x.com", "no-at.example.com", "a@b", "a@@b.com", "a@1.2.3.4"):
            with self.assertRaises(ValidationError, msg=bad):
                accounts.parse_email(bad)

    def test_find_emails(self):
        text = "write to a.b@example.com, or c_d@sub.example.co.uk. Also x[at]evil[.]top (not @handle)"
        self.assertEqual([r for _s, _e, r in accounts.find_emails(text)],
                         ["a.b@example.com", "c_d@sub.example.co.uk", "x[at]evil[.]top"])

    def test_handles(self):
        text = "IG: john_doe99, insta - @maria.k and @plain_mention. email a@b.com, url x.com/@no"
        found = {(raw, plat) for _s, _e, raw, plat in accounts.find_handles(text)}
        self.assertIn(("john_doe99", "instagram"), found)
        self.assertIn(("maria.k", "instagram"), found)
        self.assertIn(("@plain_mention", "unknown"), found)
        self.assertFalse(any(raw in ("@b", "@no") for raw, _ in found))


class ExtractTests(unittest.TestCase):
    TEXT = (
        "Στείλε στο IBAN GR16 0110 1250 0000 0001 2300 695 ή +30 694 123 4567. "
        "Link: hxxps://l[.]instagram[.]com/?u=https%3A%2F%2Fevil.top%2Fpay&e=x "
        "wa.me not-a-url https://wa.me/306941234567 insta: scam_acc https://instagram.com/fake.shop/ "
        "ETH 0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed mail boss[at]evil[.]top ip 8.8.8.8"
    )

    def setUp(self):
        self.m = extract_indicators(self.TEXT)

    def test_all_types_found(self):
        self.assertEqual(values(self.m, IndicatorType.IBAN), ["GR1601101250000000012300695"])
        self.assertIn("+306941234567", values(self.m, IndicatorType.PHONE))
        self.assertIn("https://evil.top/pay", values(self.m, IndicatorType.URL))
        self.assertIn("eth:0x5aaeb6053f3e94c9b9a09f33669435e7ef1beaed", values(self.m, IndicatorType.WALLET))
        self.assertEqual(values(self.m, IndicatorType.EMAIL), ["boss@evil.top"])
        self.assertEqual(values(self.m, IndicatorType.IP), ["8.8.8.8"])

    def test_derived_indicators(self):
        derived = values(self.m, derived=True)
        for expected in ("evil.top", "l.instagram.com", "instagram:fake.shop", "+306941234567"):
            self.assertIn(expected, derived)
        # the wa.me link produced the same phone as the +30 text number, with different provenance
        phone_matches = [x for x in self.m if x.type == IndicatorType.PHONE and x.value == "+306941234567"]
        self.assertEqual({x.derived for x in phone_matches}, {True, False})

    def test_iban_digits_are_not_reported_as_phone(self):
        text = "IBAN GR16 0110 1250 0000 0001 2300 695"
        self.assertEqual(values(extract_indicators(text), IndicatorType.PHONE), [])

    def test_offsets_point_at_raw_text(self):
        for m in self.m:
            if not m.derived:
                self.assertEqual(self.TEXT[m.start:m.end], m.raw if m.type != IndicatorType.IBAN else self.TEXT[m.start:m.end])
        iban_match = next(m for m in self.m if m.type == IndicatorType.IBAN)
        self.assertTrue(self.TEXT[iban_match.start:iban_match.end].startswith("GR16"))

    def test_handle_platforms(self):
        handles = {m.value: m.attrs["platform"] for m in self.m if m.type == IndicatorType.HANDLE}
        self.assertEqual(handles["instagram:scam_acc"], "instagram")
        self.assertIn("instagram:fake.shop", handles)

    def test_empty_and_plain_text(self):
        self.assertEqual(extract_indicators(""), [])
        self.assertEqual(extract_indicators("Hello, how are you today? Nothing to see here."), [])

    def test_deterministic_and_sorted(self):
        a, b = extract_indicators(self.TEXT), extract_indicators(self.TEXT)
        self.assertEqual(a, b)
        self.assertEqual([m.start for m in a], sorted(m.start for m in a))

    def test_ipv6_forms_and_false_positives(self):
        def ips(text):
            return sorted(m.value for m in extract_indicators(text) if m.type == IndicatorType.IP)

        self.assertEqual(ips("at 2606:4700:4700::1111, and 2001:db8:0:0:0:0:0:1."), ["2001:db8::1", "2606:4700:4700::1111"])
        self.assertEqual(ips("address 2001:db8::1: next"), ["2001:db8::1"])
        self.assertEqual(ips("loopback ::1 here"), [])  # too short to be a meaningful indicator
        for text in ("meeting at 12:34:56 sharp", "mac aa:bb:cc:dd:ee:ff", "std::vector<int>", "just :: here", "a::b",
                     "ratio 3:2:1", "time 10:30", "http://example.com:8080/x"):
            self.assertEqual(ips(text), [], text)
        global_ip = next(m for m in extract_indicators("x 2606:4700:4700::1111 y") if m.type == IndicatorType.IP)
        self.assertEqual(global_ip.confidence, Confidence.MEDIUM)
        self.assertEqual(next(m for m in extract_indicators("x fe80::1234 y") if m.type == IndicatorType.IP).confidence, Confidence.LOW)

    def test_adversarial_inputs_are_fast(self):
        n = 200_000
        nasty = {
            "letters": "a" * n, "digits": "1" * n, "dots": "a." * (n // 2), "brackets": "[.]" * (n // 3),
            "ats": "@" * n, "at_words": "@a" * (n // 2), "hex": "0x" + "a" * n, "plus": "+" * n,
            "scheme": "http://" * (n // 7), "mixed": "a1.b2@" * (n // 6), "spaces": "1 " * (n // 2),
            "iban_like": "GR16 " * (n // 5), "b58": "1" * n, "bc1": "bc1" + "q" * n, "long_label": "a" * 70 + "." + "b" * 70 + ".com " * 2000,
        }
        for name, text in nasty.items():
            started = time.perf_counter()
            extract_indicators(text)
            elapsed = time.perf_counter() - started
            self.assertLess(elapsed, 5.0, f"{name} took {elapsed:.1f}s")


if __name__ == "__main__":
    unittest.main()
