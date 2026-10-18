import json
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path

from aletheia import errors, rdap
from aletheia.capture import capture_url
from aletheia.http import HttpResult

from helpers import TestSite, VaultTestCase, make_client, make_self_signed

BOOTSTRAP = {"version": "1.0", "services": [
    [["com", "net"], ["http://insecure.example/", "https://rdap.verisign.example/com/v1/"]],
    [["top"], ["https://rdap.top.example/"]],
    [["xn--p1ai"], ["https://rdap.cctld.example/"]],
]}

RDAP_RECORD = {
    "objectClassName": "domain", "handle": "123_DOMAIN_COM-VRSN", "ldhName": "EVIL-SHOP.TOP",
    "status": ["client transfer prohibited"],
    "events": [{"eventAction": "registration", "eventDate": "2026-10-10T08:00:00Z"},
               {"eventAction": "last changed", "eventDate": "2026-10-12T09:30:00Z"},
               {"eventAction": "expiration", "eventDate": "2027-10-10T08:00:00Z"}],
    "nameservers": [{"ldhName": "NS2.Example.NET"}, {"ldhName": "ns1.example.net"}],
    "entities": [
        {"roles": ["registrar"], "vcardArray": ["vcard", [["version", {}, "text", "4.0"], ["fn", {}, "text", "Example Registrar, Inc."]]]},
        {"roles": ["registrant"], "vcardArray": ["vcard", [["version", {}, "text", "4.0"], ["fn", {}, "text", "REDACTED FOR PRIVACY"]]]},
    ],
}


class StubHttp:
    """Stands in for HttpClient: maps URL -> (status, body bytes)."""

    def __init__(self, routes):
        self.routes, self.calls = routes, []

    def get(self, url, **kw):
        self.calls.append(url)
        status, body = self.routes[url] if url in self.routes else (404, b"")
        return HttpResult(requested_url=url, final_url=url, status=status, reason="", headers=[], body=body)


def routes(**extra):
    r = {rdap.BOOTSTRAP_URL: (200, json.dumps(BOOTSTRAP).encode()),
         "https://rdap.top.example/domain/evil-shop.top": (200, json.dumps(RDAP_RECORD).encode())}
    r.update(extra)
    return r


class ParseTests(unittest.TestCase):
    def test_bootstrap_prefers_https(self):
        m = rdap.parse_bootstrap(BOOTSTRAP)
        self.assertEqual(m["com"], "https://rdap.verisign.example/com/v1/")
        self.assertEqual(m["top"], "https://rdap.top.example/")
        self.assertEqual(rdap.parse_bootstrap({}), {})
        self.assertEqual(rdap.parse_bootstrap({"services": [["bad"], [["x"], []]]}), {})

    def test_parse_domain(self):
        d = rdap.parse_domain(RDAP_RECORD, "evil-shop.top", "https://u")
        self.assertEqual((d.registered, d.expires, d.registrar), ("2026-10-10T08:00:00Z", "2027-10-10T08:00:00Z", "Example Registrar, Inc."))
        self.assertEqual(d.nameservers, ["ns1.example.net", "ns2.example.net"])
        self.assertTrue(d.registrant_redacted)
        self.assertEqual(rdap.domain_age_days(d, datetime(2026, 10, 14, tzinfo=timezone.utc)), 3)
        self.assertEqual(rdap.domain_age_days(d, datetime(2026, 1, 1, tzinfo=timezone.utc)), 0)  # never negative

    def test_visible_registrant_is_reported_as_such(self):
        rec = json.loads(json.dumps(RDAP_RECORD))
        rec["entities"][1]["vcardArray"][1][1][3] = "Some Company Ltd"
        self.assertFalse(rdap.parse_domain(rec, "x.top").registrant_redacted)

    def test_tolerates_sparse_and_odd_records(self):
        d = rdap.parse_domain({"entities": ["junk", {"roles": ["registrar"]}], "events": [None], "nameservers": [1, {}, {"ldhName": ""}]}, "x.top")
        self.assertEqual((d.registrar, d.registered, d.nameservers), (None, None, []))
        self.assertIsNone(rdap.domain_age_days(d, datetime(2026, 1, 1, tzinfo=timezone.utc)))


class ClientTests(VaultTestCase):
    def test_lookup_success_and_bootstrap_cache(self):
        cache = self.tmp_path("cache")
        http1 = StubHttp(routes())
        info, raw = rdap.RdapClient(http1, cache).lookup("WWW.Evil-Shop.top")
        self.assertEqual(info.domain, "evil-shop.top")
        self.assertEqual(json.loads(raw)["handle"], "123_DOMAIN_COM-VRSN")
        self.assertEqual(http1.calls, [rdap.BOOTSTRAP_URL, "https://rdap.top.example/domain/evil-shop.top"])
        self.assertTrue((cache / "rdap-bootstrap.json").is_file())
        http2 = StubHttp(routes())
        rdap.RdapClient(http2, cache).lookup("evil-shop.top")
        self.assertEqual(http2.calls, ["https://rdap.top.example/domain/evil-shop.top"])  # bootstrap came from cache

    def test_not_registered(self):
        http = StubHttp(routes(**{"https://rdap.top.example/domain/free-name.top": (404, b"{}")}))
        info, _ = rdap.RdapClient(http).lookup("free-name.top")
        self.assertFalse(info.found)

    def test_errors(self):
        client = rdap.RdapClient(StubHttp(routes()))
        with self.assertRaises(errors.NoRdapServiceError) as cm:
            client.lookup("example.gr")
        self.assertEqual(cm.exception.params["tld"], "gr")
        with self.assertRaises(errors.ValidationError):
            client.lookup("192.0.2.1")
        with self.assertRaises(errors.ValidationError):
            client.lookup("not a domain")
        bad_status = rdap.RdapClient(StubHttp(routes(**{"https://rdap.top.example/domain/evil-shop.top": (429, b"")})))
        with self.assertRaises(errors.HttpStatusError) as cm2:
            bad_status.lookup("evil-shop.top")
        self.assertEqual(cm2.exception.params["status"], 429)
        garbage = rdap.RdapClient(StubHttp(routes(**{"https://rdap.top.example/domain/evil-shop.top": (200, b"<html>")})))
        with self.assertRaises(errors.NetworkError) as cm3:
            garbage.lookup("evil-shop.top")
        self.assertEqual(cm3.exception.key, "error.net.invalid_response")
        broken_boot = rdap.RdapClient(StubHttp({rdap.BOOTSTRAP_URL: (500, b"")}))
        with self.assertRaises(errors.HttpStatusError):
            broken_boot.lookup("evil-shop.top")

    def test_corrupt_cache_falls_back_to_network(self):
        cache = self.tmp_path("cache2")
        cache.mkdir()
        (cache / "rdap-bootstrap.json").write_text("{broken")
        http = StubHttp(routes())
        rdap.RdapClient(http, cache).lookup("evil-shop.top")
        self.assertEqual(http.calls[0], rdap.BOOTSTRAP_URL)

    def test_idn_domain_uses_punycode_tld(self):
        http = StubHttp({rdap.BOOTSTRAP_URL: (200, json.dumps(BOOTSTRAP).encode()),
                         "https://rdap.cctld.example/domain/xn--e1afmkfd.xn--p1ai": (200, b"{}")})
        info, _ = rdap.RdapClient(http).lookup("пример.рф")
        self.assertEqual(info.domain, "xn--e1afmkfd.xn--p1ai")


class CaptureTests(VaultTestCase):
    def setUp(self):
        super().setUp()
        self.site = TestSite()
        self.site.__enter__()
        self.addCleanup(self.site.__exit__, None, None, None)
        self.case = self.new_case()

    def test_requires_explicit_active_confirmation_and_stores_nothing_otherwise(self):
        with self.assertRaises(errors.ActiveConfirmationRequired):
            capture_url(self.case, self.site.base + "/ok", make_client(), confirm_active=False, ignore_robots=True)
        self.assertEqual(self.site.hits, [])
        self.assertEqual(self.case.list_evidence(), [])
        self.assertNotIn("capture.attempt", [e.action for e in self.case.audit_entries()])

    def test_full_capture(self):
        out = capture_url(self.case, self.site.base + "/redir1", make_client(), confirm_active=True)
        self.assertEqual((out.status, out.final_url, out.tls_verified), (200, self.site.base + "/ok", True))
        body, meta = self.case.get_evidence(out.body.id), self.case.get_evidence(out.meta.id)
        self.assertEqual((body.kind, body.exposure, body.method, body.media_type), ("http_body", "active_target", "http_get", "text/html"))
        self.assertIn(b"GR16 0110", self.case.read_blob(body.sha256))
        doc = json.loads(self.case.read_blob(meta.sha256))
        self.assertEqual(doc["schema"], "aletheia-http-capture/1")
        self.assertEqual(doc["body_sha256"], body.sha256)
        self.assertEqual(doc["status"], 200)
        self.assertEqual([h["status"] for h in doc["redirect_chain"]], [302, 200])
        self.assertEqual(doc["robots"], "respected")
        self.assertTrue(doc["user_agent"].startswith("Aletheia/"))
        self.assertEqual(meta.meta["describes"], body.id)
        types = {(r.type, r.value) for r in self.case.list_indicators()}
        self.assertIn(("iban", "GR1601101250000000012300695"), types)
        self.assertIn(("phone", "+306941234567"), types)
        self.assertIn(("domain", "evil.example.top"), types)
        actions = [e.action for e in self.case.audit_entries()]
        self.assertEqual(actions.count("capture.attempt"), 1)
        self.assertTrue(self.case.verify().ok)

    def test_robots_is_respected_unless_overridden_and_override_is_audited(self):
        with self.assertRaises(errors.RobotsDisallowedError):
            capture_url(self.case, self.site.base + "/private", make_client(), confirm_active=True)
        out = capture_url(self.case, self.site.base + "/private", make_client(), confirm_active=True, ignore_robots=True)
        doc = json.loads(self.case.read_blob(out.meta.sha256))
        self.assertEqual(doc["robots"], "ignored_by_operator")
        attempts = [e.payload for e in self.case.audit_entries() if e.action == "capture.attempt"]
        self.assertEqual([a["ignore_robots"] for a in attempts], [False, True])

    def test_binary_content_is_stored_but_not_indexed(self):
        out = capture_url(self.case, self.site.base + "/png", make_client(), confirm_active=True, ignore_robots=True)
        self.assertEqual(out.indicators, 0)
        self.assertEqual(self.case.get_evidence(out.body.id).media_type, "image/png")

    def test_bad_inputs(self):
        for bad in ("http://user:pw@127.0.0.1/x", "ftp://example.com/x", "file:///etc/passwd", "javascript:alert(1)"):
            with self.assertRaises(errors.ValidationError, msg=bad):
                capture_url(self.case, bad, make_client(), confirm_active=True)
        self.assertEqual(self.case.list_evidence(), [])

    def test_custom_user_agent_is_recorded(self):
        out = capture_url(self.case, self.site.base + "/headers", make_client(), confirm_active=True,
                          ignore_robots=True, user_agent="Mozilla/5.0 (Victim phone)")
        self.assertEqual(json.loads(self.case.read_blob(out.body.sha256))["ua"], "Mozilla/5.0 (Victim phone)")
        self.assertEqual(json.loads(self.case.read_blob(out.meta.sha256))["user_agent"], "Mozilla/5.0 (Victim phone)")

    def test_http_error_pages_are_evidence_too(self):
        out = capture_url(self.case, self.site.base + "/missing", make_client(), confirm_active=True, ignore_robots=True)
        self.assertEqual(out.status, 404)
        self.assertEqual(self.case.read_blob(out.body.sha256), b"nope")


@unittest.skipUnless(make_self_signed(Path(tempfile.gettempdir())) is not None, "openssl CLI not available")
class CaptureTlsTests(VaultTestCase):
    def test_invalid_certificate_flow(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        site = TestSite(tls_cert=make_self_signed(Path(tmp.name)))
        site.__enter__()
        self.addCleanup(site.__exit__, None, None, None)
        case = self.new_case()
        with self.assertRaises(errors.TlsError):
            capture_url(case, site.base + "/ok", make_client(), confirm_active=True, ignore_robots=True)
        out = capture_url(case, site.base + "/ok", make_client(), confirm_active=True, ignore_robots=True,
                          allow_invalid_tls=True)
        self.assertFalse(out.tls_verified)
        doc = json.loads(case.read_blob(out.meta.sha256))
        self.assertFalse(doc["tls_verified"])
        self.assertTrue(doc["tls_error"])
        self.assertEqual(len(doc["tls"]["cert_sha256"]), 64)
        self.assertFalse(case.get_evidence(out.body.id).meta["tls_verified"])


if __name__ == "__main__":
    unittest.main()
