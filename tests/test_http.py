import json
import socket
import tempfile
import unittest
from pathlib import Path

from aletheia import errors, http
from aletheia.http import HttpClient, HttpPolicy

from helpers import TestSite, make_client, make_policy, make_self_signed


class PublicIpTests(unittest.TestCase):
    def test_classification(self):
        public = ["8.8.8.8", "93.184.216.34", "2606:4700:4700::1111"]
        private = ["127.0.0.1", "10.0.0.1", "172.16.5.4", "192.168.1.1", "169.254.169.254", "100.64.0.1", "0.0.0.0",
                   "224.0.0.1", "::1", "fe80::1", "fc00::1", "2001:db8::1", "::ffff:127.0.0.1", "::ffff:10.1.2.3",
                   "255.255.255.255", "192.0.2.1"]
        for ip in public:
            self.assertTrue(http.is_public_ip(ip), ip)
        for ip in private:
            self.assertFalse(http.is_public_ip(ip), ip)


class FetchTests(unittest.TestCase):
    def setUp(self):
        self.site = TestSite()
        self.site.__enter__()
        self.addCleanup(self.site.__exit__, None, None, None)

    def url(self, path):
        return self.site.base + path

    def test_basic_get_collects_evidence_fields(self):
        client = make_client()
        res = client.get(self.url("/ok"), check_robots=False)
        self.assertEqual((res.status, res.content_type), (200, "text/html"))
        self.assertIn(b"GR16 0110", res.body)
        self.assertEqual(res.remote_ip, "127.0.0.1")
        self.assertEqual(res.final_url, self.url("/ok"))
        self.assertEqual(len(res.chain), 1)
        self.assertEqual(res.body_sha256, __import__("hashlib").sha256(res.body).hexdigest())
        self.assertTrue(res.started_at.endswith("Z"))
        self.assertIsNone(res.tls)
        self.assertEqual(res.header("content-TYPE"), "text/html; charset=utf-8")

    def test_loopback_is_blocked_by_default_and_never_contacted(self):
        client = HttpClient(HttpPolicy(respect_robots=False, min_interval=0))
        with self.assertRaises(errors.BlockedTargetError) as cm:
            client.get(self.url("/ok"))
        self.assertEqual(cm.exception.params["ip"], "127.0.0.1")
        self.assertEqual(self.site.hits, [])

    def test_private_ranges_blocked_even_through_dns(self):
        for ip in ("10.0.0.5", "169.254.169.254", "::1", "192.168.0.1"):
            client = HttpClient(HttpPolicy(respect_robots=False, min_interval=0), resolver=lambda h, p, ip=ip: [ip])
            with self.assertRaises(errors.BlockedTargetError, msg=ip):
                client.get("http://innocent.example/")

    def test_mixed_public_and_private_answers_are_blocked(self):
        client = HttpClient(HttpPolicy(respect_robots=False), resolver=lambda h, p: ["93.184.216.34", "127.0.0.1"])
        with self.assertRaises(errors.BlockedTargetError):
            client.get("http://rebind.example/")

    def test_connection_is_pinned_to_the_resolved_ip_and_keeps_host_header(self):
        calls = []

        def resolver(host, port):
            calls.append(host)
            return ["127.0.0.1"]

        client = HttpClient(make_policy(respect_robots=False), resolver=resolver, sleep=lambda s: None)
        res = client.get(f"http://pinned.test:{self.site.port}/headers")
        body = json.loads(res.body)
        self.assertEqual(body["host"], f"pinned.test:{self.site.port}")
        self.assertEqual(calls, ["pinned.test"])  # resolved exactly once per request

    def test_no_cookies_credentials_and_honest_user_agent(self):
        client = make_client(respect_robots=False)
        body = json.loads(client.get(self.url("/headers")).body)
        self.assertTrue(body["ua"].startswith("Aletheia/"))
        self.assertIsNone(body["cookie"])
        self.assertIsNone(body["auth"])
        body = json.loads(client.get(self.url("/headers"), user_agent="Mozilla/5.0 (X)").body)
        self.assertEqual(body["ua"], "Mozilla/5.0 (X)")

    def test_unsupported_urls_are_rejected_before_any_io(self):
        client = make_client()
        for bad in ("file:///etc/passwd", "ftp://example.com/x", "gopher://x", "http://", "not a url",
                    "http://user:pw@example.com/", "javascript:alert(1)", "http://[::1"):
            with self.assertRaises(errors.ValidationError, msg=bad):
                client.get(bad)
        self.assertEqual(self.site.hits, [])

    def test_redirects_are_followed_and_recorded(self):
        res = make_client().get(self.url("/redir1"), check_robots=False)
        self.assertEqual((res.status, res.final_url, res.requested_url), (200, self.url("/ok"), self.url("/redir1")))
        self.assertEqual([h.status for h in res.chain], [302, 200])
        self.assertEqual(res.chain[0].location, "/ok")

    def test_redirect_to_cloud_metadata_address_is_blocked(self):
        with self.assertRaises(errors.BlockedTargetError) as cm:
            make_client().get(self.url("/redir-meta"), check_robots=False)
        self.assertEqual(cm.exception.params["ip"], "169.254.169.254")

    def test_redirect_loop(self):
        with self.assertRaises(errors.TooManyRedirectsError):
            make_client(max_redirects=3).get(self.url("/loop"), check_robots=False)
        self.assertEqual(self.site.counts["/loop"], 4)

    def test_size_limit(self):
        client = make_client(max_bytes=1024 * 1024)
        with self.assertRaises(errors.ResponseTooLargeError):
            client.get(self.url("/big"), check_robots=False)
        self.assertEqual(len(client.get(self.url("/big"), max_bytes=3 * 1024 * 1024, check_robots=False).body), 2 * 1024 * 1024)

    def test_gzip_is_decoded_and_bombs_are_capped(self):
        client = make_client(max_bytes=1024 * 1024)
        res = client.get(self.url("/gzip"), check_robots=False)
        self.assertEqual((res.body, res.decoded_gzip), (b"compressed hello", True))
        with self.assertRaises(errors.ResponseTooLargeError):
            client.get(self.url("/gzipbomb"), check_robots=False)

    def test_retries_honour_retry_after_and_stop_when_ok(self):
        client = make_client()
        res = client.get(self.url("/flaky"), check_robots=False)
        self.assertEqual((res.status, res.body, res.attempts), (200, b"finally", 3))
        self.assertEqual(client.sleeps, [1.0, 1.0])

    def test_persistent_503_returns_last_response_after_bounded_attempts(self):
        client = make_client(max_attempts=3)
        res = client.get(self.url("/always503"), check_robots=False)
        self.assertEqual((res.status, res.attempts), (503, 3))
        self.assertEqual(self.site.counts["/always503"], 3)
        self.assertEqual(client.sleeps, [2.0, 2.0])

    def test_retry_after_is_capped(self):
        client = make_client(retry_after_cap=5.0)
        self.assertEqual(client._retry_delay(1, "3600"), 5.0)
        self.assertEqual(client._retry_delay(1, "not-a-number"), 0.0)
        self.assertEqual(client._retry_delay(1, None), 0.25)  # jitter 0.5 * base 0.5
        self.assertEqual(client._retry_delay(10, None), 4.0)  # 0.5 * cap 8

    def test_transport_errors_are_retried_then_raised(self):
        probe = socket.socket()
        probe.bind(("127.0.0.1", 0))
        closed_port = probe.getsockname()[1]
        probe.close()  # nothing listens on this port any more
        client = make_client(max_attempts=3)
        with self.assertRaises(errors.TransportError):
            client.get(f"http://127.0.0.1:{closed_port}/x", check_robots=False)
        self.assertEqual(len(client.sleeps), 2)

    def test_timeout(self):
        client = make_client(timeout=0.3, max_attempts=1)
        with self.assertRaises(errors.TransportError) as cm:
            client.get(self.url("/slow"), check_robots=False)
        self.assertIn("timeout", cm.exception.detail)

    def test_rate_limit_waits_between_requests_to_the_same_host(self):
        now = [100.0]
        slept = []
        client = HttpClient(make_policy(min_interval=2.0, respect_robots=False), sleep=lambda s: (slept.append(s), now.__setitem__(0, now[0] + s)),
                            monotonic=lambda: now[0])
        client.get(self.url("/text"))
        now[0] += 0.5
        client.get(self.url("/text"))
        self.assertEqual(slept, [1.5])


class RobotsTests(unittest.TestCase):
    def setUp(self):
        self.site = TestSite()
        self.site.__enter__()
        self.addCleanup(self.site.__exit__, None, None, None)

    def test_disallowed_path_is_refused_and_not_fetched(self):
        client = make_client(respect_robots=True)
        with self.assertRaises(errors.RobotsDisallowedError):
            client.get(self.site.base + "/private")
        self.assertNotIn("/private", self.site.hits)
        self.assertEqual(client.get(self.site.base + "/public").status, 200)
        self.assertEqual(self.site.counts["/robots.txt"], 1)  # cached per origin

    def test_override_per_call(self):
        client = make_client(respect_robots=True)
        self.assertEqual(client.get(self.site.base + "/private", check_robots=False).status, 200)

    def test_missing_robots_allows_everything(self):
        self.site.robots_status = 404
        self.assertEqual(make_client(respect_robots=True).get(self.site.base + "/private").status, 200)

    def test_server_error_or_unreachable_robots_means_disallow(self):
        self.site.robots_status = 500
        with self.assertRaises(errors.RobotsDisallowedError):
            make_client(respect_robots=True, max_attempts=1).get(self.site.base + "/public")

    def test_robots_uses_product_token_of_user_agent(self):
        self.site.robots = "User-agent: Aletheia\nDisallow: /public\n\nUser-agent: *\nAllow: /\n"
        client = make_client(respect_robots=True)
        with self.assertRaises(errors.RobotsDisallowedError):
            client.get(self.site.base + "/public")


@unittest.skipUnless(make_self_signed(Path(tempfile.gettempdir())) is not None, "openssl CLI not available")
class TlsTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.site = TestSite(tls_cert=make_self_signed(Path(self._tmp.name)))
        self.site.__enter__()
        self.addCleanup(self.site.__exit__, None, None, None)

    def test_untrusted_certificate_is_refused_by_default(self):
        with self.assertRaises(errors.TlsError):
            make_client().get(self.site.base + "/text", check_robots=False)

    def test_unverified_capture_records_the_certificate(self):
        res = make_client().get(self.site.base + "/text", verify_tls=False, check_robots=False)
        self.assertEqual(res.status, 200)
        self.assertEqual(len(res.tls["cert_sha256"]), 64)
        self.assertTrue(res.tls["version"].startswith("TLS"))


if __name__ == "__main__":
    unittest.main()
