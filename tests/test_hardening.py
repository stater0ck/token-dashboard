"""Host-header guard (DNS rebinding) and vendored-asset integrity pins."""
import http.client
import http.server
import json
import os
import socket
import sqlite3
import tempfile
import threading
import unittest
from pathlib import Path

from token_dashboard import vendor
from token_dashboard.db import init_db
from token_dashboard.server import (
    WEB_ROOT, _hostname, _within, allowed_hostnames, build_handler,
)


def _free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


class HostnameParsingTests(unittest.TestCase):
    def test_strips_port(self):
        self.assertEqual(_hostname("127.0.0.1:8080"), "127.0.0.1")
        self.assertEqual(_hostname("localhost:8080"), "localhost")

    def test_bare_host(self):
        self.assertEqual(_hostname("localhost"), "localhost")

    def test_ipv6_bracketed(self):
        self.assertEqual(_hostname("[::1]:8080"), "::1")
        self.assertEqual(_hostname("[::1]"), "::1")

    def test_bare_ipv6_literal_is_not_split_as_host_port(self):
        self.assertEqual(_hostname("::1"), "::1")

    def test_case_and_whitespace_normalized(self):
        self.assertEqual(_hostname("  LOCALHOST:8080 "), "localhost")

    def test_empty(self):
        self.assertEqual(_hostname(""), "")
        self.assertEqual(_hostname(None), "")


class AllowedHostnamesTests(unittest.TestCase):
    def setUp(self):
        self._saved = os.environ.pop("TOKEN_DASHBOARD_ALLOWED_HOSTS", None)

    def tearDown(self):
        os.environ.pop("TOKEN_DASHBOARD_ALLOWED_HOSTS", None)
        if self._saved is not None:
            os.environ["TOKEN_DASHBOARD_ALLOWED_HOSTS"] = self._saved

    def test_loopback_always_allowed(self):
        allowed = allowed_hostnames("127.0.0.1")
        self.assertIn("127.0.0.1", allowed)
        self.assertIn("localhost", allowed)
        self.assertIn("::1", allowed)

    def test_wildcard_bind_does_not_widen_allowlist(self):
        self.assertEqual(allowed_hostnames("0.0.0.0"), allowed_hostnames("127.0.0.1"))
        self.assertEqual(allowed_hostnames("::"), allowed_hostnames("127.0.0.1"))

    def test_explicit_bind_address_is_allowed(self):
        self.assertIn("192.168.1.20", allowed_hostnames("192.168.1.20"))

    def test_env_var_adds_names(self):
        os.environ["TOKEN_DASHBOARD_ALLOWED_HOSTS"] = "dash.local, 192.168.1.20:8080"
        allowed = allowed_hostnames("0.0.0.0")
        self.assertIn("dash.local", allowed)
        self.assertIn("192.168.1.20", allowed)

    def test_attacker_hostname_never_allowed(self):
        self.assertNotIn("attacker.example.com", allowed_hostnames("127.0.0.1"))


class WebRootContainmentTests(unittest.TestCase):
    def test_sibling_with_shared_prefix_is_rejected(self):
        root = Path("/srv/app/web")
        self.assertFalse(_within(Path("/srv/app/web-assets/keys.txt"), root))
        self.assertFalse(_within(Path("/srv/app/webhooks/config.json"), root))

    def test_descendants_allowed(self):
        root = Path("/srv/app/web")
        self.assertTrue(_within(Path("/srv/app/web/routes/overview.js"), root))
        self.assertTrue(_within(root, root))

    def test_parent_rejected(self):
        self.assertFalse(_within(Path("/srv/app/pricing.json"), Path("/srv/app/web")))


class GuardedServerTests(unittest.TestCase):
    """End-to-end: the guard runs before routing, on GET and POST alike."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.db = os.path.join(self.tmp, "t.db")
        init_db(self.db)
        with sqlite3.connect(self.db) as c:
            c.execute(
                "INSERT INTO messages (uuid, parent_uuid, session_id, project_slug, type,"
                " timestamp, model, input_tokens, output_tokens, cache_read_tokens,"
                " cache_create_5m_tokens, cache_create_1h_tokens, prompt_text, prompt_chars)"
                " VALUES ('u',NULL,'s','secret-project','user','2026-04-19T00:00:00Z',NULL,"
                "0,0,0,0,0,'my private prompt',18)"
            )
            c.commit()
        self.port = _free_port()
        H = build_handler(self.db, projects_dir="/nonexistent")
        self.httpd = http.server.HTTPServer(("127.0.0.1", self.port), H)
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()

    def tearDown(self):
        self.httpd.shutdown()
        self.httpd.server_close()

    def _request(self, method, path, headers=None, body=None):
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=5)
        try:
            conn.putrequest(method, path, skip_host=True, skip_accept_encoding=True)
            for k, v in (headers or {}).items():
                conn.putheader(k, v)
            if body is not None:
                conn.putheader("Content-Length", str(len(body)))
            conn.endheaders(body.encode() if body else None)
            resp = conn.getresponse()
            return resp.status, resp.read()
        finally:
            conn.close()

    def test_loopback_host_is_served(self):
        status, body = self._request("GET", "/api/prompts", {"Host": f"127.0.0.1:{self.port}"})
        self.assertEqual(status, 200)
        self.assertIsInstance(json.loads(body), list)

    def test_localhost_host_is_served(self):
        status, _ = self._request("GET", "/api/overview", {"Host": f"localhost:{self.port}"})
        self.assertEqual(status, 200)

    def test_rebound_host_is_refused(self):
        status, body = self._request(
            "GET", "/api/prompts", {"Host": "attacker.example.com"}
        )
        self.assertEqual(status, 421)
        self.assertNotIn(b"my private prompt", body)

    def test_rebound_host_refused_on_session_detail(self):
        status, body = self._request("GET", "/api/sessions/s", {"Host": "evil.test"})
        self.assertEqual(status, 421)
        self.assertNotIn(b"secret-project", body)

    def test_missing_host_is_refused(self):
        status, _ = self._request("GET", "/api/overview")
        self.assertEqual(status, 421)

    def test_static_files_are_guarded_too(self):
        status, _ = self._request("GET", "/", {"Host": "attacker.example.com"})
        self.assertEqual(status, 421)

    def test_cross_origin_post_is_refused(self):
        """The CSRF case: a simple text/plain POST needs no preflight."""
        status, _ = self._request(
            "POST", "/api/plan",
            {
                "Host": f"127.0.0.1:{self.port}",
                "Origin": "https://evil.example.com",
                "Content-Type": "text/plain",
            },
            body=json.dumps({"plan": "max20"}),
        )
        self.assertEqual(status, 403)
        status, body = self._request("GET", "/api/plan", {"Host": f"127.0.0.1:{self.port}"})
        self.assertEqual(json.loads(body)["plan"], "api", "plan must be unchanged")

    def test_null_origin_is_refused(self):
        status, _ = self._request(
            "POST", "/api/tips/dismiss",
            {"Host": f"127.0.0.1:{self.port}", "Origin": "null"},
            body="{}",
        )
        self.assertEqual(status, 403)

    def test_same_origin_post_still_works(self):
        status, _ = self._request(
            "POST", "/api/plan",
            {
                "Host": f"127.0.0.1:{self.port}",
                "Origin": f"http://127.0.0.1:{self.port}",
                "Content-Type": "application/json",
            },
            body=json.dumps({"plan": "max20"}),
        )
        self.assertEqual(status, 200)

    def test_cross_origin_get_scan_is_refused(self):
        """GET /api/scan has side effects, so it must not be drive-by callable."""
        status, _ = self._request(
            "GET", "/api/scan",
            {"Host": f"127.0.0.1:{self.port}", "Origin": "https://evil.example.com"},
        )
        self.assertEqual(status, 403)


class VendorPinTests(unittest.TestCase):
    def setUp(self):
        vendor._digest_cache.clear()
        vendor._lock_cache.clear()

    def test_lock_file_lists_echarts(self):
        lock = vendor.load_lock()
        self.assertIn("echarts.min.js", lock)
        entry = lock["echarts.min.js"]
        self.assertEqual(len(entry["sha256"]), 64)
        self.assertEqual(entry["version"], "5.5.0")

    def test_every_pinned_asset_matches(self):
        errors = vendor.verify_all(WEB_ROOT)
        self.assertEqual(errors, {}, f"vendored assets changed: {errors}")

    def test_pinned_size_matches(self):
        for rel, entry in vendor.load_lock().items():
            if "bytes" in entry:
                self.assertEqual((WEB_ROOT / rel).stat().st_size, entry["bytes"], rel)

    def test_unpinned_paths_pass_through(self):
        self.assertIsNone(vendor.check("routes/overview.js", WEB_ROOT / "routes" / "overview.js"))

    def test_modified_asset_is_detected(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "echarts.min.js").write_bytes(b"/* swapped bundle */")
            errors = vendor.verify_all(root)
            self.assertIn("echarts.min.js", errors)
            self.assertIn("does not match the digest pinned", errors["echarts.min.js"])

    def test_missing_asset_is_detected(self):
        with tempfile.TemporaryDirectory() as tmp:
            errors = vendor.verify_all(Path(tmp))
            self.assertIn("echarts.min.js", errors)
            self.assertIn("missing", errors["echarts.min.js"])

    def test_server_refuses_to_serve_a_changed_bundle(self):
        """The runtime half of the pin: a swapped file 500s instead of loading."""
        # Pin echarts to a digest the real file cannot have, so the on-disk
        # bytes are hashed for real and then rejected.
        vendor._lock_cache[str(vendor.LOCK_PATH)] = {"echarts.min.js": {"sha256": "0" * 64}}
        try:
            port = _free_port()
            H = build_handler(":memory:", projects_dir="/nonexistent")
            httpd = http.server.HTTPServer(("127.0.0.1", port), H)
            threading.Thread(target=httpd.serve_forever, daemon=True).start()
            try:
                conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
                conn.request("GET", "/web/echarts.min.js")
                resp = conn.getresponse()
                payload = resp.read()
                conn.close()
                self.assertEqual(resp.status, 500)
                self.assertIn(b"vendor.lock.json", payload)
            finally:
                httpd.shutdown()
                httpd.server_close()
        finally:
            vendor._digest_cache.clear()
            vendor._lock_cache.clear()


if __name__ == "__main__":
    unittest.main()
