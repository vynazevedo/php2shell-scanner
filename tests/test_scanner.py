import contextlib
import http.server
import io
import json
import tempfile
import threading
import unittest
from pathlib import Path
from unittest.mock import patch
import php2shell_scan as scan

class ScannerTests(unittest.TestCase):
    def test_boundaries(self):
        for branch, fixed in scan.FIXED.items():
            self.assertEqual(scan.classify(f"{branch}.{fixed-1}"), "affected_range")
            self.assertEqual(scan.classify(f"{branch}.{fixed}"), "fixed_range")
            self.assertEqual(scan.classify(f"{branch}.{fixed+1}"), "fixed_range")

    def test_ambiguous_versions(self):
        for version in (None, "", "8.3", "8.3.36RC1", "8.3.36-dev", "PHP/8.3.36", "8.3.36 garbage", "9.0.0", "08.02.035"):
            self.assertEqual(scan.classify(version), "unknown", version)
        self.assertEqual(scan.classify("8.3.20-1+deb12"), "vendor_build_review")
        self.assertEqual(scan.classify("7.4.33"), "legacy_unassessed")

    def test_url_scope(self):
        for url in ("file:///etc/passwd", "https://u:p@example.com", "https://example.com/?token=x", "https://example.com/#x", "https://example.com/\n", "https://example.com:bad/"):
            with self.assertRaises(ValueError): scan.validate_url(url)

    def test_runtime_allowlist(self):
        data = scan.runtime_evidence({"version": "8.3.36", "ini": {"memory_limit": "128M", "password": "secret"}})
        self.assertNotIn("password", data["ini"])

    def test_import_partial_failure(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "inventory.json"
            path.write_text(json.dumps({"pods": [{"uid": "pod1", "runtime_cli": {"version": "8.3.20", "ini": {}}}, {"uid": "pod2", "runtime_cli": None}]}))
            results = scan.imported(path)
            self.assertEqual(len(results), 2)
            self.assertEqual(results[0]["version_status"], "affected_range")
            self.assertIsNotNone(results[1]["error"])
            self.assertTrue(all(r["exploitability"] == "not_tested" for r in results))
            path.write_text('{"pods": []}')
            with self.assertRaises(ValueError): scan.imported(path)

    def test_exit_codes(self):
        good = scan.result("local", "local_cli", {"version": "8.3.36"})
        risk = scan.result("old", "local_cli", {"version": "8.3.35"})
        remote = scan.result("web", "http_head", {"version": "8.3.36"})
        self.assertEqual(scan.exit_status([good]), 0)
        self.assertEqual(scan.exit_status([good, remote]), 2)
        self.assertEqual(scan.exit_status([good, risk]), 1)
        self.assertEqual(scan.exit_status([]), 2)

    def test_comparison(self):
        old = scan.result("same", "local_cli", {"version": "8.3.35"})
        new = scan.result("same", "local_cli", {"version": "8.3.36"})
        change = scan.compare({"results": [old]}, {"results": [new]})[0]
        self.assertEqual(change["after"], "fixed_range")
        self.assertTrue(change["evidence_changed"])
        with self.assertRaises(ValueError): scan.compare({"results": [old, old]}, {"results": []})

    def test_comparison_recomputes_hash(self):
        old = scan.result("same", "local_cli", {"version": "8.3.35"})
        new = dict(old, evidence={"version": "8.3.36"})
        self.assertTrue(scan.compare({"results": [old]}, {"results": [new]})[0]["evidence_changed"])
        for invalid in ([], None, {"results": [None]}, {"results": {}}):
            with self.assertRaises(ValueError): scan.compare(invalid, {"results": []})

    def test_bad_inventory_preserves_other_results(self):
        fixed = scan.result("local-cli", "local_cli", {"version": "8.3.36"})
        out = io.StringIO()
        with patch.object(scan, "local", return_value=fixed), contextlib.redirect_stdout(out):
            self.assertEqual(scan.main(["--local", "--inventory", "/nonexistent/inventory"]), 2)
        self.assertEqual(len(json.loads(out.getvalue())["results"]), 2)

    def test_cli_failure_is_inconclusive(self):
        self.assertIsNotNone(scan.local("/nonexistent/php")["error"])

    def test_head_does_not_follow_redirects_or_read_cookie(self):
        calls = []
        class Handler(http.server.BaseHTTPRequestHandler):
            def do_HEAD(self):
                calls.append(self.path)
                self.send_response(302)
                self.send_header("Location", "/private")
                self.send_header("X-Powered-By", "PHP/8.3.36")
                self.send_header("Set-Cookie", "secret=not-for-report")
                self.end_headers()
            def log_message(self, *args): pass
        server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            report = scan.remote(f"http://127.0.0.1:{server.server_port}/", 2)
            self.assertEqual(calls, ["/"])
            self.assertEqual(report["evidence"]["http_status"], 302)
            self.assertNotIn("not-for-report", json.dumps(report))
            self.assertEqual(scan.exit_status([report]), 2)
        finally:
            server.shutdown()
            server.server_close()
            thread.join()

    def test_report_hash_and_no_overwrite(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "report.json"
            fixed = scan.result("local-cli", "local_cli", {"version": "8.3.36"})
            with patch.object(scan, "local", return_value=fixed), contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                self.assertEqual(scan.main(["--local", "--output", str(path)]), 0)
                before = path.read_text()
                report = json.loads(before)
                checksum = report.pop("report_sha256")
                self.assertEqual(checksum, scan.digest(report))
                self.assertEqual(scan.main(["--local", "--output", str(path)]), 2)
                self.assertEqual(path.read_text(), before)

if __name__ == "__main__": unittest.main()
