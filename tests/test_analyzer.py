import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from trackerlens import analyze, compare, registrable_domain
from trackerlens.analyzer import (
    host_matches,
    is_tracking_param,
    looks_like_identifier,
    parse_set_cookie,
)

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "examples"))
from make_sample_har import UID, build  # noqa: E402


class HelperTests(unittest.TestCase):
    def test_registrable_domain(self):
        cases = {
            "www.example.com": "example.com",
            "a.b.example.co.uk": "example.co.uk",
            "example.com": "example.com",
            "user.github.io": "user.github.io",
            "127.0.0.1": "127.0.0.1",
            "localhost": "localhost",
            "": "",
        }
        for host, expected in cases.items():
            with self.subTest(host=host):
                self.assertEqual(registrable_domain(host), expected)

    def test_host_matches_respects_label_boundary(self):
        self.assertTrue(host_matches("ssl.google-analytics.com", {"google-analytics.com"}))
        self.assertFalse(host_matches("notgoogle-analytics.com", {"google-analytics.com"}))

    def test_tracking_params(self):
        self.assertTrue(is_tracking_param("utm_source"))
        self.assertTrue(is_tracking_param("FBCLID"))
        self.assertFalse(is_tracking_param("page"))

    def test_identifier_heuristic(self):
        self.assertTrue(looks_like_identifier(UID))
        self.assertFalse(looks_like_identifier("short1"))
        self.assertFalse(looks_like_identifier("onlyletterslongstring"))

    def test_parse_set_cookie(self):
        name, info = parse_set_cookie("id=abc; Max-Age=10; Secure; SameSite=none")
        self.assertEqual(name, "id")
        self.assertEqual(info, {"same_site": "None", "secure": True, "persistent": True})
        _, session = parse_set_cookie("s=1")
        self.assertEqual(session, {"same_site": None, "secure": False, "persistent": False})


class AnalyzeTests(unittest.TestCase):
    def setUp(self):
        self.report = analyze(build())

    def test_counts_and_party_split(self):
        r = self.report
        self.assertEqual(r.first_party, "news.example")
        self.assertEqual(r.total_requests, 10)
        self.assertEqual(r.third_party_requests, 6)  # cdn.news.example is first-party
        self.assertIn("google-analytics.com", r.tracker_domains)
        self.assertNotIn("cdn-provider.example", r.tracker_domains)
        self.assertIn("cdn-provider.example", r.third_party_domains)

    def test_third_party_cookies(self):
        cookies = self.report.third_party_cookies
        self.assertEqual({c.name for c in cookies}, {"_ga", "uuid2"})
        self.assertTrue(all(c.tracker and c.persistent for c in cookies))

    def test_tracking_params_on_first_party_request(self):
        hit = self.report.tracking_param_requests[0]
        self.assertEqual(hit["host"], "news.example")
        self.assertEqual(hit["params"], ["fbclid", "utm_medium", "utm_source"])

    def test_id_sync_across_three_domains_and_masking(self):
        syncs = self.report.id_syncs
        self.assertEqual(len(syncs), 1)
        self.assertEqual(syncs[0]["domains"], ["adnxs.com", "criteo.com", "google-analytics.com"])
        self.assertNotIn(UID, json.dumps(self.report.to_dict()))

    def test_third_party_redirect(self):
        self.assertEqual(
            self.report.third_party_redirects,
            [{"from": "sync.criteo.com", "to": "dis.criteo.net"}],
        )

    def test_first_party_override_and_custom_blocklist(self):
        r = analyze(build(), first_party="cdn-provider.example", blocklist={"news.example"})
        self.assertEqual(r.first_party, "cdn-provider.example")
        self.assertEqual(set(r.tracker_domains), {"news.example"})

    def test_compare(self):
        har = build()
        har["log"]["entries"] = har["log"]["entries"][:3]
        diff = compare(self.report, analyze(har))
        self.assertLess(diff["third_party_domains"]["delta"], 0)
        self.assertEqual(diff["requests"], {"a": 10, "b": 3, "delta": -7})

    def test_empty_har(self):
        r = analyze({"log": {"entries": []}})
        self.assertEqual(r.total_requests, 0)
        self.assertIn("Requests:", r.render_text())


class CliTests(unittest.TestCase):
    def _run(self, *args):
        return subprocess.run(
            [sys.executable, "-m", "trackerlens", *args],
            cwd=ROOT,
            capture_output=True,
            text=True,
        )

    def test_json_output_and_exit_codes(self):
        with tempfile.TemporaryDirectory() as d:
            d = Path(d)
            har = d / "s.har"
            har.write_text(json.dumps(build()))
            ok = self._run("analyze", str(har), "--json")
            self.assertEqual(ok.returncode, 0, ok.stderr)
            self.assertEqual(json.loads(ok.stdout)["first_party"], "news.example")
            self.assertEqual(self._run("analyze", str(har), "--max-trackers", "1").returncode, 1)
            self.assertEqual(self._run("analyze", str(d / "nope.har")).returncode, 2)
            bad = d / "bad.har"
            bad.write_text("{}")
            self.assertEqual(self._run("analyze", str(bad)).returncode, 2)


if __name__ == "__main__":
    unittest.main()
