import json
import sys
import unittest
from pathlib import Path

from trackerlens import analyze
from trackerlens.bounce import detect_bounces

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "examples"))
from make_sample_har import UID, build, build_bounce, entry, loc, sc  # noqa: E402


def bounces(har, blocklist=()):
    return detect_bounces(har["log"]["entries"], blocklist)


def by_domain(found, domain):
    return [b for b in found if b["domain"] == domain]


class BounceDetectionTests(unittest.TestCase):
    def setUp(self):
        self.found = bounces(build_bounce())

    def test_flags_cookie_setting_id_forwarding_hub(self):
        hits = by_domain(self.found, "adtech.example")
        self.assertEqual(len(hits), 2)
        for h in hits:
            self.assertTrue(h["suspected"])
            self.assertEqual(h["cookies"], ["bt_uid"])
            self.assertEqual(list(h["forwarded_params"]), ["clid"])
            self.assertEqual(h["chains_seen"], 2)
            self.assertEqual(h["score"], 5)  # cookie 2 + forwarded id 2 + hub 1
        self.assertEqual(
            hits[0]["chain"],
            ["news.example", "track.adtech.example (302)", "shop.example"],
        )

    def test_full_identifier_is_masked(self):
        self.assertNotIn(UID, json.dumps(self.found))

    def test_sso_cookie_alone_is_not_suspected(self):
        (sso,) = by_domain(self.found, "provider.example")
        self.assertEqual(sso["cookies"], ["sid"])
        self.assertEqual(sso["score"], 2)
        self.assertFalse(sso["suspected"])
        self.assertEqual(sso["chain"].count("sso.provider.example (302)"), 2)

    def test_link_shortener_is_candidate_with_no_signals(self):
        (short,) = by_domain(self.found, "short.example")
        self.assertEqual(short["score"], 0)
        self.assertFalse(short["suspected"])

    def test_sorted_by_score(self):
        scores = [b["score"] for b in self.found]
        self.assertEqual(scores, sorted(scores, reverse=True))

    def test_known_tracker_adds_score(self):
        hits = by_domain(bounces(build_bounce(), {"adtech.example"}), "adtech.example")
        self.assertTrue(all(h["known_tracker"] and h["score"] == 7 for h in hits))

    def test_tracker_without_cookie_or_id_is_not_suspected(self):
        har = {"log": {"entries": [
            entry("https://t.example/r", 302, referer="https://a.example/", headers=[loc("https://b.example/")]),
            entry("https://b.example/"),
        ]}}
        (hit,) = bounces(har, {"t.example"})
        self.assertEqual(hit["score"], 2)
        self.assertFalse(hit["suspected"])

    def test_two_hop_chain_without_referer_has_no_candidate(self):
        har = {"log": {"entries": [
            entry("https://t.example/r", 302, headers=[sc("id=abc"), loc("https://b.example/")]),
            entry("https://b.example/"),
        ]}}
        self.assertEqual(bounces(har), [])

    def test_same_site_redirect_is_ignored(self):
        har = {"log": {"entries": [
            entry("http://a.example/", 301, headers=[loc("https://www.a.example/")]),
            entry("https://www.a.example/"),
        ]}}
        self.assertEqual(bounces(har), [])

    def test_relative_location_and_dangling_final_hop(self):
        har = {"log": {"entries": [
            entry("https://a.example/go", 302, headers=[loc("https://t.example/x")]),
            entry("https://t.example/x", 302,
                  headers=[sc("u=1"), loc("https://dest.example/?cid=" + UID)]),
            # the destination request was never captured
        ]}}
        (hit,) = bounces(har)
        self.assertEqual(hit["chain"], ["a.example (302)", "t.example (302)", "dest.example"])
        self.assertTrue(hit["suspected"])

    def test_forwarded_value_already_in_hop_url_is_not_counted(self):
        har = {"log": {"entries": [
            entry(f"https://t.example/r?cid={UID}", 302, referer="https://a.example/",
                  headers=[loc(f"https://b.example/?cid={UID}")]),
            entry(f"https://b.example/?cid={UID}"),
        ]}}
        (hit,) = bounces(har)
        self.assertEqual(hit["forwarded_params"], {})

    def test_empty_and_plain_captures(self):
        self.assertEqual(detect_bounces([], []), [])
        self.assertEqual(bounces(build()), [])  # criteo 302 has no origin or final entry


class IntegrationTests(unittest.TestCase):
    def test_report_summary_and_text(self):
        r = analyze(build_bounce())
        self.assertEqual(r.summary()["bounce_trackers"], 1)  # distinct suspected domains
        self.assertIn("bounces", r.to_dict())
        text = r.render_text()
        self.assertIn("[suspected, score 5] adtech.example", text)
        self.assertIn("news.example -> track.adtech.example (302) -> shop.example", text)

    def test_default_sample_has_no_bounces(self):
        self.assertEqual(analyze(build()).summary()["bounce_trackers"], 0)


if __name__ == "__main__":
    unittest.main()
