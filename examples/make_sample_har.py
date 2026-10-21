"""Generate a small SYNTHETIC HAR file for demos and tests.

Nothing here was captured from a real site. The domains under .example are
reserved and do not exist; tracker hostnames are real-looking names only so the
built-in list matches them. Capture real HARs from your browser's dev tools
(Network tab -> "Save all as HAR") for real results.
"""

import json
import sys

UID = "a1b2c3d4e5f60718293a"  # fake cross-site identifier


def entry(url, status=200, headers=None, referer=None):
    req_headers = [{"name": "Referer", "value": referer}] if referer else []
    return {
        "request": {"method": "GET", "url": url, "headers": req_headers},
        "response": {"status": status, "headers": headers or []},
    }


def sc(value):
    return {"name": "Set-Cookie", "value": value}


def build():
    return {
        "log": {
            "version": "1.2",
            "creator": {"name": "trackerlens-sample", "version": "0"},
            "entries": [
                entry("https://news.example/?utm_source=newsletter&utm_medium=email&fbclid=IwAR0abc"),
                entry("https://news.example/static/app.js"),
                entry("https://cdn.news.example/img/hero.jpg"),
                entry(
                    f"https://www.google-analytics.com/collect?v=1&cid={UID}&t=pageview",
                    headers=[sc("_ga=GA1.2.123456789.1700000000; Max-Age=63072000; Secure; SameSite=None")],
                ),
                entry("https://www.googletagmanager.com/gtm.js?id=GTM-XXXX"),
                entry(
                    f"https://ib.adnxs.com/getuid?uid={UID}",
                    headers=[sc("uuid2=4455667788990011; Expires=Wed, 01 Jan 2031 00:00:00 GMT; SameSite=None")],
                ),
                entry(
                    f"https://sync.criteo.com/pixel?partner=news&buid={UID}",
                    status=302,
                    headers=[{"name": "Location", "value": "https://dis.criteo.net/match?x=1"}],
                ),
                entry("https://fonts.cdn-provider.example/css?family=Inter"),
                entry("https://connect.facebook.net/en_US/fbevents.js"),
                entry("https://news.example/api/articles?page=1"),
            ],
        }
    }


def loc(url):
    return {"name": "Location", "value": url}


def build_bounce():
    """Synthetic capture of link clicks that bounce through redirect chains.

    * Two clicks go news.example -> track.adtech.example (302, sets a cookie and
      adds a ``clid`` identifier) -> a different destination: a bounce tracker.
    * A login redirects through sso.provider.example and sets a session cookie:
      looks like a bounce, but is a normal SSO flow.
    * A link shortener redirects with no cookie and no identifier.
    """
    return {
        "log": {
            "version": "1.2",
            "creator": {"name": "trackerlens-sample-bounce", "version": "0"},
            "entries": [
                entry("https://news.example/"),
                entry(
                    "https://track.adtech.example/click?c=42",
                    status=302,
                    referer="https://news.example/",
                    headers=[
                        sc("bt_uid=9f8e7d6c5b4a3921; Max-Age=31536000; Secure; SameSite=None"),
                        loc(f"https://shop.example/landing?clid={UID}"),
                    ],
                ),
                entry(f"https://shop.example/landing?clid={UID}"),
                entry(
                    "https://track.adtech.example/click?c=77",
                    status=302,
                    referer="https://news.example/",
                    headers=[
                        sc("bt_uid=9f8e7d6c5b4a3921; Max-Age=31536000; Secure; SameSite=None"),
                        loc(f"https://travel.example/deal?clid={UID}"),
                    ],
                ),
                entry(f"https://travel.example/deal?clid={UID}"),
                entry(
                    "https://news.example/login",
                    status=302,
                    headers=[loc("https://sso.provider.example/auth?state=xy1")],
                ),
                entry(
                    "https://sso.provider.example/auth?state=xy1",
                    status=302,
                    headers=[sc("sid=s3ss10n; Secure"), loc("/ret")],
                ),
                entry("https://sso.provider.example/ret", status=302,
                      headers=[loc("https://news.example/callback?ok=1")]),
                entry("https://news.example/callback?ok=1"),
                entry(
                    "https://short.example/x7",
                    status=301,
                    referer="https://news.example/",
                    headers=[loc("https://blog.example/post")],
                ),
                entry("https://blog.example/post"),
            ],
        }
    }


if __name__ == "__main__":
    out = sys.argv[1] if len(sys.argv) > 1 else "sample.har"
    maker = build_bounce if len(sys.argv) > 2 and sys.argv[2] == "bounce" else build
    with open(out, "w", encoding="utf-8") as f:
        json.dump(maker(), f, indent=2)
    print(f"wrote {out}")
