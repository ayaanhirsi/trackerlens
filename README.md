# TrackerLens

A small Python tool that reads browser HAR captures and measures third-party tracking: how many requests, domains and cookies come from outside the site you visited. Capture a page twice, once normally and once with an ad blocker, and TrackerLens shows what the blocker removed.

This is a proof of concept, demonstrated on two sites.

## Demo results

I captured BBC and CNN twice each: a baseline run with no blocking, and a run with uBlock Origin enabled.

| Site | Requests (base → blocked) | Third-party requests | Third-party domains | Third-party cookies |
|------|---------------------------|----------------------|---------------------|---------------------|
| bbc.com | 213 → 108 | 112 → 14 (**-87.5%**) | 24 → 9 | 14 → 2 |
| cnn.com | 426 → 171 | 327 → 52 (**-84.1%**) | 58 → 14 | 53 → 6 |
| **Total** | | 439 → 66 | 82 → 23 | 67 → 8 |

On these two sites, the blocker cut third-party requests by 84-88%. Two sites is a demonstration of the pipeline, not a general finding about the web. The raw HAR files are not included, since they contain full request headers, so these numbers can't be reproduced without capturing your own.

What the blocker left behind is telling. On BBC, the only third-party cookies remaining in the blocked run came from `piano.io` and `tinypass.com`, a paywall and subscription service. In the baseline, cookies were set by ad and measurement hosts such as doubleclick, scorecardresearch, permutive and cxense.

## How it works

1. Export a HAR file from your browser's DevTools (Network tab, "Save all as HAR").
2. Name it after the site, with no `www.`: `bbc.com.har`, `cnn.com.har`.
3. Put baseline captures in one folder and blocked captures in another, using the same filename in both.
4. Run the batch script, which pairs files by name and writes a CSV.

```bat
python examples\batch_summary.py baseline blocked results.csv
```

The script prints headline numbers (median and mean drop in third-party requests, plus totals for domains and cookies) and writes one row per site to `results.csv`.

You can also use the library directly:

```python
from trackerlens import analyze, load_har

report = analyze(
    load_har("baseline/bbc.com.har"),
    first_party="bbc.com",
    also_first_party=["bbc.co.uk", "bbci.co.uk", "bbc.net.uk"],
)
print(report.third_party_requests, len(report.third_party_domains))
```

## Method

- **Site name** comes from the filename (`cnn.com.har` means the site is `cnn.com`).
- **First-party aliases.** Sites serve their own content from other domains (BBC uses `bbci.co.uk` for images and static files). Without handling this, those requests would be miscounted as third-party. The alias table is `FIRST_PARTY_ALIASES` at the top of `examples/batch_summary.py`. For these runs I used:
  - `bbc.com`: `bbc.co.uk`, `bbci.co.uk`, `bbc.net.uk`
  - `cnn.com`: `cnn.io`
- **Blocked entries are excluded.** HAR entries with a response status of 0 never got a response, which is how Chrome records a blocked request. They are dropped from all counts (requests, domains, cookies, bounces). The number dropped is reported in the `failed_entries_base` and `failed_entries_blocked` CSV columns. In a baseline run this should be near zero; a large value suggests a bad capture.

## Limitations

- **Cookie counts are a lower bound.** The tool only sees `Set-Cookie` response headers. Cookies set by JavaScript (`document.cookie`) never appear in a HAR. This is probably why BBC shows no first-party cookies at all.
- **The alias list is a manual judgment** about which domains a site owns, and it may be incomplete. Unlisted first-party hosts would be counted as third-party and inflate the baseline.
- **`bbc.com` and `bbc.co.uk` are different sites.** These results are for `bbc.com`.
- **Small sample.** Two sites, one capture each, so there is no variance estimate. Page content, ads and A/B tests change between loads.
- **Request counts depend on the capture.** How long the page was left open and how far it was scrolled affect what loads.

## Tests

```bat
python -m unittest discover tests
```

## Project layout

```
trackerlens/    analysis library (analyzer.py, HAR loading)
examples/       batch_summary.py, the HAR pair to CSV script
tests/          unit tests
```
