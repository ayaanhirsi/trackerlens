"""Small built-in datasets used by the analyzer.

The tracker list is intentionally tiny and illustrative. For real work, pass a
larger list (for example one derived from Disconnect or EasyPrivacy) with
``--blocklist``.
"""

# Hostnames (and all of their subdomains) treated as known trackers.
TRACKER_DOMAINS = frozenset(
    {
        "google-analytics.com",
        "googletagmanager.com",
        "googleadservices.com",
        "googlesyndication.com",
        "doubleclick.net",
        "connect.facebook.net",
        "facebook.net",
        "bat.bing.com",
        "adsrvr.org",
        "criteo.com",
        "criteo.net",
        "taboola.com",
        "outbrain.com",
        "scorecardresearch.com",
        "hotjar.com",
        "segment.io",
        "segment.com",
        "mixpanel.com",
        "amplitude.com",
        "quantserve.com",
        "demdex.net",
        "everesttech.net",
        "rubiconproject.com",
        "pubmatic.com",
        "casalemedia.com",
        "adnxs.com",
        "tiktok.com",
        "analytics.twitter.com",
        "ads-twitter.com",
        "px.ads.linkedin.com",
    }
)

# Query parameters commonly used for link decoration / cross-site tracking.
TRACKING_PARAMS_EXACT = frozenset(
    {
        "fbclid",
        "gclid",
        "gclsrc",
        "dclid",
        "msclkid",
        "yclid",
        "ttclid",
        "twclid",
        "igshid",
        "mc_eid",
        "mc_cid",
        "_hsenc",
        "_hsmi",
        "vero_id",
        "wickedid",
        "oly_enc_id",
        "oly_anon_id",
    }
)
TRACKING_PARAM_PREFIXES = ("utm_", "pk_", "mtm_", "hsa_")

# Two-label public suffixes we handle without the full Public Suffix List.
# This is a deliberate simplification; see README "Limitations".
MULTI_PART_SUFFIXES = frozenset(
    {
        "co.uk",
        "org.uk",
        "ac.uk",
        "gov.uk",
        "com.au",
        "net.au",
        "org.au",
        "co.nz",
        "co.jp",
        "ne.jp",
        "or.jp",
        "co.in",
        "co.za",
        "com.br",
        "com.cn",
        "com.mx",
        "com.tr",
        "com.hk",
        "com.sg",
        "github.io",
        "herokuapp.com",
        "appspot.com",
        "blogspot.com",
        "cloudfront.net",
    }
)
