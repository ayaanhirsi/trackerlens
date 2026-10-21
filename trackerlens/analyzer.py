"""Core analysis of HAR captures for third-party tracking signals."""

from __future__ import annotations

import json
import re
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable
from urllib.parse import parse_qsl, urlsplit

from .data import (
    MULTI_PART_SUFFIXES,
    TRACKER_DOMAINS,
    TRACKING_PARAM_PREFIXES,
    TRACKING_PARAMS_EXACT,
)

# Values that look like per-user identifiers: long, with at least one digit.
_ID_RE = re.compile(r"^[A-Za-z0-9_\-.~%]{12,}$")


# --------------------------------------------------------------------------
# Small helpers
# --------------------------------------------------------------------------
def registrable_domain(host: str) -> str:
    """Return an approximate registrable domain (eTLD+1) for ``host``.

    Uses a small built-in list of multi-part suffixes instead of the full
    Public Suffix List, so it can be wrong for rare suffixes.
    """
    host = (host or "").lower().rstrip(".")
    if not host or ":" in host or re.fullmatch(r"[\d.]+", host):
        return host  # IPv6 literal, IPv4 literal, or empty
    parts = host.split(".")
    if len(parts) <= 2:
        return host
    if ".".join(parts[-2:]) in MULTI_PART_SUFFIXES:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:])


def host_matches(host: str, domains: Iterable[str]) -> bool:
    """True if ``host`` equals or is a subdomain of any entry in ``domains``."""
    host = host.lower().rstrip(".")
    return any(host == d or host.endswith("." + d) for d in domains)


def is_tracking_param(name: str) -> bool:
    n = name.lower()
    return n in TRACKING_PARAMS_EXACT or n.startswith(TRACKING_PARAM_PREFIXES)


def looks_like_identifier(value: str) -> bool:
    return bool(_ID_RE.match(value)) and any(c.isdigit() for c in value)


def mask(value: str) -> str:
    """Shorten an identifier for display so reports don't leak whole IDs."""
    return value if len(value) <= 8 else f"{value[:4]}…{value[-2:]}"


def load_blocklist(path: str | Path) -> frozenset[str]:
    """Load one domain per line; ``#`` starts a comment."""
    out = set()
    for line in Path(path).read_text(encoding="utf-8").splitlines():
        line = line.split("#", 1)[0].strip().lower()
        if line:
            out.add(line)
    return frozenset(out)


@dataclass
class Cookie:
    domain: str  # host that set it
    name: str
    same_site: str | None
    secure: bool
    persistent: bool
    tracker: bool


@dataclass
class Report:
    first_party: str
    total_requests: int = 0
    third_party_requests: int = 0
    third_party_domains: dict[str, int] = field(default_factory=dict)
    tracker_domains: dict[str, int] = field(default_factory=dict)
    tracking_param_requests: list[dict[str, Any]] = field(default_factory=list)
    third_party_cookies: list[Cookie] = field(default_factory=list)
    id_syncs: list[dict[str, Any]] = field(default_factory=list)
    third_party_redirects: list[dict[str, str]] = field(default_factory=list)
    bounces: list[dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "first_party": self.first_party,
            "total_requests": self.total_requests,
            "third_party_requests": self.third_party_requests,
            "third_party_domains": self.third_party_domains,
            "tracker_domains": self.tracker_domains,
            "tracking_param_requests": self.tracking_param_requests,
            "third_party_cookies": [vars(c) for c in self.third_party_cookies],
            "id_syncs": self.id_syncs,
            "third_party_redirects": self.third_party_redirects,
            "bounces": self.bounces,
        }

    def summary(self) -> dict[str, int]:
        return {
            "requests": self.total_requests,
            "third_party_requests": self.third_party_requests,
            "third_party_domains": len(self.third_party_domains),
            "tracker_domains": len(self.tracker_domains),
            "third_party_cookies": len(self.third_party_cookies),
            "id_syncs": len(self.id_syncs),
            "tracking_param_requests": len(self.tracking_param_requests),
            "bounce_trackers": len({b["domain"] for b in self.bounces if b["suspected"]}),
        }

    def render_text(self) -> str:
        s = self.summary()
        pct = (
            100 * self.third_party_requests / self.total_requests
            if self.total_requests
            else 0.0
        )
        lines = [
            f"trackerlens report for {self.first_party}",
            "=" * 48,
            f"Requests:              {s['requests']}",
            f"Third-party requests:  {s['third_party_requests']} ({pct:.0f}%)",
            f"Third-party domains:   {s['third_party_domains']}",
            f"Known tracker domains: {s['tracker_domains']}",
            f"Third-party cookies:   {s['third_party_cookies']}",
            f"Cross-domain ID syncs: {s['id_syncs']}",
            f"Tracking-param reqs:   {s['tracking_param_requests']}",
            f"Bounce trackers:       {s['bounce_trackers']}",
            "",
        ]
        if self.tracker_domains:
            lines.append("Known trackers contacted:")
            for d, n in sorted(self.tracker_domains.items(), key=lambda x: -x[1]):
                lines.append(f"  {d:<36} {n} req")
            lines.append("")
        if self.third_party_cookies:
            lines.append("Third-party cookies set:")
            for c in self.third_party_cookies:
                flags = [
                    f"SameSite={c.same_site or 'unset'}",
                    "Secure" if c.secure else "not-Secure",
                    "persistent" if c.persistent else "session",
                ]
                tag = " [tracker]" if c.tracker else ""
                lines.append(f"  {c.domain}: {c.name} ({', '.join(flags)}){tag}")
            lines.append("")
        if self.id_syncs:
            lines.append("Identifier shared across third-party domains (possible ID sync):")
            for sync in self.id_syncs:
                lines.append(
                    f"  value {sync['value']} seen by: {', '.join(sync['domains'])}"
                )
            lines.append("")
        if self.tracking_param_requests:
            lines.append("Requests carrying tracking parameters:")
            for r in self.tracking_param_requests[:10]:
                lines.append(f"  {r['host']}: {', '.join(r['params'])}")
            extra = len(self.tracking_param_requests) - 10
            if extra > 0:
                lines.append(f"  … and {extra} more")
            lines.append("")
        if self.third_party_redirects:
            lines.append("Redirects from third-party hosts to other domains:")
            for r in self.third_party_redirects:
                lines.append(f"  {r['from']} -> {r['to']}")
            lines.append("")
        if self.bounces:
            lines.append("Redirect-chain hops (possible bounce tracking):")
            for b in self.bounces:
                tag = "suspected" if b["suspected"] else "candidate"
                lines.append(f"  [{tag}, score {b['score']}] {b['domain']}")
                lines.append(f"    {' -> '.join(b['chain'])}")
                signals = []
                if b["cookies"]:
                    signals.append(f"cookie set: {', '.join(b['cookies'])}")
                if b["forwarded_params"]:
                    signals.append(
                        "forwarded: " + ", ".join(f"{k}={v}" for k, v in b["forwarded_params"].items())
                    )
                if b["known_tracker"]:
                    signals.append("known tracker")
                if b["chains_seen"] >= 2:
                    signals.append(f"seen in {b['chains_seen']} chains")
                lines.append(f"    signals: {'; '.join(signals) or 'none'}")
            lines.append("")
        return "\n".join(lines).rstrip() + "\n"


# --------------------------------------------------------------------------
# HAR parsing
# --------------------------------------------------------------------------
def load_har(path: str | Path) -> dict[str, Any]:
    with open(path, encoding="utf-8") as f:
        data = json.load(f)
    if "log" not in data or "entries" not in data["log"]:
        raise ValueError(f"{path} does not look like a HAR file (missing log.entries)")
    return data


def _headers(items: list[dict[str, str]] | None, name: str) -> list[str]:
    name = name.lower()
    return [h.get("value", "") for h in (items or []) if h.get("name", "").lower() == name]


def parse_set_cookie(header: str) -> tuple[str, dict[str, Any]]:
    """Parse one Set-Cookie header into (name, attributes)."""
    first, *attrs = [p.strip() for p in header.split(";")]
    name = first.split("=", 1)[0].strip()
    info: dict[str, Any] = {
        "same_site": None,
        "secure": False,
        "persistent": False,
    }
    for a in attrs:
        k, _, v = a.partition("=")
        k = k.strip().lower()
        if k == "samesite":
            info["same_site"] = v.strip().capitalize() or None
        elif k == "secure":
            info["secure"] = True
        elif k in ("expires", "max-age"):
            info["persistent"] = True
    return name, info


def analyze(
    har: dict[str, Any],
    first_party: str | None = None,
    blocklist: Iterable[str] | None = None,
) -> Report:
    """Analyze a parsed HAR dict and return a :class:`Report`."""
    blocklist = frozenset(blocklist) if blocklist is not None else TRACKER_DOMAINS
    entries = har["log"]["entries"]

    if first_party is None:
        first_url = next((e["request"]["url"] for e in entries if "request" in e), "")
        first_party = registrable_domain(urlsplit(first_url).hostname or "")
    else:
        first_party = registrable_domain(first_party.lower())

    report = Report(first_party=first_party)
    third_hosts: Counter[str] = Counter()
    trackers: Counter[str] = Counter()
    seen_cookies: set[tuple[str, str]] = set()
    id_domains: dict[str, set[str]] = defaultdict(set)

    for entry in entries:
        req = entry.get("request", {})
        resp = entry.get("response", {})
        url = req.get("url", "")
        parts = urlsplit(url)
        host = (parts.hostname or "").lower()
        if not host:
            continue
        report.total_requests += 1
        reg = registrable_domain(host)
        third_party = reg != first_party

        query = parse_qsl(parts.query, keep_blank_values=True)

        # Link decoration can appear on first- or third-party requests.
        bad = sorted({k for k, _ in query if is_tracking_param(k)})
        if bad:
            report.tracking_param_requests.append({"host": host, "params": bad})

        if not third_party:
            continue

        report.third_party_requests += 1
        third_hosts[reg] += 1
        tracker = host_matches(host, blocklist)
        if tracker:
            trackers[reg] += 1

        # Identifier-looking query values, grouped by registrable domain.
        for _, value in query:
            if looks_like_identifier(value):
                id_domains[value].add(reg)

        # Cookies set by this third-party response.
        set_cookies = _headers(resp.get("headers"), "set-cookie")
        for header in set_cookies:
            name, info = parse_set_cookie(header)
            key = (host, name)
            if key in seen_cookies:
                continue
            seen_cookies.add(key)
            report.third_party_cookies.append(
                Cookie(domain=host, name=name, tracker=tracker, **info)
            )
            # A cookie value reused in other domains' URLs is also an ID sync.
            value = header.split(";", 1)[0].partition("=")[2].strip()
            if looks_like_identifier(value):
                id_domains[value].add(reg)

        # Redirects that hand the user off from a third party to another site.
        status = int(resp.get("status", 0) or 0)
        if 300 <= status < 400:
            loc = (_headers(resp.get("headers"), "location") or [""])[0]
            target = urlsplit(loc).hostname
            if target and registrable_domain(target) != reg:
                report.third_party_redirects.append({"from": host, "to": target.lower()})

    # Imported here because bounce.py reuses this module's helpers.
    from .bounce import detect_bounces

    report.bounces = detect_bounces(entries, blocklist)
    report.third_party_domains = dict(third_hosts.most_common())
    report.tracker_domains = dict(trackers.most_common())
    for value, domains in id_domains.items():
        if len(domains) >= 2:
            report.id_syncs.append({"value": mask(value), "domains": sorted(domains)})
    report.id_syncs.sort(key=lambda s: -len(s["domains"]))
    return report


def compare(a: Report, b: Report) -> dict[str, dict[str, int]]:
    """Return per-metric values for two reports and their difference (b - a)."""
    sa, sb = a.summary(), b.summary()
    return {k: {"a": sa[k], "b": sb[k], "delta": sb[k] - sa[k]} for k in sa}
