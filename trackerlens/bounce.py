"""Bounce-tracking detection from HTTP redirect chains in a HAR.

A bounce tracker is a domain the browser is sent *through* during a navigation
(``origin -> tracker (3xx) -> destination``). For that instant the tracker is the
top-level site, so it can read and write first-party cookies and hand an
identifier to the destination in the URL, sidestepping third-party cookie
blocking.

Only HTTP 3xx redirects are visible in a HAR. Client-side bounces (JavaScript
or meta-refresh redirects) are not detected. See the README "Limitations".
"""

from __future__ import annotations

from collections import defaultdict
from typing import Any, Iterable
from urllib.parse import parse_qsl, urldefrag, urljoin, urlsplit

from .analyzer import (
    _headers,
    host_matches,
    is_tracking_param,
    looks_like_identifier,
    mask,
    parse_set_cookie,
    registrable_domain,
)


def _hop(entry: dict[str, Any] | None, url: str) -> dict[str, Any]:
    """Summarize one request in a chain. ``entry`` is None for a dangling target."""
    resp = (entry or {}).get("response", {}) or {}
    parts = urlsplit(url)
    host = (parts.hostname or "").lower()
    return {
        "host": host,
        "reg": registrable_domain(host),
        "status": int(resp.get("status", 0) or 0),
        "cookies": [parse_set_cookie(h)[0] for h in _headers(resp.get("headers"), "set-cookie")],
        "query": parse_qsl(parts.query, keep_blank_values=True),
    }


def _redirect_target(entry: dict[str, Any]) -> str | None:
    """Absolute URL a 3xx response points to, or None if it is not a redirect."""
    req, resp = entry.get("request", {}), entry.get("response", {})
    if not 300 <= int(resp.get("status", 0) or 0) < 400:
        return None
    loc = (_headers(resp.get("headers"), "location") or [resp.get("redirectURL", "")])[0]
    return urljoin(req.get("url", ""), loc) if loc else None


def _build_chains(entries: list[dict[str, Any]]) -> list[list[dict[str, Any]]]:
    """Link each 3xx entry to the later entry whose URL is its Location."""
    by_url: dict[str, list[int]] = defaultdict(list)
    for i, e in enumerate(entries):
        by_url[urldefrag(e.get("request", {}).get("url", ""))[0]].append(i)

    claimed: set[int] = set()
    next_of: dict[int, int | str] = {}  # entry index -> next entry index, or URL if unseen
    for i, e in enumerate(entries):
        target = _redirect_target(e)
        if target is None:
            continue
        j = next((k for k in by_url.get(urldefrag(target)[0], []) if k > i and k not in claimed), None)
        if j is None:
            next_of[i] = target
        else:
            claimed.add(j)
            next_of[i] = j

    chains = []
    for start in sorted(next_of):
        if start in claimed:
            continue  # it is the middle or end of a chain that started earlier
        cur: int | str = start
        hops = []
        while True:
            entry = entries[cur]  # type: ignore[index]
            hops.append(_hop(entry, entry.get("request", {}).get("url", "")))
            nxt = next_of.get(cur)  # type: ignore[arg-type]
            if nxt is None:
                break
            if isinstance(nxt, str):  # redirect target never appears as its own entry
                hops.append(_hop(None, nxt))
                break
            cur = nxt
        hops[0]["referer"] = _referer(entries[start])
        chains.append(hops)
    return chains


def _referer(entry: dict[str, Any]) -> str:
    values = _headers(entry.get("request", {}).get("headers"), "referer")
    return values[0] if values else ""


def _with_origin(hops: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Prepend the page that started the chain when the Referer names a different site.

    In a real capture a link click is not a 3xx, so the origin page is not part of
    the redirect chain itself; its Referer on the first request is how we know it.
    """
    host = (urlsplit(hops[0].get("referer", "")).hostname or "").lower()
    reg = registrable_domain(host)
    if reg and reg != hops[0]["reg"]:
        return [{"host": host, "reg": reg, "status": 0, "cookies": [], "query": []}] + hops
    return hops


def _label(hop: dict[str, Any]) -> str:
    return f"{hop['host']} ({hop['status']})" if 300 <= hop["status"] < 400 else hop["host"]


def detect_bounces(entries: list[dict[str, Any]], blocklist: Iterable[str]) -> list[dict[str, Any]]:
    """Return bounce candidates, highest score first.

    A candidate is a hop whose registrable domain differs from both the start and
    the final destination of a redirect chain. Candidates are scored:

    * sets a cookie during the hop        +2
    * is on the tracker list              +2
    * adds an ID/tracking param to the next URL  +2
    * appears in 2+ chains in the capture (a hub) +1

    ``suspected`` additionally requires a cookie or a forwarded parameter, because
    login/SSO flows and link shorteners are otherwise indistinguishable.
    """
    blocklist = frozenset(blocklist)
    findings: list[dict[str, Any]] = []
    chain_ids: dict[str, set[int]] = defaultdict(set)

    for cid, hops in enumerate(_build_chains(entries)):
        seq = _with_origin(hops)
        if len(seq) < 3:
            continue
        start, final = seq[0]["reg"], seq[-1]["reg"]
        i = 1
        while i < len(seq) - 1:
            reg = seq[i]["reg"]
            if not reg or reg in (start, final):
                i += 1
                continue
            j = i
            while j + 1 < len(seq) - 1 and seq[j + 1]["reg"] == reg:
                j += 1
            group = seq[i : j + 1]

            forwarded: dict[str, str] = {}
            for k in range(i, j + 1):
                own = set(seq[k]["query"])
                for name, value in seq[k + 1]["query"]:
                    if (name, value) not in own and (
                        looks_like_identifier(value) or is_tracking_param(name)
                    ):
                        forwarded[name] = mask(value)

            chain_ids[reg].add(cid)
            findings.append(
                {
                    "domain": reg,
                    "chain": [_label(h) for h in seq],
                    "cookies": sorted({c for h in group for c in h["cookies"]}),
                    "forwarded_params": forwarded,
                    "known_tracker": any(host_matches(h["host"], blocklist) for h in group),
                }
            )
            i = j + 1

    for f in findings:
        f["chains_seen"] = len(chain_ids[f["domain"]])
        f["score"] = (
            2 * bool(f["cookies"])
            + 2 * f["known_tracker"]
            + 2 * bool(f["forwarded_params"])
            + (1 if f["chains_seen"] >= 2 else 0)
        )
        f["suspected"] = bool(f["cookies"] or f["forwarded_params"]) and f["score"] >= 3
    findings.sort(key=lambda f: (-f["score"], f["domain"]))
    return findings
