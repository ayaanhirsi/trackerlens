"""Command-line interface for trackerlens."""

from __future__ import annotations

import argparse
import json
import sys

from . import __version__
from .analyzer import analyze, compare, load_blocklist, load_har


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="trackerlens",
        description="Find third-party tracking signals in browser HAR captures.",
    )
    p.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    sub = p.add_subparsers(dest="command", required=True)

    a = sub.add_parser("analyze", help="analyze one HAR file")
    a.add_argument("har")
    a.add_argument("--first-party", help="site being visited (default: first request's domain)")
    a.add_argument("--blocklist", help="file with one tracker domain per line")
    a.add_argument("--json", action="store_true", help="print JSON instead of text")
    a.add_argument(
        "--max-trackers",
        type=int,
        help="exit with status 1 if more tracker domains than this are contacted",
    )

    c = sub.add_parser("compare", help="compare two captures of the same site")
    c.add_argument("har_a")
    c.add_argument("har_b")
    c.add_argument("--first-party")
    c.add_argument("--blocklist")
    c.add_argument("--json", action="store_true")
    return p


def main(argv: list[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    blocklist = load_blocklist(args.blocklist) if args.blocklist else None

    try:
        if args.command == "analyze":
            report = analyze(load_har(args.har), args.first_party, blocklist)
            print(json.dumps(report.to_dict(), indent=2) if args.json else report.render_text(), end="" if not args.json else "\n")
            if args.max_trackers is not None and len(report.tracker_domains) > args.max_trackers:
                return 1
            return 0

        a = analyze(load_har(args.har_a), args.first_party, blocklist)
        b = analyze(load_har(args.har_b), args.first_party, blocklist)
        diff = compare(a, b)
        if args.json:
            print(json.dumps(diff, indent=2))
        else:
            print(f"{'metric':<26}{'A':>8}{'B':>8}{'change':>9}")
            for k, v in diff.items():
                print(f"{k:<26}{v['a']:>8}{v['b']:>8}{v['delta']:>+9}")
        return 0
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
