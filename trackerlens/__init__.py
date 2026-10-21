"""trackerlens: find third-party tracking signals in browser HAR captures."""

from .analyzer import Report, analyze, compare, load_blocklist, load_har, registrable_domain

__all__ = ["Report", "analyze", "compare", "load_blocklist", "load_har", "registrable_domain"]
__version__ = "0.1.0"
