"""Deprecated module entry point. Use the ``neakam`` console script."""

from __future__ import annotations

import sys

from certguard.cli import main

if __name__ == "__main__":
    print("python -m certguard is deprecated; use neakam.", file=sys.stderr)
    raise SystemExit(main())
