"""Backward-compatible entrypoint for repository-based usage."""

from certguard.cli import main


if __name__ == "__main__":
    raise SystemExit(main())
