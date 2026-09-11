"""Detect upstream CA/Browser Forum Baseline Requirements changes.

This script used to regex-scrape BR.md for strings like "200-day" and rewrite
`policies/standards_baseline.yaml` with whatever it found, preferring 200 over
any smaller value:

    if 200 in values: return 200
    if 398 in values: return 398

That was unsafe in a specific, dated way. Ballot SC-081v3 reduces the maximum
subscriber validity to 100 days on 2027-03-15 and 47 days on 2029-03-15, but
the string "200-day" will almost certainly survive in the BR's own schedule
table -- so the scraper would have kept asserting 200 straight through both
reductions. A drift detector that cannot detect the one scheduled change it
exists for is worse than no detector, because it reports success.

The script therefore no longer derives policy values. It records the upstream
document's digest and reports whether it changed since the last sync. When it
has, CI opens a pull request asking a human to review the hand-maintained
schedule in `policies/standards_baseline.yaml`. Numbers in that file are only
ever changed by a person reading the ballot.
"""

from __future__ import annotations

import argparse
import hashlib
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from urllib.request import Request, urlopen

import yaml

DEFAULT_SOURCE_URL = (
    "https://raw.githubusercontent.com/cabforum/servercert/main/docs/BR.md"
)

#: Day values worth surfacing to a reviewer when the upstream document changes.
#: Purely informational -- these are never written into the baseline.
TRACKED_VALIDITY_VALUES: tuple[int, ...] = (398, 200, 100, 47, 10)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Detect upstream CABF BR changes and record a digest. Does not "
            "modify policy values; a human reviews the tracked schedule."
        )
    )
    parser.add_argument(
        "--source-url",
        default=DEFAULT_SOURCE_URL,
        help="Raw URL for CA/B Forum BR markdown source.",
    )
    parser.add_argument(
        "--baseline-file",
        default="policies/standards_baseline.yaml",
        help="Path to the hand-maintained standards baseline (read only).",
    )
    parser.add_argument(
        "--snapshot-file",
        default="policies/standards_sync_snapshot.yaml",
        help="Path to the generated sync snapshot file.",
    )
    parser.add_argument(
        "--source-file",
        default=None,
        help="Read the BR document from a local file instead of fetching it.",
    )
    parser.add_argument(
        "--fail-on-change",
        action="store_true",
        help=(
            "Exit non-zero when the upstream digest differs from the recorded "
            "snapshot. Use in a scheduled job that should raise a review task."
        ),
    )
    args = parser.parse_args(argv)

    if args.source_file:
        source_text = Path(args.source_file).read_text(encoding="utf-8")
        source_origin = f"file://{args.source_file}"
    else:
        source_text = _fetch_text(args.source_url)
        source_origin = args.source_url

    source_sha256 = hashlib.sha256(source_text.encode("utf-8")).hexdigest()
    snapshot_path = Path(args.snapshot_file)
    previous = _load_previous_snapshot(snapshot_path)
    previous_sha = previous.get("sync", {}).get("source_sha256")
    changed = previous_sha is not None and previous_sha != source_sha256

    baseline = yaml.safe_load(
        Path(args.baseline_file).read_text(encoding="utf-8")
    )
    tracked_schedule = _tracked_schedule(baseline)

    snapshot = {
        "sync": {
            "fetched_at": datetime.now(timezone.utc).isoformat(),
            "source_url": source_origin,
            "source_sha256": source_sha256,
            "previous_source_sha256": previous_sha,
            "source_changed": changed,
            "first_run": previous_sha is None,
        },
        "review": {
            "note": (
                "Values in policies/standards_baseline.yaml are hand-maintained. "
                "This snapshot records only that the upstream document changed."
            ),
            "action_required": (
                "Re-read the CABF ballot schedule and confirm the dated entries "
                "in policies/standards_baseline.yaml."
                if changed
                else "None. Upstream document digest is unchanged."
            ),
            "tracked_schedule": tracked_schedule,
        },
        "observed": {
            # Informational context for the reviewer only.
            "tracked_validity_values_present": _present_values(source_text),
            "schedule_table_lines": _schedule_mentions(source_text),
        },
    }

    snapshot_path.parent.mkdir(parents=True, exist_ok=True)
    snapshot_path.write_text(
        yaml.safe_dump(snapshot, sort_keys=False), encoding="utf-8"
    )

    print(f"source: {source_origin}")
    print(f"sha256: {source_sha256}")
    print(f"changed: {changed}")
    print(f"snapshot written to {snapshot_path}")

    if changed and args.fail_on_change:
        print(
            "Upstream Baseline Requirements changed. A human must review "
            f"{args.baseline_file}.",
            file=sys.stderr,
        )
        return 1
    return 0


def _fetch_text(url: str) -> str:
    req = Request(url, headers={"User-Agent": "certguard-standards-sync/2.0"})
    with urlopen(req, timeout=30) as response:  # nosec B310
        return response.read().decode("utf-8")


def _load_previous_snapshot(path: Path) -> dict:
    if not path.exists():
        return {}
    try:
        payload = yaml.safe_load(path.read_text(encoding="utf-8"))
    except yaml.YAMLError:
        return {}
    return payload if isinstance(payload, dict) else {}


def _tracked_schedule(baseline: object) -> list[dict]:
    if not isinstance(baseline, dict):
        return []
    schedule = baseline.get("schedule")
    if not isinstance(schedule, list):
        return []
    return [
        {
            "effective": str(entry.get("effective")),
            "max_validity_days": entry.get("max_validity_days"),
            "dcv_reuse_days": entry.get("dcv_reuse_days"),
        }
        for entry in schedule
        if isinstance(entry, dict)
    ]


def _present_values(source_text: str) -> dict[str, bool]:
    lowered = source_text.lower()
    return {
        str(value): bool(re.search(rf"\b{value}\s*-?\s*day", lowered))
        for value in TRACKED_VALIDITY_VALUES
    }


def _schedule_mentions(source_text: str, limit: int = 20) -> list[str]:
    hits: list[str] = []
    for line in source_text.splitlines():
        lowered = line.lower()
        if "validity" not in lowered and "reuse" not in lowered:
            continue
        if not re.search(r"\b\d{2,3}\s*-?\s*day", lowered):
            continue
        hits.append(line.strip()[:200])
        if len(hits) >= limit:
            break
    return hits


if __name__ == "__main__":
    raise SystemExit(main())
