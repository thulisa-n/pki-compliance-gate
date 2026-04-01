from __future__ import annotations

import argparse
import hashlib
import re
from datetime import date, datetime, timezone
from pathlib import Path
from urllib.request import Request, urlopen

import yaml

DEFAULT_SOURCE_URL = (
    "https://raw.githubusercontent.com/cabforum/servercert/main/docs/BR.md"
)


def main() -> int:
    parser = argparse.ArgumentParser(description="Sync CABF baseline snapshot and policy hints.")
    parser.add_argument(
        "--source-url",
        default=DEFAULT_SOURCE_URL,
        help="Raw URL for CA/B Forum BR markdown source.",
    )
    parser.add_argument(
        "--baseline-file",
        default="policies/standards_baseline.yaml",
        help="Path to standards baseline file.",
    )
    parser.add_argument(
        "--snapshot-file",
        default="policies/standards_sync_snapshot.yaml",
        help="Path to generated sync snapshot file.",
    )
    args = parser.parse_args()

    source_text = _fetch_text(args.source_url)
    source_sha256 = hashlib.sha256(source_text.encode("utf-8")).hexdigest()
    validity_values = _extract_validity_day_values(source_text)
    recommended_max = _recommended_subscriber_validity(validity_values)
    short_lived = 90 if 90 in validity_values else None

    baseline_path = Path(args.baseline_file)
    baseline_payload = yaml.safe_load(baseline_path.read_text(encoding="utf-8"))
    baseline_payload["baseline"]["source"] = "CA/Browser Forum BR (auto-synced)"
    baseline_payload["baseline"]["last_reviewed"] = date.today().isoformat()
    baseline_payload["baseline"]["version"] = datetime.now(timezone.utc).strftime("%Y.%m.%d")
    baseline_payload["baseline"]["references"] = sorted(
        set(
            baseline_payload["baseline"].get("references", [])
            + ["CAB Forum Baseline Requirements", "RFC 5280"]
        )
    )
    if recommended_max is not None:
        baseline_payload["expected"]["certificate"]["max_validity_days"] = recommended_max

    snapshot_payload = {
        "sync": {
            "fetched_at": datetime.now(timezone.utc).isoformat(),
            "source_url": args.source_url,
            "source_sha256": source_sha256,
        },
        "extracted": {
            "validity_day_values": validity_values,
            "recommended_subscriber_max_validity_days": recommended_max,
            "short_lived_profile_days": short_lived,
        },
    }

    baseline_path.write_text(yaml.safe_dump(baseline_payload, sort_keys=False), encoding="utf-8")
    Path(args.snapshot_file).write_text(
        yaml.safe_dump(snapshot_payload, sort_keys=False), encoding="utf-8"
    )
    return 0


def _fetch_text(url: str) -> str:
    req = Request(url, headers={"User-Agent": "certguard-standards-sync/1.0"})
    with urlopen(req, timeout=30) as response:  # nosec B310
        return response.read().decode("utf-8")


def _extract_validity_day_values(source_text: str) -> list[int]:
    values: set[int] = set()
    for line in source_text.splitlines():
        lower = line.lower()
        if "validity" not in lower and "subscriber certificate" not in lower:
            continue
        for match in re.findall(r"(\d{2,3})\s*-?\s*day", lower):
            values.add(int(match))
    return sorted(values)


def _recommended_subscriber_validity(values: list[int]) -> int | None:
    if 200 in values:
        return 200
    if 398 in values:
        return 398
    if values:
        return min(values)
    return None


if __name__ == "__main__":
    raise SystemExit(main())
