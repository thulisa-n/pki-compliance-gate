"""The standards sync script must detect change, not invent policy values."""

from __future__ import annotations

from pathlib import Path

import yaml

from scripts.sync_cabf_baseline import main

BR_TEXT = """# Baseline Requirements
Subscriber Certificates issued on or after 2026-03-15 MUST have a Validity
Period of at most 200 days.
Subscriber Certificates issued on or after 2027-03-15 MUST have a Validity
Period of at most 100 days.
"""


def _write_source(tmp_path: Path, text: str) -> Path:
    path = tmp_path / "BR.md"
    path.write_text(text, encoding="utf-8")
    return path


def test_first_run_records_digest_without_failing(tmp_path: Path) -> None:
    source = _write_source(tmp_path, BR_TEXT)
    snapshot = tmp_path / "snapshot.yaml"

    code = main(
        [
            "--source-file", str(source),
            "--snapshot-file", str(snapshot),
            "--fail-on-change",
        ]
    )

    assert code == 0
    payload = yaml.safe_load(snapshot.read_text(encoding="utf-8"))
    assert payload["sync"]["first_run"] is True
    assert payload["sync"]["source_sha256"]


def test_unchanged_source_does_not_raise(tmp_path: Path) -> None:
    source = _write_source(tmp_path, BR_TEXT)
    snapshot = tmp_path / "snapshot.yaml"
    args = [
        "--source-file", str(source),
        "--snapshot-file", str(snapshot),
        "--fail-on-change",
    ]

    assert main(args) == 0
    assert main(args) == 0
    payload = yaml.safe_load(snapshot.read_text(encoding="utf-8"))
    assert payload["sync"]["source_changed"] is False


def test_changed_source_raises_for_human_review(tmp_path: Path) -> None:
    source = _write_source(tmp_path, BR_TEXT)
    snapshot = tmp_path / "snapshot.yaml"
    args = [
        "--source-file", str(source),
        "--snapshot-file", str(snapshot),
        "--fail-on-change",
    ]
    main(args)

    source.write_text(BR_TEXT + "\nAmended by ballot SC-099.\n", encoding="utf-8")

    assert main(args) == 1
    payload = yaml.safe_load(snapshot.read_text(encoding="utf-8"))
    assert payload["sync"]["source_changed"] is True
    assert "Re-read the CABF ballot" in payload["review"]["action_required"]


def test_sync_never_rewrites_the_baseline(tmp_path: Path) -> None:
    """The scraper used to overwrite policy numbers. It must not any more."""
    baseline = Path("policies/standards_baseline.yaml")
    before = baseline.read_bytes()
    source = _write_source(tmp_path, BR_TEXT)

    main(
        [
            "--source-file", str(source),
            "--snapshot-file", str(tmp_path / "snapshot.yaml"),
            "--baseline-file", str(baseline),
        ]
    )

    assert baseline.read_bytes() == before


def test_snapshot_echoes_the_tracked_schedule_for_the_reviewer(
    tmp_path: Path,
) -> None:
    source = _write_source(tmp_path, BR_TEXT)
    snapshot = tmp_path / "snapshot.yaml"

    main(
        [
            "--source-file", str(source),
            "--snapshot-file", str(snapshot),
            "--baseline-file", "policies/standards_baseline.yaml",
        ]
    )

    payload = yaml.safe_load(snapshot.read_text(encoding="utf-8"))
    effective_dates = {
        entry["effective"] for entry in payload["review"]["tracked_schedule"]
    }
    assert {"2026-03-15", "2027-03-15", "2029-03-15"} <= effective_dates
