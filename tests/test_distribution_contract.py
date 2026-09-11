from __future__ import annotations

from pathlib import Path

import yaml

from certguard.cli import default_policy_path


REPO_ROOT = Path(__file__).resolve().parents[1]


def test_packaged_policy_matches_repository_source() -> None:
    repository_policy = REPO_ROOT / "policies" / "cabf_policy.yaml"
    packaged_policy = REPO_ROOT / "src" / "certguard" / "data" / "cabf_policy.yaml"

    assert packaged_policy.read_bytes() == repository_policy.read_bytes()


def test_default_policy_is_available_outside_repository(
    tmp_path: Path, monkeypatch
) -> None:
    monkeypatch.chdir(tmp_path)

    policy_path = Path(default_policy_path())

    assert policy_path.exists()
    assert yaml.safe_load(policy_path.read_text(encoding="utf-8"))["certificate"][
        "max_validity_days"
    ] == 200


def test_root_action_wires_documented_outputs() -> None:
    action = yaml.safe_load((REPO_ROOT / "action.yml").read_text(encoding="utf-8"))

    assert action["outputs"]["exit_code"]["value"] == "${{ steps.gate.outputs.exit_code }}"
    assert action["outputs"]["report_path"]["value"] == (
        "${{ steps.gate.outputs.report_path }}"
    )
    assert any(step.get("id") == "gate" for step in action["runs"]["steps"])
