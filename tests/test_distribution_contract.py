from __future__ import annotations

import re
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


def test_readme_action_tag_matches_the_packaged_version() -> None:
    """Stop the README pointing at a tag that does not exist.

    Before 0.2.0 the README told Marketplace users
    ``uses: thulisa-n/pki-compliance-gate@v0.1.3`` while the newest tag in the
    repository was v0.1.2. Asserting Action pins, pip pins, and the release
    badge agree with ``pyproject.toml`` makes that drift a test failure.
    """
    pyproject = (REPO_ROOT / "pyproject.toml").read_text(encoding="utf-8")
    version = re.search(r'^version = "([^"]+)"', pyproject, re.M).group(1)
    readme = (REPO_ROOT / "README.md").read_text(encoding="utf-8")

    action_tags = set(re.findall(r"pki-compliance-gate@v([0-9][^\s`\"']*)", readme))
    pip_pins = set(re.findall(r"pki-compliance-gate==([0-9][^\s`\"']*)", readme))
    badges = set(re.findall(r"badge/release-v([^-\s)]+)", readme))

    assert action_tags, "README no longer shows an Action usage example"
    assert action_tags == {version}, (
        f"README Action tag(s) {sorted(action_tags)} but package version is {version}"
    )
    assert pip_pins == {version}, (
        f"README pip pin(s) {sorted(pip_pins)} but package version is {version}"
    )
    assert badges == {version}, (
        f"README release badge(s) {sorted(badges)} but package version is {version}"
    )
