"""The OPA gate must be derived from the YAML, not a second hand-written limit."""

from __future__ import annotations

import json
from pathlib import Path

import yaml

import certguard.engine as engine_module
from certguard.engine import ComplianceGateEngine
from certguard.policy import load_policy
from certguard.rego import export_policy_to_rego, render_validity_rego

REPO_ROOT = Path(__file__).resolve().parents[1]


def test_generated_rego_uses_the_yaml_validity_limit() -> None:
    policy = load_policy(Path("policies/cabf_policy.yaml"))
    rendered = render_validity_rego(policy)
    max_days = policy["certificate"]["max_validity_days"]

    assert f"certificate.max_validity_days = {max_days}" in rendered
    assert f"input.validity_days <= {max_days}" in rendered
    assert "Do not edit" in rendered


def test_generated_rego_follows_a_100_day_profile() -> None:
    policy = load_policy(Path("policies/cabf_policy.yaml"))
    policy["certificate"]["max_validity_days"] = 100
    rendered = render_validity_rego(policy)

    assert "input.validity_days <= 100" in rendered
    assert "input.validity_days <= 200" not in rendered


def test_export_policy_to_rego_writes_the_file(tmp_path: Path) -> None:
    out = tmp_path / "validity.rego"
    export_policy_to_rego("policies/cabf_policy.yaml", out)
    assert out.exists()
    assert "input.validity_days <=" in out.read_text(encoding="utf-8")


def test_checked_in_rego_cannot_be_a_hand_written_limit() -> None:
    """Any committed .rego must declare it was generated from the YAML."""
    for path in (REPO_ROOT / "policies").rglob("*.rego"):
        text = path.read_text(encoding="utf-8")
        assert "Generated from certificate.max_validity_days" in text, path


def test_opa_evaluation_uses_generated_rego_not_the_policy_file_path(
    tmp_path: Path, monkeypatch
) -> None:
    policy = yaml.safe_load(Path("policies/cabf_policy.yaml").read_text(encoding="utf-8"))
    policy["opa"]["enabled"] = True
    policy["opa"]["policy_file"] = str(tmp_path / "missing.rego")
    policy["certificate"]["max_validity_days"] = 100
    policy_path = tmp_path / "policy.yaml"
    policy_path.write_text(yaml.safe_dump(policy, sort_keys=False), encoding="utf-8")

    captured: dict[str, str] = {}

    def _fake_run(cmd, capture_output, text, check):
        data_file = Path(cmd[cmd.index("--data") + 1])
        captured["rego"] = data_file.read_text(encoding="utf-8")

        class _Result:
            returncode = 0
            stdout = "true\n"
            stderr = ""

        return _Result()

    monkeypatch.setattr(engine_module.subprocess, "run", _fake_run)

    engine = ComplianceGateEngine(policy_path=policy_path)
    engine.evaluate(
        cert_path=Path("tests/certificates/valid_cert.pem"),
        report_path=tmp_path / "report.json",
        evidence_dir=tmp_path / "audit_evidence",
    )

    assert "input.validity_days <= 100" in captured["rego"]
    assert "input.validity_days <= 200" not in captured["rego"]
    evidence = json.loads(
        (tmp_path / "audit_evidence" / "opa_results.json").read_text(encoding="utf-8")
    )
    assert evidence["source"] == "certificate.max_validity_days"
    assert evidence["max_validity_days"] == 100
    generated = (tmp_path / "audit_evidence" / "opa_policy.rego").read_text(encoding="utf-8")
    assert generated == captured["rego"]
