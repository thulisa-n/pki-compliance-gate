from __future__ import annotations

import json
import subprocess
from pathlib import Path

import yaml

from certguard.engine import ComplianceGateEngine


def _write_policy(
    path: Path, *, fail_severities: list[str], enable_zlint: bool = True, fail_on_error: bool = True
) -> None:
    policy = {
        "metadata": {"standard": "CABF", "version": "test", "terms": "test"},
        "certificate": {"max_validity_days": 398, "require_san": True},
        "key": {"minimum_rsa_bits": 2048},
        "signature": {"prohibited_algorithms": ["sha1", "md5"]},
        "domains": {"forbid_internal_names": True, "blocked_suffixes": [".local"]},
        "lint": {
            "enable_zlint": enable_zlint,
            "fail_on_error": fail_on_error,
            "fail_severities": fail_severities,
        },
    }
    path.write_text(yaml.safe_dump(policy, sort_keys=False), encoding="utf-8")


def test_zlint_fails_on_configured_error(monkeypatch, tmp_path: Path) -> None:
    policy_path = tmp_path / "policy.yaml"
    _write_policy(policy_path, fail_severities=["error", "fatal"])
    engine = ComplianceGateEngine(policy_path=policy_path)

    output = json.dumps(
        {
            "results": {
                "e_subject_common_name_not_exactly_from_san": {"result": "error"},
                "w_basic_constraints_not_critical": {"result": "warn"},
            }
        }
    )

    def _fake_run(*args, **kwargs):
        return subprocess.CompletedProcess(args=args, returncode=0, stdout=output, stderr="")

    monkeypatch.setattr(subprocess, "run", _fake_run)
    result = engine._run_zlint_if_enabled(Path("tests/certificates/valid_cert.pem"))

    assert result["status"] == "fail"
    assert "error" in result["summary"]["counts"]
    assert result["summary"]["matched_failures"] == ["e_subject_common_name_not_exactly_from_san"]


def test_zlint_warn_passes_if_warn_not_configured(monkeypatch, tmp_path: Path) -> None:
    policy_path = tmp_path / "policy.yaml"
    _write_policy(policy_path, fail_severities=["error", "fatal"])
    engine = ComplianceGateEngine(policy_path=policy_path)

    output = json.dumps({"results": {"w_test_warn": {"result": "warn"}}})

    def _fake_run(*args, **kwargs):
        return subprocess.CompletedProcess(args=args, returncode=0, stdout=output, stderr="")

    monkeypatch.setattr(subprocess, "run", _fake_run)
    result = engine._run_zlint_if_enabled(Path("tests/certificates/valid_cert.pem"))

    assert result["status"] == "pass"
    assert result["summary"]["counts"].get("warn") == 1
    assert result["summary"]["matched_failures"] == []


def test_zlint_fallback_honors_fail_on_error(monkeypatch, tmp_path: Path) -> None:
    policy_path = tmp_path / "policy.yaml"
    _write_policy(policy_path, fail_severities=["error"], fail_on_error=False)
    engine = ComplianceGateEngine(policy_path=policy_path)

    def _fake_run(*args, **kwargs):
        return subprocess.CompletedProcess(args=args, returncode=1, stdout="not-json", stderr="bad output")

    monkeypatch.setattr(subprocess, "run", _fake_run)
    result = engine._run_zlint_if_enabled(Path("tests/certificates/valid_cert.pem"))

    assert result["status"] == "pass"
    assert result["details"].startswith("zlint output not parseable")
