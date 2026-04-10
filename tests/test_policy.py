from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from certguard.policy import PolicyValidationError, load_policy


def test_policy_loader_accepts_current_policy() -> None:
    policy_path = Path("policies/cabf_policy.yaml")
    policy = load_policy(policy_path)
    assert policy["certificate"]["max_validity_days"] == 200


def test_policy_loader_rejects_missing_required_section(tmp_path: Path) -> None:
    invalid_policy = {
        "metadata": {"standard": "CABF", "version": "test"},
        "certificate": {"max_validity_days": 200, "require_san": True},
    }
    policy_path = tmp_path / "invalid_missing_section.yaml"
    policy_path.write_text(yaml.safe_dump(invalid_policy), encoding="utf-8")

    with pytest.raises(PolicyValidationError, match="Missing required policy section"):
        load_policy(policy_path)


def test_policy_loader_rejects_wrong_type(tmp_path: Path) -> None:
    invalid_policy = {
        "metadata": {"standard": "CABF", "version": "test"},
        "certificate": {"max_validity_days": "200", "require_san": True},
        "key": {"minimum_rsa_bits": 2048},
        "signature": {"prohibited_algorithms": ["sha1"]},
        "domains": {"forbid_internal_names": True, "blocked_suffixes": [".local"]},
        "lint": {
            "enable_zlint": False,
            "fail_on_error": True,
            "fail_severities": ["error", "fatal"],
        },
    }
    policy_path = tmp_path / "invalid_type.yaml"
    policy_path.write_text(yaml.safe_dump(invalid_policy), encoding="utf-8")

    with pytest.raises(PolicyValidationError, match="certificate.max_validity_days"):
        load_policy(policy_path)


def test_policy_loader_rejects_invalid_crypto_transition_type(tmp_path: Path) -> None:
    policy = yaml.safe_load(Path("policies/cabf_policy.yaml").read_text(encoding="utf-8"))
    policy["crypto_transition"]["target_min_rsa_bits"] = "3072"
    policy_path = tmp_path / "invalid_crypto_transition_type.yaml"
    policy_path.write_text(yaml.safe_dump(policy), encoding="utf-8")

    with pytest.raises(PolicyValidationError, match="crypto_transition.target_min_rsa_bits"):
        load_policy(policy_path)
