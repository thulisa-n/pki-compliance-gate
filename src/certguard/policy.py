from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml


class PolicyValidationError(ValueError):
    """Raised when a policy file is missing required keys or types."""


def load_policy(policy_path: Path) -> dict[str, Any]:
    if not policy_path.exists():
        raise FileNotFoundError(f"Policy file not found: {policy_path}")

    with policy_path.open("r", encoding="utf-8") as stream:
        policy = yaml.safe_load(stream)

    if not isinstance(policy, dict):
        raise PolicyValidationError("Policy root must be a mapping/object.")

    _validate_policy(policy)
    return policy


def _validate_policy(policy: dict[str, Any]) -> None:
    required_sections = ["metadata", "certificate", "key", "signature", "domains", "lint"]
    for section in required_sections:
        if section not in policy:
            raise PolicyValidationError(f"Missing required policy section: {section}")
        if not isinstance(policy[section], dict):
            raise PolicyValidationError(f"Policy section '{section}' must be an object.")

    certificate = policy["certificate"]
    _require_key_type(certificate, "max_validity_days", int, "certificate")
    _require_key_type(certificate, "require_san", bool, "certificate")

    key = policy["key"]
    _require_key_type(key, "minimum_rsa_bits", int, "key")

    signature = policy["signature"]
    _require_key_type(signature, "prohibited_algorithms", list, "signature")

    domains = policy["domains"]
    _require_key_type(domains, "forbid_internal_names", bool, "domains")
    _require_key_type(domains, "blocked_suffixes", list, "domains")

    lint = policy["lint"]
    _require_key_type(lint, "enable_zlint", bool, "lint")
    _require_key_type(lint, "fail_on_error", bool, "lint")


def _require_key_type(
    section: dict[str, Any], key: str, expected_type: type, section_name: str
) -> None:
    if key not in section:
        raise PolicyValidationError(f"Missing key '{section_name}.{key}' in policy.")
    if not isinstance(section[key], expected_type):
        type_name = expected_type.__name__
        raise PolicyValidationError(
            f"Policy key '{section_name}.{key}' must be of type {type_name}."
        )
