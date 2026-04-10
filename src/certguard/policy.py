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

    _apply_defaults(policy)
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
    _require_key_type(lint, "fail_severities", list, "lint")
    _require_key_type(lint, "enable_asn1parse", bool, "lint")
    _require_key_type(lint, "fail_on_asn1_error", bool, "lint")
    _require_list_of_strings(lint["fail_severities"], "lint.fail_severities")

    dcv = policy["dcv"]
    _require_key_type(dcv, "required", bool, "dcv")
    _require_key_type(dcv, "allowed_methods", list, "dcv")
    _require_key_type(dcv, "max_age_days", int, "dcv")
    _require_list_of_strings(dcv["allowed_methods"], "dcv.allowed_methods")

    rfc5280 = policy["rfc5280"]
    _require_key_type(rfc5280, "require_end_entity_not_ca", bool, "rfc5280")
    _require_key_type(rfc5280, "require_key_usage", bool, "rfc5280")
    _require_key_type(rfc5280, "required_key_usages", list, "rfc5280")
    _require_key_type(rfc5280, "require_subject_key_identifier", bool, "rfc5280")
    _require_key_type(rfc5280, "require_authority_key_identifier", bool, "rfc5280")
    _require_key_type(rfc5280, "allowed_critical_extensions", list, "rfc5280")
    _require_key_type(
        rfc5280, "require_path_issuer_subject_match", bool, "rfc5280"
    )
    _require_key_type(rfc5280, "require_path_aki_ski_match", bool, "rfc5280")
    _require_list_of_strings(rfc5280["required_key_usages"], "rfc5280.required_key_usages")
    _require_list_of_strings(
        rfc5280["allowed_critical_extensions"], "rfc5280.allowed_critical_extensions"
    )

    opa = policy["opa"]
    _require_key_type(opa, "enabled", bool, "opa")
    _require_key_type(opa, "policy_file", str, "opa")

    issuance = policy["issuance"]
    _require_key_type(issuance, "require_hsm_attestation", bool, "issuance")
    _require_key_type(issuance, "min_fips_level", int, "issuance")

    crypto_transition = policy["crypto_transition"]
    _require_key_type(crypto_transition, "enabled", bool, "crypto_transition")
    _require_key_type(
        crypto_transition,
        "target_max_validity_days",
        int,
        "crypto_transition",
    )
    _require_key_type(
        crypto_transition,
        "target_min_rsa_bits",
        int,
        "crypto_transition",
    )
    _require_key_type(
        crypto_transition,
        "approved_signature_algorithms",
        list,
        "crypto_transition",
    )
    _require_list_of_strings(
        crypto_transition["approved_signature_algorithms"],
        "crypto_transition.approved_signature_algorithms",
    )


def _apply_defaults(policy: dict[str, Any]) -> None:
    policy.setdefault("lint", {})
    policy["lint"].setdefault("enable_asn1parse", False)
    policy["lint"].setdefault("fail_on_asn1_error", True)

    policy.setdefault("dcv", {})
    policy["dcv"].setdefault("required", False)
    policy["dcv"].setdefault("allowed_methods", [])
    policy["dcv"].setdefault("max_age_days", 30)

    policy.setdefault("rfc5280", {})
    policy["rfc5280"].setdefault("require_end_entity_not_ca", False)
    policy["rfc5280"].setdefault("require_key_usage", False)
    policy["rfc5280"].setdefault("required_key_usages", [])
    policy["rfc5280"].setdefault("require_subject_key_identifier", False)
    policy["rfc5280"].setdefault("require_authority_key_identifier", False)
    policy["rfc5280"].setdefault("allowed_critical_extensions", [])
    policy["rfc5280"].setdefault("require_path_issuer_subject_match", False)
    policy["rfc5280"].setdefault("require_path_aki_ski_match", False)

    policy.setdefault("opa", {})
    policy["opa"].setdefault("enabled", False)
    policy["opa"].setdefault("policy_file", "policies/rego/validity.rego")

    policy.setdefault("issuance", {})
    policy["issuance"].setdefault("require_hsm_attestation", False)
    policy["issuance"].setdefault("min_fips_level", 2)

    policy.setdefault("crypto_transition", {})
    policy["crypto_transition"].setdefault("enabled", False)
    policy["crypto_transition"].setdefault("target_max_validity_days", 90)
    policy["crypto_transition"].setdefault("target_min_rsa_bits", 3072)
    policy["crypto_transition"].setdefault(
        "approved_signature_algorithms", ["sha256", "sha384", "sha512"]
    )


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


def _require_list_of_strings(values: list[Any], field_name: str) -> None:
    for value in values:
        if not isinstance(value, str):
            raise PolicyValidationError(f"Policy key '{field_name}' must contain only strings.")
