from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Any

import yaml

#: Version of the policy YAML structure this build understands. Recorded in
#: reports so a finding can be traced to the schema that produced it.
POLICY_SCHEMA_VERSION = "2.0"

#: CA/Browser Forum BR 6.1.5 permits only these NIST curves for subscriber
#: ECDSA keys. Exposed as the default so a policy that says nothing about
#: elliptic curves still rejects an off-profile curve.
CABF_APPROVED_EC_CURVES: tuple[str, ...] = ("secp256r1", "secp384r1", "secp521r1")


class PolicyValidationError(ValueError):
    """Raised when a policy file is missing required keys or types."""


def load_policy(policy_path: Path) -> dict[str, Any]:
    if not policy_path.exists():
        raise FileNotFoundError(f"Policy file not found: {policy_path}")

    raw = policy_path.read_text(encoding="utf-8")
    policy = yaml.safe_load(raw)

    if not isinstance(policy, dict):
        raise PolicyValidationError("Policy root must be a mapping/object.")

    _apply_defaults(policy)
    _validate_policy(policy)
    # Recorded so evidence can prove which policy bytes produced a verdict,
    # not merely which version string the file claimed.
    policy.setdefault("_meta", {})["sha256"] = hashlib.sha256(
        raw.encode("utf-8")
    ).hexdigest()
    policy["_meta"]["source_path"] = str(policy_path)
    return policy


def policy_digest(policy: dict[str, Any]) -> str:
    return str(policy.get("_meta", {}).get("sha256", "unknown"))


# (section, key, expected_type) for every key the engine reads. Keeping this as
# data rather than a wall of calls means a new control adds one row here and
# one default below, and the pair cannot drift apart unnoticed.
_REQUIRED_KEYS: tuple[tuple[str, str, type], ...] = (
    ("certificate", "max_validity_days", int),
    ("certificate", "require_san", bool),
    ("certificate", "reject_expired", bool),
    ("certificate", "reject_not_yet_valid", bool),
    ("certificate", "warn_if_expires_within_days", int),
    ("key", "minimum_rsa_bits", int),
    ("key", "allowed_algorithms", list),
    ("key", "minimum_ec_bits", int),
    ("key", "allowed_ec_curves", list),
    ("signature", "prohibited_algorithms", list),
    ("domains", "forbid_internal_names", bool),
    ("domains", "blocked_suffixes", list),
    ("lint", "enable_zlint", bool),
    ("lint", "fail_on_error", bool),
    ("lint", "fail_severities", list),
    ("lint", "enable_asn1parse", bool),
    ("lint", "fail_on_asn1_error", bool),
    ("dcv", "required", bool),
    ("dcv", "allowed_methods", list),
    ("dcv", "max_age_days", int),
    ("rfc5280", "require_end_entity_not_ca", bool),
    ("rfc5280", "require_key_usage", bool),
    ("rfc5280", "required_key_usages", list),
    ("rfc5280", "require_subject_key_identifier", bool),
    ("rfc5280", "require_authority_key_identifier", bool),
    ("rfc5280", "allowed_critical_extensions", list),
    ("rfc5280", "require_path_issuer_subject_match", bool),
    ("rfc5280", "require_path_aki_ski_match", bool),
    ("opa", "enabled", bool),
    ("opa", "policy_file", str),
    ("issuance", "require_hsm_attestation", bool),
    ("issuance", "min_fips_level", int),
    ("crypto_transition", "enabled", bool),
    ("crypto_transition", "target_max_validity_days", int),
    ("crypto_transition", "target_min_rsa_bits", int),
    ("crypto_transition", "approved_signature_algorithms", list),
)

_STRING_LISTS: tuple[tuple[str, str], ...] = (
    ("key", "allowed_algorithms"),
    ("key", "allowed_ec_curves"),
    ("lint", "fail_severities"),
    ("dcv", "allowed_methods"),
    ("rfc5280", "required_key_usages"),
    ("rfc5280", "allowed_critical_extensions"),
    ("crypto_transition", "approved_signature_algorithms"),
)

_REQUIRED_SECTIONS: tuple[str, ...] = (
    "metadata",
    "certificate",
    "key",
    "signature",
    "domains",
    "lint",
)

_KNOWN_KEY_ALGORITHMS: frozenset[str] = frozenset(
    {"rsa", "ec", "ed25519", "ed448", "dsa"}
)


def _validate_policy(policy: dict[str, Any]) -> None:
    for section in _REQUIRED_SECTIONS:
        if section not in policy:
            raise PolicyValidationError(f"Missing required policy section: {section}")
        if not isinstance(policy[section], dict):
            raise PolicyValidationError(f"Policy section '{section}' must be an object.")

    for section, key, expected_type in _REQUIRED_KEYS:
        _require_key_type(policy[section], key, expected_type, section)

    for section, key in _STRING_LISTS:
        _require_list_of_strings(policy[section][key], f"{section}.{key}")

    unknown_algorithms = sorted(
        {value.strip().lower() for value in policy["key"]["allowed_algorithms"]}
        - _KNOWN_KEY_ALGORITHMS
    )
    if unknown_algorithms:
        raise PolicyValidationError(
            "Policy key 'key.allowed_algorithms' contains unsupported algorithms: "
            f"{', '.join(unknown_algorithms)}. "
            f"Supported: {', '.join(sorted(_KNOWN_KEY_ALGORITHMS))}."
        )
    if not policy["key"]["allowed_algorithms"]:
        raise PolicyValidationError(
            "Policy key 'key.allowed_algorithms' must list at least one algorithm; "
            "an empty list would reject every certificate."
        )

    for section, key in (
        ("certificate", "max_validity_days"),
        ("key", "minimum_rsa_bits"),
        ("key", "minimum_ec_bits"),
        ("dcv", "max_age_days"),
        ("crypto_transition", "target_max_validity_days"),
        ("crypto_transition", "target_min_rsa_bits"),
    ):
        if policy[section][key] <= 0:
            raise PolicyValidationError(
                f"Policy key '{section}.{key}' must be greater than zero."
            )

    if policy["certificate"]["warn_if_expires_within_days"] < 0:
        raise PolicyValidationError(
            "Policy key 'certificate.warn_if_expires_within_days' must be zero "
            "(disabled) or a positive number of days."
        )


def _apply_defaults(policy: dict[str, Any]) -> None:
    policy.setdefault("metadata", {})
    policy["metadata"].setdefault("policy_schema_version", POLICY_SCHEMA_VERSION)

    policy.setdefault("certificate", {})
    # Expiry enforcement defaults ON. An expired certificate previously
    # evaluated as fully compliant because nothing compared notAfter to the
    # evaluation time -- only the length of the validity window was checked.
    policy["certificate"].setdefault("reject_expired", True)
    policy["certificate"].setdefault("reject_not_yet_valid", True)
    # Renewal pressure is an operational signal, not a compliance defect, so it
    # stays opt-in: a certificate valid for another 10 days is still compliant.
    # Set a positive number of days to surface it as a low-severity finding.
    policy["certificate"].setdefault("warn_if_expires_within_days", 0)

    policy.setdefault("key", {})
    # Defaults ON. Previously any non-RSA key skipped key-strength policy
    # entirely, so a 192-bit EC certificate passed unchallenged.
    policy["key"].setdefault("allowed_algorithms", ["rsa", "ec"])
    policy["key"].setdefault("minimum_ec_bits", 256)
    policy["key"].setdefault("allowed_ec_curves", list(CABF_APPROVED_EC_CURVES))

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
    # bool is a subclass of int in Python; an int field must not silently accept
    # `true`, and a bool field must not accept `1`.
    value = section[key]
    if expected_type is int and isinstance(value, bool):
        raise PolicyValidationError(
            f"Policy key '{section_name}.{key}' must be of type int, not bool."
        )
    if expected_type is bool and not isinstance(value, bool):
        raise PolicyValidationError(
            f"Policy key '{section_name}.{key}' must be of type bool."
        )
    if not isinstance(value, expected_type):
        raise PolicyValidationError(
            f"Policy key '{section_name}.{key}' must be of type {expected_type.__name__}."
        )


def _require_list_of_strings(values: list[Any], field_name: str) -> None:
    for value in values:
        if not isinstance(value, str):
            raise PolicyValidationError(
                f"Policy key '{field_name}' must contain only strings."
            )
