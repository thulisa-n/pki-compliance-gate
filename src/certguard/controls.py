"""Declarative control registry.

Metadata, CP/CPS export, assurance defaults, and the README coverage matrix
all derive from ``CONTROLS``. Adding a control means adding one ``Control``
row (and an evaluator in the policy validator), not five copy-pasted tables.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class Control:
    name: str
    rule_id: str
    category: str
    severity: str
    standard_reference: str
    rationale: str
    recommendation: str
    policy_path: str | None = None
    enabled_when: str | None = None

    def metadata(self) -> dict[str, str]:
        return {
            "rule_id": self.rule_id,
            "category": self.category,
            "severity": self.severity,
            "standard_reference": self.standard_reference,
            "rationale": self.rationale,
            "recommendation": self.recommendation,
        }


def registry_from_metadata(
    metadata: dict[str, dict[str, str]],
    policy_paths: dict[str, str] | None = None,
    enabled_when: dict[str, str] | None = None,
) -> tuple[Control, ...]:
    paths = policy_paths or {}
    gates = enabled_when or {}
    return tuple(
        Control(
            name=name,
            policy_path=paths.get(name),
            enabled_when=gates.get(name),
            **fields,
        )
        for name, fields in metadata.items()
    )


def metadata_from_registry(controls: tuple[Control, ...]) -> dict[str, dict[str, str]]:
    return {control.name: control.metadata() for control in controls}


CONTROL_POLICY_PATHS: dict[str, str] = {
    "validity_days": "certificate.max_validity_days",
    "certificate_not_expired": "certificate.reject_expired",
    "certificate_not_yet_valid": "certificate.reject_not_yet_valid",
    "certificate_expiry_window": "certificate.warn_if_expires_within_days",
    "san_extension": "certificate.require_san",
    "key_algorithm_allowed": "key.allowed_algorithms",
    "rsa_key_size": "key.minimum_rsa_bits",
    "ec_key_size": "key.minimum_ec_bits",
    "ec_curve_allowed": "key.allowed_ec_curves",
    "signature_algorithm": "signature.prohibited_algorithms",
    "signature_algorithm_oid": "signature.allowed_oids",
    "internal_domain_check": "domains.forbid_internal_names",
    "serial_entropy": "certificate.min_serial_bits",
    "sct_presence": "certificate.require_sct",
    "extended_key_usage": "certificate.require_eku",
    "dcv_method": "dcv.required",
    "dcv_recency": "dcv.required",
    "rfc5280_end_entity_ca": "rfc5280.require_end_entity_not_ca",
    "rfc5280_key_usage_profile": "rfc5280.require_key_usage",
    "rfc5280_subject_key_identifier": "rfc5280.require_subject_key_identifier",
    "rfc5280_authority_key_identifier": "rfc5280.require_authority_key_identifier",
    "rfc5280_path_issuer_subject_match": "rfc5280.require_path_issuer_subject_match",
    "rfc5280_path_aki_ski_match": "rfc5280.require_path_aki_ski_match",
    "issuance_hsm_attestation": "issuance.require_hsm_attestation",
    "issuance_fips_level": "issuance.min_fips_level",
    "crypto_transition_validity_target": "crypto_transition.enabled",
    "crypto_transition_rsa_target": "crypto_transition.enabled",
    "crypto_transition_signature_hash": "crypto_transition.enabled",
}


def nested_get(payload: dict[str, Any], path: str) -> Any:
    current: Any = payload
    for part in path.split("."):
        if not isinstance(current, dict):
            return None
        current = current.get(part)
    return current
