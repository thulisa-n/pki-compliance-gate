from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from certguard.agents.base import BaseAgent
from certguard.models import AgentResult, CheckResult

CHECK_METADATA: dict[str, dict[str, str]] = {
    "validity_days": {
        "rule_id": "CAB-BR-6.3.2",
        "category": "VALIDITY",
        "severity": "high",
        "standard_reference": "CA/B Forum BR 7.1.2.4",
        "rationale": "Long validity windows increase exposure when private keys are compromised.",
        "recommendation": "Reissue certificate with validity at or below policy threshold.",
    },
    "san_extension": {
        "rule_id": "RFC-5280-4.2.1.6",
        "category": "IDENTITY",
        "severity": "high",
        "standard_reference": "CA/B Forum BR 7.1.4.2.1",
        "rationale": "Modern TLS clients rely on SAN for hostname validation.",
        "recommendation": "Issue certificate with SAN entries matching intended hostnames.",
    },
    "rsa_key_size": {
        "rule_id": "CAB-BR-6.1.5",
        "category": "CRYPTOGRAPHY",
        "severity": "critical",
        "standard_reference": "CA/B Forum BR 6.1.5",
        "rationale": "Weak RSA keys reduce cryptographic strength and trust assurance.",
        "recommendation": "Generate key pair with RSA 2048+ before issuance.",
    },
    "signature_algorithm": {
        "rule_id": "CAB-BR-7.1.3",
        "category": "CRYPTOGRAPHY",
        "severity": "critical",
        "standard_reference": "CA/B Forum BR 7.1.3",
        "rationale": "Deprecated hash algorithms can be vulnerable to collision attacks.",
        "recommendation": "Use SHA-256 or stronger signature algorithm.",
    },
    "internal_domain_check": {
        "rule_id": "CAB-BR-7.1.4.2.1",
        "category": "POLICY",
        "severity": "high",
        "standard_reference": "CA/B Forum BR 7.1.4.2.1",
        "rationale": "Internal names are not valid for publicly trusted certificates.",
        "recommendation": "Replace internal SAN values with public DNS names.",
    },
    "dcv_method": {
        "rule_id": "CAB-BR-3.2.2.4",
        "category": "DCV",
        "severity": "high",
        "standard_reference": "CA/B Forum BR 3.2.2.4",
        "rationale": "Domain Control Validation must use approved methods before issuance.",
        "recommendation": "Use an approved DCV method and record validation evidence.",
    },
    "dcv_recency": {
        "rule_id": "CAB-BR-4.2.1",
        "category": "DCV",
        "severity": "high",
        "standard_reference": "CA/B Forum BR 4.2.1",
        "rationale": "Stale domain validation evidence can invalidate issuance decisions.",
        "recommendation": "Re-run DCV within the allowed validation window.",
    },
    "rfc5280_end_entity_ca": {
        "rule_id": "RFC-5280-4.2.1.9",
        "category": "RFC5280",
        "severity": "high",
        "standard_reference": "RFC 5280 4.2.1.9",
        "rationale": "Subscriber certificates should not present CA basic constraints.",
        "recommendation": "Issue end-entity certificate with BasicConstraints CA set to FALSE.",
    },
    "rfc5280_key_usage_profile": {
        "rule_id": "RFC-5280-4.2.1.3",
        "category": "RFC5280",
        "severity": "high",
        "standard_reference": "RFC 5280 4.2.1.3",
        "rationale": "Key usage extensions must align with intended certificate purpose.",
        "recommendation": "Set key usage extension to include required subscriber usages.",
    },
    "rfc5280_subject_key_identifier": {
        "rule_id": "RFC-5280-4.2.1.2",
        "category": "RFC5280",
        "severity": "medium",
        "standard_reference": "RFC 5280 4.2.1.2",
        "rationale": "SKI helps bind subject keys to certificate lifecycle and chain processing.",
        "recommendation": "Include Subject Key Identifier extension for leaf profile consistency.",
    },
    "rfc5280_authority_key_identifier": {
        "rule_id": "RFC-5280-4.2.1.1",
        "category": "RFC5280",
        "severity": "medium",
        "standard_reference": "RFC 5280 4.2.1.1",
        "rationale": "AKI supports robust issuer key linkage during path validation.",
        "recommendation": "Include Authority Key Identifier extension for issuer linkage.",
    },
    "rfc5280_critical_extension_profile": {
        "rule_id": "RFC-5280-4.2",
        "category": "RFC5280",
        "severity": "high",
        "standard_reference": "RFC 5280 4.2",
        "rationale": "Unexpected critical extensions can break relying-party validation behavior.",
        "recommendation": "Restrict critical extensions to an approved extension profile.",
    },
    "rfc5280_path_issuer_subject_match": {
        "rule_id": "RFC-5280-6",
        "category": "RFC5280",
        "severity": "high",
        "standard_reference": "RFC 5280 6.1",
        "rationale": "Issuer and subject linkage is required for path construction.",
        "recommendation": "Provide the issuing certificate and validate issuer-subject linkage.",
    },
    "rfc5280_path_aki_ski_match": {
        "rule_id": "RFC-5280-4.2.1.1",
        "category": "RFC5280",
        "severity": "medium",
        "standard_reference": "RFC 5280 4.2.1.1",
        "rationale": "AKI/SKI linkage improves deterministic path validation.",
        "recommendation": "Ensure leaf AKI matches issuer SKI.",
    },
    "issuance_hsm_attestation": {
        "rule_id": "PKCS11-HSM-ATTESTATION",
        "category": "ISSUANCE",
        "severity": "high",
        "standard_reference": "PKCS#11 / FIPS operations",
        "rationale": "Key custody controls require evidence of hardware-backed issuance operations.",
        "recommendation": "Provide issuance attestation indicating HSM-backed key operations.",
    },
    "issuance_fips_level": {
        "rule_id": "FIPS-140-CONTROL",
        "category": "ISSUANCE",
        "severity": "medium",
        "standard_reference": "FIPS 140-2/140-3",
        "rationale": "Cryptographic module assurance levels are key audit controls.",
        "recommendation": "Provide attested FIPS level meeting minimum policy requirement.",
    },
    "crypto_transition_validity_target": {
        "rule_id": "CRYPTO-AGILITY-VALIDITY",
        "category": "CRYPTO-TRANSITION",
        "severity": "high",
        "standard_reference": "Crypto transition readiness profile",
        "rationale": "Short-lived certificate profiles reduce exposure and improve rotation agility.",
        "recommendation": "Reduce certificate validity to transition target or lower.",
    },
    "crypto_transition_rsa_target": {
        "rule_id": "CRYPTO-AGILITY-RSA",
        "category": "CRYPTO-TRANSITION",
        "severity": "medium",
        "standard_reference": "Crypto transition readiness profile",
        "rationale": "Stronger key sizes improve resilience during algorithm transition periods.",
        "recommendation": "Issue RSA certificates at or above the transition RSA key target.",
    },
    "crypto_transition_signature_hash": {
        "rule_id": "CRYPTO-AGILITY-HASH",
        "category": "CRYPTO-TRANSITION",
        "severity": "high",
        "standard_reference": "Crypto transition readiness profile",
        "rationale": "Approved signature hashes reduce risk from weak or deprecated digests.",
        "recommendation": "Use signature hash algorithms from the approved transition allowlist.",
    },
}


class PolicyValidatorAgent(BaseAgent):
    def __init__(self) -> None:
        super().__init__(name="policy_validator_agent")

    def run(self, context: dict[str, Any]) -> AgentResult:
        policy = context["policy"]
        parser_data = context["parser_data"]
        dcv_attestation = context.get("dcv_attestation")
        issuer_parser_data = context.get("issuer_parser_data")
        issuance_attestation = context.get("issuance_attestation")
        checks: list[CheckResult] = []

        max_validity = policy["certificate"]["max_validity_days"]
        validity_days = parser_data["validity_days"]
        checks.append(
            self._check(
                "validity_days",
                validity_days <= max_validity,
                f"Certificate validity is {validity_days} days (max {max_validity})",
                policy_value=max_validity,
                actual_value=validity_days,
            )
        )

        require_san = policy["certificate"]["require_san"]
        san_dns = parser_data["san_dns"]
        checks.append(
            self._check(
                "san_extension",
                (not require_san) or bool(san_dns),
                "SAN extension present" if san_dns else "SAN extension missing",
                policy_value=require_san,
                actual_value=bool(san_dns),
            )
        )

        min_rsa_bits = policy["key"]["minimum_rsa_bits"]
        is_rsa = parser_data["is_rsa"]
        rsa_bits = parser_data["rsa_key_size"]
        rsa_ok = (not is_rsa) or (rsa_bits is not None and rsa_bits >= min_rsa_bits)
        checks.append(
            self._check(
                "rsa_key_size",
                rsa_ok,
                (
                    f"RSA key size is {rsa_bits} bits (min {min_rsa_bits})"
                    if is_rsa
                    else "Non-RSA key; RSA size check not applicable"
                ),
                policy_value=min_rsa_bits,
                actual_value=rsa_bits,
            )
        )

        forbidden_algorithms = {
            algo.lower() for algo in policy["signature"]["prohibited_algorithms"]
        }
        signature_algorithm = parser_data["signature_algorithm"].lower()
        checks.append(
            self._check(
                "signature_algorithm",
                signature_algorithm not in forbidden_algorithms,
                f"Signature algorithm is {signature_algorithm}",
                policy_value=sorted(forbidden_algorithms),
                actual_value=signature_algorithm,
            )
        )

        domain_checks = self._internal_domain_checks(policy, parser_data)
        checks.extend(domain_checks)
        checks.extend(self._dcv_checks(policy, dcv_attestation))
        checks.extend(self._rfc5280_checks(policy, parser_data, issuer_parser_data))
        checks.extend(self._issuance_checks(policy, issuance_attestation))
        checks.extend(self._crypto_transition_checks(policy, parser_data))

        success = all(check.status == "pass" for check in checks)
        return AgentResult(agent=self.name, success=success, checks=checks)

    def _dcv_checks(
        self, policy: dict[str, Any], dcv_attestation: dict[str, Any] | None
    ) -> list[CheckResult]:
        dcv_cfg = policy["dcv"]
        if not dcv_cfg["required"]:
            return [
                self._check(
                    "dcv_method",
                    True,
                    "DCV checks disabled by policy",
                    policy_value=False,
                    actual_value=False,
                ),
                self._check(
                    "dcv_recency",
                    True,
                    "DCV recency checks disabled by policy",
                    policy_value=False,
                    actual_value=False,
                ),
            ]

        if not isinstance(dcv_attestation, dict):
            return [
                self._check(
                    "dcv_method",
                    False,
                    "DCV attestation is required but missing.",
                    policy_value=dcv_cfg["allowed_methods"],
                    actual_value=None,
                ),
                self._check(
                    "dcv_recency",
                    False,
                    "DCV attestation timestamp is required but missing.",
                    policy_value=dcv_cfg["max_age_days"],
                    actual_value=None,
                ),
            ]

        method = str(dcv_attestation.get("method", "")).strip().lower()
        allowed = {value.lower() for value in dcv_cfg["allowed_methods"]}
        method_ok = method in allowed if allowed else False

        recency_ok, recency_details, actual_age = self._dcv_recency(
            dcv_attestation.get("validated_at"), dcv_cfg["max_age_days"]
        )

        return [
            self._check(
                "dcv_method",
                method_ok,
                (
                    f"DCV method '{method}' accepted."
                    if method_ok
                    else f"DCV method '{method or 'missing'}' not allowed."
                ),
                policy_value=sorted(allowed),
                actual_value=method or None,
            ),
            self._check(
                "dcv_recency",
                recency_ok,
                recency_details,
                policy_value=dcv_cfg["max_age_days"],
                actual_value=actual_age,
            ),
        ]

    def _dcv_recency(
        self, validated_at: Any, max_age_days: int
    ) -> tuple[bool, str, int | None]:
        if not isinstance(validated_at, str) or not validated_at.strip():
            return False, "DCV attestation missing validated_at timestamp.", None
        try:
            timestamp = datetime.fromisoformat(validated_at.replace("Z", "+00:00"))
        except ValueError:
            return False, "DCV validated_at timestamp is not ISO-8601.", None

        now = datetime.now(timezone.utc)
        if timestamp.tzinfo is None:
            timestamp = timestamp.replace(tzinfo=timezone.utc)
        age_days = (now - timestamp.astimezone(timezone.utc)).days
        if age_days < 0:
            return False, "DCV validated_at is in the future.", age_days
        if age_days <= max_age_days:
            return True, f"DCV attestation age is {age_days} days (max {max_age_days}).", age_days
        return False, f"DCV attestation age is {age_days} days (max {max_age_days}).", age_days

    def _rfc5280_checks(
        self,
        policy: dict[str, Any],
        parser_data: dict[str, Any],
        issuer_parser_data: dict[str, Any] | None,
    ) -> list[CheckResult]:
        rfc_cfg = policy["rfc5280"]
        checks: list[CheckResult] = []

        if rfc_cfg["require_end_entity_not_ca"]:
            basic_ca = parser_data.get("basic_constraints_ca")
            checks.append(
                self._check(
                    "rfc5280_end_entity_ca",
                    basic_ca is False,
                    (
                        "BasicConstraints CA is FALSE."
                        if basic_ca is False
                        else "BasicConstraints CA is TRUE or missing for end-entity profile."
                    ),
                    policy_value=False,
                    actual_value=basic_ca,
                )
            )
        else:
            checks.append(
                self._check(
                    "rfc5280_end_entity_ca",
                    True,
                    "RFC 5280 end-entity CA check disabled by policy.",
                    policy_value=False,
                    actual_value=False,
                )
            )

        if rfc_cfg["require_key_usage"]:
            required = {value.lower() for value in rfc_cfg["required_key_usages"]}
            actual = {value.lower() for value in parser_data.get("key_usage", [])}
            missing = sorted(required - actual)
            checks.append(
                self._check(
                    "rfc5280_key_usage_profile",
                    not missing,
                    (
                        "Required key usage flags are present."
                        if not missing
                        else f"Missing key usage flags: {', '.join(missing)}"
                    ),
                    policy_value=sorted(required),
                    actual_value=sorted(actual),
                )
            )
        else:
            checks.append(
                self._check(
                    "rfc5280_key_usage_profile",
                    True,
                    "RFC 5280 key usage profile check disabled by policy.",
                    policy_value=False,
                    actual_value=False,
                )
            )

        if rfc_cfg["require_subject_key_identifier"]:
            has_ski = bool(parser_data.get("has_subject_key_identifier"))
            checks.append(
                self._check(
                    "rfc5280_subject_key_identifier",
                    has_ski,
                    "Subject Key Identifier extension present."
                    if has_ski
                    else "Subject Key Identifier extension missing.",
                    policy_value=True,
                    actual_value=has_ski,
                )
            )
        else:
            checks.append(
                self._check(
                    "rfc5280_subject_key_identifier",
                    True,
                    "RFC 5280 SKI check disabled by policy.",
                    policy_value=False,
                    actual_value=False,
                )
            )

        if rfc_cfg["require_authority_key_identifier"]:
            has_aki = bool(parser_data.get("has_authority_key_identifier"))
            checks.append(
                self._check(
                    "rfc5280_authority_key_identifier",
                    has_aki,
                    "Authority Key Identifier extension present."
                    if has_aki
                    else "Authority Key Identifier extension missing.",
                    policy_value=True,
                    actual_value=has_aki,
                )
            )
        else:
            checks.append(
                self._check(
                    "rfc5280_authority_key_identifier",
                    True,
                    "RFC 5280 AKI check disabled by policy.",
                    policy_value=False,
                    actual_value=False,
                )
            )

        allowed_critical = {
            value.strip() for value in rfc_cfg["allowed_critical_extensions"] if value.strip()
        }
        critical_oids = {
            value.strip() for value in parser_data.get("critical_extension_oids", []) if value
        }
        if allowed_critical:
            unknown_critical = sorted(critical_oids - allowed_critical)
            checks.append(
                self._check(
                    "rfc5280_critical_extension_profile",
                    not unknown_critical,
                    (
                        "Critical extensions align with policy profile."
                        if not unknown_critical
                        else f"Unexpected critical extensions: {', '.join(unknown_critical)}"
                    ),
                    policy_value=sorted(allowed_critical),
                    actual_value=sorted(critical_oids),
                )
            )
        else:
            checks.append(
                self._check(
                    "rfc5280_critical_extension_profile",
                    True,
                    "Critical extension profile linting disabled by policy.",
                    policy_value=[],
                    actual_value=sorted(critical_oids),
                )
            )

        if rfc_cfg["require_path_issuer_subject_match"]:
            if not isinstance(issuer_parser_data, dict):
                checks.append(
                    self._check(
                        "rfc5280_path_issuer_subject_match",
                        False,
                        "Issuer certificate parser data missing for path linkage check.",
                        policy_value=True,
                        actual_value=False,
                    )
                )
            else:
                issuer_match = parser_data.get("issuer") == issuer_parser_data.get("subject")
                checks.append(
                    self._check(
                        "rfc5280_path_issuer_subject_match",
                        issuer_match,
                        "Leaf issuer matches issuer certificate subject."
                        if issuer_match
                        else "Leaf issuer does not match provided issuer certificate subject.",
                        policy_value=True,
                        actual_value=issuer_match,
                    )
                )
        else:
            checks.append(
                self._check(
                    "rfc5280_path_issuer_subject_match",
                    True,
                    "RFC 5280 issuer-subject path check disabled by policy.",
                    policy_value=False,
                    actual_value=False,
                )
            )

        if rfc_cfg["require_path_aki_ski_match"]:
            if not isinstance(issuer_parser_data, dict):
                checks.append(
                    self._check(
                        "rfc5280_path_aki_ski_match",
                        False,
                        "Issuer certificate parser data missing for AKI/SKI path check.",
                        policy_value=True,
                        actual_value=False,
                    )
                )
            else:
                leaf_aki = parser_data.get("authority_key_identifier")
                issuer_ski = issuer_parser_data.get("subject_key_identifier")
                aki_match = bool(leaf_aki and issuer_ski and leaf_aki == issuer_ski)
                checks.append(
                    self._check(
                        "rfc5280_path_aki_ski_match",
                        aki_match,
                        "Leaf AKI matches issuer SKI."
                        if aki_match
                        else "Leaf AKI does not match issuer SKI (or one is missing).",
                        policy_value=True,
                        actual_value=aki_match,
                    )
                )
        else:
            checks.append(
                self._check(
                    "rfc5280_path_aki_ski_match",
                    True,
                    "RFC 5280 AKI/SKI path check disabled by policy.",
                    policy_value=False,
                    actual_value=False,
                )
            )

        return checks

    def _crypto_transition_checks(
        self, policy: dict[str, Any], parser_data: dict[str, Any]
    ) -> list[CheckResult]:
        cfg = policy["crypto_transition"]
        if not cfg["enabled"]:
            return [
                self._check(
                    "crypto_transition_validity_target",
                    True,
                    "Crypto transition validity target check disabled by policy.",
                    policy_value=False,
                    actual_value=False,
                ),
                self._check(
                    "crypto_transition_rsa_target",
                    True,
                    "Crypto transition RSA target check disabled by policy.",
                    policy_value=False,
                    actual_value=False,
                ),
                self._check(
                    "crypto_transition_signature_hash",
                    True,
                    "Crypto transition signature hash check disabled by policy.",
                    policy_value=False,
                    actual_value=False,
                ),
            ]

        target_validity = cfg["target_max_validity_days"]
        validity_days = parser_data.get("validity_days")
        is_rsa = bool(parser_data.get("is_rsa"))
        rsa_bits = parser_data.get("rsa_key_size")
        target_rsa = cfg["target_min_rsa_bits"]
        signature_algorithm = str(parser_data.get("signature_algorithm", "")).lower()
        approved_hashes = {
            value.lower() for value in cfg["approved_signature_algorithms"] if value.strip()
        }

        validity_ok = isinstance(validity_days, int) and validity_days <= target_validity
        rsa_ok = (not is_rsa) or (isinstance(rsa_bits, int) and rsa_bits >= target_rsa)
        hash_ok = signature_algorithm in approved_hashes

        return [
            self._check(
                "crypto_transition_validity_target",
                validity_ok,
                (
                    f"Certificate validity is {validity_days} days (target <= {target_validity})."
                    if isinstance(validity_days, int)
                    else "Certificate validity value missing for crypto transition check."
                ),
                policy_value=target_validity,
                actual_value=validity_days,
            ),
            self._check(
                "crypto_transition_rsa_target",
                rsa_ok,
                (
                    f"RSA key size is {rsa_bits} bits (target >= {target_rsa})."
                    if is_rsa
                    else "Non-RSA key; RSA transition target not applicable."
                ),
                policy_value=target_rsa,
                actual_value=rsa_bits,
            ),
            self._check(
                "crypto_transition_signature_hash",
                hash_ok,
                f"Signature algorithm is {signature_algorithm or 'missing'}.",
                policy_value=sorted(approved_hashes),
                actual_value=signature_algorithm or None,
            ),
        ]

    def _issuance_checks(
        self, policy: dict[str, Any], issuance_attestation: dict[str, Any] | None
    ) -> list[CheckResult]:
        issuance_cfg = policy["issuance"]
        if not issuance_cfg["require_hsm_attestation"]:
            return [
                self._check(
                    "issuance_hsm_attestation",
                    True,
                    "Issuance HSM attestation checks disabled by policy.",
                    policy_value=False,
                    actual_value=False,
                ),
                self._check(
                    "issuance_fips_level",
                    True,
                    "Issuance FIPS level checks disabled by policy.",
                    policy_value=issuance_cfg["min_fips_level"],
                    actual_value=issuance_cfg["min_fips_level"],
                ),
            ]

        if not isinstance(issuance_attestation, dict):
            return [
                self._check(
                    "issuance_hsm_attestation",
                    False,
                    "Issuance attestation is required but missing.",
                    policy_value=True,
                    actual_value=False,
                ),
                self._check(
                    "issuance_fips_level",
                    False,
                    "FIPS level attestation missing.",
                    policy_value=issuance_cfg["min_fips_level"],
                    actual_value=None,
                ),
            ]

        hsm_backed = bool(issuance_attestation.get("hsm_backed"))
        fips_level = issuance_attestation.get("fips_level")
        fips_ok = isinstance(fips_level, int) and fips_level >= issuance_cfg["min_fips_level"]

        return [
            self._check(
                "issuance_hsm_attestation",
                hsm_backed,
                "Issuance attestation confirms HSM-backed key operations."
                if hsm_backed
                else "Issuance attestation does not confirm HSM-backed key operations.",
                policy_value=True,
                actual_value=hsm_backed,
            ),
            self._check(
                "issuance_fips_level",
                fips_ok,
                f"Attested FIPS level is {fips_level} (min {issuance_cfg['min_fips_level']}).",
                policy_value=issuance_cfg["min_fips_level"],
                actual_value=fips_level,
            ),
        ]

    def _internal_domain_checks(
        self, policy: dict[str, Any], parser_data: dict[str, Any]
    ) -> list[CheckResult]:
        domains_cfg = policy["domains"]
        if not domains_cfg["forbid_internal_names"]:
            return [
                self._check(
                    "internal_domain_check",
                    True,
                    "Internal domain check disabled by policy",
                    policy_value=False,
                    actual_value=False,
                )
            ]

        blocked_suffixes = tuple(s.lower() for s in domains_cfg["blocked_suffixes"])
        san_dns = [d.lower() for d in parser_data["san_dns"]]
        offending = [d for d in san_dns if d.endswith(blocked_suffixes)]
        return [
            self._check(
                "internal_domain_check",
                not offending,
                (
                    "Blocked internal domains found: " + ", ".join(offending)
                    if offending
                    else "No blocked internal domains detected"
                ),
                policy_value=list(blocked_suffixes),
                actual_value=san_dns,
            )
        ]

    def _check(
        self,
        name: str,
        condition: bool,
        details: str,
        policy_value: Any = None,
        actual_value: Any = None,
    ) -> CheckResult:
        meta = CHECK_METADATA.get(name, {})
        return CheckResult(
            name=name,
            status="pass" if condition else "fail",
            details=details,
            rule_id=meta.get("rule_id"),
            category=meta.get("category"),
            severity=meta.get("severity"),
            standard_reference=meta.get("standard_reference"),
            policy_value=policy_value,
            actual_value=actual_value,
            rationale=meta.get("rationale"),
            recommendation=meta.get("recommendation"),
        )
