# Policy Configuration

The compliance engine behavior is controlled by `cabf_policy.yaml`.

## Core required sections

- `metadata`
- `certificate`
- `key`
- `signature`
- `domains`
- `lint`

## Optional advanced sections (with defaults)

- `dcv`
- `rfc5280`
- `opa`
- `issuance`
- `crypto_transition`

## Key fields

- `certificate.max_validity_days` (`int`)
- `certificate.require_san` (`bool`)
- `key.minimum_rsa_bits` (`int`)
- `signature.prohibited_algorithms` (`list[str]`)
- `domains.forbid_internal_names` (`bool`)
- `domains.blocked_suffixes` (`list[str]`)
- `lint.enable_zlint` (`bool`)
- `lint.fail_on_error` (`bool`)
- `lint.fail_severities` (`list[str]`, for example `["error", "fatal"]`)
- `lint.enable_asn1parse` (`bool`)
- `lint.fail_on_asn1_error` (`bool`)
- `dcv.required` (`bool`)
- `dcv.allowed_methods` (`list[str]`)
- `dcv.max_age_days` (`int`)
- `rfc5280.require_end_entity_not_ca` (`bool`)
- `rfc5280.require_key_usage` (`bool`)
- `rfc5280.required_key_usages` (`list[str]`)
- `rfc5280.require_subject_key_identifier` (`bool`)
- `rfc5280.require_authority_key_identifier` (`bool`)
- `rfc5280.allowed_critical_extensions` (`list[str]`, extension OID allowlist)
- `rfc5280.require_path_issuer_subject_match` (`bool`)
- `rfc5280.require_path_aki_ski_match` (`bool`)
- `opa.enabled` (`bool`)
- `opa.policy_file` (`str`)
- `issuance.require_hsm_attestation` (`bool`)
- `issuance.min_fips_level` (`int`)
- `crypto_transition.enabled` (`bool`)
- `crypto_transition.target_max_validity_days` (`int`)
- `crypto_transition.target_min_rsa_bits` (`int`)
- `crypto_transition.approved_signature_algorithms` (`list[str]`)

The loader performs validation and raises an explicit error when required keys are missing or typed incorrectly.
