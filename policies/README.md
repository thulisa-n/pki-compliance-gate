# Policy Configuration

The compliance engine behavior is controlled by `cabf_policy.yaml`.

## Required sections

- `metadata`
- `certificate`
- `key`
- `signature`
- `domains`
- `lint`

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

The loader performs validation and raises an explicit error when required keys are missing or typed incorrectly.
