# Certificate Fixture Dataset

This directory contains test certificates used to validate compliance rules and regression behavior.

## Fixtures

- `valid_cert.pem` - valid baseline certificate (SAN present, RSA 2048, SHA-256, short validity)
- `long_validity_cert.pem` - certificate validity intentionally exceeds policy threshold
- `internal_domain_cert.pem` - SAN includes blocked internal suffix (`.local`)
- `weak_key_cert.pem` - RSA 1024 key for minimum key size validation
- `no_san_cert.pem` - SAN extension intentionally missing
- `sha1_cert.pem` - SHA-1 signature for prohibited algorithm validation

These fixtures are committed as public test data only and are not used for real trust decisions.
