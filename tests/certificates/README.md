# Certificate Fixture Dataset

This directory contains test certificates used to validate compliance rules and regression behavior.

## Fixtures

- `valid_cert.pem` - valid baseline certificate (SAN present, RSA 2048, SHA-256, short validity)
- `long_validity_cert.pem` - certificate validity intentionally exceeds policy threshold
- `internal_domain_cert.pem` - SAN includes blocked internal suffix (`.local`)
- `weak_key_cert.pem` - RSA 1024 key for minimum key size validation
- `no_san_cert.pem` - SAN extension intentionally missing
- `sha1_cert.pem` - SHA-1 signature for prohibited algorithm validation
- `expired_cert.pem` - expired on purpose (0.2.0 false-negative lock)
- `ec_p192_cert.pem` - undersized/unapproved EC curve (0.2.0 false-negative lock)
- `csrs/` - PEM CSRs for the pre-issuance gate (`valid`, `weak_key`, `internal`, `no_san`)

Expected verdicts: [`corpus/verdicts.yaml`](../../corpus/verdicts.yaml).

These fixtures are committed as public test data only and are not used for real trust decisions.
