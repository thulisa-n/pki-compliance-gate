# PKI Compliance Gate (CertGuard Engine)

[![Compliance Gate](https://github.com/thulisa-n/pki-compliance-gate/actions/workflows/compliance.yml/badge.svg)](https://github.com/thulisa-n/pki-compliance-gate/actions/workflows/compliance.yml)
[![Security Scans](https://github.com/thulisa-n/pki-compliance-gate/actions/workflows/security-scans.yml/badge.svg)](https://github.com/thulisa-n/pki-compliance-gate/actions/workflows/security-scans.yml)
![Python](https://img.shields.io/badge/python-3.11%2B-blue)
![License](https://img.shields.io/badge/license-Apache%202.0-blue)
![Release](https://img.shields.io/badge/release-v0.2.1-blue)

**PKI Compliance Gate** (CertGuard Engine) is a Policy-as-Code engine for X.509 certificates, CA/Browser Forum Baseline Requirements, and API TLS posture checks.

One YAML policy profile is the source of truth for evaluation, CI gating, and generated CP/CPS Section 7 documentation.

---

## Quick Start

### Option 1: GitHub Action in CI/CD

Pin an immutable release tag (there is no moving `v1` tag). `v0.2.1` is the
current source version; use the most recent published tag.

> **Upgrading from 0.1.x is a breaking change.** Expiry and EC key policy are
> now enforced by default, and the report no longer carries a `score` field.
> See [`CHANGELOG.md`](CHANGELOG.md).

```yaml
steps:
  - uses: actions/checkout@v4
  - name: Run PKI Compliance Gate
    uses: thulisa-n/pki-compliance-gate@v0.2.1
    with:
      cert: 'tests/certificates/valid_cert.pem'
```

### Option 2: Install from PyPI

```bash
python3 -m pip install "pki-compliance-gate==0.2.1"
pki-gate --cert path/to/server.crt
pki-gate --version
```

### Option 3: Run from a clone

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"

# Evaluate a certificate
pki-gate --cert tests/certificates/valid_cert.pem

# Export CP/CPS Section 7 documentation from the policy YAML
pki-gate --mode export-cps-doc --policy policies/cabf_policy.yaml --summary-output CPS_SECTION_7.md
```

---

## What this repo enforces

The default profile (`policies/cabf_policy.yaml`) enforces:

- **Validity**: maximum 200 days; certificate must be inside its notBefore/notAfter window.
- **Key material**: RSA >= 2048; ECDSA >= 256 bits on P-256/P-384/P-521 only; RSA and EC are the only permitted algorithms.
- **Signature**: no SHA-1 or MD5.
- **Identity**: SAN required; internal suffixes blocked (`.local`, `.internal`, `.intranet`).
- **Optional overlays** (off by default): DCV attestation, RFC 5280 extension and path profile, HSM/FIPS issuance attestation, crypto-transition targets, OPA/Rego gate, zlint and `openssl asn1parse`.
- **API TLS posture** (`--mode apisec --endpoint example.com`): live TLS version, weak-cipher, expiry and certificate checks.

### Coverage matrix

Every control the engine can emit. A control the active profile does not enable
is reported as `not_applicable` -- defined but **not assessed** -- and is never
counted as a pass.

| Control | Rule ID | Category | Severity | Standard reference |
| :--- | :--- | :--- | :--- | :--- |
| `certificate_expiry_window` | OPS-RENEWAL-WINDOW | VALIDITY | low | Operational renewal policy |
| `certificate_not_expired` | RFC-5280-4.1.2.5 | VALIDITY | critical | RFC 5280 4.1.2.5 / CA/B Forum BR 6.3.2 |
| `certificate_not_yet_valid` | RFC-5280-4.1.2.5 | VALIDITY | high | RFC 5280 4.1.2.5 |
| `crypto_transition_rsa_target` | CRYPTO-AGILITY-RSA | CRYPTO-TRANSITION | medium | Crypto transition readiness profile |
| `crypto_transition_signature_hash` | CRYPTO-AGILITY-HASH | CRYPTO-TRANSITION | high | Crypto transition readiness profile |
| `crypto_transition_validity_target` | CRYPTO-AGILITY-VALIDITY | CRYPTO-TRANSITION | high | Crypto transition readiness profile |
| `dcv_method` | CAB-BR-3.2.2.4 | DCV | high | CA/B Forum BR 3.2.2.4 |
| `dcv_recency` | CAB-BR-4.2.1 | DCV | high | CA/B Forum BR 4.2.1 |
| `ec_curve_allowed` | CAB-BR-6.1.5 | CRYPTOGRAPHY | critical | CA/B Forum BR 6.1.5 |
| `ec_key_size` | CAB-BR-6.1.5 | CRYPTOGRAPHY | critical | CA/B Forum BR 6.1.5 |
| `internal_domain_check` | CAB-BR-7.1.4.2.1 | POLICY | high | CA/B Forum BR 7.1.4.2.1 |
| `issuance_fips_level` | FIPS-140-CONTROL | ISSUANCE | medium | FIPS 140-2/140-3 |
| `issuance_hsm_attestation` | PKCS11-HSM-ATTESTATION | ISSUANCE | high | PKCS#11 / FIPS operations |
| `key_algorithm_allowed` | CAB-BR-6.1.5 | CRYPTOGRAPHY | critical | CA/B Forum BR 6.1.5 |
| `rfc5280_authority_key_identifier` | RFC-5280-4.2.1.1 | RFC5280 | medium | RFC 5280 4.2.1.1 |
| `rfc5280_critical_extension_profile` | RFC-5280-4.2 | RFC5280 | high | RFC 5280 4.2 |
| `rfc5280_end_entity_ca` | RFC-5280-4.2.1.9 | RFC5280 | high | RFC 5280 4.2.1.9 |
| `rfc5280_key_usage_profile` | RFC-5280-4.2.1.3 | RFC5280 | high | RFC 5280 4.2.1.3 |
| `rfc5280_path_aki_ski_match` | RFC-5280-4.2.1.1 | RFC5280 | medium | RFC 5280 4.2.1.1 |
| `rfc5280_path_issuer_subject_match` | RFC-5280-6 | RFC5280 | high | RFC 5280 6.1 |
| `rfc5280_subject_key_identifier` | RFC-5280-4.2.1.2 | RFC5280 | medium | RFC 5280 4.2.1.2 |
| `rsa_key_size` | CAB-BR-6.1.5 | CRYPTOGRAPHY | critical | CA/B Forum BR 6.1.5 |
| `san_extension` | RFC-5280-4.2.1.6 | IDENTITY | high | CA/B Forum BR 7.1.4.2.1 |
| `signature_algorithm` | CAB-BR-7.1.3 | CRYPTOGRAPHY | critical | CA/B Forum BR 7.1.3 |
| `validity_days` | CAB-BR-6.3.2 | VALIDITY | high | CA/B Forum BR 6.3.2 |

### Not covered yet

Stated plainly so the matrix above is not mistaken for full BR conformance.
None of the following are implemented: revocation checking (CRL/OCSP),
OCSP must-staple, Certificate Transparency / SCT embedding, chain building and
full path validation, `extendedKeyUsage` profiles, CN-in-SAN consistency,
wildcard placement rules, reserved or internal **IP addresses** in SANs (only
DNS suffixes are checked), and serial-number entropy.

### Evidence and integrity

Each run writes a compliance report, per-control evidence, and an
`evidence_manifest.json` that records a **SHA-256 digest of every evidence
file**, the engine version, and the digest of the policy bytes that produced
the verdict.

Digests detect accidental change and single-file tampering. They are **not
signatures** -- a party able to rewrite the whole bundle can recompute them.
Tamper-evident custody comes from the cosign keyless signature produced in this
repository's CI on `push` to `main` (GitHub native attestations are published
only on public repositories). The integrity sidecar is `*.digest` (a SHA-256
digest, not a signature). A `*.seal` copy is still written so existing
pipelines do not break.

### Exit codes

- `0`: no failing checks (and lint not failed)
- `1`: only low-severity check failures
- `2`: medium/high failures, lint failure, or CLI usage/input errors
- `3`: at least one critical check failure

`--fail-on-waived` counts waived findings as failures, for audit runs where an
approved exception must still block.

### Reports carry no percentage score

A single percentage was removed in report schema 2.0. It counted controls the
policy had never enabled, so an almost-empty profile read 100%, and a
certificate failing a *critical* control could still present as ~95%. Reports
now carry `findings` bucketed by severity and a `coverage` block stating how
much was actually assessed:

```text
Compliant: NO
Risk Level: HIGH
Findings: critical=2
Coverage: 12 of 29 controls evaluated (10 pass, 2 fail, 0 waived, 17 not applicable)
```

## How it flows

```mermaid
flowchart LR
    A[PEM Certificate / Domain] --> B[X509 and TLS Parser]
    B --> C[Policy Validator Engine]
    C --> D[Compliance Report]
    C --> E[CP/CPS Docs Exporter]
    C --> F[Audit Evidence]
    D --> G[CI Exit Code 0..3]
```

---

## Execution modes

| Mode | Example | What the code does |
| :--- | :--- | :--- |
| `evaluate` | `pki-gate --cert server.crt` | Full policy evaluation of a certificate file. |
| `export-cps-doc` | `pki-gate --mode export-cps-doc` | Renders the YAML policy as CP/CPS Section 7 Markdown. |
| `apisec` | `pki-gate --mode apisec --endpoint example.com` | Scans a live endpoint for TLS posture. |
| `triage` | `pki-gate --mode triage --report-input report.json` | Turns report findings into severity-ranked next actions. |
| `assure` | `pki-gate --mode assure --report-input report.json` | Independently recomputes whether the report's `compliant` flag matches checks and lint. |
| `watch` | `pki-gate --mode watch` | Diffs the loaded policy against `policies/standards_baseline.yaml`. |
| `heal` | `pki-gate --mode heal --healed-cert new_cert.pem` | Writes a remediation plan; re-evaluates only if `--healed-cert` is provided. |
| `summary` | `pki-gate --mode summary --report-input report.json` | Writes a reviewer Markdown summary. |
| `trend` | `pki-gate --mode trend --report-input report.json` | Writes a trend snapshot JSON. |
| `signals` | `pki-gate --mode signals` | Reads curated external signals JSON and writes recommendations. |
| `readiness` | `pki-gate --mode readiness --as-of 2027-03-15` | Assesses the loaded policy against the dated CA/B validity schedule. |

## Repository structure

```text
src/certguard/          Core agents, CLI, bundled policy, and engine
src/certguard/policy_exporter.py  CP/CPS exporter
src/main.py             Backward-compatible repository entrypoint
policies/               Policy YAML profiles and Rego rules
tests/                  Automated test suite
action.yml              Composite GitHub Action
.github/workflows/      CI workflows
```

---

## Distribution status

The GitHub Action, wheel, and sdist are published from the `v0.2.2` tag.
Install the CLI with `pip install pki-compliance-gate==0.2.2`. Later GitHub
releases reuse `.github/workflows/publish.yml` with PyPI trusted publishing
(OIDC, no API token in the repository).

---

## License

Licensed under the [Apache License 2.0](LICENSE).
