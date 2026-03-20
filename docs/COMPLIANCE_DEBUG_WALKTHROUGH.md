# Compliance Debug Walkthrough

This guide explains how to troubleshoot common compliance failures using the project fixtures.

## 1) Signature algorithm failure (critical)

Command:

```bash
python src/main.py --cert tests/certificates/sha1_cert.pem --explain
```

What to review:

- failed control: `signature_algorithm`
- severity and standard reference
- recommendation output

Fix approach:

- reissue with SHA-256 or stronger
- rerun and confirm score/risk improve

## 2) Internal domain policy failure (high)

Command:

```bash
python src/main.py --cert tests/certificates/internal_domain_cert.pem --explain
```

What to review:

- failed control: `internal_domain_check`
- SAN values vs blocked suffix policy

Fix approach:

- replace internal SAN values with public DNS names
- rerun checks and ensure policy alignment

## 3) Weak key size failure (critical)

Command:

```bash
python src/main.py --cert tests/certificates/weak_key_cert.pem --explain
```

What to review:

- failed control: `rsa_key_size`
- key size actual value vs policy threshold

Fix approach:

- regenerate certificate with RSA 2048+
- revalidate with `evaluate`, then run `assure`

## 4) Remediation and healed-state verification

```bash
python src/main.py --cert tests/certificates/sha1_cert.pem --report reports/compliance_report.json || true
python src/main.py --mode heal \
  --report-input reports/compliance_report.json \
  --healed-cert tests/certificates/valid_cert.pem \
  --healed-report reports/healed_compliance_report.json
```

Expected:

- remediation plan generated
- healed state marked compliant
- assurance check passes
