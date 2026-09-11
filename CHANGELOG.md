# Changelog

All notable changes to this project are documented here.
This project follows [Semantic Versioning](https://semver.org/).

## [0.2.0] - 2026-09-11

A correctness release. Three false negatives meant certificates that should
have been rejected evaluated as fully compliant. **Upgrading changes verdicts**
for certificates that previously passed.

### Fixed

- **An expired certificate evaluated as compliant.** Nothing compared `notAfter`
  to the evaluation time -- only the *length* of the validity window was checked.
  A certificate that expired in April 2024 reported compliant, 100%, exit 0.
  Added `certificate_not_expired` (critical) and `certificate_not_yet_valid`
  (high), both enabled by default.
- **Partial days above the validity limit were rounded down.** A certificate
  valid for 200 days and 23 hours appeared as 200 days and passed. Enforcement
  now compares the exact duration while retaining whole days for compatibility.
- **Any non-RSA key bypassed key-strength policy.** `rsa_ok = (not is_rsa) or ...`
  meant a 192-bit ECDSA certificate reported compliant with exit 0. Added
  `key_algorithm_allowed`, `ec_key_size` and `ec_curve_allowed`; the default
  profile permits only RSA and EC, and only the NIST curves CA/Browser Forum
  BR 6.1.5 allows (P-256, P-384, P-521).
- **Controls the policy had not enabled were recorded as `pass`.** On the
  shipped default profile 13 of 19 "checks" were synthetic passes, so the
  report read 100% while 6 controls were actually evaluated. Introduced a
  `not_applicable` status; such controls are now excluded from results and from
  the coverage denominator.
- **A waiver erased the risk statement.** A waived critical finding produced
  `failed_controls == []`, therefore `risk_level: LOW` and exit 0. Waivers now
  suppress the *gate* only; risk still reflects the underlying weakness.
- **`risk_level` ignored lint failures.** A certificate non-compliant purely
  because zlint failed reported `LOW`. Lint failure now contributes `MEDIUM`.
- **Waiver application mutated the validator agent's results in place**, so
  `AgentResult.checks` was rewritten after the fact. Waivers now produce copies.
- **`evidence_manifest.json` listed evidence file paths with no digests**,
  making the "evidence manifest" an index that could not detect a changed file.
  It now records a SHA-256 digest and size for every listed file, the engine
  version, and the policy digest.
- **The standards sync script would have missed the 2027 tightening.** It
  regex-scraped BR.md and hard-preferred the string "200", which survives in the
  ballot's own schedule table -- so it would have kept asserting a 200-day
  maximum through the reductions to 100 days (2027-03-15) and 47 days
  (2029-03-15). The baseline is now a hand-maintained dated schedule; the script
  only detects that the upstream document changed and asks a human to review.
- **`policies/standards_baseline.yaml` had an empty `terms` list**, because the
  sync script overwrote the file, leaving term alignment with nothing to check.
- **The CP/CPS exporter covered five parameters** and ignored the `rfc5280`,
  `dcv`, `issuance`, `opa` and `crypto_transition` sections, so the module whose
  purpose was preventing documentation drift was itself the drift. It is now
  driven by the control registry, and a test asserts full coverage.
- **Five of six committed certificate fixtures had already expired**, including
  `valid_cert.pem`, which CI asserts exits 0. The suite stayed green only
  because nothing checked expiry. Tests now mint certificates at run time, and
  `tests/test_certificate_fixtures.py` fails if a committed fixture drifts
  toward expiry.
- **Triage disagreed with the verdict it was triaging** -- a second hardcoded
  severity table rated `validity_days` medium where the engine rated it high.
  Severity and remediation advice now come from the report.
- **The reviewer summary rendered anything that was not `pass` as `FAIL`**, so a
  control the policy never enabled looked like a defect.
- Possibly-unbound `matched` in the zlint result path.

### Added

- `not_applicable` status, and a `coverage` block stating controls defined,
  evaluated, passed, failed, waived and not applicable.
- `findings` bucketed by severity, replacing the percentage score.
- `engine_version`, `report_schema_version` and `policy_sha256` in reports,
  evidence manifests and decision-log entries, so a finding is reproducible.
- `pki-gate --version`.
- `pki-gate --fail-on-waived` for audit runs where an approved exception must
  still block.
- `certificate.warn_if_expires_within_days` -- an opt-in low-severity renewal
  warning (exit 1). Off by default: a certificate valid for another 10 days is
  still compliant.
- Dated SC-081v3 schedule in `policies/standards_baseline.yaml`, plus
  `upcoming_standards_readiness`, which reports gaps against the *next*
  scheduled tightening before it lands.
- `signature_algorithm_oid` / `signature_algorithm_name`, `serial_number_bits`,
  `extended_key_usage`, and normalised `key_algorithm` / `key_size_bits` /
  `ec_curve` in parser output.
- `scripts/generate_test_certificates.py` and `tests/support/certificates.py`.
- Validity-boundary tests at `max-1`, `max` and `max+1`, pinning the BR 1.6.1
  interpretation (whole-day `notAfter - notBefore`).
- ruff, mypy (strict) and coverage configuration, wired into CI.
- A published coverage matrix and an explicit "not covered yet" list in the
  README.

### Changed

- **BREAKING**: the compliance report no longer contains `score`. Consumers
  should read `findings` and `coverage`. `report_schema_version` is `2.0`.
- **BREAKING**: expiry and EC key controls are enabled by default. Certificates
  that passed under 0.1.x may now fail.
- **BREAKING**: controls the policy does not enable report `not_applicable`
  rather than `pass`.
- Default policy version is `2.0.0`; profile versions are `2026.2`.
- The `.seal` file and `evidence_manifest.json` state explicitly that a SHA-256
  digest is not a signature.
- `pki-gate` warns when the policy was auto-detected from the working directory
  rather than passed with `--policy`.
- Policy loading rejects a `bool` where an `int` is required, a non-positive
  threshold, an empty `key.allowed_algorithms`, and unknown key algorithms.

## [0.1.3] - 2026-09-11

- Installable CLI and working composite GitHub Action.
- Keyless cosign release provenance, SBOM, hash-chained decision log.
- Policy profile packs for EV, S/MIME, root program, CP/CPS and crypto agility.
