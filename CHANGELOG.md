# Changelog

All notable changes to this project are documented here.
This project follows [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Changed

- Text reports, `neakam --help`, and the GitHub job summary header say
  `Neakam policy gate`. JSON and SARIF field names are unchanged, including
  the `compliant` key.
- README calls the written report a policy report. The flow diagram calls the
  evidence output "Evidence files + digest manifest". The `signals` mode reads
  a signals JSON file you supply. The `assure` mode recomputes `policy_result`
  and the legacy `compliant` field. `compliant` means "passed this policy",
  not a compliance claim; `policy_result` is preferred.
- `--external-signals` help text says the path is a signals JSON file you
  supply. The flag name is unchanged.
- Contributor guidance states that paid or proprietary content is out of scope
  for this repository. The repository-boundary test still fails on the same
  paths, imports, profiles, and dependency names. Code Quality installs only
  this repository's locked dependencies.
- The Compliance Gate workflow name, its badge, the repository name, and the
  `pki-gate` deprecation notice are unchanged.

## [0.2.7] - 2026-11-06

### Fixed

- `neakam --mode apisec` reports a TLS certificate verification failure as a
  finding, not a tool error. Expired, not-yet-valid, hostname mismatch,
  self-signed, and unknown-issuer or incomplete-chain results fail
  `endpoint_certificate_trust` (plus `endpoint_certificate_expiry` or
  `endpoint_hostname_match` when those apply) at high risk. A second handshake
  to the same vetted host and IP may read the presented certificate with
  verification disabled, only to report expiry, key size, and signature
  algorithm. That certificate is not trusted. DNS failure, timeout, and
  connection refused stay errors, with `Status: ERROR` and
  `Risk Level: UNKNOWN` (exit code 2, the existing CLI error code).

### Changed

- Human-readable text, Markdown, and the GitHub job summary (Markdown rendered
  as HTML) say `Policy result: PASS` or `Policy result: FAIL`. JSON keeps
  `compliant` and adds `policy_result`. SARIF field names are unchanged. The
  SARIF exit-code description no longer uses the word "compliant".

## [0.2.6] - 2026-11-06

### Added

- Trust scope for CA/B Forum controls that apply only to publicly-trusted TLS.
  The default is public. `--trust-scope {public,private,auto}` and policy key
  `trust.scope` select the scope. `private` makes those CA/B-only controls
  `not_applicable`. `auto` infers private only from an offline-verified chain
  whose root is absent from user-supplied public roots (`--public-trust-roots`
  or `trust.public_roots`). JSON records `trust_scope`. SARIF records
  `trustScope`.
- Hash-pinned `requirements.txt` and `requirements-dev.txt`. CI installs with
  `--require-hashes`. `scripts/update_lockfile.sh` regenerates them.
- Golden CLI JSON and SARIF snapshots under `tests/golden/`.
- `docs/BRANCH_PROTECTION.md` for the `main` settings to turn on by hand.
- `python -m neakam` as a non-deprecated module entry point.
- `neakam` console script. `pki-gate` and `certguard` remain as deprecated
  aliases and print a one-line notice to stderr.
- `neakam doctor` offline self-test (`--json`, exit codes 0, 1, and 2).
- `NO_TELEMETRY.md`. Live TLS checks require `--allow-network` and stay on the
  hosts listed with `--endpoint`.

### Changed

- Code Quality runs ruff, then unit tests, then the neakam certificate
  fixtures. Bandit and pip-audit fail on medium and above. GitHub Actions are
  pinned to commit SHAs. Workflow permissions default to `contents: read`.
  Wheel builds set `SOURCE_DATE_EPOCH` from the commit timestamp.
- User-facing name in the CLI, output headers, and docs is Neakam. The import
  package remains `certguard`. The PyPI distribution name is unchanged.

### Fixed

- Keyless provenance signing writes the cosign bundle only. Verification uses
  that bundle with the workflow OIDC identity and issuer. Separate certificate
  and signature files are no longer produced.

## [0.2.5] - 2026-11-04

### Fixed

- `failed_controls` entries include the check's `recommendation`. SARIF result
  properties include it as well; the finding message already did.
- `pki-gate --mode` help lists first-class modes separately from derived
  helpers (`summary`, `trend`, `export-cps-doc`, `export-rego`).
- Standards sync no longer falls back to `github.token` when opening a review
  pull request. If a Baseline Requirements change has no review pull request,
  the job summary explains how to set `STANDARDS_SYNC_PR_TOKEN` and the job
  fails. Snapshots still record `sync.fetched_at`, which Standards PR Guard
  requires.
- Secret detection grants `pull-requests: read` so gitleaks can read pull
  request metadata.

## [0.2.4] - 2026-09-18

### Added

- Published verdict corpus (`corpus/verdicts.yaml`) with expected exit codes
  and failing controls for committed PEMs and CSRs, including the 0.2.0
  expired-certificate false negative.
- Pre-issuance CSR evaluation (`pki-gate --csr` / Action `csr` input). Issued-
  certificate controls are `not_applicable`, not guessed.
- Report `verdict_digest` and JSON Schema
  `src/certguard/data/compliance-report-2.0.schema.json`. Same PEM, policy, and
  `--as-of` instant produce the same digest.
- `SECURITY.md`, a false-positive issue template, and `docs/COMPARE.md`
  (CertGuard vs zlint vs `openssl verify`).

### Changed

- README leads with `pki-gate --cert`. Other CLI modes are listed as advanced.
- `--as-of` pins evaluate-mode expiry checks, not only watch/readiness.

## [0.2.3] - 2026-09-18

### Removed

- Kubernetes Kyverno admission examples and the phase-oriented project status
  document. Certificate policy lives in YAML and CI, not a hardcoded cluster
  demo.

### Changed

- Generate the optional OPA/Rego validity gate from
  `certificate.max_validity_days` instead of reading a hand-written
  `policies/rego/validity.rego`. A 2027 100-day profile no longer leaves a
  200-day OPA allow rule behind.

## [0.2.2] - 2026-09-11

Review-gap follow-up on 0.2.1. Verdicts for the default CABF profile stay the
same for locally minted certificates: SCT and EKU stay opt-in, serial entropy
and the signature OID allowlist are on.

### Added

- Signature OID allowlist (`signature_algorithm_oid`), serial entropy, SCT
  presence, and EKU profile controls.
- A `CONTROLS` registry so CP/CPS export, SARIF rules, and assurance share one
  source of metadata.
- `assess()` / `persist()` split so a hosted API can return a verdict without
  a throwaway directory per request.
- Optional Ed25519 signatures on waiver files (`--require-signed-waivers`).
- SARIF 2.1.0 output, GitHub job summaries, workflow annotations, and a
  `readiness` mode for the dated 100/47-day validity schedule.
- Apache-2.0 relicensing and a DCO requirement for contributions.

### Changed

- Evidence integrity files are written as `.digest` (`.seal` remains a
  compatibility alias).
- Curated EV / S/MIME / root-program / CP-CPS profiles move to the enterprise
  content pack. Public core keeps CI lint, short-lived, and crypto-agility
  profiles plus the default CABF policy.

## [0.2.1] - 2026-09-11

Post-release hardening for the 0.2.0 correctness changes.

### Fixed

- Recompute certificate validity state from timestamps when legacy parser
  payloads omit boolean flags, and fail closed when validity evidence is absent.
- Do not emit renewal-window findings for expired or not-yet-valid certificates.
- Treat future standards-readiness gaps as planning information rather than
  current failed controls, and ignore DCV age while DCV evidence is disabled.
- Load watch-mode policies through the same default-merging path as evaluation
  mode and support reproducible `--as-of YYYY-MM-DD` checks.
- Avoid weekly standards-sync snapshot churn when the upstream digest is
  unchanged.
- Regenerate time-sensitive certificate fixtures before distribution smoke
  tests.
- Restrict package discovery to the public `certguard` namespace and explicitly
  prevent forks or private repositories from publishing the public PyPI name.

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
