"""Regenerate the committed certificate fixtures with a current validity window.

Run this when the freshness guard in ``tests/test_certificate_fixtures.py``
fails, or from CI before the fixture matrix runs.

Why this exists: every fixture was originally minted with notBefore
2026-03-16, so five of six had expired by September 2026 -- including
``valid_cert.pem``, which the CI matrix asserts exits 0. The suite stayed green
only because nothing checked expiry. Regeneration keeps the committed artefacts
usable; tests that must not depend on file freshness mint their own via
``tests/support/certificates.py``.

``sha1_cert.pem`` is never regenerated: cryptography >= 42 refuses to produce
SHA-1 signatures, so that artefact can only exist as a committed file. It is
expected to be expired and is exempt from the freshness guard.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT))

from tests.support.certificates import (  # noqa: E402
    INTENTIONALLY_EXPIRED_FIXTURES,
    CertSpec,
    fixture_expiry_report,
    write_certificate,
)

DEFAULT_DIR = REPO_ROOT / "tests" / "certificates"

#: filename -> spec. Mirrors the CI fixture matrix in
#: .github/workflows/compliance.yml; keep the two in step.
FIXTURES: dict[str, CertSpec] = {
    "valid_cert.pem": CertSpec(validity_days=90),
    "long_validity_cert.pem": CertSpec(validity_days=500),
    "no_san_cert.pem": CertSpec(san_dns=()),
    "internal_domain_cert.pem": CertSpec(
        common_name="dev.local", san_dns=("dev.local",)
    ),
    "weak_key_cert.pem": CertSpec(key="rsa1024", validity_days=90),
    # Locks in the two false negatives fixed in 0.2.0.
    "expired_cert.pem": CertSpec(starts_in_days=-400, validity_days=90),
    "ec_p192_cert.pem": CertSpec(key="ec192", validity_days=90),
}

NEVER_REGENERATE: frozenset[str] = frozenset({"sha1_cert.pem"})


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--output-dir",
        default=str(DEFAULT_DIR),
        help="Directory holding the committed fixtures.",
    )
    parser.add_argument(
        "--check",
        action="store_true",
        help="Report fixture freshness without writing anything.",
    )
    args = parser.parse_args(argv)
    out_dir = Path(args.output_dir)

    if args.check:
        stale = False
        for entry in fixture_expiry_report(out_dir):
            flag = ""
            if entry["intentionally_expired"]:
                flag = "(intentionally expired)"
            elif entry["expired"]:
                flag, stale = "EXPIRED", True
            elif int(entry["days_until_expiry"]) < 30:
                flag, stale = "EXPIRING SOON", True
            print(
                f"{entry['name']:26} expires {entry['not_after'].date()} "
                f"({entry['days_until_expiry']:>5}d) {flag}"
            )
        if stale:
            print(
                "\nRegenerate with: python scripts/generate_test_certificates.py",
                file=sys.stderr,
            )
            return 1
        return 0

    for filename, spec in FIXTURES.items():
        if filename in NEVER_REGENERATE:
            continue
        write_certificate(out_dir / filename, spec)
        print(f"wrote {out_dir / filename}")

    for filename in sorted(NEVER_REGENERATE):
        if (out_dir / filename).exists():
            print(f"kept  {out_dir / filename} (cannot be regenerated)")

    print(
        "\nIntentionally expired fixtures: "
        + ", ".join(sorted(INTENTIONALLY_EXPIRED_FIXTURES))
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
