"""Shared pytest fixtures.

The certificate factory here replaces reliance on committed PEM files for any
test that needs a currently valid certificate.
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Callable

import pytest

# Make `tests.support` and `src` importable without relying on pyproject's
# pytest pythonpath setting, so the suite runs the same way under pytest, a
# bare interpreter, or a script.
REPO_ROOT = Path(__file__).resolve().parents[1]
for candidate in (REPO_ROOT, REPO_ROOT / "src"):
    if str(candidate) not in sys.path:
        sys.path.insert(0, str(candidate))

from tests.support.certificates import CertSpec, write_certificate  # noqa: E402

POLICY_PATH = Path("policies/cabf_policy.yaml")
FIXTURES_DIR = Path("tests/certificates")


@pytest.fixture
def make_cert(tmp_path: Path) -> Callable[..., Path]:
    """Mint a certificate in tmp_path.

    Usage: ``make_cert()`` for a compliant default, or
    ``make_cert(key="ec192", validity_days=30)`` to vary one property.
    """
    counter = {"n": 0}

    def _factory(name: str | None = None, **overrides) -> Path:
        counter["n"] += 1
        filename = name or f"cert_{counter['n']}.pem"
        return write_certificate(tmp_path / filename, CertSpec(**overrides))

    return _factory


@pytest.fixture
def policy_path() -> Path:
    return POLICY_PATH


@pytest.fixture
def fixtures_dir() -> Path:
    return FIXTURES_DIR
