"""Offline self-test for a Neakam install.

Checks Python, the import package, bundled policies, and one bundled fixture
certificate. This command does not use the network. Messages stay short and
never include key or licence material.
"""

from __future__ import annotations

import argparse
import json
import sys
import traceback
from collections.abc import Callable
from dataclasses import dataclass
from importlib.resources import as_file, files
from io import StringIO
from pathlib import Path

import yaml
from cryptography import x509

from certguard import REPORT_SCHEMA_VERSION, __version__
from certguard.engine import ComplianceGateEngine

EXIT_OK = 0
EXIT_CHECK_FAILED = 1
EXIT_USAGE = 2

_SECRET_MARKERS = (
    "-----begin",
    "private key",
    "licence",
    "license",
)

CheckFn = Callable[[], tuple[bool, str]]


@dataclass(frozen=True)
class DoctorCheck:
    name: str
    ok: bool
    detail: str


def run_doctor(argv: list[str] | None = None) -> int:
    """Run the self-test and return 0, 1, or 2."""
    args, usage = _parse_args(argv)
    if usage is not None:
        return usage
    assert args is not None
    try:
        checks = _run_checks(debug=bool(args.debug))
    except Exception as exc:
        if args.debug:
            _write_traceback(exc)
        else:
            print("ERROR: doctor failed", file=sys.stderr)
        return EXIT_CHECK_FAILED

    ok = all(check.ok for check in checks)
    _emit(checks, as_json=bool(args.json), version=__version__)
    if not ok:
        print("ERROR: doctor found a failed check", file=sys.stderr)
        return EXIT_CHECK_FAILED
    return EXIT_OK


def _parse_args(
    argv: list[str] | None,
) -> tuple[argparse.Namespace | None, int | None]:
    parser = argparse.ArgumentParser(
        prog="neakam doctor",
        description=(
            "Offline self-test. Checks Python 3.11 or newer, bundled policies, "
            "and a bundled fixture certificate. Does not use the network."
        ),
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Print the result as JSON.",
    )
    parser.add_argument(
        "--debug",
        action="store_true",
        help="Include a traceback if a check crashes. Key and licence material stays redacted.",
    )
    try:
        return parser.parse_args(argv), None
    except SystemExit as exc:
        code = exc.code
        if code in (0, None):
            return None, EXIT_OK
        return None, EXIT_USAGE


def _run_checks(*, debug: bool) -> list[DoctorCheck]:
    steps: tuple[tuple[str, CheckFn], ...] = (
        ("python", _check_python),
        ("package", _check_package),
        ("policies", _check_policies),
        ("fixture", _check_fixture),
    )
    checks: list[DoctorCheck] = []
    for name, function in steps:
        try:
            ok, detail = function()
        except Exception as exc:
            if debug:
                _write_traceback(exc)
            ok = False
            detail = _safe_detail(str(exc) or exc.__class__.__name__)
        else:
            detail = _safe_detail(detail)
        checks.append(DoctorCheck(name=name, ok=ok, detail=detail))
    return checks


def _check_python() -> tuple[bool, str]:
    version = sys.version_info
    label = f"Python {version[0]}.{version[1]}"
    if version < (3, 11):
        return False, f"{label} is older than 3.11"
    return True, label


def _check_package() -> tuple[bool, str]:
    import certguard

    version = certguard.__version__
    if not isinstance(version, str) or not version:
        return False, "package did not load"
    if not isinstance(REPORT_SCHEMA_VERSION, str) or not REPORT_SCHEMA_VERSION:
        return False, "package did not load"
    return True, f"certguard {version}"


def _check_policies() -> tuple[bool, str]:
    root = files("certguard.data")
    names = _bundled_policy_names()
    if not names:
        return False, "no bundled policy files"
    for name in names:
        parsed = yaml.safe_load(root.joinpath(name).read_text(encoding="utf-8"))
        if not isinstance(parsed, dict):
            return False, f"{name} did not parse as a mapping"
    return True, "parsed " + ", ".join(names)


def _check_fixture() -> tuple[bool, str]:
    root = files("certguard.data")
    policy_res = root.joinpath("cabf_policy.yaml")
    cert_res = root.joinpath("doctor_fixture.pem")
    if not policy_res.is_file() or not cert_res.is_file():
        return False, "bundled policy or fixture certificate is missing"
    pem = cert_res.read_bytes()
    if b"PRIVATE KEY" in pem or b"BEGIN CERTIFICATE" not in pem:
        return False, "bundled fixture certificate is unusable"
    parsed = x509.load_pem_x509_certificate(pem)
    when = (
        parsed.not_valid_before_utc + (parsed.not_valid_after_utc - parsed.not_valid_before_utc) / 2
    )
    with as_file(policy_res) as policy_path, as_file(cert_res) as cert_path:
        engine = ComplianceGateEngine(policy_path=Path(policy_path))
        report, _artifacts = engine.assess(
            cert_path=Path(cert_path),
            evaluated_at=when,
        )
    if not report.checks:
        return False, "fixture evaluation produced no checks"
    failed = [check.name for check in report.checks if check.status == "fail"]
    if failed:
        return False, "fixture evaluation failed: " + ", ".join(failed[:5])
    return True, f"evaluated {len(report.checks)} controls"


def _bundled_policy_names() -> list[str]:
    names: list[str] = []
    for item in files("certguard.data").iterdir():
        if item.name.endswith((".yaml", ".yml")) and item.is_file():
            names.append(item.name)
    return sorted(names)


def _safe_detail(detail: str) -> str:
    text = " ".join(detail.split())
    if not text or _contains_secret(text):
        return "check failed"
    if len(text) > 180:
        return text[:177] + "..."
    return text


def _contains_secret(text: str) -> bool:
    lowered = text.lower()
    return any(marker in lowered for marker in _SECRET_MARKERS)


def _write_traceback(exc: BaseException) -> None:
    buffer = StringIO()
    traceback.print_exception(type(exc), exc, exc.__traceback__, file=buffer)
    lines = [
        "[redacted]" if _contains_secret(line) else line for line in buffer.getvalue().splitlines()
    ]
    print("\n".join(lines), file=sys.stderr)


def _emit(checks: list[DoctorCheck], *, as_json: bool, version: str) -> None:
    if as_json:
        payload = {
            "checks": [
                {"detail": check.detail, "name": check.name, "ok": check.ok} for check in checks
            ],
            "command": "doctor",
            "ok": all(check.ok for check in checks),
            "tool": "neakam",
            "version": version,
        }
        print(json.dumps(payload, indent=2, sort_keys=True))
        return
    print("Neakam doctor")
    for check in checks:
        label = "ok" if check.ok else "fail"
        print(f"[{label}] {check.name}: {check.detail}")
