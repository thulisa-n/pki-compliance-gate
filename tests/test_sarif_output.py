"""SARIF 2.1.0 output.

SARIF is what puts findings in GitHub's Security tab instead of leaving them as
an exit code in a log. The invariants that matter:

* a passing control is not a finding
* a not_applicable control was never assessed and must not appear either
* a waived finding stays visible, at note level, marked as waived
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Callable

from certguard import __version__
from certguard.agents.policy_validator import CHECK_METADATA
from certguard.engine import ComplianceGateEngine
from certguard.sarif import SARIF_VERSION, to_sarif

POLICY_PATH = Path("policies/cabf_policy.yaml")


def _evaluate(cert: Path, tmp_path: Path, waiver_path: Path | None = None):
    engine = ComplianceGateEngine(policy_path=POLICY_PATH)
    return engine.evaluate(
        cert_path=cert,
        report_path=tmp_path / "report.json",
        evidence_dir=tmp_path / "evidence",
        waiver_path=waiver_path,
    )


def test_sarif_is_well_formed(make_cert: Callable[..., Path], tmp_path: Path) -> None:
    _, report = _evaluate(make_cert(), tmp_path)
    log = to_sarif(report, policy_path=POLICY_PATH)

    assert log["version"] == SARIF_VERSION
    assert log["$schema"].endswith("sarif-schema-2.1.0.json")
    assert len(log["runs"]) == 1
    driver = log["runs"][0]["tool"]["driver"]
    assert driver["name"] == "CertGuard"
    assert driver["version"] == __version__


def test_every_control_is_declared_as_a_rule(
    make_cert: Callable[..., Path], tmp_path: Path
) -> None:
    """Rule documentation must be complete and stable between runs."""
    _, report = _evaluate(make_cert(), tmp_path)
    log = to_sarif(report)

    declared = {rule["id"] for rule in log["runs"][0]["tool"]["driver"]["rules"]}
    assert declared == set(CHECK_METADATA)


def test_compliant_certificate_yields_no_results(
    make_cert: Callable[..., Path], tmp_path: Path
) -> None:
    compliant, report = _evaluate(make_cert(), tmp_path)
    log = to_sarif(report)

    assert compliant is True
    assert log["runs"][0]["results"] == []
    assert log["runs"][0]["invocations"][0]["executionSuccessful"] is True


def test_passes_and_not_applicable_never_become_findings(
    make_cert: Callable[..., Path], tmp_path: Path
) -> None:
    _, report = _evaluate(make_cert(key="ec192"), tmp_path)
    log = to_sarif(report)

    statuses = {r["properties"]["status"] for r in log["runs"][0]["results"]}
    assert statuses <= {"fail", "waived"}
    assert report.coverage["not_applicable"] > 0, "fixture should leave controls off"


def test_critical_failures_map_to_error_level(
    make_cert: Callable[..., Path], tmp_path: Path
) -> None:
    _, report = _evaluate(make_cert(key="ec192"), tmp_path)
    log = to_sarif(report)
    run = log["runs"][0]

    results = {r["ruleId"]: r for r in run["results"]}
    assert set(results) == {"ec_key_size", "ec_curve_allowed"}
    assert all(r["level"] == "error" for r in results.values())

    rules = {rule["id"]: rule for rule in run["tool"]["driver"]["rules"]}
    assert rules["ec_key_size"]["properties"]["security-severity"] == "9.3"


def test_medium_and_low_map_to_warning_and_note(
    make_cert: Callable[..., Path], tmp_path: Path
) -> None:
    log = to_sarif(_evaluate(make_cert(), tmp_path)[1])
    rules = {rule["id"]: rule for rule in log["runs"][0]["tool"]["driver"]["rules"]}

    assert rules["rfc5280_subject_key_identifier"]["defaultConfiguration"][
        "level"
    ] == "warning"
    assert rules["certificate_expiry_window"]["defaultConfiguration"]["level"] == "note"


def test_waived_finding_stays_visible_at_note_level(
    make_cert: Callable[..., Path], tmp_path: Path
) -> None:
    """A waiver suppresses the gate, not the record."""
    waiver = tmp_path / "waivers.json"
    waiver.write_text(
        json.dumps(
            {
                "waivers": [
                    {
                        "check": "rsa_key_size",
                        "reason": "Legacy appliance",
                        "ticket": "PKI-1",
                        "expires_on": "2099-01-01",
                    }
                ]
            }
        ),
        encoding="utf-8",
    )
    _, report = _evaluate(make_cert(key="rsa1024"), tmp_path, waiver)
    log = to_sarif(report)

    results = log["runs"][0]["results"]
    assert len(results) == 1
    assert results[0]["ruleId"] == "rsa_key_size"
    assert results[0]["level"] == "note"
    assert results[0]["properties"]["status"] == "waived"
    assert "[WAIVED]" in results[0]["message"]["text"]


def test_results_carry_a_location_github_can_anchor(
    make_cert: Callable[..., Path], tmp_path: Path
) -> None:
    _, report = _evaluate(make_cert(key="ec192"), tmp_path)
    log = to_sarif(report)

    location = log["runs"][0]["results"][0]["locations"][0]["physicalLocation"]
    assert location["artifactLocation"]["uri"]
    assert location["artifactLocation"]["uriBaseId"] == "%SRCROOT%"
    assert location["region"]["startLine"] == 1


def test_location_uri_is_not_an_absolute_path(
    make_cert: Callable[..., Path], tmp_path: Path
) -> None:
    """An absolute container path would produce an unattached annotation."""
    _, report = _evaluate(make_cert(key="ec192"), tmp_path)
    log = to_sarif(report, repo_root=Path.cwd())

    uri = log["runs"][0]["results"][0]["locations"][0]["physicalLocation"][
        "artifactLocation"
    ]["uri"]
    assert not uri.startswith("/")


def test_coverage_travels_with_the_sarif_log(
    make_cert: Callable[..., Path], tmp_path: Path
) -> None:
    _, report = _evaluate(make_cert(), tmp_path)
    properties = to_sarif(report)["runs"][0]["properties"]

    assert properties["coverage"] == report.coverage
    assert properties["engineVersion"] == __version__
    assert properties["riskLevel"] == report.risk_level


def test_fingerprints_are_stable_across_runs(
    make_cert: Callable[..., Path], tmp_path: Path
) -> None:
    cert = make_cert(key="ec192", name="stable.pem")
    _, first = _evaluate(cert, tmp_path)
    _, second = _evaluate(cert, tmp_path)

    def prints(report):
        return {
            r["ruleId"]: r["partialFingerprints"]["certguardControl/v1"]
            for r in to_sarif(report)["runs"][0]["results"]
        }

    assert prints(first) == prints(second)


def test_cli_writes_sarif(make_cert: Callable[..., Path], tmp_path: Path) -> None:
    import subprocess
    import sys

    cert = make_cert(key="ec192")
    sarif_path = tmp_path / "out.sarif"
    subprocess.run(
        [
            sys.executable, "src/main.py",
            "--cert", str(cert),
            "--report", str(tmp_path / "r.json"),
            "--evidence-dir", str(tmp_path / "e"),
            "--sarif-output", str(sarif_path),
        ],
        capture_output=True,
        text=True,
        check=False,
    )

    assert sarif_path.is_file()
    log = json.loads(sarif_path.read_text(encoding="utf-8"))
    assert log["version"] == SARIF_VERSION
    assert len(log["runs"][0]["results"]) == 2
