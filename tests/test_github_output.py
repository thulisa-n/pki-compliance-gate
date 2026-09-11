"""GitHub Actions surfaces: job summary and workflow annotations."""

from __future__ import annotations

from pathlib import Path
from typing import Callable

from certguard import github_output
from certguard.engine import ComplianceGateEngine

POLICY_PATH = Path("policies/cabf_policy.yaml")


def _evaluate(cert: Path, tmp_path: Path):
    engine = ComplianceGateEngine(policy_path=POLICY_PATH)
    return engine.evaluate(
        cert_path=cert,
        report_path=tmp_path / "report.json",
        evidence_dir=tmp_path / "evidence",
    )


def test_is_github_actions_reads_the_environment() -> None:
    assert github_output.is_github_actions({"GITHUB_ACTIONS": "true"}) is True
    assert github_output.is_github_actions({}) is False


def test_summary_states_verdict_risk_and_coverage(
    make_cert: Callable[..., Path], tmp_path: Path
) -> None:
    _, report = _evaluate(make_cert(key="ec192"), tmp_path)
    markdown = github_output.render_job_summary(report, policy_path=POLICY_PATH)

    assert "NON-COMPLIANT" in markdown
    assert "**Risk:** HIGH" in markdown
    assert "of 29 controls evaluated" in markdown
    assert "ec_curve_allowed" in markdown


def test_summary_separates_not_applicable_from_findings(
    make_cert: Callable[..., Path], tmp_path: Path
) -> None:
    """A control the policy never enabled must not read as a defect."""
    _, report = _evaluate(make_cert(), tmp_path)
    markdown = github_output.render_job_summary(report)

    assert "No failing controls." in markdown
    assert "not assessed, never counted as a pass" in markdown
    assert "<details>" in markdown


def test_summary_orders_findings_by_severity(
    make_cert: Callable[..., Path], tmp_path: Path
) -> None:
    _, report = _evaluate(make_cert(key="ec192", validity_days=500), tmp_path)
    markdown = github_output.render_job_summary(report)

    critical_at = markdown.index("critical")
    high_at = markdown.index("| high")
    assert critical_at < high_at


def test_summary_escapes_pipes_so_the_table_survives(
    make_cert: Callable[..., Path], tmp_path: Path
) -> None:
    _, report = _evaluate(make_cert(key="ec192"), tmp_path)
    for check in report.checks:
        if check.status == "fail":
            check.details = "detail | with | pipes"
    markdown = github_output.render_job_summary(report)

    assert "detail \\| with \\| pipes" in markdown


def test_write_job_summary_appends_to_the_env_path(
    make_cert: Callable[..., Path], tmp_path: Path
) -> None:
    _, report = _evaluate(make_cert(), tmp_path)
    summary = tmp_path / "step_summary.md"

    first = github_output.write_job_summary(
        report, env={"GITHUB_STEP_SUMMARY": str(summary)}
    )
    github_output.write_job_summary(report, env={"GITHUB_STEP_SUMMARY": str(summary)})

    assert first == summary
    # $GITHUB_STEP_SUMMARY is append-only by contract.
    assert summary.read_text(encoding="utf-8").count("## CertGuard compliance gate") == 2


def test_write_job_summary_is_a_noop_outside_actions(
    make_cert: Callable[..., Path], tmp_path: Path
) -> None:
    _, report = _evaluate(make_cert(), tmp_path)
    assert github_output.write_job_summary(report, env={}) is None


def test_annotations_use_error_for_critical_and_high(
    make_cert: Callable[..., Path], tmp_path: Path
) -> None:
    _, report = _evaluate(make_cert(key="ec192"), tmp_path)
    lines = github_output.annotation_lines(report)

    assert len(lines) == 2
    assert all(line.startswith("::error ") for line in lines)
    assert all("CertGuard critical" in line for line in lines)


def test_annotations_include_the_recommendation(
    make_cert: Callable[..., Path], tmp_path: Path
) -> None:
    _, report = _evaluate(make_cert(key="rsa1024"), tmp_path)
    lines = github_output.annotation_lines(report)

    assert "Recommendation:" in lines[0]


def test_annotations_escape_workflow_command_data(
    make_cert: Callable[..., Path], tmp_path: Path
) -> None:
    _, report = _evaluate(make_cert(key="rsa1024"), tmp_path)
    for check in report.checks:
        if check.status == "fail":
            check.details = "line one\nline two 50% done"
    lines = github_output.annotation_lines(report)

    assert "%0A" in lines[0], "newlines must be escaped or the annotation truncates"
    assert "%25" in lines[0], "percent must be escaped first"
    assert "\n" not in lines[0]


def test_clean_run_emits_a_single_notice(
    make_cert: Callable[..., Path], tmp_path: Path
) -> None:
    _, report = _evaluate(make_cert(), tmp_path)
    lines = github_output.annotation_lines(report)

    assert len(lines) == 1
    assert lines[0].startswith("::notice ")
    assert "No failing controls" in lines[0]


def test_emit_annotations_writes_to_the_stream(
    make_cert: Callable[..., Path], tmp_path: Path
) -> None:
    import io

    _, report = _evaluate(make_cert(key="ec192"), tmp_path)
    buffer = io.StringIO()
    count = github_output.emit_annotations(report, buffer)

    assert count == 2
    assert buffer.getvalue().count("::error ") == 2
