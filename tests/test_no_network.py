"""Main CLI paths must not open sockets.

The live TLS check is the only exemption, and only when ``--allow-network``
is set. Any other outbound attempt fails this test.
"""

from __future__ import annotations

import socket
from pathlib import Path

import pytest

from certguard.cli import main

ROOT = Path(__file__).resolve().parents[1]
POLICY = ROOT / "policies" / "cabf_policy.yaml"
CERT = ROOT / "tests" / "certificates" / "valid_cert.pem"
CSR = ROOT / "tests" / "certificates" / "csrs" / "valid.csr"
BASELINE = ROOT / "policies" / "standards_baseline.yaml"
SIGNALS = ROOT / "examples" / "external_signals.json"


def _invoke(argv: list[str]) -> int:
    try:
        return main(argv)
    except SystemExit as exc:
        code = exc.code
        if code in (0, None):
            return 0
        if isinstance(code, int):
            return code
        raise


def _block_outbound(monkeypatch: pytest.MonkeyPatch) -> list[str]:
    """Fail the test on socket creation, DNS, or connect."""
    attempts: list[str] = []
    real_socket = socket.socket

    def blocked_connect(self: object, address: object) -> None:
        attempts.append(f"connect {address!r}")
        raise AssertionError(f"socket.connect {address!r}")

    def blocked_socket(*args: object, **kwargs: object) -> object:
        attempts.append(f"socket {args!r}")
        raise AssertionError(f"socket.socket {args!r}")

    def blocked_dns(host: object, *args: object, **kwargs: object) -> object:
        attempts.append(f"dns {host!r}")
        raise AssertionError(f"getaddrinfo {host!r}")

    def blocked_cc(address: object, *args: object, **kwargs: object) -> object:
        attempts.append(f"create_connection {address!r}")
        raise AssertionError(f"create_connection {address!r}")

    monkeypatch.setattr(real_socket, "connect", blocked_connect)
    monkeypatch.setattr(socket, "socket", blocked_socket)
    monkeypatch.setattr(socket, "getaddrinfo", blocked_dns)
    monkeypatch.setattr(socket, "create_connection", blocked_cc)
    return attempts


def test_main_cli_paths_make_no_outbound_attempt(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    attempts = _block_outbound(monkeypatch)
    report = tmp_path / "report.json"
    common = ["--policy", str(POLICY)]

    evaluate = _invoke(
        [
            "--cert",
            str(CERT),
            *common,
            "--report",
            str(report),
            "--evidence-dir",
            str(tmp_path / "evidence"),
            "--output",
            "json",
        ]
    )
    assert evaluate == 0
    assert report.is_file()

    csr_code = _invoke(
        [
            "--csr",
            str(CSR),
            *common,
            "--as-of",
            "2026-09-18",
            "--report",
            str(tmp_path / "csr.json"),
            "--evidence-dir",
            str(tmp_path / "csr-evidence"),
            "--output",
            "json",
        ]
    )
    assert csr_code == 0

    flagged = _invoke(
        [
            "--allow-network",
            "--cert",
            str(CERT),
            *common,
            "--report",
            str(tmp_path / "flagged.json"),
            "--evidence-dir",
            str(tmp_path / "flagged-evidence"),
            "--output",
            "json",
        ]
    )
    assert flagged == 0

    invocations = [
        ["--mode", "triage", "--report-input", str(report)],
        ["--mode", "assure", "--report-input", str(report)],
        [
            "--mode",
            "summary",
            "--report-input",
            str(report),
            "--summary-output",
            str(tmp_path / "summary.md"),
        ],
        [
            "--mode",
            "trend",
            "--report-input",
            str(report),
            "--trend-output",
            str(tmp_path / "trend.json"),
        ],
        ["--mode", "heal", "--report-input", str(report), "--policy", str(POLICY)],
        [
            "--mode",
            "watch",
            "--policy",
            str(POLICY),
            "--standards-baseline",
            str(BASELINE),
            "--watch-output",
            str(tmp_path / "watch.json"),
            "--as-of",
            "2026-09-18",
        ],
        [
            "--mode",
            "signals",
            "--external-signals",
            str(SIGNALS),
            "--signals-output",
            str(tmp_path / "signals.json"),
            "--signal-recommendations-output",
            str(tmp_path / "recs.json"),
        ],
        [
            "--mode",
            "readiness",
            "--policy",
            str(POLICY),
            "--standards-baseline",
            str(BASELINE),
            "--readiness-output",
            str(tmp_path / "ready.json"),
            "--as-of",
            "2026-09-18",
            "--output",
            "json",
        ],
        [
            "--mode",
            "export-cps-doc",
            "--policy",
            str(POLICY),
            "--summary-output",
            str(tmp_path / "cps.md"),
        ],
        [
            "--mode",
            "export-rego",
            "--policy",
            str(POLICY),
            "--summary-output",
            str(tmp_path / "validity.rego"),
        ],
        ["doctor"],
        ["doctor", "--json"],
        ["--help"],
        ["--version"],
        ["--mode", "apisec", "--endpoint", "https://api.example.com"],
        [
            "--mode",
            "apisec",
            "--endpoint",
            "https://api.example.com",
            "--endpoint",
            "https://other.example",
        ],
    ]
    for argv in invocations:
        code = _invoke(argv)
        assert code in {0, 1, 2, 3}, argv
        if argv[0] == "doctor" or argv in (["--help"], ["--version"]):
            assert code == 0, argv
        if argv[:2] == ["--mode", "apisec"]:
            assert code == 2, argv

    roots = tmp_path / "public-roots.txt"
    roots.write_text("ab" * 32 + "\n", encoding="utf-8")
    auto = _invoke(
        [
            "--cert",
            str(CERT),
            *common,
            "--trust-scope",
            "auto",
            "--chain",
            str(CERT),
            "--public-trust-roots",
            str(roots),
            "--report",
            str(tmp_path / "auto.json"),
            "--evidence-dir",
            str(tmp_path / "auto-evidence"),
            "--output",
            "json",
        ]
    )
    assert auto == 0

    assert attempts == []


def test_opt_in_tls_check_connects_only_to_listed_hosts(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    queries: list[tuple[object, object]] = []
    contacts: list[tuple[object, object]] = []
    allowed = {"api.example.com": "203.0.113.10", "other.example": "203.0.113.11"}

    def fake_dns(host: str, port: int, *args: object, **kwargs: object) -> list[tuple]:
        queries.append((host, port))
        if host not in allowed:
            raise AssertionError(f"dns for unlisted host {host}")
        return [
            (
                socket.AF_INET,
                socket.SOCK_STREAM,
                socket.IPPROTO_TCP,
                "",
                (allowed[host], port),
            )
        ]

    def intercepted_connect(self: object, address: tuple[str, int]) -> None:
        contacts.append((address[0], address[1]))
        if address[0] not in set(allowed.values()) or address[1] != 443:
            raise AssertionError(f"connect to unexpected destination {address!r}")
        raise OSError("intercepted opt-in connection")

    monkeypatch.setattr(socket, "getaddrinfo", fake_dns)
    monkeypatch.setattr(socket.socket, "connect", intercepted_connect)

    code = _invoke(
        [
            "--mode",
            "apisec",
            "--allow-network",
            "--endpoint",
            "https://api.example.com",
            "--endpoint",
            "other.example",
            "--network-timeout",
            "5",
        ]
    )
    assert code == 2
    assert queries == [("api.example.com", 443), ("other.example", 443)]
    assert contacts == [("203.0.113.10", 443), ("203.0.113.11", 443)]


def test_no_telemetry_doc_states_the_guarantee() -> None:
    text = (ROOT / "NO_TELEMETRY.md").read_text(encoding="utf-8")
    lowered = text.lower()
    assert "Neakam" in text
    assert "telemetry" in lowered
    assert "--allow-network" in text
    assert "redirect" in lowered
    assert "doctor" in lowered
