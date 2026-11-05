"""Fail pip-audit results at medium severity or above.

pip-audit reports every known advisory and does not attach a severity. This
gate reads that JSON, asks OSV for each advisory, and exits 1 when any
advisory is medium, high, or critical. Low and none are printed and do not
fail the run. An advisory with no usable severity fails closed.
"""

from __future__ import annotations

import argparse
import json
import math
import re
import subprocess
import sys
import urllib.error
import urllib.request
from collections.abc import Callable
from pathlib import Path
from typing import Any

OSV_VULN_URL = "https://api.osv.dev/v1/vulns/"
_VULN_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_PASSING = frozenset({"LOW", "NONE"})

_AV = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.20}
_AC = {"L": 0.77, "H": 0.44}
_UI = {"N": 0.85, "R": 0.62}
_CIA = {"H": 0.56, "L": 0.22, "N": 0.0}
_PR_UNCHANGED = {"N": 0.85, "L": 0.62, "H": 0.27}
_PR_CHANGED = {"N": 0.85, "L": 0.68, "H": 0.50}

Lookup = Callable[[str], dict[str, Any]]


def roundup_1(value: float) -> float:
    """CVSS v3.1 Roundup: smallest one-decimal value greater than or equal to ``value``."""
    scaled = round(value * 100000)
    if scaled % 10000 == 0:
        return scaled / 100000.0
    return (math.floor(scaled / 10000) + 1) / 10.0


def cvss_v3_base_score(vector: str) -> float | None:
    """Return the CVSS v3.0/v3.1 base score, or None when the vector is incomplete."""
    text = vector.strip()
    if not text.startswith(("CVSS:3.0/", "CVSS:3.1/")):
        return None
    metrics: dict[str, str] = {}
    for part in text.split("/")[1:]:
        if ":" not in part:
            return None
        key, value = part.split(":", 1)
        metrics[key] = value
    try:
        av = _AV[metrics["AV"]]
        ac = _AC[metrics["AC"]]
        ui = _UI[metrics["UI"]]
        scope = metrics["S"]
        pr_table = _PR_CHANGED if scope == "C" else _PR_UNCHANGED
        if scope not in {"U", "C"}:
            return None
        pr = pr_table[metrics["PR"]]
        confidentiality = _CIA[metrics["C"]]
        integrity = _CIA[metrics["I"]]
        availability = _CIA[metrics["A"]]
    except KeyError:
        return None
    exploitability = 8.22 * av * ac * pr * ui
    impact = 1 - ((1 - confidentiality) * (1 - integrity) * (1 - availability))
    if impact <= 0:
        return 0.0
    if scope == "U":
        impact_score = 6.42 * impact
        base = min(impact_score + exploitability, 10)
    else:
        impact_score = 7.52 * (impact - 0.029) - 3.25 * pow(impact - 0.02, 15)
        base = min(1.08 * (impact_score + exploitability), 10)
    return roundup_1(base)


def qualitative(score: float) -> str:
    if score <= 0:
        return "NONE"
    if score < 4.0:
        return "LOW"
    if score < 7.0:
        return "MEDIUM"
    if score < 9.0:
        return "HIGH"
    return "CRITICAL"


def label_from_document(document: dict[str, Any]) -> str | None:
    """Read a severity label from an OSV vulnerability document."""
    specific = document.get("database_specific")
    if isinstance(specific, dict):
        raw = specific.get("severity")
        if isinstance(raw, str) and raw.strip():
            return raw.strip().upper()
    for item in document.get("severity") or []:
        if not isinstance(item, dict):
            continue
        score = item.get("score")
        kind = str(item.get("type") or "")
        if isinstance(score, int | float):
            return qualitative(float(score))
        if not isinstance(score, str):
            continue
        stripped = score.strip()
        if stripped[:1].isdigit():
            try:
                return qualitative(float(stripped))
            except ValueError:
                continue
        if kind.startswith("CVSS_V3") or stripped.startswith("CVSS:3"):
            parsed = cvss_v3_base_score(stripped)
            if parsed is not None:
                return qualitative(parsed)
    return None


def is_blocking(label: str) -> bool:
    """Medium and above block. Missing severity blocks. Low and none do not."""
    return label.upper() not in _PASSING


def fetch_osv(vuln_id: str, timeout: float = 15.0) -> dict[str, Any]:
    """Fetch one OSV vulnerability document. The id is restricted to a safe token."""
    if not _VULN_ID.fullmatch(vuln_id):
        raise ValueError(f"unexpected vulnerability id: {vuln_id!r}")
    request = urllib.request.Request(
        OSV_VULN_URL + vuln_id,
        headers={"Accept": "application/json"},
    )
    with urllib.request.urlopen(request, timeout=timeout) as response:
        payload = json.load(response)
    if not isinstance(payload, dict):
        raise ValueError("OSV response was not a JSON object")
    return payload


def severity_for(vuln: dict[str, Any], lookup: Lookup) -> str:
    ids: list[str] = []
    primary = vuln.get("id")
    if isinstance(primary, str) and primary:
        ids.append(primary)
    aliases = vuln.get("aliases") or []
    if isinstance(aliases, list):
        ids.extend(alias for alias in aliases if isinstance(alias, str) and alias)
    for vuln_id in ids:
        try:
            document = lookup(vuln_id)
        except (urllib.error.URLError, TimeoutError, ValueError, json.JSONDecodeError, OSError):
            continue
        label = label_from_document(document)
        if label:
            return label
    return "UNKNOWN"


def collect(report: dict[str, Any], lookup: Lookup) -> list[dict[str, str]]:
    rows: list[dict[str, str]] = []
    dependencies = report.get("dependencies") or []
    if not isinstance(dependencies, list):
        return rows
    for dep in dependencies:
        if not isinstance(dep, dict):
            continue
        name = str(dep.get("name") or "")
        version = str(dep.get("version") or "")
        vulns = dep.get("vulns") or []
        if not isinstance(vulns, list):
            continue
        for vuln in vulns:
            if not isinstance(vuln, dict):
                continue
            label = severity_for(vuln, lookup)
            rows.append(
                {
                    "name": name,
                    "version": version,
                    "id": str(vuln.get("id") or ""),
                    "severity": label,
                    "blocking": "yes" if is_blocking(label) else "no",
                }
            )
    return rows


def render(rows: list[dict[str, str]]) -> str:
    if not rows:
        return "No known vulnerabilities found\n"
    lines = ["name\tversion\tid\tseverity\tblocking"]
    lines.extend(
        f"{row['name']}\t{row['version']}\t{row['id']}\t{row['severity']}\t{row['blocking']}"
        for row in rows
    )
    blocking = [row for row in rows if row["blocking"] == "yes"]
    lines.append(
        f"{len(blocking)} blocking of {len(rows)} advisories (medium and above, or unscored)"
    )
    return "\n".join(lines) + "\n"


def run_pip_audit(requirements: list[str]) -> dict[str, Any]:
    """Run pip-audit on hashed requirement files and return its JSON object."""
    command = [
        sys.executable,
        "-m",
        "pip_audit",
        "--disable-pip",
        "--progress-spinner",
        "off",
        "--format",
        "json",
        "--desc",
        "off",
    ]
    for requirement in requirements:
        command.extend(["--requirement", requirement])
    process = subprocess.run(command, capture_output=True, text=True, check=False)
    stdout = process.stdout.strip()
    try:
        report = json.loads(stdout) if stdout else None
    except json.JSONDecodeError:
        report = None
    if not isinstance(report, dict):
        sys.stderr.write(process.stderr)
        if process.stdout:
            sys.stderr.write(process.stdout)
            if not process.stdout.endswith("\n"):
                sys.stderr.write("\n")
        raise SystemExit(process.returncode or 1)
    return report


def main(argv: list[str] | None = None, lookup: Lookup | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--requirement",
        action="append",
        default=[],
        help="Hashed requirements file. Repeat for runtime and dev.",
    )
    parser.add_argument(
        "--report",
        type=Path,
        help="Existing pip-audit JSON. Skips the pip-audit subprocess.",
    )
    parser.add_argument("--output", type=Path, help="Write the severity table here as well.")
    args = parser.parse_args(argv)

    if args.report is not None:
        loaded = json.loads(args.report.read_text(encoding="utf-8"))
        if not isinstance(loaded, dict):
            print("pip-audit JSON was not an object", file=sys.stderr)
            return 1
        report = loaded
    else:
        if not args.requirement:
            parser.error("pass --requirement or --report")
        report = run_pip_audit(args.requirement)

    rows = collect(report, lookup or fetch_osv)
    text = render(rows)
    sys.stdout.write(text)
    if args.output is not None:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(text, encoding="utf-8")
    if any(row["blocking"] == "yes" for row in rows):
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
