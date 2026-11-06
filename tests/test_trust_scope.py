"""Trust scope: public results stay, private PKI skips CA/B public-TLS controls."""

from __future__ import annotations

import base64
import json
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
import yaml
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.x509.oid import NameOID

from certguard.agents.policy_validator import PUBLIC_TLS_ONLY_CONTROLS
from certguard.agents.reviewer_summary import ReviewerSummaryAgent
from certguard.engine import ComplianceGateEngine
from certguard.github_output import render_job_summary
from certguard.policy import PolicyValidationError, load_policy
from certguard.sarif import to_sarif
from certguard.trust_scope import (
    PUBLIC_TLS_NA_REASON,
    choose_issuer,
    load_public_trust_roots,
    spki_sha256,
)
from tests.support.certificates import CertSpec, write_certificate, write_csr
from tests.support.neakam_cli import run

ROOT = Path(__file__).resolve().parents[1]
POLICY = ROOT / "policies" / "cabf_policy.yaml"
_AUTO = object()

HYGIENE_CONTROLS = (
    "certificate_not_expired",
    "certificate_not_yet_valid",
    "san_extension",
    "key_algorithm_allowed",
    "rsa_key_size",
    "ec_key_size",
    "ec_curve_allowed",
    "signature_algorithm",
    "signature_algorithm_oid",
    "extended_key_usage",
    "rfc5280_end_entity_ca",
    "crypto_transition_validity_target",
    "crypto_transition_rsa_target",
    "crypto_transition_signature_hash",
)


def _status(report, name: str) -> str:
    return next(check.status for check in report.checks if check.name == name)


def _check(report, name: str):
    return next(check for check in report.checks if check.name == name)


def _write_policy(
    directory: Path,
    *,
    scope: str | None = "public",
    public_roots: str | None = None,
    drop_trust: bool = False,
    mutate: Callable[[dict], None] | None = None,
    name: str = "policy.yaml",
) -> Path:
    data = yaml.safe_load(POLICY.read_text(encoding="utf-8"))
    if drop_trust:
        data.pop("trust", None)
    else:
        data.setdefault("trust", {})
        if scope is not None:
            data["trust"]["scope"] = scope
        if public_roots is not None:
            data["trust"]["public_roots"] = public_roots
    if mutate is not None:
        mutate(data)
    path = directory / name
    path.write_text(yaml.safe_dump(data), encoding="utf-8")
    return path


def _name(common_name: str) -> x509.Name:
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])


def _ec_key():
    return ec.generate_private_key(ec.SECP256R1())


def _build_cert(
    *,
    subject: x509.Name,
    issuer_name: x509.Name,
    subject_key,
    issuer_key,
    not_before: datetime,
    not_after: datetime,
    ca: bool | None,
    san: tuple[str, ...] = (),
    serial: int | None = None,
    aki: object = _AUTO,
) -> x509.Certificate:
    public = subject_key.public_key()
    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer_name)
        .public_key(public)
        .serial_number(serial if serial is not None else x509.random_serial_number())
        .not_valid_before(not_before)
        .not_valid_after(not_after)
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(public),
            critical=False,
        )
    )
    if ca is not None:
        builder = builder.add_extension(
            x509.BasicConstraints(ca=ca, path_length=None),
            critical=True,
        )
    if aki is _AUTO and subject != issuer_name:
        issuer_ski = x509.SubjectKeyIdentifier.from_public_key(issuer_key.public_key())
        builder = builder.add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_subject_key_identifier(issuer_ski),
            critical=False,
        )
    elif isinstance(aki, bytes):
        builder = builder.add_extension(
            x509.AuthorityKeyIdentifier(
                key_identifier=aki,
                authority_cert_issuer=None,
                authority_cert_serial_number=None,
            ),
            critical=False,
        )
    if san:
        builder = builder.add_extension(
            x509.SubjectAlternativeName([x509.DNSName(item) for item in san]),
            critical=False,
        )
    return builder.sign(issuer_key, hashes.SHA256())


def _pem(certificate: x509.Certificate) -> bytes:
    return certificate.public_bytes(Encoding.PEM)


def issue_chain(
    directory: Path,
    *,
    leaf_days: int = 90,
    san: tuple[str, ...] = ("example.com",),
    serial: int | None = None,
    with_intermediate: bool = True,
    intermediate_ca: bool = True,
    intermediate_expired: bool = False,
    root_ca: bool | None = True,
    leaf_aki: object = _AUTO,
) -> dict[str, object]:
    """Mint a leaf plus a chain bundle of intermediate (optional) and root."""
    directory.mkdir(parents=True, exist_ok=True)
    now = datetime.now(UTC)
    root_key = _ec_key()
    root_name = _name("Trust Scope Root")
    root = _build_cert(
        subject=root_name,
        issuer_name=root_name,
        subject_key=root_key,
        issuer_key=root_key,
        not_before=now - timedelta(days=2),
        not_after=now + timedelta(days=3650),
        ca=root_ca,
    )
    issuer_key = root_key
    issuer_name = root_name
    bundle = [_pem(root)]
    if with_intermediate:
        intermediate_key = _ec_key()
        intermediate_name = _name("Trust Scope Intermediate")
        if intermediate_expired:
            not_before = now - timedelta(days=40)
            not_after = now - timedelta(days=1)
        else:
            not_before = now - timedelta(days=1)
            not_after = now + timedelta(days=3000)
        intermediate = _build_cert(
            subject=intermediate_name,
            issuer_name=root_name,
            subject_key=intermediate_key,
            issuer_key=root_key,
            not_before=not_before,
            not_after=not_after,
            ca=intermediate_ca,
        )
        issuer_key = intermediate_key
        issuer_name = intermediate_name
        bundle.insert(0, _pem(intermediate))
    leaf_key = _ec_key()
    leaf_not_before = now - timedelta(minutes=5)
    leaf_cert = _build_cert(
        subject=_name(san[0]),
        issuer_name=issuer_name,
        subject_key=leaf_key,
        issuer_key=issuer_key,
        not_before=leaf_not_before,
        not_after=leaf_not_before + timedelta(days=leaf_days),
        ca=False,
        san=san,
        serial=serial,
        aki=leaf_aki,
    )
    leaf_path = directory / "leaf.pem"
    chain_path = directory / "chain.pem"
    root_path = directory / "root.pem"
    leaf_path.write_bytes(_pem(leaf_cert))
    chain_path.write_bytes(b"".join(bundle))
    root_path.write_bytes(_pem(root))
    return {
        "leaf": leaf_path,
        "chain": chain_path,
        "root": root,
        "root_path": root_path,
    }


def _assess(policy: Path, cert: Path, **kwargs):
    engine = ComplianceGateEngine(policy_path=policy)
    report, _artifacts = engine.assess(cert_path=cert, **kwargs)
    return report


def test_public_tls_control_set_is_the_audited_list() -> None:
    assert {
        "validity_days",
        "internal_domain_check",
        "serial_entropy",
        "sct_presence",
        "dcv_method",
        "dcv_recency",
    } == PUBLIC_TLS_ONLY_CONTROLS
    assert PUBLIC_TLS_ONLY_CONTROLS.isdisjoint(HYGIENE_CONTROLS)


def test_public_default_still_fails_long_validity_and_matches_explicit_public(
    tmp_path: Path,
) -> None:
    cert = write_certificate(
        tmp_path / "long.pem",
        CertSpec(
            validity_days=400,
            san_dns=("app.local",),
            common_name="app.local",
            serial_number=1,
        ),
    )
    policy = _write_policy(tmp_path)
    default = _assess(policy, cert)
    explicit = _assess(policy, cert, cli_trust_scope="public")

    assert default.trust_scope["requested"] == "public"
    assert default.trust_scope["effective"] == "public"
    assert default.trust_scope["source"] == "policy"
    assert [(check.name, check.status, check.details) for check in default.checks] == [
        (check.name, check.status, check.details) for check in explicit.checks
    ]
    assert _status(default, "validity_days") == "fail"
    assert "400" in _check(default, "validity_days").details
    assert _status(default, "internal_domain_check") == "fail"
    assert _status(default, "serial_entropy") == "fail"
    assert PUBLIC_TLS_NA_REASON not in _check(default, "validity_days").details
    assert _status(default, "rsa_key_size") == "pass"
    assert _status(default, "signature_algorithm") == "pass"


def _enable_every_public_tls_control(policy: dict) -> None:
    policy["certificate"]["require_sct"] = True
    policy["certificate"]["require_eku"] = True
    policy["dcv"]["required"] = True
    policy["rfc5280"]["require_end_entity_not_ca"] = True
    policy["crypto_transition"]["enabled"] = True


def test_private_scope_marks_every_public_tls_control_not_applicable(
    tmp_path: Path,
) -> None:
    cert = write_certificate(
        tmp_path / "private.pem",
        CertSpec(
            validity_days=400,
            san_dns=("app.local",),
            common_name="app.local",
            serial_number=1,
            key="rsa1024",
            basic_constraints_ca=True,
        ),
    )
    policy = _write_policy(tmp_path, mutate=_enable_every_public_tls_control)
    public = _assess(policy, cert, cli_trust_scope="public")
    private = _assess(policy, cert, cli_trust_scope="private")

    for name in PUBLIC_TLS_ONLY_CONTROLS:
        assert _status(public, name) == "fail", name
        assert _status(private, name) == "not_applicable", name
        assert _check(private, name).details == PUBLIC_TLS_NA_REASON

    for name in (
        "rsa_key_size",
        "extended_key_usage",
        "rfc5280_end_entity_ca",
        "crypto_transition_validity_target",
        "crypto_transition_rsa_target",
        "signature_algorithm",
        "signature_algorithm_oid",
        "san_extension",
        "certificate_not_expired",
        "key_algorithm_allowed",
    ):
        assert _status(private, name) == _status(public, name), name
        assert _status(private, name) in {"pass", "fail"}
    assert _status(private, "rsa_key_size") == "fail"
    assert _status(private, "signature_algorithm") == "pass"
    assert _status(private, "certificate_not_expired") == "pass"
    assert private.trust_scope["effective"] == "private"
    assert private.trust_scope["reason"] == PUBLIC_TLS_NA_REASON
    assert private.trust_scope["source"] == "cli"


@pytest.mark.parametrize("control", sorted(PUBLIC_TLS_ONLY_CONTROLS))
def test_each_public_tls_control_fails_in_public_and_is_not_applicable_in_private(
    control: str, tmp_path: Path
) -> None:
    spec = CertSpec()
    attestation = None

    def mutate(policy: dict) -> None:
        if control == "sct_presence":
            policy["certificate"]["require_sct"] = True
        if control in {"dcv_method", "dcv_recency"}:
            policy["dcv"]["required"] = True

    if control == "validity_days":
        spec = CertSpec(validity_days=400)
    elif control == "internal_domain_check":
        spec = CertSpec(san_dns=("app.local",), common_name="app.local")
    elif control == "serial_entropy":
        spec = CertSpec(serial_number=1)
    elif control == "dcv_method":
        attestation = {
            "method": "email",
            "validated_at": datetime.now(UTC).isoformat(),
        }
    elif control == "dcv_recency":
        attestation = {"method": "dns-01", "validated_at": "2020-01-01T00:00:00+00:00"}

    cert = write_certificate(tmp_path / f"{control}.pem", spec)
    policy = _write_policy(tmp_path, mutate=mutate, name=f"{control}-policy.yaml")
    public = _assess(policy, cert, cli_trust_scope="public", dcv_attestation=attestation)
    private = _assess(policy, cert, cli_trust_scope="private", dcv_attestation=attestation)

    assert _status(public, control) == "fail"
    assert _status(private, control) == "not_applicable"
    assert _check(private, control).details == PUBLIC_TLS_NA_REASON
    assert _check(private, control).actual_value == _check(public, control).actual_value
    for name in (
        "rsa_key_size",
        "signature_algorithm",
        "certificate_not_expired",
        "san_extension",
        "key_algorithm_allowed",
    ):
        assert _status(private, name) == _status(public, name)
        assert _status(public, name) == "pass"


def test_private_scope_still_rejects_weak_curves_and_expired_certificates(
    tmp_path: Path,
) -> None:
    weak = write_certificate(tmp_path / "ec192.pem", CertSpec(key="ec192"))
    expired = write_certificate(
        tmp_path / "expired.pem",
        CertSpec(starts_in_days=-400, validity_days=30),
    )
    policy = _write_policy(tmp_path)
    weak_report = _assess(policy, weak, cli_trust_scope="private")
    expired_report = _assess(policy, expired, cli_trust_scope="private")

    assert _status(weak_report, "ec_curve_allowed") == "fail"
    assert _status(weak_report, "ec_key_size") == "fail"
    assert _status(weak_report, "validity_days") == "not_applicable"
    assert _status(expired_report, "certificate_not_expired") == "fail"
    assert _status(expired_report, "validity_days") == "not_applicable"


def test_private_scope_still_rejects_sha1(tmp_path: Path) -> None:
    policy = _write_policy(tmp_path)
    report = _assess(
        policy,
        ROOT / "tests" / "certificates" / "sha1_cert.pem",
        cli_trust_scope="private",
        evaluated_at="2026-09-18",
    )
    assert _status(report, "signature_algorithm") == "fail"
    assert _status(report, "signature_algorithm_oid") == "fail"


def test_private_scope_on_a_csr_skips_internal_names_and_keeps_key_size(
    tmp_path: Path,
) -> None:
    csr = write_csr(
        tmp_path / "app.csr",
        CertSpec(san_dns=("app.local",), common_name="app.local", key="rsa1024"),
    )
    policy = _write_policy(tmp_path)
    public = _assess(policy, csr, input_kind="csr", cli_trust_scope="public")
    private = _assess(policy, csr, input_kind="csr", cli_trust_scope="private")

    assert _status(public, "internal_domain_check") == "fail"
    assert _status(private, "internal_domain_check") == "not_applicable"
    assert _check(private, "internal_domain_check").details == PUBLIC_TLS_NA_REASON
    assert _status(public, "rsa_key_size") == "fail"
    assert _status(private, "rsa_key_size") == "fail"


def test_auto_public_root_stays_public_and_private_root_becomes_private(
    tmp_path: Path,
) -> None:
    issued = issue_chain(tmp_path / "issued", leaf_days=400)
    leaf = issued["leaf"]
    assert isinstance(leaf, Path)
    chain = issued["chain"]
    assert isinstance(chain, Path)
    root = issued["root"]
    assert isinstance(root, x509.Certificate)
    root_path = issued["root_path"]
    assert isinstance(root_path, Path)

    other = issue_chain(tmp_path / "other")
    other_root = other["root_path"]
    assert isinstance(other_root, Path)
    policy = _write_policy(tmp_path)

    on_public_root = _assess(
        policy,
        leaf,
        cli_trust_scope="auto",
        cli_public_roots=str(root_path),
        chain_path=chain,
    )
    on_private_root = _assess(
        policy,
        leaf,
        cli_trust_scope="auto",
        cli_public_roots=str(other_root),
        chain_path=chain,
    )

    assert on_public_root.trust_scope["effective"] == "public"
    assert on_public_root.trust_scope["requested"] == "auto"
    assert "in the configured public-trust root set" in on_public_root.trust_scope["reason"]
    assert on_public_root.trust_scope["root_spki_sha256"] == spki_sha256(root)
    assert _status(on_public_root, "validity_days") == "fail"
    assert _status(on_public_root, "ec_key_size") == "pass"
    assert _status(on_public_root, "ec_curve_allowed") == "pass"

    assert on_private_root.trust_scope["effective"] == "private"
    assert "not in the configured public-trust root set" in on_private_root.trust_scope["reason"]
    assert _status(on_private_root, "validity_days") == "not_applicable"
    assert _check(on_private_root, "validity_days").details == PUBLIC_TLS_NA_REASON
    assert _status(on_private_root, "ec_key_size") == "pass"
    assert _status(on_private_root, "signature_algorithm") == "pass"
    assert _status(on_private_root, "certificate_not_expired") == "pass"


def test_auto_accepts_a_root_directory_and_an_spki_hash_file(tmp_path: Path) -> None:
    issued = issue_chain(tmp_path / "issued", leaf_days=400)
    leaf = issued["leaf"]
    chain = issued["chain"]
    root = issued["root"]
    root_path = issued["root_path"]
    assert isinstance(leaf, Path)
    assert isinstance(chain, Path)
    assert isinstance(root, x509.Certificate)
    assert isinstance(root_path, Path)

    directory = tmp_path / "roots"
    directory.mkdir()
    (directory / "README.md").write_text("notes\n", encoding="utf-8")
    (directory / "root.pem").write_bytes(root_path.read_bytes())
    digest = spki_sha256(root)
    hash_file = tmp_path / "hashes.txt"
    hash_file.write_text(f"# comment\nsha256:{digest.upper()}\n", encoding="utf-8")
    policy = _write_policy(tmp_path)

    from_directory = _assess(
        policy,
        leaf,
        cli_trust_scope="auto",
        cli_public_roots=str(directory),
        chain_path=chain,
    )
    from_hash = _assess(
        policy,
        leaf,
        cli_trust_scope="auto",
        cli_public_roots=str(hash_file),
        chain_path=chain,
    )
    assert from_directory.trust_scope["effective"] == "public"
    assert from_hash.trust_scope["effective"] == "public"
    assert from_hash.trust_scope["root_spki_sha256"] == digest


def test_auto_without_chain_root_set_or_a_verifying_path_stays_public(
    tmp_path: Path,
) -> None:
    issued = issue_chain(tmp_path / "issued", leaf_days=400)
    other = issue_chain(tmp_path / "other")
    leaf = issued["leaf"]
    chain = issued["chain"]
    root_path = issued["root_path"]
    other_chain = other["chain"]
    assert isinstance(leaf, Path)
    assert isinstance(chain, Path)
    assert isinstance(root_path, Path)
    assert isinstance(other_chain, Path)
    policy = _write_policy(tmp_path, scope="auto", public_roots=str(root_path))

    no_chain = _assess(policy, leaf)
    no_roots = _assess(
        _write_policy(tmp_path, scope="auto", name="no-roots.yaml"),
        leaf,
        chain_path=chain,
    )
    broken = _assess(
        policy,
        leaf,
        chain_path=other_chain,
    )
    missing = _assess(
        policy,
        leaf,
        chain_path=chain,
        cli_public_roots=str(tmp_path / "missing-roots"),
    )
    empty = tmp_path / "empty-roots.txt"
    empty.write_text("\n", encoding="utf-8")
    empty_set = _assess(policy, leaf, chain_path=chain, cli_public_roots=str(empty))
    garbage = tmp_path / "garbage.txt"
    garbage.write_text("not-a-root\n", encoding="utf-8")
    unparsed = _assess(policy, leaf, chain_path=chain, cli_public_roots=str(garbage))

    assert no_chain.trust_scope["effective"] == "public"
    assert "no certificate chain was provided" in no_chain.trust_scope["reason"]
    assert no_chain.trust_scope["source"] == "policy"
    assert _status(no_chain, "validity_days") == "fail"

    assert no_roots.trust_scope["effective"] == "public"
    assert "no public-trust root set was configured" in no_roots.trust_scope["reason"]
    assert _status(no_roots, "validity_days") == "fail"

    assert broken.trust_scope["effective"] == "public"
    assert "does not verify to a root" in broken.trust_scope["reason"]
    assert _status(broken, "validity_days") == "fail"

    assert "path does not exist" in missing.trust_scope["reason"]
    assert "contained no certificates or SPKI hashes" in empty_set.trust_scope["reason"]
    assert "could not be parsed" in unparsed.trust_scope["reason"]
    assert missing.trust_scope["effective"] == "public"
    assert empty_set.trust_scope["effective"] == "public"
    assert unparsed.trust_scope["effective"] == "public"


def test_auto_rejects_unclear_chains(tmp_path: Path) -> None:
    policy = _write_policy(tmp_path, scope="auto")
    expired = issue_chain(tmp_path / "expired", intermediate_expired=True)
    not_ca = issue_chain(tmp_path / "not-ca", intermediate_ca=False)
    bad_aki = issue_chain(tmp_path / "aki", leaf_aki=b"\x11" * 20)
    bare_root = issue_chain(tmp_path / "bare", root_ca=None, with_intermediate=False)
    roots = tmp_path / "anchor.txt"
    roots.write_text("ab" * 32 + "\n", encoding="utf-8")

    cases = (
        (expired, "outside its validity period"),
        (not_ca, "not a CA"),
        (bad_aki, "does not verify to a root"),
        (bare_root, "not a CA"),
    )
    for issued, expected in cases:
        leaf = issued["leaf"]
        chain = issued["chain"]
        assert isinstance(leaf, Path)
        assert isinstance(chain, Path)
        report = _assess(
            policy,
            leaf,
            chain_path=chain,
            cli_public_roots=str(roots),
        )
        assert report.trust_scope["effective"] == "public"
        assert expected in report.trust_scope["reason"]


def test_auto_loop_and_unlinked_self_signed_leaf_stay_public(tmp_path: Path) -> None:
    now = datetime.now(UTC)
    key_a = _ec_key()
    key_b = _ec_key()
    name_a = _name("IssuerA")
    name_b = _name("IssuerB")
    window = {
        "not_before": now - timedelta(days=1),
        "not_after": now + timedelta(days=365),
    }
    cert_a = _build_cert(
        subject=name_a,
        issuer_name=name_b,
        subject_key=key_a,
        issuer_key=key_b,
        ca=True,
        **window,
    )
    cert_b = _build_cert(
        subject=name_b,
        issuer_name=name_a,
        subject_key=key_b,
        issuer_key=key_a,
        ca=True,
        **window,
    )
    leaf_key = _ec_key()
    leaf = _build_cert(
        subject=_name("leaf.example.com"),
        issuer_name=name_a,
        subject_key=leaf_key,
        issuer_key=key_a,
        ca=False,
        san=("leaf.example.com",),
        not_before=now - timedelta(minutes=5),
        not_after=now + timedelta(days=30),
    )
    leaf_path = tmp_path / "loop-leaf.pem"
    chain_path = tmp_path / "loop-chain.pem"
    leaf_path.write_bytes(_pem(leaf))
    chain_path.write_bytes(_pem(cert_a) + _pem(cert_b))

    self_signed = _build_cert(
        subject=_name("solo.example.com"),
        issuer_name=_name("solo.example.com"),
        subject_key=leaf_key,
        issuer_key=leaf_key,
        ca=True,
        san=("solo.example.com",),
        not_before=now - timedelta(minutes=5),
        not_after=now + timedelta(days=30),
    )
    solo_path = tmp_path / "solo.pem"
    solo_path.write_bytes(_pem(self_signed))
    unrelated = issue_chain(tmp_path / "unrelated")
    unrelated_chain = unrelated["chain"]
    assert isinstance(unrelated_chain, Path)

    roots = tmp_path / "roots.txt"
    roots.write_text("cd" * 32 + "\n", encoding="utf-8")
    policy = _write_policy(tmp_path)
    loop = _assess(
        policy,
        leaf_path,
        cli_trust_scope="auto",
        chain_path=chain_path,
        cli_public_roots=str(roots),
    )
    unlinked = _assess(
        policy,
        solo_path,
        cli_trust_scope="auto",
        chain_path=unrelated_chain,
        cli_public_roots=str(roots),
    )
    assert "contains a loop" in loop.trust_scope["reason"]
    assert loop.trust_scope["effective"] == "public"
    assert "does not link the leaf" in unlinked.trust_scope["reason"]
    assert unlinked.trust_scope["effective"] == "public"


def test_auto_self_signed_root_in_the_chain_can_be_private(tmp_path: Path) -> None:
    now = datetime.now(UTC)
    key = _ec_key()
    subject = _name("private.example.com")
    certificate = _build_cert(
        subject=subject,
        issuer_name=subject,
        subject_key=key,
        issuer_key=key,
        ca=True,
        san=("private.example.com",),
        not_before=now - timedelta(days=1),
        not_after=now + timedelta(days=800),
    )
    leaf = tmp_path / "root-leaf.pem"
    leaf.write_bytes(_pem(certificate))
    roots = tmp_path / "elsewhere.txt"
    roots.write_text("ef" * 32 + "\n", encoding="utf-8")
    policy = _write_policy(tmp_path)
    report = _assess(
        policy,
        leaf,
        cli_trust_scope="auto",
        chain_path=leaf,
        cli_public_roots=str(roots),
    )
    assert report.trust_scope["effective"] == "private"
    assert _status(report, "validity_days") == "not_applicable"
    assert _status(report, "ec_curve_allowed") == "pass"


def test_auto_on_a_csr_stays_public(tmp_path: Path) -> None:
    csr = write_csr(
        tmp_path / "name.csr",
        CertSpec(san_dns=("app.local",), common_name="app.local"),
    )
    policy = _write_policy(tmp_path, scope="auto")
    report = _assess(policy, csr, input_kind="csr")
    assert report.trust_scope["effective"] == "public"
    assert "CSR" in report.trust_scope["reason"]
    assert _status(report, "internal_domain_check") == "fail"


def test_cli_flag_overrides_policy_and_policy_applies_when_the_flag_is_omitted(
    tmp_path: Path,
) -> None:
    cert = write_certificate(tmp_path / "long.pem", CertSpec(validity_days=400))
    private_policy = _write_policy(tmp_path, scope="private", name="private.yaml")
    public_policy = _write_policy(tmp_path, scope="public", name="public.yaml")
    default_policy = _write_policy(tmp_path, drop_trust=True, name="default.yaml")

    def invoke(policy: Path, *extra: str) -> dict:
        result = run(
            [
                "--cert",
                str(cert),
                "--policy",
                str(policy),
                "--output",
                "json",
                "--report",
                str(tmp_path / f"{policy.stem}.json"),
                "--evidence-dir",
                str(tmp_path / policy.stem),
                *extra,
            ],
            cwd=ROOT,
        )
        assert result.returncode in {0, 1, 2, 3}, result.stderr
        assert result.stderr == ""
        return json.loads(result.stdout)

    from_policy = invoke(private_policy)
    from_cli = invoke(private_policy, "--trust-scope", "public")
    cli_private = invoke(public_policy, "--trust-scope", "private")
    from_default = invoke(default_policy)

    assert from_policy["trust_scope"]["source"] == "policy"
    assert from_policy["trust_scope"]["effective"] == "private"
    assert _json_status(from_policy, "validity_days") == "not_applicable"

    assert from_cli["trust_scope"]["source"] == "cli"
    assert from_cli["trust_scope"]["requested"] == "public"
    assert from_cli["trust_scope"]["effective"] == "public"
    assert _json_status(from_cli, "validity_days") == "fail"

    assert cli_private["trust_scope"]["source"] == "cli"
    assert cli_private["trust_scope"]["effective"] == "private"
    assert _json_status(cli_private, "validity_days") == "not_applicable"

    assert from_default["trust_scope"]["source"] == "default"
    assert from_default["trust_scope"]["effective"] == "public"
    assert _json_status(from_default, "validity_days") == "fail"


def test_cli_public_roots_override_the_policy_path(tmp_path: Path) -> None:
    issued = issue_chain(tmp_path / "issued", leaf_days=400)
    other = issue_chain(tmp_path / "other")
    leaf = issued["leaf"]
    chain = issued["chain"]
    root_path = issued["root_path"]
    other_root = other["root_path"]
    assert isinstance(leaf, Path)
    assert isinstance(chain, Path)
    assert isinstance(root_path, Path)
    assert isinstance(other_root, Path)
    policy = _write_policy(tmp_path, scope="auto", public_roots=str(root_path), name="auto.yaml")

    def invoke(*extra: str) -> dict:
        result = run(
            [
                "--cert",
                str(leaf),
                "--policy",
                str(policy),
                "--chain",
                str(chain),
                "--output",
                "json",
                "--report",
                str(tmp_path / "out.json"),
                "--evidence-dir",
                str(tmp_path / "evidence"),
                *extra,
            ],
            cwd=ROOT,
        )
        assert result.returncode in {0, 1, 2, 3}, result.stderr
        return json.loads(result.stdout)

    from_policy = invoke()
    from_cli = invoke("--public-trust-roots", str(other_root))
    assert from_policy["trust_scope"]["effective"] == "public"
    assert from_policy["trust_scope"]["source"] == "policy"
    assert from_cli["trust_scope"]["effective"] == "private"
    assert from_cli["trust_scope"]["public_roots"] == str(other_root)


def test_text_sarif_and_summary_record_the_trust_scope(tmp_path: Path) -> None:
    cert = write_certificate(tmp_path / "long.pem", CertSpec(validity_days=400))
    policy = _write_policy(tmp_path, scope="public")
    result = run(
        [
            "--cert",
            str(cert),
            "--policy",
            str(policy),
            "--trust-scope",
            "private",
            "--output",
            "text",
            "--report",
            str(tmp_path / "report.json"),
            "--evidence-dir",
            str(tmp_path / "evidence"),
            "--sarif-output",
            str(tmp_path / "out.sarif"),
        ],
        cwd=ROOT,
    )
    assert result.returncode in {0, 1, 2, 3}, result.stderr
    assert "Trust scope: private (requested private, source cli)" in result.stdout
    assert f"Trust scope reason: {PUBLIC_TLS_NA_REASON}" in result.stdout

    payload = json.loads((tmp_path / "report.json").read_text(encoding="utf-8"))
    assert payload["trust_scope"]["effective"] == "private"
    sarif = json.loads((tmp_path / "out.sarif").read_text(encoding="utf-8"))
    assert sarif["runs"][0]["properties"]["trustScope"]["effective"] == "private"

    report = _assess(policy, cert, cli_trust_scope="private")
    summary = ReviewerSummaryAgent().run(
        {"report": report.to_dict(), "output_path": str(tmp_path / "summary.md")}
    )
    assert summary.success is True
    text = (tmp_path / "summary.md").read_text(encoding="utf-8")
    assert "Trust scope: `private`" in text
    assert PUBLIC_TLS_NA_REASON in text
    markdown = render_job_summary(report)
    assert "Trust scope" in markdown
    assert "private" in markdown
    assert to_sarif(report)["runs"][0]["properties"]["trustScope"]["reason"] == (
        PUBLIC_TLS_NA_REASON
    )


def test_private_scope_does_not_run_the_opa_validity_gate(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def explode(*_args, **_kwargs):
        raise AssertionError("OPA must not run when trust scope is private")

    monkeypatch.setattr("certguard.engine.subprocess.run", explode)
    cert = write_certificate(tmp_path / "long.pem", CertSpec(validity_days=400))

    def mutate(policy: dict) -> None:
        policy["opa"]["enabled"] = True

    policy = _write_policy(tmp_path, mutate=mutate)
    report = _assess(policy, cert, cli_trust_scope="private")
    opa = _check(report, "opa_policy_gate")
    assert opa.status == "not_applicable"
    assert opa.details == PUBLIC_TLS_NA_REASON
    assert _status(report, "validity_days") == "not_applicable"
    assert _status(report, "rsa_key_size") == "pass"


def test_invalid_trust_scope_is_rejected(tmp_path: Path) -> None:
    policy = _write_policy(tmp_path, scope="local")
    with pytest.raises(PolicyValidationError, match=r"trust\.scope"):
        load_policy(policy)

    broken = tmp_path / "broken.yaml"
    data = yaml.safe_load(POLICY.read_text(encoding="utf-8"))
    data["trust"] = ["public"]
    broken.write_text(yaml.safe_dump(data), encoding="utf-8")
    with pytest.raises(PolicyValidationError, match="trust"):
        load_policy(broken)

    result = run(
        ["--trust-scope", "nope", "--cert", str(tmp_path / "missing.pem")],
        cwd=ROOT,
    )
    assert result.returncode == 2


def test_root_set_formats_and_ambiguous_issuer_selection(tmp_path: Path) -> None:
    issued = issue_chain(tmp_path / "issued")
    root = issued["root"]
    root_path = issued["root_path"]
    assert isinstance(root, x509.Certificate)
    assert isinstance(root_path, Path)
    digest = spki_sha256(root)

    der_path = tmp_path / "root.der"
    der_path.write_bytes(root.public_bytes(serialization.Encoding.DER))
    assert digest in load_public_trust_roots(der_path)

    b64 = base64.b64encode(bytes.fromhex(digest)).decode("ascii")
    pin_path = tmp_path / "pin.txt"
    pin_path.write_text(f"sha256/{b64}\n", encoding="utf-8")
    assert load_public_trust_roots(pin_path) == {digest}

    duplicate = choose_issuer([root, root])
    assert duplicate[0] == root
    other = issue_chain(tmp_path / "second")["root"]
    assert isinstance(other, x509.Certificate)
    chosen, detail = choose_issuer([root, other])
    assert chosen is None
    assert detail == "the certificate chain has more than one issuer candidate"


def test_docs_and_changelog_describe_trust_scope() -> None:
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    assert "The gate supports three trust scopes" in readme
    assert "--trust-scope" in readme
    assert "trust.scope" in readme
    for name in sorted(PUBLIC_TLS_ONLY_CONTROLS):
        assert f"`{name}`" in readme
    policy_doc = (ROOT / "policies" / "README.md").read_text(encoding="utf-8")
    assert "trust.scope" in policy_doc
    assert "--trust-scope" in policy_doc
    changelog = (ROOT / "CHANGELOG.md").read_text(encoding="utf-8")
    released = changelog.split("## [0.2.6]", 1)[1].split("\n## [", 1)[0]
    assert "--trust-scope" in released
    assert "trust.scope" in released


def test_trust_scope_module_does_not_reference_the_network() -> None:
    source = (ROOT / "src" / "certguard" / "trust_scope.py").read_text(encoding="utf-8")
    for token in ("urllib", "requests", "socket", "http.client", "urlopen"):
        assert token not in source


def _json_status(payload: dict, name: str) -> str:
    return next(item["status"] for item in payload["checks"] if item["name"] == name)
