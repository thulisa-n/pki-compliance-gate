from __future__ import annotations

from pathlib import Path

from cryptography import x509


def test_certificate_fixture_dataset_exists_and_is_parseable() -> None:
    fixture_dir = Path("tests/certificates")
    pem_files = sorted(path for path in fixture_dir.glob("*.pem"))

    assert len(pem_files) >= 5

    expected_files = {
        "valid_cert.pem",
        "long_validity_cert.pem",
        "internal_domain_cert.pem",
        "weak_key_cert.pem",
        "no_san_cert.pem",
        "sha1_cert.pem",
    }
    assert expected_files.issubset({file.name for file in pem_files})

    for pem_file in pem_files:
        content = pem_file.read_bytes()
        cert = x509.load_pem_x509_certificate(content)
        assert cert.subject is not None
