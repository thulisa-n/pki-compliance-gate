from __future__ import annotations

import json
from pathlib import Path

from certguard.release_provenance import generate_release_provenance


def test_generate_release_provenance_writes_manifest_and_signature(tmp_path: Path) -> None:
    artifact = tmp_path / "sample.txt"
    artifact.write_text("hello provenance", encoding="utf-8")
    output = tmp_path / "release_provenance.json"

    manifest_path, signature_path = generate_release_provenance([artifact], output)

    assert manifest_path.exists()
    assert signature_path.exists()
    payload = json.loads(manifest_path.read_text(encoding="utf-8"))
    assert payload["artifacts"][0]["path"] == str(artifact)
    assert len(payload["artifacts"][0]["sha256"]) == 64
    assert len(signature_path.read_text(encoding="utf-8").strip()) == 64
