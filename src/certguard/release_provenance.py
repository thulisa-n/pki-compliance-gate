from __future__ import annotations

import hashlib
import json
import os
from datetime import datetime, timezone
from pathlib import Path

from certguard.artifact_signing import key_id, sign_bytes, verify_signature


def generate_release_provenance(
    artifact_paths: list[Path],
    output_path: Path,
    signing_private_key_b64: str | None = None,
    signing_public_key_b64: str | None = None,
) -> tuple[Path, Path, Path | None]:
    output_path.parent.mkdir(parents=True, exist_ok=True)

    missing_artifacts = [str(path) for path in artifact_paths if not path.exists()]
    if missing_artifacts:
        raise ValueError(
            "Missing required provenance artifacts: " + ", ".join(missing_artifacts)
        )

    artifacts = []
    for artifact in artifact_paths:
        artifacts.append(
            {
                "path": str(artifact),
                "sha256": _sha256_file(artifact),
                "size_bytes": artifact.stat().st_size,
            }
        )

    payload = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "git_commit": os.getenv("GITHUB_SHA", "local-dev"),
        "workflow": os.getenv("GITHUB_WORKFLOW", "local-dev"),
        "run_id": os.getenv("GITHUB_RUN_ID", "local-run"),
        "actor": os.getenv("GITHUB_ACTOR", "manual-run"),
        "artifacts": artifacts,
    }
    output_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")

    digest_path = output_path.with_suffix(output_path.suffix + ".digest")
    digest_path.write_text(_sha256_bytes(output_path.read_bytes()), encoding="utf-8")
    signature_path: Path | None = None

    private_key = signing_private_key_b64 or os.getenv("CERTGUARD_SIGNING_PRIVATE_KEY")
    public_key = signing_public_key_b64 or os.getenv("CERTGUARD_SIGNING_PUBLIC_KEY")
    if private_key and public_key:
        signature_path = output_path.with_suffix(output_path.suffix + ".sig")
        signature = sign_bytes(output_path.read_bytes(), private_key)
        signature_path.write_text(signature, encoding="utf-8")
        signature_meta = {
            "algorithm": "ed25519",
            "key_id": key_id(public_key),
            "public_key_b64": public_key,
            "signed_at": datetime.now(timezone.utc).isoformat(),
            "artifact": str(output_path),
        }
        signature_path.with_suffix(signature_path.suffix + ".meta.json").write_text(
            json.dumps(signature_meta, indent=2),
            encoding="utf-8",
        )

    return output_path, digest_path, signature_path


def verify_release_provenance_signature(
    output_path: Path, signature_path: Path, public_key_b64: str
) -> bool:
    if not output_path.exists() or not signature_path.exists():
        return False
    signature = signature_path.read_text(encoding="utf-8").strip()
    return verify_signature(output_path.read_bytes(), signature, public_key_b64)


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        while True:
            chunk = stream.read(8192)
            if not chunk:
                break
            digest.update(chunk)
    return digest.hexdigest()


def _sha256_bytes(content: bytes) -> str:
    return hashlib.sha256(content).hexdigest()
