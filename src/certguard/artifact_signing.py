from __future__ import annotations

import base64
import hashlib
from typing import Tuple

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, PublicFormat, NoEncryption


def generate_ed25519_keypair_b64() -> Tuple[str, str]:
    private_key = Ed25519PrivateKey.generate()
    public_key = private_key.public_key()
    private_bytes = private_key.private_bytes(
        encoding=Encoding.Raw,
        format=PrivateFormat.Raw,
        encryption_algorithm=NoEncryption(),
    )
    public_bytes = public_key.public_bytes(
        encoding=Encoding.Raw,
        format=PublicFormat.Raw,
    )
    return _b64(private_bytes), _b64(public_bytes)


def sign_bytes(content: bytes, private_key_b64: str) -> str:
    private_key = Ed25519PrivateKey.from_private_bytes(_from_b64(private_key_b64))
    signature = private_key.sign(content)
    return _b64(signature)


def verify_signature(content: bytes, signature_b64: str, public_key_b64: str) -> bool:
    public_key = Ed25519PublicKey.from_public_bytes(_from_b64(public_key_b64))
    try:
        public_key.verify(_from_b64(signature_b64), content)
    except Exception:
        return False
    return True


def key_id(public_key_b64: str) -> str:
    return hashlib.sha256(_from_b64(public_key_b64)).hexdigest()[:16]


def _b64(content: bytes) -> str:
    return base64.b64encode(content).decode("ascii")


def _from_b64(value: str) -> bytes:
    return base64.b64decode(value.encode("ascii"))
