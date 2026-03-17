from __future__ import annotations

from collections.abc import Mapping


class ProtectedRunError(PermissionError):
    """Raised when protected execution requirements are not satisfied."""


def enforce_protected_context(env: Mapping[str, str]) -> None:
    if env.get("GITHUB_ACTIONS") != "true":
        raise ProtectedRunError("Protected run requires execution inside GitHub Actions.")

    if env.get("GITHUB_REF_PROTECTED") != "true":
        raise ProtectedRunError(
            "Protected run requires a protected branch or tag context."
        )

    actor = env.get("GITHUB_ACTOR", "").strip()
    if not actor:
        raise ProtectedRunError("Protected run requires a valid GitHub actor identity.")
