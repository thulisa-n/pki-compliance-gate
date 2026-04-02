from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from certguard.agents.base import BaseAgent
from certguard.models import AgentResult


class ExternalSignalWatchAgent(BaseAgent):
    def __init__(self) -> None:
        super().__init__(name="external_signal_watch_agent")

    def run(self, context: dict[str, Any]) -> AgentResult:
        signals = context.get("signals")
        if not isinstance(signals, list):
            return AgentResult(
                agent=self.name,
                success=False,
                errors=["External signal watch requires a list of signals."],
            )

        normalized = [self._normalize_signal(item) for item in signals if isinstance(item, dict)]
        recommendations = [self._recommendation_for(item) for item in normalized]
        recommendations = [item for item in recommendations if item is not None]

        summary = {
            "signal_count": len(normalized),
            "high_priority_signals": len(
                [item for item in normalized if item.get("priority") in {"high", "critical"}]
            ),
            "recommendation_count": len(recommendations),
            "signals": normalized,
            "recommendations": recommendations,
            "generated_at": datetime.now(timezone.utc).isoformat(),
        }
        return AgentResult(agent=self.name, success=True, data=summary)

    def _normalize_signal(self, signal: dict[str, Any]) -> dict[str, Any]:
        return {
            "id": str(signal.get("id", "unknown")),
            "title": str(signal.get("title", "Untitled signal")),
            "category": str(signal.get("category", "general")).lower(),
            "priority": str(signal.get("priority", "medium")).lower(),
            "published_at": str(signal.get("published_at", "")),
            "source_url": str(signal.get("source_url", "")),
            "notes": str(signal.get("notes", "")),
        }

    def _recommendation_for(self, signal: dict[str, Any]) -> dict[str, Any] | None:
        category = signal["category"]
        if category == "certificate_lifecycle":
            return {
                "signal_id": signal["id"],
                "control": "max_validity_days",
                "action": "Review and tighten validity windows in baseline policy/profile overlays.",
                "target_files": [
                    "policies/cabf_policy.yaml",
                    "policies/standards_baseline.yaml",
                ],
            }
        if category == "deprecated_algorithms":
            return {
                "signal_id": signal["id"],
                "control": "prohibited_algorithms",
                "action": "Extend prohibited algorithm list and rerun fixture matrix.",
                "target_files": ["policies/cabf_policy.yaml", "tests/test_engine.py"],
            }
        if category == "root_program_update":
            return {
                "signal_id": signal["id"],
                "control": "profile_overlay_alignment",
                "action": "Update root program profile overlays and watch baseline drift.",
                "target_files": ["policies/profiles/root_program_baseline.yaml"],
            }
        if category == "crypto_transition":
            return {
                "signal_id": signal["id"],
                "control": "crypto_transition_readiness",
                "action": "Add migration checks/profiles for algorithm agility and quantum-safe readiness.",
                "target_files": ["README.md", "policies/profiles/"],
            }
        return None
