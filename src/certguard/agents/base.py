from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any

from certguard.models import AgentResult


class BaseAgent(ABC):
    def __init__(self, name: str) -> None:
        self.name = name

    @abstractmethod
    def run(self, context: dict[str, Any]) -> AgentResult:
        raise NotImplementedError
