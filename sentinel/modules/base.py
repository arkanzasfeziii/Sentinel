"""Abstract base class for all Sentinel modules."""

from __future__ import annotations

from abc import ABC, abstractmethod

from sentinel.models import AttackResult, EngagementSession


class BaseModule(ABC):

    name: str = "base"

    @abstractmethod
    def run(self, es: EngagementSession, **kwargs: object) -> list[AttackResult]:
        ...
