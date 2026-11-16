from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class PromptSet:
    system: str
    sub_agent: str
    user: str
