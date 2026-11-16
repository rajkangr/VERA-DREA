from __future__ import annotations

from .base import PromptSet
from .drea import PROMPT_SET as DREA_PROMPT_SET
from .single_agent import PROMPT_SET as SINGLE_AGENT_PROMPT_SET

DEFAULT_PROMPT_VERSION = "drea"

PROMPT_SETS: dict[str, PromptSet] = {
    "drea": DREA_PROMPT_SET,
    "single-agent": SINGLE_AGENT_PROMPT_SET,
}


def get_prompt_set(version: str | None = None) -> PromptSet:
    prompt_version = version or DEFAULT_PROMPT_VERSION
    try:
        return PROMPT_SETS[prompt_version]
    except KeyError as exc:
        available = ", ".join(sorted(PROMPT_SETS))
        raise ValueError(
            f"Unknown prompt version: {prompt_version}. Available: {available}"
        ) from exc


def list_prompt_versions() -> list[str]:
    return sorted(PROMPT_SETS.keys())
