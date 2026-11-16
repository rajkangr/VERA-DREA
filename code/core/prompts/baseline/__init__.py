from __future__ import annotations

from ..base import PromptSet
from .function_only import PROMPT_SET as FUNCTION_ONLY_PROMPT_SET
from .whole_file import PROMPT_SET as WHOLE_FILE_PROMPT_SET

DEFAULT_BASELINE_PROMPT_VERSION = "function-only"

BASELINE_PROMPT_SETS: dict[str, PromptSet] = {
    "function-only": FUNCTION_ONLY_PROMPT_SET,
    "whole-file": WHOLE_FILE_PROMPT_SET,
}


def get_baseline_prompt_set(version: str | None = None) -> PromptSet:
    prompt_version = version or DEFAULT_BASELINE_PROMPT_VERSION
    try:
        return BASELINE_PROMPT_SETS[prompt_version]
    except KeyError as exc:
        available = ", ".join(sorted(BASELINE_PROMPT_SETS))
        raise ValueError(
            f"Unknown baseline prompt version: {prompt_version}. Available: {available}"
        ) from exc


def list_baseline_prompt_versions() -> list[str]:
    return sorted(BASELINE_PROMPT_SETS.keys())
