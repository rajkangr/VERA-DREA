from __future__ import annotations

import asyncio
import random
from datetime import datetime
from typing import Any

from langchain_core.messages import HumanMessage, SystemMessage

from .trace import extract_usage_entry, normalize_assistant_content


def _now_iso_timestamp() -> str:
    return datetime.now().isoformat(timespec="microseconds")


async def run_baseline_inference(
    llm: Any,
    system_prompt: str,
    user_prompt: str,
    timeout: float = 120.0,
    max_retries: int = 3,
    retry_base_seconds: float = 2.0,
) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    if max_retries < 0:
        max_retries = 0
    if timeout <= 0:
        timeout = 120.0

    user_entry: dict[str, Any] = {
        "role": "user",
        "content": [{"type": "text", "content": user_prompt}],
        "timestamp": _now_iso_timestamp(),
    }

    last_error: Exception | None = None
    for attempt in range(max_retries + 1):
        try:
            response = await asyncio.wait_for(
                llm.ainvoke(
                    [
                        SystemMessage(content=system_prompt),
                        HumanMessage(content=user_prompt),
                    ]
                ),
                timeout=timeout,
            )
            assistant_entry: dict[str, Any] = {
                "role": "assistant",
                "content": normalize_assistant_content(
                    getattr(response, "content", None)
                ),
                "timestamp": _now_iso_timestamp(),
            }
            usage_entry = extract_usage_entry(response) or {
                "role": "_usage",
                "token_count": 0,
                "timestamp": _now_iso_timestamp(),
            }
            return user_entry, assistant_entry, usage_entry
        except Exception as exc:  # noqa: BLE001 - caller handles final failure
            last_error = exc
            if attempt >= max_retries:
                break
            backoff = retry_base_seconds * (2**attempt) + random.uniform(
                0.0, 1.0
            )
            await asyncio.sleep(backoff)

    assert last_error is not None
    raise last_error
