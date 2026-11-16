from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path
import threading
from typing import Any


def _now_iso_timestamp() -> str:
    """Return a stable ISO 8601 timestamp with microsecond precision."""
    return datetime.now().isoformat(timespec="microseconds")

_TRACE_WRITE_LOCK = threading.Lock()


def stringify_content(content: Any) -> str:
    if content is None:
        return ""
    if isinstance(content, str):
        return content
    return str(content)


def get_tool_calls(message: Any) -> list[dict[str, Any]]:
    tool_calls = None
    if message is None:
        return []
    if isinstance(message, dict):
        tool_calls = message.get("tool_calls")
    else:
        tool_calls = getattr(message, "tool_calls", None)
    return tool_calls or []


def extract_model_messages(response: Any) -> list[Any]:
    if response is None:
        return []
    result = getattr(response, "result", None)
    if isinstance(result, list):
        return result
    return [response]


def normalize_role(role: Any) -> str | None:
    if role is None:
        return None
    role_text = str(role)
    role_map = {
        "human": "user",
        "ai": "assistant",
        "tool": "tool",
        "system": "system",
    }
    return role_map.get(role_text, role_text)


def get_message_id(message: Any) -> str | None:
    if message is None:
        return None
    if isinstance(message, dict):
        return message.get("id")
    return getattr(message, "id", None)


def get_message_role(message: Any) -> str | None:
    if message is None:
        return None
    if isinstance(message, dict):
        role = message.get("role") or message.get("type")
    else:
        role = getattr(message, "type", None)
        if role is None:
            role = message.__class__.__name__.replace("Message", "").lower()
    return normalize_role(role)


def get_tool_name(message: Any) -> str | None:
    if message is None:
        return None
    if isinstance(message, dict):
        return message.get("tool_name") or message.get("name")
    return getattr(message, "tool_name", None) or getattr(message, "name", None)


def normalize_assistant_content(content: Any) -> list[dict[str, str]]:
    if content is None:
        return []
    if isinstance(content, list):
        normalized: list[dict[str, str]] = []
        for item in content:
            if isinstance(item, dict):
                if "type" in item and "content" in item:
                    normalized.append(
                        {
                            "type": stringify_content(item["type"]),
                            "content": stringify_content(item["content"]),
                        }
                    )
                elif "type" in item and "text" in item:
                    normalized.append(
                        {
                            "type": stringify_content(item["type"]),
                            "content": stringify_content(item["text"]),
                        }
                    )
                elif "thinking" in item:
                    normalized.append(
                        {
                            "type": "thinking",
                            "content": stringify_content(item["thinking"]),
                        }
                    )
                elif "text" in item:
                    normalized.append(
                        {
                            "type": "text",
                            "content": stringify_content(item["text"]),
                        }
                    )
                else:
                    normalized.append(
                        {"type": "text", "content": stringify_content(item)}
                    )
            else:
                normalized.append(
                    {"type": "text", "content": stringify_content(item)}
                )
        return normalized
    if isinstance(content, dict):
        if "type" in content and "content" in content:
            return [
                {
                    "type": stringify_content(content["type"]),
                    "content": stringify_content(content["content"]),
                }
            ]
        if "thinking" in content:
            return [
                {
                    "type": "thinking",
                    "content": stringify_content(content["thinking"]),
                }
            ]
        if "text" in content:
            return [
                {
                    "type": "text",
                    "content": stringify_content(content["text"]),
                }
            ]
        return [{"type": "text", "content": stringify_content(content)}]
    return [{"type": "text", "content": stringify_content(content)}]


def get_message_signature(message: Any) -> tuple[Any, ...]:
    message_id = get_message_id(message)
    if message_id:
        return ("id", message_id)

    role = get_message_role(message)
    if isinstance(message, dict):
        content = message.get("content")
        tool_calls = message.get("tool_calls")
        tool_call_id = message.get("tool_call_id")
    else:
        content = getattr(message, "content", None)
        tool_calls = getattr(message, "tool_calls", None)
        tool_call_id = getattr(message, "tool_call_id", None)

    try:
        tool_calls_repr = json.dumps(tool_calls, sort_keys=True, default=str)
    except Exception:
        tool_calls_repr = str(tool_calls)

    return (
        "content",
        role,
        stringify_content(content),
        tool_calls_repr,
        stringify_content(tool_call_id),
    )


def message_to_jsonl_entry(
    message: Any, agent: str | None = None
) -> dict[str, Any] | None:
    role = get_message_role(message)
    if role is None:
        return None

    if isinstance(message, dict):
        content = message.get("content")
        tool_calls = message.get("tool_calls")
        tool_call_id = message.get("tool_call_id")
    else:
        content = getattr(message, "content", None)
        tool_calls = getattr(message, "tool_calls", None)
        tool_call_id = getattr(message, "tool_call_id", None)

    entry: dict[str, Any] = {"role": role, "timestamp": _now_iso_timestamp()}
    if role == "assistant":
        entry["content"] = normalize_assistant_content(content)
    elif role == "tool":
        entry["content"] = [
            {"type": "text", "content": stringify_content(content)}
        ]
    elif role == "user":
        entry["content"] = [
            {"type": "text", "content": stringify_content(content)}
        ]
    elif content is not None:
        entry["content"] = content
    if tool_calls:
        entry["tool_calls"] = tool_calls
    if tool_call_id:
        entry["tool_call_id"] = tool_call_id
    tool_name = get_tool_name(message)
    if role == "tool" and tool_name:
        entry["tool_name"] = tool_name
    if agent:
        entry["agent"] = agent
    return entry


def extract_usage_entry(
    message: Any, agent: str | None = None
) -> dict[str, Any] | None:
    if message is None:
        return None
    if isinstance(message, dict):
        metadata = message.get("response_metadata")
    else:
        metadata = getattr(message, "response_metadata", None)

    if not metadata:
        return None

    usage = metadata.get("token_usage") or metadata.get("usage")
    if not usage:
        return None

    prompt_tokens = usage.get("prompt_tokens")
    completion_tokens = usage.get("completion_tokens")
    input_tokens = usage.get("input_tokens")
    output_tokens = usage.get("output_tokens")
    total_tokens = usage.get("total_tokens")

    if total_tokens is None:
        total_tokens = (prompt_tokens or input_tokens or 0) + (
            completion_tokens or output_tokens or 0
        )

    if total_tokens == 0:
        return None

    entry: dict[str, Any] = {
        "role": "_usage",
        "token_count": total_tokens,
        "timestamp": _now_iso_timestamp(),
    }
    if prompt_tokens is not None:
        entry["prompt_tokens"] = prompt_tokens
    if completion_tokens is not None:
        entry["completion_tokens"] = completion_tokens
    if input_tokens is not None:
        entry["input_tokens"] = input_tokens
    if output_tokens is not None:
        entry["output_tokens"] = output_tokens
    if agent and agent != "main":
        entry["agent"] = agent
    return entry


def record_trace_entry(
    entry: dict[str, Any],
    trace_collector: list[dict[str, Any]],
    jsonl_path: Path,
) -> None:
    trace_collector.append(entry)
    append_trace_jsonl(entry, jsonl_path)


class MessageTracker:
    def __init__(self) -> None:
        self._seen_signatures: set[tuple[Any, ...]] = set()

    def extract_new_messages(self, messages: list[Any]) -> list[Any]:
        if not messages:
            return []

        new_messages: list[Any] = []
        for message in messages:
            signature = get_message_signature(message)
            if signature in self._seen_signatures:
                continue
            self._seen_signatures.add(signature)
            new_messages.append(message)
        return new_messages


def append_trace_jsonl(trace_entry: dict[str, Any], jsonl_path: Path) -> None:
    # Build the full line first to avoid interleaving writes across agents.
    line = json.dumps(trace_entry, ensure_ascii=False) + "\n"
    with _TRACE_WRITE_LOCK:
        with jsonl_path.open("a", encoding="utf-8") as f:
            f.write(line)
