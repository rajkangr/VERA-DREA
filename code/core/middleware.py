from __future__ import annotations

from collections.abc import Callable
from pathlib import Path
from typing import Any

from langchain.agents.middleware import (
    AgentMiddleware,
    ModelRequest,
    ModelResponse,
)
from langgraph.prebuilt.tool_node import ToolCallRequest

from .trace import (
    MessageTracker,
    extract_model_messages,
    extract_usage_entry,
    message_to_jsonl_entry,
    record_trace_entry,
)


class SubAgentTraceMiddleware(AgentMiddleware):
    def __init__(
        self,
        name: str,
        trace_collector: list[dict[str, Any]],
        jsonl_path: Path,
        message_tracker: MessageTracker,
    ) -> None:
        super().__init__()
        self._name = name
        self._trace_collector = trace_collector
        self._jsonl_path = jsonl_path
        self._message_tracker = message_tracker
        self._parent_tool_call_id: str | None = None

    def set_parent_tool_call_id(self, tool_call_id: str | None) -> None:
        if tool_call_id:
            self._parent_tool_call_id = tool_call_id

    def _attach_parent(self, entry: dict[str, Any]) -> None:
        if self._parent_tool_call_id and "parent_tool_call_id" not in entry:
            entry["parent_tool_call_id"] = self._parent_tool_call_id

    def wrap_model_call(
        self,
        request: ModelRequest,
        handler: Callable[[ModelRequest], ModelResponse],
    ) -> ModelResponse:
        response = handler(request)

        for message in extract_model_messages(response):
            message_type = getattr(message, "type", None)
            if (
                message_type != "ai"
                and message.__class__.__name__ != "AIMessage"
            ):
                continue

            entry = message_to_jsonl_entry(message, agent=self._name)
            if entry:
                self._attach_parent(entry)
                record_trace_entry(
                    entry, self._trace_collector, self._jsonl_path
                )

            usage_entry = extract_usage_entry(message, agent=self._name)
            if usage_entry:
                self._attach_parent(usage_entry)
                record_trace_entry(
                    usage_entry, self._trace_collector, self._jsonl_path
                )

        return response

    def wrap_tool_call(
        self,
        request: ToolCallRequest,
        handler: Callable[[ToolCallRequest], Any],
    ) -> Any:
        result = handler(request)

        tool_entry = message_to_jsonl_entry(result, agent=self._name)
        if tool_entry:
            if "tool_call_id" not in tool_entry:
                tool_entry["tool_call_id"] = getattr(
                    request, "tool_call_id", None
                )
            tool_name = getattr(request, "tool_name", None) or getattr(
                request, "name", None
            )
            if tool_name and "tool_name" not in tool_entry:
                tool_entry["tool_name"] = tool_name
            self._attach_parent(tool_entry)
            record_trace_entry(
                tool_entry, self._trace_collector, self._jsonl_path
            )

        return result
