from __future__ import annotations

import os
from datetime import datetime
from pathlib import Path

from langgraph.errors import GraphRecursionError

from .agent_builder import build_agent
from .trace import (
    MessageTracker,
    extract_usage_entry,
    get_tool_calls,
    message_to_jsonl_entry,
    record_trace_entry,
    stringify_content,
)


def repl(
    workspace_path: Path,
    prompt: str,
    jsonl_path: Path,
    main_model_id: str | None = None,
    prompt_version: str | None = None,
    recursion_limit: int | None = None,
) -> None:
    thread_id = os.getenv("THREAD_ID", "demo")
    final_assistant_text = ""

    trace_data = []
    main_tracker = MessageTracker()
    subagent_tracker = MessageTracker()
    user_logged = False

    user_entry = {
        "role": "user",
        "content": [{"type": "text", "content": prompt}],
        "timestamp": datetime.now().isoformat(timespec="microseconds"),
    }
    record_trace_entry(user_entry, trace_data, jsonl_path)
    user_logged = True

    agent, subagent_trace = build_agent(
        workspace_path,
        trace_data,
        jsonl_path,
        subagent_tracker,
        main_model_id=main_model_id,
        prompt_version=prompt_version,
    )

    env_recursion_limit = os.getenv("LANGGRAPH_RECURSION_LIMIT")
    if recursion_limit is None and env_recursion_limit:
        try:
            recursion_limit = int(env_recursion_limit)
        except ValueError:
            recursion_limit = None

    if recursion_limit is None:
        recursion_limit = 200
    if recursion_limit <= 0:
        recursion_limit = 200

    try:
        for chunk in agent.stream(
            {"messages": [{"role": "user", "content": prompt}]},
            stream_mode="updates",
            config={
                "recursion_limit": recursion_limit,
                "configurable": {"thread_id": thread_id},
            },
        ):
            if not isinstance(chunk, dict):
                continue
            for step, data in chunk.items():
                if not isinstance(data, dict):
                    continue

                messages = data.get("messages") or []
                last_message = messages[-1] if messages else None

                for message in main_tracker.extract_new_messages(messages):
                    entry = message_to_jsonl_entry(message)
                    if entry:
                        if entry.get("role") == "user" and user_logged:
                            continue
                        if (
                            entry.get("role") == "assistant"
                            and "agent" not in entry
                        ):
                            entry["agent"] = "main"
                        record_trace_entry(entry, trace_data, jsonl_path)

                    usage_entry = extract_usage_entry(message)
                    if usage_entry:
                        record_trace_entry(usage_entry, trace_data, jsonl_path)

                if step in {"agent", "model"}:
                    assistant_content = getattr(last_message, "content", None)
                    if isinstance(last_message, dict):
                        assistant_content = last_message.get("content")
                    assistant_text = stringify_content(assistant_content)
                    if assistant_text:
                        final_assistant_text = assistant_text

                    for tool_call in get_tool_calls(last_message):
                        tool_name = tool_call.get("name")
                        if tool_name == "task":
                            subagent_trace.set_parent_tool_call_id(
                                tool_call.get("id")
                                or tool_call.get("tool_call_id")
                            )
                elif step == "tools":
                    pass
    except GraphRecursionError as e:
        record_trace_entry(
            {
                "role": "system",
                "content": [
                    {
                        "type": "text",
                        "content": (
                            f"GraphRecursionError: {e} "
                            f"(recursion_limit={recursion_limit})"
                        ),
                    }
                ],
                "timestamp": datetime.now().isoformat(timespec="microseconds"),
            },
            trace_data,
            jsonl_path,
        )
        raise
    except Exception as e:
        record_trace_entry(
            {
                "role": "system",
                "content": [
                    {
                        "type": "text",
                        "content": f"Unhandled error: {type(e).__name__}: {e}",
                    }
                ],
                "timestamp": datetime.now().isoformat(timespec="microseconds"),
            },
            trace_data,
            jsonl_path,
        )
        raise

    print(f"Trace JSONL saved to: {jsonl_path}")
    print(f"Total trace entries: {len(trace_data)}")

    if final_assistant_text:
        print(final_assistant_text)
    else:
        print("No assistant response captured.")
