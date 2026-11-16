from pathlib import Path
from typing import Any

from deepagents.backends import FilesystemBackend
from deepagents.middleware.filesystem import FilesystemMiddleware
from deepagents.middleware.subagents import SubAgentMiddleware
from dotenv import load_dotenv
from langchain.agents import create_agent
from langchain.agents.middleware import TodoListMiddleware
from langgraph.checkpoint.memory import MemorySaver

from core.prompts import DEFAULT_PROMPT_VERSION, get_prompt_set

from .middleware import SubAgentTraceMiddleware
from .models import build_models
from .trace import MessageTracker


def build_agent(
    workspace_path: Path,
    trace_collector: list[dict[str, Any]],
    jsonl_path: Path,
    subagent_tracker: MessageTracker,
    main_model_id: str | None = None,
    prompt_version: str | None = None,
):
    load_dotenv()
    prompt_set = get_prompt_set(prompt_version or DEFAULT_PROMPT_VERSION)

    is_baseline = not prompt_set.sub_agent

    checkpointer = MemorySaver()

    if is_baseline:
        main_llm, _ = build_models(
            main_model_id=main_model_id, skip_sub=True,
        )
        subagent_trace = SubAgentTraceMiddleware(
            "explore", trace_collector, jsonl_path, subagent_tracker,
        )
        agent = create_agent(
            model=main_llm,
            system_prompt=prompt_set.system,
            tools=[],
            middleware=[],
            checkpointer=checkpointer,
        )
        return agent, subagent_trace

    main_llm, sub_llm = build_models(main_model_id=main_model_id)

    fs_root = workspace_path.resolve()
    fs_backend = FilesystemBackend(
        root_dir=str(fs_root),
        virtual_mode=True,
    )

    fs_middleware = FilesystemMiddleware(backend=fs_backend)
    subagent_trace = SubAgentTraceMiddleware(
        "explore", trace_collector, jsonl_path, subagent_tracker
    )

    subagents = [
        {
            "name": "explore",
            "description": "A file search specialist, excel at thoroughly navigating and exploring codebases.",
            "system_prompt": prompt_set.sub_agent,
            "model": sub_llm,
            "tools": [],
            "middleware": [fs_middleware, subagent_trace],
        }
    ]

    agent = create_agent(
        model=main_llm,
        system_prompt=prompt_set.system,
        tools=[],
        middleware=[
            TodoListMiddleware(
                system_prompt="In complex multi-step tasks, use write_todos to list plans; update the todo list and completion status continuously."
            ),
            SubAgentMiddleware(
                default_model=sub_llm,
                default_tools=[],
                subagents=subagents,
                general_purpose_agent=False,
                task_description="Delegate tasks to subagents when needed.",
            ),
        ],
        checkpointer=checkpointer,
    )
    return agent, subagent_trace
