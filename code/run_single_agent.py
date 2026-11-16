"""
Single-Agent Baseline runner.

Uses the same strong model for both reasoning AND repository exploration,
without the Planner-Explorer decoupling. The model directly holds filesystem
tools (ls, glob, grep, read_file) and performs exploration itself.

This isolates the contribution of the decoupled architecture in DREA.

Usage:
    uv run python run_single_agent.py <item_id> --model <model_id> --type vul
    uv run python run_single_agent.py --model <model_id> --type vul  # batch
"""

from __future__ import annotations

import argparse
import json
import os
import re
import signal
import subprocess
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import datetime
from pathlib import Path
from typing import Any

from dotenv import load_dotenv
from langgraph.checkpoint.memory import MemorySaver
from langgraph.errors import GraphRecursionError

from core.model_registry import build_main_model
from core.prompts import get_prompt_set, list_prompt_versions
from core.trace import (
    MessageTracker,
    extract_usage_entry,
    get_tool_calls,
    message_to_jsonl_entry,
    record_trace_entry,
    stringify_content,
)

DEFAULT_DATASET_PATH = Path("../data/repopairbench_100.jsonl")
DEFAULT_REPO_CACHE_DIR = Path("../repos")
LOG_DIR = Path("logs-single-agent")
LOG_DIR.mkdir(parents=True, exist_ok=True)
DEFAULT_ANALYSIS_TIMEOUT_MINUTES = 20


class AnalysisTimeoutError(TimeoutError):
    pass


def _env_path(name: str) -> Path | None:
    value = os.getenv(name)
    if not value:
        return None
    return Path(value)


def get_latest_jsonl(log_dir: Path) -> Path | None:
    if not log_dir.exists():
        return None
    jsonl_files = list(log_dir.glob("*.jsonl"))
    if not jsonl_files:
        return None
    return max(jsonl_files, key=lambda path: path.stat().st_mtime)


def is_completed_log(jsonl_path: Path) -> bool:
    last_entry = None
    with jsonl_path.open("r", encoding="utf-8") as handle:
        for line in handle:
            line = line.strip()
            if not line:
                continue
            try:
                entry = json.loads(line)
            except json.JSONDecodeError:
                continue
            if entry.get("role") == "_usage":
                continue
            last_entry = entry
    if not last_entry:
        return False
    if last_entry.get("role") != "assistant":
        return False
    return True


def load_item_by_id(jsonl_path: Path, item_id: str) -> dict[str, Any] | None:
    with jsonl_path.open("r", encoding="utf-8") as handle:
        for raw_line in handle:
            line = raw_line.strip()
            if not line:
                continue
            item = json.loads(line)
            if item.get("id") == item_id:
                return item
    return None


def iter_items(jsonl_path: Path) -> Iterator[tuple[str, dict[str, Any]]]:
    with jsonl_path.open("r", encoding="utf-8") as handle:
        for raw_line in handle:
            line = raw_line.strip()
            if not line:
                continue
            item = json.loads(line)
            item_id = item.get("id")
            if item_id:
                yield item_id, item


def get_repo_path(repo_url: str, base_dir: Path) -> Path:
    parts = repo_url.rstrip("/").split("/")
    if len(parts) < 2:
        raise ValueError(f"Invalid repo_url: {repo_url}")
    org, repo = parts[-2], parts[-1]
    return base_dir / org / repo


def resolve_target_commit(
    repo_path: Path, commit_hash: str, task_type: str
) -> str:
    if task_type == "vul":
        result = subprocess.run(
            ["git", "rev-parse", f"{commit_hash}^"],
            cwd=repo_path, capture_output=True, text=True, check=True,
        )
        return result.stdout.strip()
    result = subprocess.run(
        ["git", "rev-parse", commit_hash],
        cwd=repo_path, capture_output=True, text=True, check=True,
    )
    return result.stdout.strip()


def checkout_commit(repo_path: Path, target_commit: str) -> None:
    subprocess.run(
        ["git", "config", "advice.detachedHead", "false"],
        cwd=repo_path, check=True, capture_output=True,
    )
    subprocess.run(
        ["git", "checkout", target_commit],
        cwd=repo_path, check=True, capture_output=True,
    )


@contextmanager
def preserve_head(repo_path: Path):
    result = subprocess.run(
        ["git", "symbolic-ref", "--quiet", "--short", "HEAD"],
        cwd=repo_path, capture_output=True, text=True,
    )
    original_branch = result.stdout.strip() if result.returncode == 0 else None
    result = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=repo_path, capture_output=True, text=True, check=True,
    )
    original_head = result.stdout.strip()
    try:
        yield
    finally:
        try:
            checkout_commit(repo_path, original_branch or original_head)
        except subprocess.CalledProcessError:
            pass


@contextmanager
def analysis_timeout(seconds: int):
    if seconds <= 0 or not hasattr(signal, "SIGALRM"):
        yield
        return

    def _handle_timeout(signum: int, frame: Any) -> None:
        raise AnalysisTimeoutError(
            f"analysis exceeded timeout ({seconds} seconds)"
        )

    previous_handler = signal.getsignal(signal.SIGALRM)
    signal.signal(signal.SIGALRM, _handle_timeout)
    signal.alarm(seconds)
    try:
        yield
    finally:
        signal.alarm(0)
        signal.signal(signal.SIGALRM, previous_handler)


def normalize_language_tag(language: str | None) -> str:
    if not language:
        return "text"
    normalized = language.strip().lower()
    aliases = {"c++": "cpp", "c#": "csharp", "js": "javascript", "ts": "typescript", "py": "python"}
    return aliases.get(normalized, normalized)


def sanitize_path_component(name: str) -> str:
    sanitized = re.sub(r"[^A-Za-z0-9._-]+", "-", name.strip())
    return sanitized.strip("-._")


def build_single_agent(workspace_path: Path, model_id: str, prompt_version: str):
    """Build a single agent with direct filesystem tools (no subagent).
    
    Only read-only tools are exposed: ls, glob, grep, read_file.
    Write tools (write_file, edit_file, execute) are excluded.
    """
    from deepagents.backends import FilesystemBackend
    from deepagents.middleware.filesystem import FilesystemMiddleware
    from langchain.agents import create_agent

    prompt_set = get_prompt_set(prompt_version)
    llm = build_main_model(model_id)

    fs_backend = FilesystemBackend(
        root_dir=str(workspace_path.resolve()),
        virtual_mode=True,
    )
    fs_middleware = FilesystemMiddleware(backend=fs_backend)

    # Filter to read-only tools only
    ALLOWED_TOOLS = {"ls", "glob", "grep", "read_file"}
    fs_middleware.tools = [
        t for t in fs_middleware.tools if t.name in ALLOWED_TOOLS
    ]

    checkpointer = MemorySaver()
    agent = create_agent(
        model=llm,
        system_prompt=prompt_set.system,
        tools=[],
        middleware=[fs_middleware],
        checkpointer=checkpointer,
    )
    return agent, prompt_set


def run_single_agent_analysis(
    workspace_path: Path,
    prompt: str,
    jsonl_path: Path,
    model_id: str,
    prompt_version: str,
    recursion_limit: int = 100,
) -> None:
    """Run single-agent analysis loop."""
    trace_data: list[dict[str, Any]] = []
    main_tracker = MessageTracker()

    user_entry = {
        "role": "user",
        "content": [{"type": "text", "content": prompt}],
        "timestamp": datetime.now().isoformat(timespec="microseconds"),
    }
    record_trace_entry(user_entry, trace_data, jsonl_path)

    agent, _ = build_single_agent(workspace_path, model_id, prompt_version)

    thread_id = f"single-{datetime.now().strftime('%Y%m%d%H%M%S')}"

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
                for message in main_tracker.extract_new_messages(messages):
                    entry = message_to_jsonl_entry(message)
                    if entry:
                        if entry.get("role") == "user":
                            continue  # already logged
                        if entry.get("role") == "assistant" and "agent" not in entry:
                            entry["agent"] = "main"
                        record_trace_entry(entry, trace_data, jsonl_path)
                    usage_entry = extract_usage_entry(message)
                    if usage_entry:
                        record_trace_entry(usage_entry, trace_data, jsonl_path)
    except GraphRecursionError as e:
        record_trace_entry(
            {
                "role": "system",
                "content": [{"type": "text", "content": f"GraphRecursionError: {e}"}],
                "timestamp": datetime.now().isoformat(timespec="microseconds"),
            },
            trace_data, jsonl_path,
        )
    except Exception as e:
        record_trace_entry(
            {
                "role": "system",
                "content": [{"type": "text", "content": f"Error: {type(e).__name__}: {e}"}],
                "timestamp": datetime.now().isoformat(timespec="microseconds"),
            },
            trace_data, jsonl_path,
        )

    print(f"  Trace saved: {jsonl_path} ({len(trace_data)} entries)")


def process_item(
    item_id: str, item: dict[str, Any], args: argparse.Namespace
) -> bool:
    raw_project_name = item.get("project_name")
    project_component = (
        sanitize_path_component(raw_project_name) if raw_project_name else ""
    )
    log_root = f"{project_component}_{item_id}" if project_component else item_id

    repo_url = item["repo_url"]
    commit_hash = item["commit_hash"]
    vuln_data = item["vuln_data"]
    file_path = vuln_data["file_path"]
    code_key = "code_before" if args.type == "vul" else "code_after"
    code = vuln_data[code_key]
    language_tag = normalize_language_tag(item.get("language"))

    repo_path = get_repo_path(repo_url, args.repo_cache_dir)
    if not repo_path.exists():
        print(f"  Repo not found: {repo_path}, skipping {item_id}")
        return False

    log_dir = LOG_DIR / log_root / args.type / args.model / args.prompt_version
    if not args.force:
        latest_jsonl = get_latest_jsonl(log_dir)
        if latest_jsonl and is_completed_log(latest_jsonl):
            print(f"  Skipping completed: {latest_jsonl}")
            return False

    try:
        target_commit = resolve_target_commit(repo_path, commit_hash, args.type)
    except subprocess.CalledProcessError as exc:
        print(f"  Cannot resolve commit for {item_id}: {exc}")
        return False

    prompt_set = get_prompt_set(args.prompt_version)
    prompt = prompt_set.user.format(
        file_path=file_path, code=code, language=language_tag,
    )

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    jsonl_path = log_dir / f"{timestamp}.jsonl"
    jsonl_path.parent.mkdir(parents=True, exist_ok=True)

    print(f"[{item_id}] {raw_project_name} | {args.type} | commit={target_commit[:8]}")

    with preserve_head(repo_path):
        checkout_commit(repo_path, target_commit)
        timeout_seconds = int(args.analysis_timeout_minutes * 60)
        try:
            with analysis_timeout(timeout_seconds):
                run_single_agent_analysis(
                    workspace_path=repo_path,
                    prompt=prompt,
                    jsonl_path=jsonl_path,
                    model_id=args.model,
                    prompt_version=args.prompt_version,
                    recursion_limit=args.recursion_limit,
                )
        except AnalysisTimeoutError:
            print(f"  TIMEOUT after {args.analysis_timeout_minutes}min")
        except Exception as exc:
            print(f"  ERROR: {exc}")
            return False

    return True


def main() -> None:
    load_dotenv()

    parser = argparse.ArgumentParser(
        description="Run single-agent baseline vulnerability detection"
    )
    parser.add_argument("item_id", nargs="?", type=str, help="Item id (omit for batch)")
    parser.add_argument("--type", type=str, default="vul", choices=["sec", "vul"])
    parser.add_argument("--model", type=str, required=True)
    parser.add_argument(
        "--prompt-version",
        type=str,
        default="single-agent",
        choices=["single-agent"],
    )
    parser.add_argument(
        "--dataset-path",
        type=Path,
        default=_env_path("REPOPAIRBENCH_JSONL") or DEFAULT_DATASET_PATH,
    )
    parser.add_argument(
        "--repo-cache-dir",
        type=Path,
        default=_env_path("DREA_REPO_CACHE_DIR") or DEFAULT_REPO_CACHE_DIR,
    )
    parser.add_argument("--recursion-limit", type=int, default=100)
    parser.add_argument("--analysis-timeout-minutes", type=float, default=DEFAULT_ANALYSIS_TIMEOUT_MINUTES)
    parser.add_argument("--force", action="store_true")
    args = parser.parse_args()

    dataset_path = args.dataset_path
    if not dataset_path.exists():
        raise FileNotFoundError(f"Dataset not found: {dataset_path}")

    if args.item_id:
        item = load_item_by_id(dataset_path, args.item_id)
        if item is None:
            raise KeyError(f"Item '{args.item_id}' not found")
        process_item(args.item_id, item, args)
        return

    processed = skipped = failed = 0
    for item_id, item in iter_items(dataset_path):
        try:
            ran = process_item(item_id, item, args)
        except Exception as exc:
            failed += 1
            print(f"  FAILED {item_id}: {exc}")
            continue
        if ran:
            processed += 1
        else:
            skipped += 1

    print(f"\nSingle-agent batch complete. Processed: {processed}, Skipped: {skipped}, Failed: {failed}")


if __name__ == "__main__":
    main()
