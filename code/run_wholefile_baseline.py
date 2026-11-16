"""
Whole-file Context Baseline runner.

Similar to run_baseline.py but provides the entire file content as additional
context alongside the target function. Requires access to the git repository
cache to read the file at the correct commit.

Usage:
    uv run run_wholefile_baseline.py --model DeepSeek-V3.2_mify --type vul
    uv run run_wholefile_baseline.py --model DeepSeek-V3.2_mify --type sec
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import re
import subprocess
from collections.abc import Iterator
from datetime import datetime
from pathlib import Path
from typing import Any

from aiolimiter import AsyncLimiter
from dotenv import load_dotenv

from core.baseline_runner import run_baseline_inference
from core.model_registry import build_main_model
from core.prompts.baseline import (
    get_baseline_prompt_set,
)

DEFAULT_DATASET_PATH = Path("../data/repopairbench_100.jsonl")
DEFAULT_REPO_CACHE_DIR = Path("../repos")
LOG_DIR = Path("logs-baseline")
LOG_DIR.mkdir(parents=True, exist_ok=True)

# Maximum whole-file size to include (avoid blowing up context)
MAX_WHOLE_FILE_LINES = 2000


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
    roles: list[str] = []
    malformed_lines = 0
    with jsonl_path.open("r", encoding="utf-8") as handle:
        for line in handle:
            line = line.strip()
            if not line:
                continue
            try:
                entry = json.loads(line)
            except json.JSONDecodeError:
                malformed_lines += 1
                continue
            role = entry.get("role")
            if isinstance(role, str):
                roles.append(role)
    if malformed_lines:
        print(
            f"Warning: skipped {malformed_lines} malformed JSONL line(s) in {jsonl_path}"
        )
    return roles[-3:] == ["user", "assistant", "_usage"]


def load_item_by_id(jsonl_path: Path, item_id: str) -> dict[str, Any] | None:
    with jsonl_path.open("r", encoding="utf-8") as handle:
        for line_number, raw_line in enumerate(handle, start=1):
            line = raw_line.strip()
            if not line:
                continue
            try:
                item = json.loads(line)
            except json.JSONDecodeError as exc:
                raise ValueError(
                    f"Invalid JSON on line {line_number} in {jsonl_path}"
                ) from exc
            if item.get("id") == item_id:
                return item
    return None


def iter_items(jsonl_path: Path) -> Iterator[tuple[str, dict[str, Any]]]:
    with jsonl_path.open("r", encoding="utf-8") as handle:
        for line_number, raw_line in enumerate(handle, start=1):
            line = raw_line.strip()
            if not line:
                continue
            try:
                item = json.loads(line)
            except json.JSONDecodeError as exc:
                raise ValueError(
                    f"Invalid JSON on line {line_number} in {jsonl_path}"
                ) from exc
            item_id = item.get("id")
            if not item_id:
                raise KeyError(
                    f"Missing 'id' on line {line_number} in {jsonl_path}"
                )
            yield item_id, item


def normalize_language_tag(language: str | None) -> str:
    if not language:
        return "text"
    normalized = language.strip().lower()
    aliases = {
        "c++": "cpp",
        "c#": "csharp",
        "js": "javascript",
        "ts": "typescript",
        "py": "python",
    }
    return aliases.get(normalized, normalized)


def sanitize_path_component(name: str) -> str:
    sanitized = re.sub(r"[^A-Za-z0-9._-]+", "-", name.strip())
    return sanitized.strip("-._")


def get_repo_path(repo_url: str, base_dir: Path) -> Path:
    """Derive local repo path from GitHub URL.

    Supports the artifact repository-cache layout: repos/{org}/{repo}
    """
    parts = repo_url.rstrip("/").split("/")
    if len(parts) < 2:
        raise ValueError(f"Invalid repo_url: {repo_url}")
    org, repo = parts[-2], parts[-1]
    return base_dir / org / repo


def git_show_file(repo_path: Path, commit: str, file_path: str) -> str | None:
    """Read a file at a specific commit using git show."""
    try:
        result = subprocess.run(
            ["git", "show", f"{commit}:{file_path}"],
            cwd=repo_path,
            capture_output=True,
            text=True,
            check=True,
        )
        return result.stdout
    except subprocess.CalledProcessError:
        return None


def resolve_target_commit(
    repo_path: Path, commit_hash: str, task_type: str
) -> str:
    """For 'vul' task, use parent commit; for 'sec' task, use the fix commit."""
    if task_type == "vul":
        result = subprocess.run(
            ["git", "rev-parse", f"{commit_hash}^"],
            cwd=repo_path,
            capture_output=True,
            text=True,
            check=True,
        )
        return result.stdout.strip()
    result = subprocess.run(
        ["git", "rev-parse", commit_hash],
        cwd=repo_path,
        capture_output=True,
        text=True,
        check=True,
    )
    return result.stdout.strip()


def extract_required_fields(
    item: dict[str, Any], task_type: str
) -> tuple[str, str, str, str, str]:
    """Extract fields needed for whole-file baseline."""
    repo_url = item["repo_url"]
    commit_hash = item["commit_hash"]
    vuln_data = item["vuln_data"]
    file_path = vuln_data["file_path"]
    code_key = "code_before" if task_type == "vul" else "code_after"
    code = vuln_data[code_key]
    language_tag = normalize_language_tag(item.get("language"))
    return repo_url, commit_hash, file_path, code, language_tag


def save_jsonl_entries(jsonl_path: Path, entries: list[dict[str, Any]]) -> None:
    jsonl_path.parent.mkdir(parents=True, exist_ok=True)
    with jsonl_path.open("w", encoding="utf-8") as handle:
        for entry in entries:
            handle.write(json.dumps(entry, ensure_ascii=False) + "\n")


async def process_item(
    item_id: str,
    item: dict[str, Any],
    args: argparse.Namespace,
    llm: Any,
    prompt_set: Any,
    semaphore: asyncio.Semaphore,
    rate_limiter: AsyncLimiter | None,
) -> str:
    raw_project_name = item.get("project_name")
    project_component = (
        sanitize_path_component(raw_project_name) if raw_project_name else ""
    )
    log_root = (
        f"{project_component}_{item_id}" if project_component else item_id
    )

    log_dir = (
        LOG_DIR
        / log_root
        / args.type
        / args.model
        / args.prompt_version
    )
    if not args.force:
        latest_jsonl = get_latest_jsonl(log_dir)
        if latest_jsonl and is_completed_log(latest_jsonl):
            return "skipped"

    repo_url, commit_hash, file_path, code, language_tag = (
        extract_required_fields(item, args.type)
    )

    # Get the whole file from the repo at the correct commit
    repo_path = get_repo_path(repo_url, args.repo_cache_dir)
    if not repo_path.exists():
        print(f"  Repo not found: {repo_path}, skipping {item_id}")
        return "failed"

    try:
        target_commit = resolve_target_commit(repo_path, commit_hash, args.type)
    except subprocess.CalledProcessError as exc:
        print(f"  Cannot resolve commit for {item_id}: {exc}")
        return "failed"

    whole_file = git_show_file(repo_path, target_commit, file_path)
    if whole_file is None:
        print(f"  Cannot read file {file_path} at {target_commit[:8]} for {item_id}")
        # Fall back to just the function code
        whole_file = code

    # Truncate if too large
    lines = whole_file.splitlines()
    if len(lines) > MAX_WHOLE_FILE_LINES:
        whole_file = "\n".join(lines[:MAX_WHOLE_FILE_LINES]) + f"\n\n... (truncated, {len(lines)} total lines)"

    # Format the prompt with whole_file context
    prompt = prompt_set.user.format(
        file_path=file_path,
        code=code,
        language=language_tag,
        whole_file=whole_file,
    )

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    jsonl_path = log_dir / f"{timestamp}.jsonl"

    print(f"[{item_id}] {raw_project_name or 'N/A'} | {args.type} | file={file_path} | whole_file_lines={len(lines)}")

    async with semaphore:
        if rate_limiter:
            await rate_limiter.acquire()
        try:
            user_entry, assistant_entry, usage_entry = (
                await run_baseline_inference(
                    llm=llm,
                    system_prompt=prompt_set.system,
                    user_prompt=prompt,
                    timeout=args.timeout,
                    max_retries=args.max_retries,
                )
            )
        except Exception as exc:  # noqa: BLE001
            print(f"  Error processing item {item_id}: {exc}")
            return "failed"

    save_jsonl_entries(jsonl_path, [user_entry, assistant_entry, usage_entry])
    return "processed"


async def async_main(args: argparse.Namespace) -> None:
    load_dotenv()

    dataset_path = args.dataset_path
    if not dataset_path.exists():
        raise FileNotFoundError(
            f"Dataset JSONL not found: {dataset_path}. "
            "Pass --dataset-path or set REPOPAIRBENCH_JSONL."
        )

    llm = build_main_model(args.model)
    prompt_set = get_baseline_prompt_set(args.prompt_version)
    semaphore = asyncio.Semaphore(args.concurrency)
    rate_limiter = AsyncLimiter(args.rpm, 60.0) if args.rpm > 0 else None

    if args.item_id:
        item = load_item_by_id(dataset_path, args.item_id)
        if item is None:
            raise KeyError(
                f"Item id '{args.item_id}' not found in {dataset_path}"
            )
        status = await process_item(
            args.item_id, item, args, llm, prompt_set, semaphore, rate_limiter
        )
        if status == "failed":
            raise SystemExit(1)
        return

    tasks: list[asyncio.Task[str]] = []
    for item_id, item in iter_items(dataset_path):
        tasks.append(
            asyncio.create_task(
                process_item(
                    item_id, item, args, llm, prompt_set, semaphore, rate_limiter
                )
            )
        )

    processed = 0
    skipped = 0
    failed = 0
    for result in await asyncio.gather(*tasks):
        if result == "processed":
            processed += 1
        elif result == "skipped":
            skipped += 1
        else:
            failed += 1

    print(
        f"\nWhole-file baseline complete. "
        f"Processed: {processed}, Skipped: {skipped}, Failed: {failed}"
    )
    if failed:
        print(f"WARNING: {failed} items failed")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Run whole-file context baseline vulnerability detection"
    )
    parser.add_argument(
        "item_id",
        nargs="?",
        type=str,
        help="JSONL item id to analyze (omit to process all items)",
    )
    parser.add_argument(
        "--type",
        type=str,
        default="vul",
        choices=["sec", "vul"],
        help="Task type: sec (patched) or vul (vulnerable)",
    )
    parser.add_argument(
        "--model",
        type=str,
        required=True,
        help="Model id from config/models.json",
    )
    parser.add_argument(
        "--prompt-version",
        type=str,
        default="whole-file",
        choices=["whole-file"],
        help="Baseline prompt version to use",
    )
    parser.add_argument(
        "--dataset-path",
        type=Path,
        default=_env_path("REPOPAIRBENCH_JSONL") or DEFAULT_DATASET_PATH,
        help="Path to RepoPairBench JSONL dataset",
    )
    parser.add_argument(
        "--repo-cache-dir",
        type=Path,
        default=_env_path("DREA_REPO_CACHE_DIR") or DEFAULT_REPO_CACHE_DIR,
        help="Base directory containing cached git repos",
    )
    parser.add_argument(
        "--concurrency",
        type=int,
        default=5,
        help="Number of concurrent requests",
    )
    parser.add_argument(
        "--rpm",
        type=int,
        default=0,
        help="Max requests per minute (0 disables)",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=180.0,
        help="Per-request timeout in seconds",
    )
    parser.add_argument(
        "--max-retries",
        type=int,
        default=3,
        help="Max retries per request",
    )
    parser.add_argument(
        "--force",
        action="store_true",
        help="Force run even if completed log exists",
    )
    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()
    asyncio.run(async_main(args))


if __name__ == "__main__":
    main()
