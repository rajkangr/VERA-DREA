from __future__ import annotations

import argparse
import asyncio
import json
import os
import re
from collections.abc import Iterator
from datetime import datetime
from pathlib import Path
from typing import Any

from aiolimiter import AsyncLimiter
from dotenv import load_dotenv

from core.baseline_runner import run_baseline_inference
from core.model_registry import build_main_model
from core.prompts.baseline import DEFAULT_BASELINE_PROMPT_VERSION, get_baseline_prompt_set

DEFAULT_DATASET_PATH = Path("../data/repopairbench_100.jsonl")
LOG_DIR = Path("logs-baseline")
LOG_DIR.mkdir(parents=True, exist_ok=True)


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


def extract_required_fields(
    item: dict[str, Any], task_type: str
) -> tuple[str, str, str]:
    vuln_data = item["vuln_data"]
    file_path = vuln_data["file_path"]
    code_key = "code_before" if task_type == "vul" else "code_after"
    code = vuln_data[code_key]
    language_tag = normalize_language_tag(item.get("language"))
    return file_path, code, language_tag


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
            print(f"Skipping completed task: {latest_jsonl}")
            return "skipped"

    file_path, code, language_tag = extract_required_fields(item, args.type)
    prompt = prompt_set.user.format(
        file_path=file_path,
        code=code,
        language=language_tag,
    )

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    jsonl_path = log_dir / f"{timestamp}.jsonl"

    print(f"Processing RepoPairBench baseline item: {item_id}")
    print(f"Project: {raw_project_name or 'N/A'}")
    print(f"Language tag: {language_tag}")
    print(f"Log root: {log_root}")
    print(f"JSONL file: {jsonl_path}")

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
        except Exception as exc:  # noqa: BLE001 - batch mode continues on errors
            print(f"Error processing item {item_id}: {exc}")
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

    if args.concurrency <= 0:
        raise ValueError("--concurrency must be a positive integer")
    if args.rpm < 0:
        raise ValueError("--rpm must be >= 0")
    if args.timeout <= 0:
        raise ValueError("--timeout must be greater than 0")
    if args.max_retries < 0:
        raise ValueError("--max-retries must be >= 0")

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
            args.item_id,
            item,
            args,
            llm,
            prompt_set,
            semaphore,
            rate_limiter,
        )
        if status == "failed":
            raise SystemExit(1)
        return

    tasks: list[asyncio.Task[str]] = []
    for item_id, item in iter_items(dataset_path):
        tasks.append(
            asyncio.create_task(
                process_item(
                    item_id,
                    item,
                    args,
                    llm,
                    prompt_set,
                    semaphore,
                    rate_limiter,
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
        "Batch baseline run complete. "
        f"Processed: {processed}, Skipped: {skipped}, Failed: {failed}"
    )
    if failed:
        raise SystemExit(1)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Run baseline vulnerability detection on RepoPairBench JSONL"
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
        help="Type of the task: sec for security task, vul for vulnerability task",
    )
    parser.add_argument(
        "--model",
        type=str,
        required=True,
        help="Main model id from config/models.json",
    )
    parser.add_argument(
        "--prompt-version",
        type=str,
        default=DEFAULT_BASELINE_PROMPT_VERSION,
        choices=["function-only"],
        help="Baseline prompt version to use",
    )
    parser.add_argument(
        "--dataset-path",
        type=Path,
        default=_env_path("REPOPAIRBENCH_JSONL") or DEFAULT_DATASET_PATH,
        help="Path to RepoPairBench JSONL dataset (env: REPOPAIRBENCH_JSONL)",
    )
    parser.add_argument(
        "--concurrency",
        type=int,
        default=5,
        help="Number of concurrent baseline requests",
    )
    parser.add_argument(
        "--rpm",
        type=int,
        default=0,
        help="Max requests per minute (0 disables RPM limiting)",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=120.0,
        help="Per-request timeout in seconds",
    )
    parser.add_argument(
        "--max-retries",
        type=int,
        default=3,
        help="Max retries for each request",
    )
    parser.add_argument(
        "--force",
        action="store_true",
        help="Force run even if a completed log exists",
    )
    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()
    asyncio.run(async_main(args))


if __name__ == "__main__":
    main()
