from __future__ import annotations

import argparse
import asyncio
from pathlib import Path

from process.eval.assessment import (
    DEFAULT_DATASET_DIR,
    DEFAULT_MAX_CONCURRENCY,
    assess_log_file_async,
    assess_logs_async,
)


def _collect_jsonl_files(root: Path) -> list[Path]:
    return sorted([path for path in root.rglob("*.jsonl") if path.is_file()])


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Run LLM-as-judge assessment on log JSONL files."
    )
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument(
        "--log",
        type=Path,
        help="Path to a single JSONL log file",
    )
    group.add_argument(
        "--logs-root",
        type=Path,
        default=Path("logs"),
        help="Root directory containing JSONL logs",
    )
    parser.add_argument(
        "--model",
        required=True,
        help="Judge model id from config/models.json",
    )
    parser.add_argument(
        "--dataset-dir",
        type=Path,
        default=DEFAULT_DATASET_DIR,
        help="Dataset root directory",
    )
    parser.add_argument(
        "--dataset-jsonl",
        type=Path,
        default=None,
        help="RepoPairBench JSONL dataset file or directory",
    )
    parser.add_argument(
        "--source",
        choices=["auto", "paired", "jsonl"],
        default="auto",
        help="Ground truth source: paired dataset, JSONL, or auto",
    )
    parser.add_argument(
        "--max-concurrency",
        type=int,
        default=DEFAULT_MAX_CONCURRENCY,
        help="Maximum concurrent judge requests",
    )
    parser.add_argument(
        "--force",
        action="store_true",
        help="Re-run assessment even if output exists",
    )
    parser.add_argument(
        "--project",
        type=str,
        default=None,
        help="Fallback project name if it cannot be inferred from log path",
    )
    parser.add_argument(
        "--type",
        choices=["vul", "sec"],
        default=None,
        help="Fallback task type if it cannot be inferred from log path",
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=None,
        help="Optional output directory for assessment JSON files",
    )
    args = parser.parse_args()

    if args.log:
        jsonl_path = args.log
        result = asyncio.run(
            assess_log_file_async(
                jsonl_path,
                model_id=args.model,
                dataset_dir=args.dataset_dir,
                dataset_jsonl=args.dataset_jsonl,
                source=args.source,
                logs_root=args.logs_root,
                default_project=args.project,
                default_task_type=args.type,
                output_path=(
                    args.output_dir / f"{jsonl_path.stem}.assessment.json"
                    if args.output_dir
                    else None
                ),
                force=args.force,
            )
        )
        print(result)
        return

    jsonl_paths = _collect_jsonl_files(args.logs_root)
    if not jsonl_paths:
        print(f"No JSONL files found in {args.logs_root}")
        return

    results = asyncio.run(
        assess_logs_async(
            jsonl_paths,
            model_id=args.model,
            dataset_dir=args.dataset_dir,
            dataset_jsonl=args.dataset_jsonl,
            source=args.source,
            logs_root=args.logs_root,
            default_project=args.project,
            default_task_type=args.type,
            output_dir=args.output_dir,
            force=args.force,
            max_concurrency=args.max_concurrency,
        )
    )
    print(f"Completed assessments: {len(results)}")


if __name__ == "__main__":
    main()
