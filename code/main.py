import argparse
import json
import os
from datetime import datetime
from pathlib import Path

from core.prompts import (
    DEFAULT_PROMPT_VERSION,
    get_prompt_set,
)
from core.runner import repl

DATASET_BASE_DIR = Path(os.getenv("DREA_DATASET_DIR", "../dataset"))
LOG_DIR = Path("logs")
LOG_DIR.mkdir(parents=True, exist_ok=True)


def normalize_language_tag(language: str | None) -> str:
    if not language:
        return "c"
    normalized = language.strip().lower()
    aliases = {
        "c++": "cpp",
        "c#": "csharp",
        "js": "javascript",
        "ts": "typescript",
        "py": "python",
    }
    return aliases.get(normalized, normalized)


def get_latest_jsonl(log_dir: Path) -> Path | None:
    if not log_dir.exists():
        return None
    jsonl_files = list(log_dir.glob("*.jsonl"))
    if not jsonl_files:
        return None
    return max(jsonl_files, key=lambda path: path.stat().st_mtime)


def is_completed_log(jsonl_path: Path) -> bool:
    last_entry = None
    malformed_lines = 0
    with jsonl_path.open("r", encoding="utf-8") as handle:
        for line in handle:
            line = line.strip()
            if not line:
                continue
            try:
                entry = json.loads(line)
            except json.JSONDecodeError:
                # JSONL logs can end with a partially-written line if a run is interrupted.
                malformed_lines += 1
                continue
            if entry.get("role") == "_usage":
                continue
            last_entry = entry
    if malformed_lines:
        print(
            f"Warning: skipped {malformed_lines} malformed JSONL line(s) in {jsonl_path}"
        )
    if not last_entry:
        return False
    if last_entry.get("role") != "assistant":
        return False
    if last_entry.get("agent") not in (None, "main"):
        return False
    return True


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Run vulnerability detection on a project"
    )
    parser.add_argument(
        "project_name", type=str, help="Name of the project to analyze"
    )
    parser.add_argument(
        "--model",
        type=str,
        default=None,
        help="Main model id from config/models.json (defaults to MAIN_* envs)",
    )
    parser.add_argument(
        "--type",
        type=str,
        default="vul",
        choices=["sec", "vul"],
        help="Type of the task: sec for security task, vul for vulnerability task",
    )
    parser.add_argument(
        "--prompt-version",
        type=str,
        default=DEFAULT_PROMPT_VERSION,
        choices=["drea"],
        help="Prompt version to use",
    )
    parser.add_argument(
        "--force",
        action="store_true",
        help="Force run even if a completed log exists",
    )
    parser.add_argument(
        "--recursion-limit",
        type=int,
        default=None,
        help=(
            "LangGraph recursion limit (default: 500; can also set "
            "LANGGRAPH_RECURSION_LIMIT)"
        ),
    )
    parser.add_argument(
        "--dataset-dir",
        type=Path,
        default=DATASET_BASE_DIR,
        help="Root directory of the reconstructed paired dataset",
    )
    args = parser.parse_args()

    project_name = args.project_name
    paired_dataset_dir = args.dataset_dir / project_name

    if args.type == "sec":
        meta_file = "sec_meta.json"
        workspace_path = paired_dataset_dir / project_name.split("_")[-1]
    elif args.type == "vul":
        meta_file = "vul_meta.json"
        workspace_path = paired_dataset_dir / project_name.split("_")[1]
    else:
        raise ValueError(f"Invalid type: {args.type}")

    if not args.force:
        log_dir = (
            LOG_DIR
            / project_name
            / args.type
            / args.model
            / args.prompt_version
        )
        latest_jsonl = get_latest_jsonl(log_dir)
        if latest_jsonl and is_completed_log(latest_jsonl):
            print(f"Skipping completed task: {latest_jsonl}")
            return

    # build the user prompt
    with open(paired_dataset_dir / meta_file) as f:
        vul_data = json.load(f)
    file_name = vul_data["file_name"]
    language_tag = normalize_language_tag(vul_data.get("language"))

    code_path = paired_dataset_dir / args.type
    with open(code_path) as f:
        code = f.read()

    prompt_set = get_prompt_set(args.prompt_version)
    prompt = prompt_set.user.format(
        file_path=file_name,
        code=code,
        language=language_tag,
    )

    # build the jsonl log file path
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    jsonl_path = (
        LOG_DIR
        / project_name
        / args.type
        / args.model
        / args.prompt_version
        / f"{timestamp}.jsonl"
    )
    jsonl_path.parent.mkdir(parents=True, exist_ok=True)

    print(f"Processing project: {project_name}")
    print(f"Workspace: {workspace_path}")
    print(f"JSONL file: {jsonl_path}")

    repl(
        workspace_path,
        prompt,
        jsonl_path,
        main_model_id=args.model,
        prompt_version=args.prompt_version,
        recursion_limit=args.recursion_limit,
    )


if __name__ == "__main__":
    main()
