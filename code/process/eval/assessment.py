from __future__ import annotations

import asyncio
import difflib
import json
import os
import re
import threading
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Literal

from dotenv import load_dotenv
from pydantic import BaseModel, Field

from core.model_registry import build_instructor_client

DEFAULT_DATASET_DIR = Path(os.getenv("DREA_DATASET_DIR", "../dataset"))
DEFAULT_MAX_CONCURRENCY = 5
DEFAULT_REPOPAIRBENCH_JSONL = Path(
    os.getenv("REPOPAIRBENCH_JSONL", "../data/repopairbench_100.jsonl")
)
_JSONL_ID_SUFFIX_RE = re.compile(r".*_([0-9a-f]{8})$", re.IGNORECASE)
_JSONL_INDEX_CACHE: dict[Path, dict[str, Path]] = {}
_JSONL_INDEX_LOCK = threading.Lock()

AssessmentRating = Literal["Accurate", "Inaccurate"]
ConclusionAssessment = Literal["Consistent", "Inconsistent"]


class ConclusionEvaluation(BaseModel):
    agent_judgement: str = Field(
        ..., description="Agent's conclusion (Vulnerable/Benign/Uncertain)"
    )
    ground_truth: str = Field(
        ..., description="Ground truth label (Vulnerable/Benign)"
    )
    assessment: ConclusionAssessment = Field(
        ..., description="Consistency with ground truth"
    )


class ReasoningEvaluation(BaseModel):
    agent_analysis: str = Field(
        ..., description="Summary of the agent's reasoning"
    )
    ground_truth_inference: str = Field(
        ..., description="Summary of the true vulnerability reasoning"
    )
    assessment: AssessmentRating = Field(
        ..., description="Accuracy of the agent's reasoning"
    )
    analysis: str = Field(
        ..., description="Detailed critique of reasoning quality"
    )


class ItemizedEvaluation(BaseModel):
    conclusion: ConclusionEvaluation
    reasoning: ReasoningEvaluation


VULNERABLE_CODE_PROMPT = """
You will act as a senior AI security auditor and code reviewer. Your task is to
evaluate the correctness and depth of a vulnerability analysis report from an
AI agent.

CONTEXT: The agent analyzed the ORIGINAL VULNERABLE code (pre-fix) and was asked
to determine whether the code contains security vulnerabilities.

### Ground Truth
This code IS VULNERABLE - it contains a confirmed security vulnerability that
was later fixed.

1. CWE Types
{cwe}

2. CVE Description
{cve_desc}

3. Commit Message
{commit_message}

4. File Path
{file_path}

5. Vulnerable Code (the code the agent analyzed)
{code_patch_before}

6. Fixed Code (the secure version after fixes)
{code_patch_after}

7. Code Diff
{code_diff}

### Agent Analysis Result to be Evaluated
{predictions}

### Evaluation Instructions
When filling the "conclusion" object:
- ground_truth: Always use "Vulnerable"
- agent_judgement: Map the agent's final verdict (use the <security_assessment>
  tag if present):
  - "VULNERABLE" or similar positive indicators -> "Vulnerable"
  - "SECURE", "BENIGN", "NO_VULNERABILITY", or similar negatives -> "Benign"
  - "UNCERTAIN"/ambiguous -> "Uncertain"
- assessment:
  - "Consistent" if agent_judgement is "Vulnerable"
  - "Inconsistent" if agent_judgement is "Benign" or "Uncertain"

For the "reasoning" object:
- agent_analysis: Summarize the agent's reasoning in 3-6 sentences.
- ground_truth_inference: Summarize the real vulnerability based on the fix,
  diff, and commit message.
- assessment: Choose one of {assessment_rating}.
- analysis: Provide a detailed critique of reasoning quality. If inconsistent,
  do deep root-cause analysis of why the agent went wrong, citing specific
  evidence from both the agent output and ground truth.

Return JSON only, with no extra text or code fences, matching this schema:
{{
  "conclusion": {{
    "agent_judgement": "...",
    "ground_truth": "Vulnerable",
    "assessment": "Consistent|Inconsistent"
  }},
  "reasoning": {{
    "agent_analysis": "...",
    "ground_truth_inference": "...",
    "assessment": "Accurate|Inaccurate",
    "analysis": "..."
  }}
}}
"""

SECURE_CODE_PROMPT = """
You will act as a senior AI security auditor and code reviewer. Your task is to
evaluate the correctness and depth of a vulnerability analysis report from an
AI agent.

CONTEXT: The agent analyzed the FIXED BENIGN code (post-fix) and was asked to
determine whether the code contains security vulnerabilities.

### Ground Truth
This code is BENIGN - it does NOT contain vulnerabilities (issues were fixed).

1. CWE Types (from the original vulnerability, for reference only)
{cwe}

2. CVE Description (from the original vulnerability, for reference only)
{cve_desc}

3. Commit Message (describes the original vulnerability and fix)
{commit_message}

4. File Path
{file_path}

5. Original Vulnerable Code (for reference)
{code_patch_before}

6. Fixed Benign Code (the code the agent analyzed)
{code_patch_after}

7. Code Diff
{code_diff}

### Agent Analysis Result to be Evaluated
{predictions}

### Evaluation Instructions
When filling the "conclusion" object:
- ground_truth: Always use "Benign"
- agent_judgement: Map the agent's final verdict (use the <security_assessment>
  tag if present):
  - "VULNERABLE" or similar positives -> "Vulnerable"
  - "SECURE", "BENIGN", "NO_VULNERABILITY", or similar negatives -> "Benign"
  - "UNCERTAIN"/ambiguous -> "Uncertain"
- assessment:
  - "Consistent" if agent_judgement is "Benign"
  - "Inconsistent" if agent_judgement is "Vulnerable" or "Uncertain"

For the "reasoning" object:
- agent_analysis: Summarize the agent's reasoning in 3-6 sentences.
- ground_truth_inference: Summarize the real vulnerability based on the fix,
  diff, and commit message (even though the analyzed code is benign).
- assessment: Choose one of {assessment_rating}.
- analysis: Provide a detailed critique of reasoning quality. If inconsistent,
  do deep root-cause analysis of why the agent went wrong, citing specific
  evidence from both the agent output and ground truth.

Return JSON only, with no extra text or code fences, matching this schema:
{{
  "conclusion": {{
    "agent_judgement": "...",
    "ground_truth": "Benign",
    "assessment": "Consistent|Inconsistent"
  }},
  "reasoning": {{
    "agent_analysis": "...",
    "ground_truth_inference": "...",
    "assessment": "Accurate|Inaccurate",
    "analysis": "..."
  }}
}}
"""


@dataclass(frozen=True)
class LogMetadata:
    project_name: str
    task_type: str
    model_id: str | None = None
    prompt_version: str | None = None
    ground_truth_source: str | None = None


def _env_path(name: str) -> Path | None:
    value = os.getenv(name)
    if not value:
        return None
    return Path(value)


def _read_text(path: Path) -> str:
    return path.read_text(encoding="utf-8", errors="replace")


def _candidate_item_ids(item_id: str) -> list[str]:
    candidates = [item_id]
    match = _JSONL_ID_SUFFIX_RE.match(item_id)
    if match:
        suffix = match.group(1)
        if suffix not in candidates:
            candidates.append(suffix)
    return candidates


def _build_jsonl_index(jsonl_paths: list[Path]) -> dict[str, Path]:
    index: dict[str, Path] = {}
    for jsonl_path in jsonl_paths:
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
                if item_id not in index:
                    index[item_id] = jsonl_path
    return index


def _get_jsonl_index(jsonl_root: Path) -> dict[str, Path]:
    root = jsonl_root.resolve()
    cached = _JSONL_INDEX_CACHE.get(root)
    if cached is not None:
        return cached
    with _JSONL_INDEX_LOCK:
        cached = _JSONL_INDEX_CACHE.get(root)
        if cached is not None:
            return cached
        jsonl_paths = sorted(
            [path for path in root.rglob("*.jsonl") if path.is_file()]
        )
        if not jsonl_paths:
            raise FileNotFoundError(f"No JSONL files found under {jsonl_root}")
        index = _build_jsonl_index(jsonl_paths)
        _JSONL_INDEX_CACHE[root] = index
        return index


def generate_unified_diff(
    before: str, after: str, before_label: str = "vul", after_label: str = "sec"
) -> str:
    before_lines = before.splitlines(keepends=True)
    after_lines = after.splitlines(keepends=True)
    diff = difflib.unified_diff(
        before_lines,
        after_lines,
        fromfile=before_label,
        tofile=after_label,
        lineterm="",
    )
    return "".join(diff)


def _load_meta(project_dir: Path, task_type: str) -> dict[str, Any]:
    meta_name = "vul_meta.json" if task_type == "vul" else "sec_meta.json"
    meta_path = project_dir / meta_name
    if not meta_path.exists():
        raise FileNotFoundError(f"Missing meta file: {meta_path}")
    with meta_path.open("r", encoding="utf-8") as handle:
        return json.load(handle)


def _first_present(item: dict[str, Any], keys: list[str]) -> Any | None:
    for key in keys:
        if key in item and item[key] not in (None, ""):
            return item[key]
    return None


def _normalize_cwe(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, list):
        return [str(v) for v in value if v not in (None, "")]
    if isinstance(value, str):
        return [value]
    return [str(value)]


def load_ground_truth_from_paired_dataset(
    project_dir: Path, task_type: str
) -> dict[str, Any]:
    meta = _load_meta(project_dir, task_type)
    code_patch_before = _read_text(project_dir / "vul")
    code_patch_after = _read_text(project_dir / "sec")
    code_diff = generate_unified_diff(code_patch_before, code_patch_after)
    return {
        "cwe": _normalize_cwe(meta.get("cwe", [])),
        "cve_desc": meta.get("cve_desc", ""),
        "commit_message": meta.get("commit_message", ""),
        "file_path": meta.get("file_name", ""),
        "commit_url": meta.get("commit_url", ""),
        "code_patch_before": code_patch_before,
        "code_patch_after": code_patch_after,
        "code_diff": code_diff,
    }


def _load_jsonl_item_by_id(jsonl_path: Path, item_id: str) -> dict[str, Any]:
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
    raise KeyError(f"Item id '{item_id}' not found in {jsonl_path}")


def _build_ground_truth_from_jsonl_item(item: dict[str, Any]) -> dict[str, Any]:
    vuln_data = item.get("vuln_data")
    if not isinstance(vuln_data, dict):
        vuln_data = item

    cwe = _first_present(item, ["cwe", "cwe_id", "cwe_ids", "cwe_list"])
    if cwe is None:
        cwe = _first_present(
            vuln_data, ["cwe", "cwe_id", "cwe_ids", "cwe_list"]
        )

    cve_desc = _first_present(
        item,
        [
            "cve_desc",
            "cve_description",
            "cve_description_en",
            "description",
        ],
    )
    if cve_desc is None:
        cve_desc = _first_present(
            vuln_data,
            [
                "cve_desc",
                "cve_description",
                "cve_description_en",
                "description",
            ],
        )

    commit_message = _first_present(
        item, ["commit_message", "commit_msg", "message"]
    )
    if commit_message is None:
        commit_message = _first_present(
            vuln_data, ["commit_message", "commit_msg", "message"]
        )

    file_path = _first_present(
        vuln_data, ["file_path", "file_name", "path", "filename"]
    )

    code_before = _first_present(
        vuln_data,
        ["code_before", "before", "vul_code", "code_vul", "code"],
    )
    code_after = _first_present(
        vuln_data,
        ["code_after", "after", "fixed_code", "code_sec", "code"],
    )

    if not isinstance(code_before, str) or not code_before:
        raise KeyError("Missing code_before in JSONL item")
    if not isinstance(code_after, str) or not code_after:
        raise KeyError("Missing code_after in JSONL item")

    code_diff = generate_unified_diff(code_before, code_after)
    repo_url = _first_present(item, ["repo_url", "repository_url", "repo"])
    if repo_url is None:
        repo_url = _first_present(
            vuln_data, ["repo_url", "repository_url", "repo"]
        )
    commit_hash = _first_present(item, ["commit_hash", "commit_id", "sha"])
    if commit_hash is None:
        commit_hash = _first_present(
            vuln_data, ["commit_hash", "commit_id", "sha"]
        )
    commit_url = ""
    if repo_url and commit_hash:
        commit_url = f"{str(repo_url).rstrip('/')}/commit/{commit_hash}"

    return {
        "cwe": _normalize_cwe(cwe),
        "cve_desc": str(cve_desc or ""),
        "commit_message": str(commit_message or ""),
        "file_path": str(file_path or ""),
        "commit_url": commit_url,
        "code_patch_before": code_before,
        "code_patch_after": code_after,
        "code_diff": code_diff,
    }


def load_ground_truth_from_jsonl(
    jsonl_path: Path, item_id: str
) -> dict[str, Any]:
    last_error: Exception | None = None
    for candidate_id in _candidate_item_ids(item_id):
        try:
            item = _load_jsonl_item_by_id(jsonl_path, candidate_id)
        except KeyError as exc:
            last_error = exc
            continue
        return _build_ground_truth_from_jsonl_item(item)
    raise KeyError(
        f"Item id '{item_id}' not found in {jsonl_path}"
    ) from last_error


def load_ground_truth_from_jsonl_root(
    jsonl_root: Path, item_id: str
) -> dict[str, Any]:
    index = _get_jsonl_index(jsonl_root)
    last_error: Exception | None = None
    for candidate_id in _candidate_item_ids(item_id):
        jsonl_path = index.get(candidate_id)
        if jsonl_path is None:
            continue
        try:
            item = _load_jsonl_item_by_id(jsonl_path, candidate_id)
        except KeyError as exc:
            last_error = exc
            continue
        return _build_ground_truth_from_jsonl_item(item)
    raise KeyError(
        f"Item id '{item_id}' not found under {jsonl_root}"
    ) from last_error


def _extract_text_from_content(content: Any, *, include_thinking: bool) -> str:
    if content is None:
        return ""
    if isinstance(content, str):
        return content
    if isinstance(content, dict):
        if "content" in content:
            return str(content["content"])
        if "text" in content:
            return str(content["text"])
        return str(content)
    if isinstance(content, list):
        parts = []
        for item in content:
            if not isinstance(item, dict):
                parts.append(str(item))
                continue
            item_type = str(item.get("type", ""))
            if item_type == "thinking" and not include_thinking:
                continue
            if "content" in item:
                parts.append(str(item["content"]))
            elif "text" in item:
                parts.append(str(item["text"]))
        return "\n".join(p for p in parts if p)
    return str(content)


def is_trace_complete(jsonl_path: Path) -> bool:
    """Check if a trace file is complete.

    A complete trace has its last non-_usage message as a main assistant
    message WITHOUT tool_calls.
    """
    lines = []
    try:
        with jsonl_path.open("r", encoding="utf-8") as handle:
            for raw_line in handle:
                raw_line = raw_line.strip()
                if raw_line:
                    lines.append(json.loads(raw_line))
    except (json.JSONDecodeError, IOError):
        return False

    if len(lines) < 2:
        return False

    idx = len(lines) - 1
    while idx >= 0 and lines[idx].get("role") == "_usage":
        idx -= 1

    if idx < 0:
        return False

    last_msg = lines[idx]
    if last_msg.get("role") != "assistant":
        return False
    if last_msg.get("agent") not in (None, "main"):
        return False
    if last_msg.get("tool_calls"):
        return False

    return True


def extract_final_assistant_output(jsonl_path: Path) -> str:
    last_text = ""
    with jsonl_path.open("r", encoding="utf-8") as handle:
        for line in handle:
            line = line.strip()
            if not line:
                continue
            try:
                entry = json.loads(line)
            except json.JSONDecodeError:
                continue
            if entry.get("role") != "assistant":
                continue
            if entry.get("agent") not in (None, "main"):
                continue
            content = entry.get("content")
            text = _extract_text_from_content(content, include_thinking=False)
            if text:
                last_text = text
            elif not last_text:
                fallback = _extract_text_from_content(
                    content, include_thinking=True
                )
                if fallback:
                    last_text = fallback
    if not last_text:
        raise ValueError(f"No assistant output found in {jsonl_path}")
    return last_text


def infer_log_metadata(
    jsonl_path: Path,
    logs_root: Path | None = None,
    default_project: str | None = None,
    default_task_type: str | None = None,
) -> LogMetadata:
    logs_root = logs_root or Path("logs")
    project_name = default_project
    task_type = default_task_type
    model_id = None
    prompt_version = None

    parts = jsonl_path.resolve().parts
    if logs_root.resolve() in jsonl_path.resolve().parents:
        root_parts = logs_root.resolve().parts
        try:
            idx = parts.index(root_parts[-1])
            project_name = project_name or parts[idx + 1]
            task_type = task_type or parts[idx + 2]
            model_id = parts[idx + 3] if len(parts) > idx + 3 else None
            prompt_version = parts[idx + 4] if len(parts) > idx + 4 else None
        except (ValueError, IndexError):
            pass

    if project_name is None:
        stem = jsonl_path.stem
        match = re.match(r"(.+)_\d{8}_\d{6}$", stem)
        if match:
            project_name = match.group(1)

    if project_name is None or task_type is None:
        raise ValueError(
            "Unable to infer project/type from log path. "
            "Provide --project and --type."
        )

    return LogMetadata(
        project_name=project_name,
        task_type=task_type,
        model_id=model_id,
        prompt_version=prompt_version,
    )


def _resolve_dataset_jsonl_path(
    dataset_jsonl: Path | None,
) -> Path | None:
    if dataset_jsonl is not None:
        return dataset_jsonl
    return (
        _env_path("ASSESSMENT_DATASET_JSONL")
        or _env_path("REPOPAIRBENCH_JSONL")
        or DEFAULT_REPOPAIRBENCH_JSONL
    )


def load_ground_truth(
    metadata: LogMetadata,
    *,
    dataset_dir: Path,
    dataset_jsonl: Path | None,
    source: str,
) -> tuple[dict[str, Any], str]:
    if source not in {"auto", "paired", "jsonl"}:
        raise ValueError(
            f"Unsupported ground truth source '{source}'. "
            "Use one of: auto, paired, jsonl."
        )

    if source in {"auto", "paired"}:
        project_dir = dataset_dir / metadata.project_name
        if project_dir.exists():
            return (
                load_ground_truth_from_paired_dataset(
                    project_dir, metadata.task_type
                ),
                "paired",
            )
        if source == "paired":
            raise FileNotFoundError(f"Dataset not found: {project_dir}")

    jsonl_path = _resolve_dataset_jsonl_path(dataset_jsonl)
    if jsonl_path is None:
        raise FileNotFoundError(
            "JSONL dataset path not provided. "
            "Pass --dataset-jsonl or set REPOPAIRBENCH_JSONL."
        )
    if not jsonl_path.exists():
        raise FileNotFoundError(f"Dataset JSONL not found: {jsonl_path}")
    if jsonl_path.is_dir():
        return (
            load_ground_truth_from_jsonl_root(
                jsonl_path, metadata.project_name
            ),
            "jsonl",
        )
    return (
        load_ground_truth_from_jsonl(jsonl_path, metadata.project_name),
        "jsonl",
    )


async def _call_judge_model(
    prompt: str, model_id: str, *, max_tokens: int = 4096
) -> ItemizedEvaluation:
    client = build_instructor_client(model_id, async_client=True)
    response = await client.chat.completions.create(
        messages=[{"role": "user", "content": prompt}],
        response_model=ItemizedEvaluation,
        max_tokens=max_tokens,
    )
    if isinstance(response, ItemizedEvaluation):
        return response
    return ItemizedEvaluation.model_validate(response)


async def assess_log_file_async(
    jsonl_path: Path,
    model_id: str,
    dataset_dir: Path = DEFAULT_DATASET_DIR,
    dataset_jsonl: Path | None = None,
    source: str = "auto",
    logs_root: Path | None = None,
    default_project: str | None = None,
    default_task_type: str | None = None,
    output_path: Path | None = None,
    force: bool = False,
    max_retries: int = 3,
) -> dict[str, Any]:
    load_dotenv()
    metadata = infer_log_metadata(
        jsonl_path,
        logs_root=logs_root,
        default_project=default_project,
        default_task_type=default_task_type,
    )

    if metadata.task_type not in {"vul", "sec"}:
        raise ValueError(f"Unsupported task type: {metadata.task_type}")

    if output_path is None:
        output_path = jsonl_path.with_suffix(".assessment.json")

    if output_path.exists() and not force:
        return {
            "status": "skipped",
            "reason": "assessment already exists",
            "output_path": str(output_path),
        }

    if not is_trace_complete(jsonl_path):
        return {
            "status": "skipped",
            "reason": "incomplete trace",
            "log_file": str(jsonl_path),
        }

    ground_truth, ground_truth_source = load_ground_truth(
        metadata,
        dataset_dir=dataset_dir,
        dataset_jsonl=dataset_jsonl,
        source=source,
    )
    predictions = extract_final_assistant_output(jsonl_path)

    prompt_template = (
        VULNERABLE_CODE_PROMPT
        if metadata.task_type == "vul"
        else SECURE_CODE_PROMPT
    )
    prompt = prompt_template.format(
        cwe=ground_truth["cwe"],
        cve_desc=ground_truth["cve_desc"],
        commit_message=ground_truth["commit_message"],
        file_path=ground_truth["file_path"],
        code_patch_before=ground_truth["code_patch_before"],
        code_patch_after=ground_truth["code_patch_after"],
        code_diff=ground_truth["code_diff"],
        predictions=predictions,
        assessment_rating=" | ".join(
            [
                "Accurate",
                "Inaccurate",
            ]
        ),
    )

    attempt = 0
    last_error: Exception | None = None
    while attempt < max_retries:
        attempt += 1
        try:
            assessment_model = await _call_judge_model(prompt, model_id)
            assessment = assessment_model.model_dump()
            result = {
                "metadata": {
                    "project": metadata.project_name,
                    "task_type": metadata.task_type,
                    "judge_model_id": model_id,
                    "log_file": str(jsonl_path),
                    "prompt_version": metadata.prompt_version,
                    "ground_truth_source": ground_truth_source,
                },
                "ground_truth": {
                    "label": "Vulnerable"
                    if metadata.task_type == "vul"
                    else "Benign",
                    "cwe": ground_truth["cwe"],
                    "cve_desc": ground_truth["cve_desc"],
                    "commit_message": ground_truth["commit_message"],
                    "file_path": ground_truth["file_path"],
                    "commit_url": ground_truth.get("commit_url", ""),
                },
                "assessment": assessment,
            }
            output_path.parent.mkdir(parents=True, exist_ok=True)
            with output_path.open("w", encoding="utf-8") as handle:
                json.dump(result, handle, indent=2, ensure_ascii=False)
            return result
        except Exception as exc:
            last_error = exc
            if attempt >= max_retries:
                break
            await asyncio.sleep(min(2**attempt, 10))

    raise RuntimeError(
        f"Assessment failed for {jsonl_path}: {last_error}"
    ) from last_error


async def _assess_with_semaphore(
    jsonl_path: Path,
    semaphore: asyncio.Semaphore,
    **kwargs: Any,
) -> tuple[Path, dict[str, Any]]:
    async with semaphore:
        try:
            result = await assess_log_file_async(jsonl_path, **kwargs)
            return jsonl_path, result
        except Exception as exc:
            return jsonl_path, {"error": str(exc)}


async def assess_logs_async(
    jsonl_paths: list[Path],
    model_id: str,
    dataset_dir: Path = DEFAULT_DATASET_DIR,
    dataset_jsonl: Path | None = None,
    source: str = "auto",
    logs_root: Path | None = None,
    default_project: str | None = None,
    default_task_type: str | None = None,
    output_dir: Path | None = None,
    force: bool = False,
    max_concurrency: int = DEFAULT_MAX_CONCURRENCY,
) -> dict[str, Any]:
    semaphore = asyncio.Semaphore(max_concurrency)
    results: dict[str, Any] = {}

    tasks = []
    for jsonl_path in jsonl_paths:
        output_path = None
        if output_dir is not None:
            output_path = output_dir / f"{jsonl_path.stem}.assessment.json"
        tasks.append(
            _assess_with_semaphore(
                jsonl_path,
                semaphore,
                model_id=model_id,
                dataset_dir=dataset_dir,
                dataset_jsonl=dataset_jsonl,
                source=source,
                logs_root=logs_root,
                default_project=default_project,
                default_task_type=default_task_type,
                output_path=output_path,
                force=force,
            )
        )

    for idx, task in enumerate(asyncio.as_completed(tasks), 1):
        jsonl_path, result = await task
        key = str(jsonl_path)
        results[key] = result
        status = "error" if "error" in result else result.get("status", "ok")
        print(f"[{idx}/{len(tasks)}] {status}: {jsonl_path}")

    return results
