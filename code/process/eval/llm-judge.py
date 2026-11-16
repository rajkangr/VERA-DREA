from __future__ import annotations

import argparse
import json
import re
from pathlib import Path

PROJECT_DIR_RE = re.compile(r".+_[0-9a-f]{8}$", re.IGNORECASE)
ASSESSMENT_FILE_GLOB = "*.assessment.json"


def latest_file(directory: Path, pattern: str) -> Path | None:
    files = [path for path in directory.glob(pattern) if path.is_file()]
    if not files:
        return None
    return max(files, key=lambda path: path.stat().st_mtime)


def extract_record(
    assessment_path: Path,
) -> tuple[str, str, str, str, int | None, int | None] | None:
    try:
        data = json.loads(assessment_path.read_text(encoding="utf-8"))
    except Exception:
        return None

    metadata = data.get("metadata", {})
    assessment = data.get("assessment", {})
    conclusion = assessment.get("conclusion", {})
    reasoning = assessment.get("reasoning", {})

    project = str(metadata.get("project", "")).strip()
    task_type = str(metadata.get("task_type", "")).strip()
    prompt_version = str(metadata.get("prompt_version", "")).strip()
    log_file = str(metadata.get("log_file", "")).strip()

    if project == "" or task_type not in {"vul", "sec"}:
        return None
    if not PROJECT_DIR_RE.fullmatch(project):
        return None

    model = ""
    parts = Path(log_file).parts
    if len(parts) >= 5:
        model = parts[-3]
    if model == "":
        return None

    version = prompt_version if prompt_version else "unknown"

    conclusion_value = str(conclusion.get("assessment", "")).strip()
    if conclusion_value == "Consistent":
        conclusion_correct = 1
    elif conclusion_value == "Inconsistent":
        conclusion_correct = 0
    else:
        conclusion_correct = None

    vul_reasoning_correct: int | None = None
    if task_type == "vul":
        reasoning_value = str(reasoning.get("assessment", "")).strip()
        if reasoning_value == "Accurate":
            vul_reasoning_correct = 1
        elif reasoning_value == "Inaccurate":
            vul_reasoning_correct = 0

    return (
        project,
        task_type,
        model,
        version,
        conclusion_correct,
        vul_reasoning_correct,
    )


def collect_records(
    logs_dir: Path,
    model_filter: set[str] | None = None,
    version_filter: set[str] | None = None,
) -> dict[str, dict[str, dict[str, dict[str, int | None]]]]:
    grouped: dict[str, dict[str, dict[str, dict[str, int | None]]]] = {}

    if not logs_dir.exists() or not logs_dir.is_dir():
        return grouped

    for project_dir in sorted(path for path in logs_dir.iterdir() if path.is_dir()):
        if not PROJECT_DIR_RE.fullmatch(project_dir.name):
            continue

        for task_type in ("vul", "sec"):
            task_dir = project_dir / task_type
            if not task_dir.exists() or not task_dir.is_dir():
                continue

            for model_dir in sorted(
                path for path in task_dir.iterdir() if path.is_dir()
            ):
                if model_filter is not None and model_dir.name not in model_filter:
                    continue

                for version_dir in sorted(
                    path for path in model_dir.iterdir() if path.is_dir()
                ):
                    if (
                        version_filter is not None
                        and version_dir.name not in version_filter
                    ):
                        continue

                    model = model_dir.name
                    version = version_dir.name
                    versions = grouped.setdefault(model, {})
                    projects = versions.setdefault(version, {})
                    project_result = projects.setdefault(
                        project_dir.name,
                        {
                            "vul": None,
                            "benign": None,
                            "vul_reasoning": None,
                        },
                    )

                    latest_assessment = latest_file(
                        version_dir, ASSESSMENT_FILE_GLOB
                    )
                    if latest_assessment is None:
                        continue

                    record = extract_record(latest_assessment)
                    if record is None:
                        continue

                    (
                        project,
                        record_task_type,
                        model,
                        _version_from_record,
                        conclusion_correct,
                        vul_reasoning_correct,
                    ) = record

                    if record_task_type == "vul":
                        project_result["vul"] = conclusion_correct
                        project_result["vul_reasoning"] = vul_reasoning_correct
                    else:
                        project_result["benign"] = conclusion_correct

    return grouped


def format_ratio(numerator: int, denominator: int) -> str:
    if denominator <= 0:
        return "0.00% (0/0)"
    value = numerator / denominator * 100
    return f"{value:.2f}% ({numerator}/{denominator})"


def calculate_metrics(
    projects: dict[str, dict[str, int | None]]
) -> dict[str, object]:
    tp = fp = tn = fn = 0
    vul_count = sec_count = 0
    vul_reasoning_correct = vul_reasoning_total = 0
    pair_total = pair_c = pair_b = pair_v = 0

    missing_vul = missing_sec = 0
    missing_vul_reasoning = 0

    for result in projects.values():
        vul = result.get("vul")
        benign = result.get("benign")
        vul_reasoning = result.get("vul_reasoning")

        if vul in {0, 1}:
            vul_count += 1
            if vul == 1:
                tp += 1
            else:
                fn += 1
        else:
            missing_vul += 1

        if benign in {0, 1}:
            sec_count += 1
            if benign == 1:
                tn += 1
            else:
                fp += 1
        else:
            missing_sec += 1

        if vul_reasoning in {0, 1}:
            vul_reasoning_total += 1
            if vul_reasoning == 1:
                vul_reasoning_correct += 1
        elif vul in {0, 1}:
            missing_vul_reasoning += 1

        if vul in {0, 1} and benign in {0, 1}:
            pair_total += 1
            if vul == 1:
                pair_v += 1
            if benign == 1:
                pair_b += 1
            if vul == 1 and benign == 1:
                pair_c += 1

    recall_num = tp
    recall_den = tp + fn
    fpr_num = fp
    fpr_den = fp + tn
    acc_num = tp + tn
    acc_den = tp + tn + fp + fn
    f1_num = 2 * tp
    f1_den = 2 * tp + fp + fn

    metrics = {
        "recall": format_ratio(recall_num, recall_den),
        "fpr": format_ratio(fpr_num, fpr_den),
        "f1": format_ratio(f1_num, f1_den),
        "p_c": format_ratio(pair_c, pair_total),
        "p_b": format_ratio(pair_b, pair_total),
        "p_v": format_ratio(pair_v, pair_total),
        "acc": format_ratio(acc_num, acc_den),
        "vul_reasoning_acc": format_ratio(
            vul_reasoning_correct, vul_reasoning_total
        ),
    }

    return {
        "metrics": metrics,
        "confusion_matrix": {"tp": tp, "fp": fp, "tn": tn, "fn": fn},
        "sample_counts": {
            "vul": vul_count,
            "benign": sec_count,
            "pair_total": pair_total,
            "vul_reasoning_total": vul_reasoning_total,
        },
        "missing_counts": {
            "vul": missing_vul,
            "benign": missing_sec,
            "vul_reasoning": missing_vul_reasoning,
        },
        "projects": dict(sorted(projects.items())),
    }


def parse_model_filter(models: list[str]) -> set[str] | None:
    collected: set[str] = set()
    for value in models:
        for item in value.split(","):
            candidate = item.strip()
            if candidate:
                collected.add(candidate)
    if not collected:
        return None
    return collected


def parse_version_filter(versions: list[str]) -> set[str] | None:
    collected: set[str] = set()
    for value in versions:
        for item in value.split(","):
            candidate = item.strip()
            if candidate:
                collected.add(candidate)
    if not collected:
        return None
    return collected


def infer_logs_kind(logs_dir: Path) -> str:
    name = logs_dir.name.lower()
    if name == "logs":
        return "agent"
    if "baseline" in name:
        return "baseline"
    return logs_dir.name


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Compute model metrics from assessment.json files."
    )
    parser.add_argument(
        "--logs-dir",
        type=Path,
        default=Path("logs"),
        help="Logs directory root, e.g. logs or logs-baseline",
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=Path("."),
        help="Base directory to write per-model outputs",
    )
    parser.add_argument(
        "--model",
        action="append",
        default=[],
        help=(
            "Model filter. Can be provided multiple times "
            "or comma-separated, e.g. --model glm-4.7,gpt-5.2"
        ),
    )
    parser.add_argument(
        "--version",
        action="append",
        default=[],
        help=(
            "Version filter. Can be provided multiple times "
            "or comma-separated, e.g. --version drea,function-only"
        ),
    )
    args = parser.parse_args()

    model_filter = parse_model_filter(args.model)
    version_filter = parse_version_filter(args.version)
    grouped = collect_records(
        args.logs_dir,
        model_filter=model_filter,
        version_filter=version_filter,
    )
    if not grouped:
        print("No matching results found.")
        raise SystemExit(1)

    args.output_dir.mkdir(parents=True, exist_ok=True)
    logs_kind = infer_logs_kind(args.logs_dir)
    write_count = 0
    for model in sorted(grouped):
        for version in sorted(grouped[model]):
            payload = calculate_metrics(grouped[model][version])
            model_dir = args.output_dir / logs_kind / version / model
            model_dir.mkdir(parents=True, exist_ok=True)
            output_path = model_dir / "llm-judge.json"
            output_path.write_text(
                json.dumps(payload, indent=2, ensure_ascii=False),
                encoding="utf-8",
            )
            write_count += 1
            print(f"Wrote {output_path}")
    print(f"Completed: {write_count} version/model outputs")


if __name__ == "__main__":
    main()
