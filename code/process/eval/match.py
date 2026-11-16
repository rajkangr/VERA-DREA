from __future__ import annotations

import argparse
import json
import re
from pathlib import Path

PROJECT_DIR_RE = re.compile(r".+_[0-9a-f]{8}$", re.IGNORECASE)
ASSESSMENT_TAG_RE = re.compile(
    r"<security_assessment>\s*(VULNERABLE|SECURE)\s*</security_assessment>",
    re.IGNORECASE,
)


def latest_file(directory: Path, pattern: str) -> Path | None:
    files = [path for path in directory.glob(pattern) if path.is_file()]
    if not files:
        return None
    return max(files, key=lambda path: path.stat().st_mtime)


def content_to_text(content: object) -> str:
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        parts: list[str] = []
        for item in content:
            if not isinstance(item, dict):
                continue
            value = item.get("content")
            if value is None:
                value = item.get("text")
            if value is not None:
                parts.append(str(value))
        return "\n".join(parts)
    if isinstance(content, dict):
        value = content.get("content")
        if value is None:
            value = content.get("text")
        if value is None:
            return ""
        return str(value)
    return ""


def extract_prediction(jsonl_path: Path) -> str | None:
    try:
        lines = [
            json.loads(raw_line)
            for raw_line in jsonl_path.read_text(encoding="utf-8").splitlines()
            if raw_line.strip() != ""
        ]
    except Exception:
        return None

    final_message = None
    for entry in reversed(lines):
        if entry.get("role") == "_usage":
            continue
        final_message = entry
        break

    if final_message is None:
        return None
    if final_message.get("role") != "assistant":
        return None
    if final_message.get("agent") not in (None, "main"):
        return None
    if final_message.get("tool_calls"):
        return None

    text = content_to_text(final_message.get("content"))
    matched = ASSESSMENT_TAG_RE.search(text)
    if matched:
        verdict = matched.group(1).upper()
        if verdict == "VULNERABLE":
            return "Vulnerable"
        if verdict == "SECURE":
            return "Benign"

    return None


def collect_results(
    logs_dir: Path,
    model_filter: set[str] | None = None,
    version_filter: set[str] | None = None,
) -> dict[str, dict[str, dict[str, dict[str, int]]]]:
    grouped: dict[str, dict[str, dict[str, dict[str, int]]]] = {}

    if not logs_dir.exists() or not logs_dir.is_dir():
        return grouped

    for project_dir in sorted(path for path in logs_dir.iterdir() if path.is_dir()):
        if not PROJECT_DIR_RE.fullmatch(project_dir.name):
            continue

        project = project_dir.name
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

                    latest_jsonl = latest_file(version_dir, "*.jsonl")
                    if latest_jsonl is None:
                        continue

                    prediction = extract_prediction(latest_jsonl)
                    if prediction is None:
                        score = -1
                    elif task_type == "vul":
                        score = 1 if prediction == "Vulnerable" else 0
                    else:
                        score = 1 if prediction == "Benign" else 0

                    versions = grouped.setdefault(model_dir.name, {})
                    projects = versions.setdefault(version_dir.name, {})
                    project_result = projects.setdefault(
                        project, {"vul": -1, "benign": -1}
                    )
                    if task_type == "vul":
                        project_result["vul"] = score
                    else:
                        project_result["benign"] = score

    return grouped


def format_ratio(numerator: int, denominator: int) -> str:
    if denominator <= 0:
        return "0.00% (0/0)"
    value = numerator / denominator * 100
    return f"{value:.2f}% ({numerator}/{denominator})"


def calculate_metrics(projects: dict[str, dict[str, int]]) -> dict[str, object]:
    tp = fp = tn = fn = 0
    parse_fail_vul = parse_fail_sec = 0
    pair_total = pair_c = pair_b = pair_v = 0

    for result in projects.values():
        vul = result.get("vul", -1)
        benign = result.get("benign", -1)

        if vul == 1:
            tp += 1
        elif vul == 0:
            fn += 1
        else:
            parse_fail_vul += 1
            fn += 1

        if benign == 1:
            tn += 1
        elif benign == 0:
            fp += 1
        else:
            parse_fail_sec += 1
            fp += 1

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
    }

    return {
        "metrics": metrics,
        "confusion_matrix": {"tp": tp, "fp": fp, "tn": tn, "fn": fn},
        "sample_counts": {
            "vul_total": tp + fn,
            "benign_total": tn + fp,
            "pair_total": pair_total,
        },
        "parse_failures": {
            "vul": parse_fail_vul,
            "benign": parse_fail_sec,
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
        description="Compute model metrics from trace JSONL files."
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
    grouped = collect_results(
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
            output_path = model_dir / "match.json"
            output_path.write_text(
                json.dumps(payload, indent=2, ensure_ascii=False),
                encoding="utf-8",
            )
            write_count += 1
            print(f"Wrote {output_path}")
    print(f"Completed: {write_count} version/model outputs")


if __name__ == "__main__":
    main()
