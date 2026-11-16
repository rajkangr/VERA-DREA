from __future__ import annotations

import argparse
import json
import shutil
import subprocess
from pathlib import Path
from typing import Any


def repo_path(repo_url: str, repos_root: Path) -> Path:
    parts = repo_url.rstrip("/").split("/")
    if len(parts) < 2:
        raise ValueError(f"Invalid repo_url: {repo_url}")
    return repos_root / parts[-2] / parts[-1]


def git_text(repo: Path, args: list[str]) -> str:
    result = subprocess.run(
        ["git", *args],
        cwd=repo,
        check=True,
        capture_output=True,
        text=True,
    )
    return result.stdout.strip()


def checkout_tree(repo: Path, commit: str, destination: Path) -> None:
    destination.parent.mkdir(parents=True, exist_ok=True)
    if destination.exists():
        shutil.rmtree(destination)
    archive = subprocess.run(
        ["git", "archive", "--format=tar", commit],
        cwd=repo,
        check=True,
        stdout=subprocess.PIPE,
    )
    destination.mkdir(parents=True, exist_ok=True)
    extract = subprocess.run(
        ["tar", "-xf", "-", "-C", str(destination)],
        input=archive.stdout,
        check=True,
    )
    if extract.returncode != 0:
        raise RuntimeError(f"Failed to extract archive for {commit}")


def project_dir_name(item: dict[str, Any]) -> str:
    return f"{item['project_name']}_{item['id']}"


def write_pair(item: dict[str, Any], repos_root: Path, output_root: Path) -> None:
    repo = repo_path(item["repo_url"], repos_root)
    if not repo.exists():
        raise FileNotFoundError(f"Repository not found: {repo}")

    fixed_commit = git_text(repo, ["rev-parse", item["commit_hash"]])
    vulnerable_commit = git_text(repo, ["rev-parse", f"{item['commit_hash']}^"])

    pair_name = project_dir_name(item)
    pair_root = output_root / pair_name
    vul_tree_name = vulnerable_commit[:12]
    sec_tree_name = fixed_commit[:12]

    checkout_tree(repo, vulnerable_commit, pair_root / vul_tree_name)
    checkout_tree(repo, fixed_commit, pair_root / sec_tree_name)

    vuln_data = item["vuln_data"]
    common_meta = {
        "id": item["id"],
        "project_name": item["project_name"],
        "repo_url": item["repo_url"],
        "commit_hash": item["commit_hash"],
        "language": item.get("language"),
        "cve_ids": item.get("cve_ids", []),
        "cwe_ids": item.get("cwe_ids", []),
        "file_name": vuln_data["file_path"],
    }

    (pair_root / "vul").write_text(vuln_data["code_before"], encoding="utf-8")
    (pair_root / "sec").write_text(vuln_data["code_after"], encoding="utf-8")
    (pair_root / "vul_meta.json").write_text(
        json.dumps({**common_meta, "tree_commit": vulnerable_commit}, indent=2),
        encoding="utf-8",
    )
    (pair_root / "sec_meta.json").write_text(
        json.dumps({**common_meta, "tree_commit": fixed_commit}, indent=2),
        encoding="utf-8",
    )


def iter_jsonl(path: Path):
    with path.open("r", encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, start=1):
            line = line.strip()
            if not line:
                continue
            try:
                yield json.loads(line)
            except json.JSONDecodeError as exc:
                raise ValueError(f"Invalid JSON on line {line_number}") from exc


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Build the paired dataset layout consumed by code/main.py"
    )
    parser.add_argument("--jsonl", type=Path, required=True)
    parser.add_argument("--repos", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument(
        "--item-id",
        action="append",
        default=None,
        help="Optional item id to build. May be passed multiple times.",
    )
    args = parser.parse_args()

    selected = set(args.item_id or [])
    count = 0
    for item in iter_jsonl(args.jsonl):
        if selected and item["id"] not in selected:
            continue
        try:
            write_pair(item, args.repos, args.output)
        except Exception as exc:
            raise SystemExit(
                f"Failed to build {project_dir_name(item)}: {exc}"
            ) from exc
        count += 1
        print(f"built {project_dir_name(item)}")

    print(f"Built {count} paired dataset item(s) under {args.output}")


if __name__ == "__main__":
    main()
