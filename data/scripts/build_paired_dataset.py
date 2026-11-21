from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import tarfile
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


def checkout_tree(repo: Path, commit: str, destination: Path) -> int:
    """Write the files of `commit` into `destination` (no .git folder).

    Uses Python's tarfile instead of the `tar` program so it behaves the same
    on Windows, Mac and Linux. Windows cannot create symlinks without admin
    rights (the `tar` program failed with "Invalid argument" on galaxy), so
    no symlink is ever created, on any OS, so every dataset is identical:
      - a symlink to a FILE in the same commit becomes a copy of that file
        (e.g. galaxy's lib/galaxy/main.py), so the agent can read the code;
      - a symlink to a folder, or to something missing, becomes a small text
        file that says where it pointed.
    Files Windows cannot create (bad characters in the name) are skipped.
    Returns the number of skipped files.
    """
    destination.parent.mkdir(parents=True, exist_ok=True)
    if destination.exists():
        shutil.rmtree(destination)
    destination.mkdir(parents=True, exist_ok=True)
    root = destination.resolve()

    proc = subprocess.Popen(
        ["git", "archive", "--format=tar", commit],
        cwd=repo,
        stdout=subprocess.PIPE,
    )
    skipped: list[str] = []
    links: list[tuple[Path, str]] = []
    with tarfile.open(fileobj=proc.stdout, mode="r|") as archive:
        for member in archive:
            try:
                target = (destination / member.name).resolve()
                if root not in target.parents and target != root:
                    skipped.append(member.name)  # path escapes the folder
                    continue
                if member.isdir():
                    target.mkdir(parents=True, exist_ok=True)
                elif member.issym() or member.islnk():
                    target.parent.mkdir(parents=True, exist_ok=True)
                    target.write_text(
                        f"[symlink in the original repository] -> {member.linkname}\n",
                        encoding="utf-8",
                    )
                    links.append((target, member.linkname))
                elif member.isfile():
                    target.parent.mkdir(parents=True, exist_ok=True)
                    source = archive.extractfile(member)
                    with open(target, "wb") as out:
                        shutil.copyfileobj(source, out)
            except OSError:
                skipped.append(member.name)
    proc.stdout.close()
    if proc.wait() != 0:
        raise RuntimeError(f"git archive failed for {commit}")
    _copy_link_targets(links, root)
    if skipped:
        print(f"  note: skipped {len(skipped)} file(s) this OS cannot create, e.g. {skipped[0]}")
    return len(skipped)


NOTE_PREFIX = b"[symlink in the original repository]"


def _is_note(path: Path) -> bool:
    try:
        with open(path, "rb") as f:
            return f.read(len(NOTE_PREFIX)) == NOTE_PREFIX
    except OSError:
        return False


def _copy_link_targets(links: list[tuple[Path, str]], root: Path) -> None:
    """Replace each symlink note with a copy of the file it pointed to.

    Several passes, so a link to another link also resolves. Links to
    folders, missing paths or paths outside the tree keep their note.
    """
    pending = list(links)
    for _ in range(5):
        still = []
        for note, linkname in pending:
            try:
                source = (note.parent / linkname).resolve()
                inside = root in source.parents
                if inside and source.is_file() and not _is_note(source):
                    shutil.copyfile(source, note)
                elif inside and source.is_file():
                    still.append((note, linkname))  # points at another link
            except OSError:
                pass
        if len(still) == len(pending):
            break
        pending = still


def is_built(pair_root: Path) -> bool:
    """A pair is complete only when both meta files exist (they are written last)."""
    return (pair_root / "vul_meta.json").is_file() and (pair_root / "sec_meta.json").is_file()


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