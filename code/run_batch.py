"""Run feedback_loop.py over many RepoPairBench pairs (both vul and sec).

- Fixed dev/test split: 20 dev pairs (for tuning prompts and the verifier) and
  80 test pairs (final numbers only). The split is a hash of the item id, so
  everyone gets the same split.
- --build clones missing repositories (blobless, fast) and builds the pairs.
- Skips any (pair, type) whose logs already exist for the requested conditions,
  so a crashed or interrupted batch can simply be re-run.
- --workers runs several pairs in parallel (each in its own process).

Examples (run from the code/ folder):
  uv run run_batch.py --split dev --limit 2 --build --model deepseek-v3.2 --conditions none
  uv run run_batch.py --split dev --build --model deepseek-v3.2 --workers 4
  uv run run_batch.py --split test --model deepseek-v3.2 --workers 6
"""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
DEFAULT_JSONL = ROOT / "data" / "repopairbench_100.jsonl"
DEV_SIZE = 20


def load_items(jsonl: Path) -> list[dict]:
    return [json.loads(l) for l in jsonl.read_text(encoding="utf-8").splitlines() if l.strip()]


def split_items(items: list[dict], split: str) -> list[dict]:
    ordered = sorted(items, key=lambda it: hashlib.sha1(it["id"].encode()).hexdigest())
    if split == "dev":
        return ordered[:DEV_SIZE]
    if split == "test":
        return ordered[DEV_SIZE:]
    return ordered


def pair_name(item: dict) -> str:
    return f"{item['project_name']}_{item['id']}"


def ensure_built(item: dict, repos: Path, dataset: Path) -> None:
    if (dataset / pair_name(item)).is_dir():
        return
    owner, name = item["repo_url"].rstrip("/").split("/")[-2:]
    repo_dir = repos / owner / name
    if not repo_dir.exists():
        repo_dir.parent.mkdir(parents=True, exist_ok=True)
        print(f"cloning {item['repo_url']} ...")
        subprocess.run(["git", "clone", "-q", "--filter=blob:none", item["repo_url"],
                        str(repo_dir)], check=True)
    spec = importlib.util.spec_from_file_location(
        "build_paired_dataset", ROOT / "data" / "scripts" / "build_paired_dataset.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    module.write_pair(item, repos, dataset)
    print(f"built {pair_name(item)}")


def already_done(pair: str, task_type: str, model: str, conditions: list[str]) -> bool:
    base = HERE / "logs" / pair / task_type / model
    labels = ["drea"] + conditions
    return all(any((base / label).glob("*.rounds.json")) for label in labels)


def run_one(pair: str, task_type: str, args, conditions: list[str]) -> tuple[str, int, float]:
    cmd = [sys.executable, str(HERE / "feedback_loop.py"), pair, "--type", task_type,
           "--model", args.model, "--max-rounds", str(args.max_rounds),
           "--dataset-dir", str(args.dataset_dir),
           "--conditions", ",".join(conditions) if conditions else "none"]
    log_dir = HERE / "logs" / "_batch"
    log_dir.mkdir(parents=True, exist_ok=True)
    started = time.time()
    with (log_dir / f"{pair}_{task_type}.out").open("w", encoding="utf-8") as out:
        code = subprocess.run(cmd, cwd=HERE, stdout=out, stderr=subprocess.STDOUT).returncode
    return f"{pair}/{task_type}", code, time.time() - started


def main() -> None:
    p = argparse.ArgumentParser(description="Batch runner for VERA-DREA experiments")
    p.add_argument("--model", required=True)
    p.add_argument("--split", choices=["dev", "test", "all"], default="dev")
    p.add_argument("--ids", default="", help="Comma list of item ids (overrides --split)")
    p.add_argument("--limit", type=int, default=0, help="Only the first N pairs")
    p.add_argument("--types", default="vul,sec")
    p.add_argument("--conditions", default="self_refine,explore,verified,filter")
    p.add_argument("--max-rounds", type=int, default=2)
    p.add_argument("--workers", type=int, default=2)
    p.add_argument("--build", action="store_true", help="Clone and build missing pairs")
    p.add_argument("--jsonl", type=Path, default=DEFAULT_JSONL)
    p.add_argument("--repos", type=Path, default=ROOT / "repos")
    p.add_argument("--dataset-dir", type=Path, default=ROOT / "dataset")
    p.add_argument("--dry-run", action="store_true")
    args = p.parse_args()

    conditions = [] if args.conditions.strip().lower() == "none" else [
        c.strip() for c in args.conditions.split(",") if c.strip()]
    items = load_items(args.jsonl)
    if args.ids:
        wanted = {i.strip() for i in args.ids.split(",")}
        items = [it for it in items if it["id"] in wanted]
    else:
        items = split_items(items, args.split)
    if args.limit:
        items = items[: args.limit]

    if args.build:
        for item in items:
            ensure_built(item, args.repos, args.dataset_dir)

    jobs = []
    for item in items:
        for t in [t.strip() for t in args.types.split(",") if t.strip()]:
            if already_done(pair_name(item), t, args.model, conditions):
                print(f"skip (done): {pair_name(item)}/{t}")
                continue
            if not (args.dataset_dir / pair_name(item)).is_dir():
                print(f"skip (not built, use --build): {pair_name(item)}")
                continue
            jobs.append((pair_name(item), t))

    print(f"{len(jobs)} job(s) to run with {args.workers} worker(s)")
    if args.dry_run:
        for j in jobs:
            print("  ", *j)
        return
    failures = 0
    with ThreadPoolExecutor(max_workers=args.workers) as pool:
        futures = [pool.submit(run_one, pair, t, args, conditions) for pair, t in jobs]
        for fut in as_completed(futures):
            name, code, secs = fut.result()
            failures += code != 0
            print(f"{'OK  ' if code == 0 else 'FAIL'} {name} ({secs/60:.1f} min)"
                  + ("" if code == 0 else "  -> see logs/_batch/"))
    print(f"done: {len(jobs) - failures} ok, {failures} failed")


if __name__ == "__main__":
    main()
