"""Re-check saved answers with the CURRENT verifier, for free (no API calls).

Raj's verifier is plain code (no LLM), so we can run it again on the answers
already saved in code/logs and see what `filter` and `verified+gate` WOULD
have decided with it. Use this to tune the verifier on the dev pairs before
spending money on new runs.

For every pair/type (the same run analyze.py reads) it:
  - runs the verifier on DREA's round-0 answer  -> new `filter` verdict
  - runs the evidence gate on the final `verified` answer -> new `verified+gate`
  - checks whether `verified` would start a feedback round on the round-0
    answer with the current rule (tuning fix #3: a SECURE answer only gets one
    if a claim is CONTRADICTED)
  - counts the verifier's findings by status and failure type

Usage (from code/):
  uv run reverify.py --split dev --dataset-dir C:\\vera-data\\dataset

Prints a before/after table and writes results/reverify_<model>_<split>.csv
with one row per pair/type (to see exactly which pairs changed).
"""

from __future__ import annotations

import argparse
import csv
import json
from collections import Counter
from pathlib import Path

from core import verifier as verifier_module
from core.verdict import parse_assessment
from feedback_loop import FILTER_FIELDS, GATE_FIELDS, needs_feedback, resolve_workspace
from run_batch import DEFAULT_JSONL, load_items, pair_name, pick_run, split_items

HERE = Path(__file__).resolve().parent


def correct(task_type: str, verdict: str | None) -> bool:
    return verdict == ("VULNERABLE" if task_type == "vul" else "SECURE")


def answer_text(summary: dict) -> str:
    """Last round's text that has a verdict (the condition's final answer)."""
    for r in reversed(summary.get("rounds", [])):
        text = r.get("final_text") or ""
        if parse_assessment(text).verdict is not None:
            return text
    return ""


def discard(parsed, audit, fields) -> bool:
    return parsed.verdict == "VULNERABLE" and any(
        c.status == "CONTRADICTED" and c.field.startswith(fields) for c in audit.checks)


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--model", default="deepseek-v3.2")
    ap.add_argument("--split", choices=["dev", "test", "all", "any"], default="dev",
                    help="any = every pair folder in --logs (used by the smoke test)")
    ap.add_argument("--logs", type=Path, default=HERE / "logs")
    ap.add_argument("--dataset-dir", type=Path, default=HERE.parent / "dataset")
    ap.add_argument("--out", type=Path, default=HERE / "results")
    args = ap.parse_args()

    allowed = None if args.split == "any" else {
        pair_name(it) for it in split_items(load_items(DEFAULT_JSONL), args.split)}
    rows, statuses, failures = [], Counter(), Counter()
    for pair_dir in sorted(p for p in args.logs.iterdir() if p.is_dir() and not p.name.startswith("_")
                           and (allowed is None or p.name in allowed)):
        for task_type in ("vul", "sec"):
            _, files = pick_run(pair_dir / task_type / args.model)
            if "drea" not in files or "verified" not in files:
                continue
            data_dir = args.dataset_dir / pair_dir.name
            meta = json.loads((data_dir / f"{task_type}_meta.json").read_text(encoding="utf-8"))
            target = (data_dir / task_type).read_text(encoding="utf-8")
            workspace = resolve_workspace(data_dir, task_type, meta)

            drea = json.loads(files["drea"].read_text(encoding="utf-8"))
            ver = json.loads(files["verified"].read_text(encoding="utf-8"))
            old_filter = None
            if "filter" in files:
                old_filter = json.loads(files["filter"].read_text(encoding="utf-8")).get("final_verdict")

            r0 = parse_assessment(answer_text(drea))
            audit0 = verifier_module.verify(r0, workspace, target)
            new_filter = "SECURE" if discard(r0, audit0, FILTER_FIELDS) else r0.verdict
            ver_rounds = ver.get("rounds", [])
            feedback_old = len(ver_rounds) > 1 and not ver_rounds[1].get("skipped")
            feedback_new = needs_feedback(r0, audit0)

            fin = parse_assessment(answer_text(ver))
            audit1 = verifier_module.verify(fin, workspace, target)
            new_gate = "SECURE" if discard(fin, audit1, GATE_FIELDS) else fin.verdict

            for audit in (audit0, audit1):
                for c in audit.checks:
                    statuses[c.status] += 1
                    if c.status in ("CONTRADICTED", "UNRESOLVED") and c.failure_type:
                        failures[c.failure_type] += 1
            rows.append({
                "pair": pair_dir.name, "type": task_type,
                "drea": r0.verdict, "verified": fin.verdict,
                "filter_old": old_filter, "filter_new": new_filter,
                "gate_old": ver.get("gated_verdict"), "gate_new": new_gate,
                "feedback_old": feedback_old, "feedback_new": feedback_new,
                "contradicted_r0": sum(c.status == "CONTRADICTED" for c in audit0.checks),
                "contradicted_final": sum(c.status == "CONTRADICTED" for c in audit1.checks),
                "findings_final": "; ".join(f"[{c.status}] {c.field}: {c.finding}"[:200]
                                            for c in audit1.checks
                                            if c.status in ("CONTRADICTED", "UNRESOLVED")),
            })

    if not rows:
        print("No runs found. Check --logs and --dataset-dir.")
        return

    pairs = sorted({r["pair"] for r in rows})

    def score(col: str) -> tuple[int, int, int]:
        right = sum(correct(r["type"], r[col]) for r in rows)
        pc = sum(all(correct(r["type"], r[col]) for r in rows if r["pair"] == p
                     and r[col] is not None) and
                 len([r for r in rows if r["pair"] == p]) == 2 for p in pairs)
        broken = sum(correct(r["type"], r["drea"]) and not correct(r["type"], r[col]) for r in rows)
        return right, pc, broken

    print(f"{len(rows)} instances, {len(pairs)} pairs (re-checked with the current verifier)\n")
    print("| answer | correct | P-C | broken vs DREA |")
    print("|---|---|---|---|")
    for label, col in [("drea (round 0)", "drea"), ("verified (no gate)", "verified"),
                       ("filter, old verifier", "filter_old"), ("filter, NEW verifier", "filter_new"),
                       ("verified+gate, old verifier", "gate_old"),
                       ("verified+gate, NEW verifier", "gate_new")]:
        right, pc, broken = score(col)
        print(f"| {label} | {right}/{len(rows)} | {pc}/{len(pairs)} | {broken} |")

    secure_r0 = [r for r in rows if r["drea"] == "SECURE"]
    for label, col in [("old run", "feedback_old"), ("current rule", "feedback_new")]:
        n = sum(bool(r[col]) for r in secure_r0)
        no_contra = sum(bool(r[col]) and r["contradicted_r0"] == 0 for r in secure_r0)
        print(f"\nverified, SECURE round-0 answers ({len(secure_r0)}): {n} get a feedback round "
              f"({label}); {no_contra} of them without a CONTRADICTED claim", end="")
    print()
    print("\nVerifier findings (round 0 + final answers):", dict(statuses))
    print("Most common failure types:")
    for name, n in failures.most_common(8):
        print(f"  {n:3d}  {name}")

    out = args.out / f"reverify_{args.model}_{args.split}.csv"
    out.parent.mkdir(exist_ok=True)
    with out.open("w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0]))
        w.writeheader()
        w.writerows(rows)
    print(f"\nWrote {out} (one row per pair/type; see which pairs changed)")


if __name__ == "__main__":
    main()
