"""Compute the numbers that answer Shayan's three questions.

Reads every logs/<pair>/<vul|sec>/<model>/<condition>/*.rounds.json (latest
run per pair/type/condition) and, if present, the judge's *.assessment.json
files for reasoning accuracy.

Q1 Does feedback improve DETECTION?   recall, FPR, F1, pair-correctness (P-C)
Q2 Does it fix errors without NEW false positives?
                                      per-instance flips vs. DREA round 0:
                                      fixed / broken, new FPs on patched code,
                                      McNemar exact test on fixed vs. broken
Q3 Is it worth the cost?             extra Planner/Explorer tokens and time,
                                      $ (with --price-*), $ per extra correct pair
Reasoning (needs the judge):          Lucky Hit Rate among true positives

Usage (from code/):
  uv run analyze.py --model deepseek-v3.2
  uv run analyze.py --model deepseek-v3.2 --split test --price-main 0.28 --price-explorer 0.28
"""

from __future__ import annotations

import argparse
import csv
import json
from math import comb
from pathlib import Path

from run_batch import DEFAULT_JSONL, load_items, pair_name, split_items

HERE = Path(__file__).resolve().parent
ORDER = ["drea", "self_refine", "explore", "verified", "filter"]


def latest(paths):
    paths = sorted(paths, key=lambda p: p.name)
    return paths[-1] if paths else None


def judge_reasoning(rounds_path: Path) -> str | None:
    """'Accurate' / 'Inaccurate' from DREA's judge, if it was run."""
    a = rounds_path.with_name(rounds_path.name.replace(".rounds.json", ".assessment.json"))
    if not a.exists():
        return None
    data = json.loads(a.read_text(encoding="utf-8"))
    return (data.get("assessment", {}).get("reasoning", {}) or {}).get("assessment")


def mcnemar_p(fixed: int, broken: int) -> float:
    n = fixed + broken
    if n == 0:
        return 1.0
    k = min(fixed, broken)
    p = sum(comb(n, i) for i in range(k + 1)) / 2 ** n
    return min(1.0, 2 * p)


def collect(logs: Path, model: str, allowed_pairs: set[str] | None):
    """rows[(pair, type, condition)] = summary dict (with round-0 verdict)."""
    rows = {}
    for pair_dir in sorted(p for p in logs.iterdir() if p.is_dir() and not p.name.startswith("_")):
        if allowed_pairs is not None and pair_dir.name not in allowed_pairs:
            continue
        for task_type in ("vul", "sec"):
            base = pair_dir / task_type / model
            if not base.is_dir():
                continue
            for cond_dir in base.iterdir():
                f = latest(cond_dir.glob("*.rounds.json"))
                if f is None:
                    continue
                s = json.loads(f.read_text(encoding="utf-8"))
                r0 = s["rounds"][0]
                rows[(pair_dir.name, task_type, cond_dir.name)] = {
                    "initial": r0.get("verdict"),
                    "final": s.get("final_verdict", r0.get("verdict")),
                    "extra_main": s.get("extra_main_tokens", 0),
                    "extra_explorer": s.get("extra_explorer_tokens", 0),
                    "extra_seconds": s.get("extra_seconds", 0),
                    "r0_main": r0.get("main_tokens", 0),
                    "r0_explorer": r0.get("explorer_tokens", 0),
                    "reasoning": judge_reasoning(f),
                    "stop": s.get("stop_reason"),
                }
    return rows


def correct(task_type: str, verdict: str | None) -> bool:
    return verdict == ("VULNERABLE" if task_type == "vul" else "SECURE")


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--model", required=True)
    ap.add_argument("--logs", type=Path, default=HERE / "logs")
    ap.add_argument("--split", choices=["dev", "test", "all"], default="all")
    ap.add_argument("--price-main", type=float, default=0.0, help="$ per 1M Planner tokens")
    ap.add_argument("--price-explorer", type=float, default=0.0, help="$ per 1M Explorer tokens")
    ap.add_argument("--out", type=Path, default=HERE / "results")
    args = ap.parse_args()

    allowed = None
    if args.split != "all":
        allowed = {pair_name(it) for it in split_items(load_items(DEFAULT_JSONL), args.split)}
    rows = collect(args.logs, args.model, allowed)
    if not rows:
        print("No .rounds.json files found for this model.")
        return

    # DREA baseline = round 0 (identical across conditions within a run).
    baseline = {}
    for (pair, t, cond), r in rows.items():
        baseline.setdefault((pair, t), r["initial"])
    conds = [c for c in ORDER if c == "drea" or any(k[2] == c for k in rows)]

    def cost(main_tok, exp_tok):
        return main_tok / 1e6 * args.price_main + exp_tok / 1e6 * args.price_explorer

    args.out.mkdir(parents=True, exist_ok=True)
    table, per_instance = [], []
    base_pc = None
    for cond in conds:
        inst = {}
        for (pair, t), v0 in baseline.items():
            if cond == "drea":
                r = rows.get((pair, t, "drea")) or {"final": v0, "extra_main": 0, "extra_explorer": 0,
                                                    "extra_seconds": 0, "reasoning": None}
                final = v0
            else:
                r = rows.get((pair, t, cond))
                if r is None:
                    continue
                final = r["final"]
            inst[(pair, t)] = (v0, final, r)
            per_instance.append({"condition": cond, "pair": pair, "type": t, "initial": v0,
                                 "final": final, "correct": correct(t, final),
                                 "reasoning": r.get("reasoning"), "stop": r.get("stop")})

        vul = [(k, x) for k, x in inst.items() if k[1] == "vul"]
        sec = [(k, x) for k, x in inst.items() if k[1] == "sec"]
        tp = sum(correct("vul", x[1]) for _, x in vul)
        fp = sum(not correct("sec", x[1]) for _, x in sec)
        recall = tp / len(vul) if vul else 0
        fpr = fp / len(sec) if sec else 0
        prec = tp / (tp + fp) if tp + fp else 0
        f1 = 2 * prec * recall / (prec + recall) if prec + recall else 0
        pairs = {k[0] for k in inst}
        full = [p for p in pairs if (p, "vul") in inst and (p, "sec") in inst]
        pc = sum(correct("vul", inst[(p, "vul")][1]) and correct("sec", inst[(p, "sec")][1]) for p in full)
        if cond == "drea":
            base_pc = pc
        fixed = sum((not correct(k[1], x[0])) and correct(k[1], x[1]) for k, x in inst.items())
        broken = sum(correct(k[1], x[0]) and not correct(k[1], x[1]) for k, x in inst.items())
        new_fp = sum(correct("sec", x[0]) and not correct("sec", x[1]) for _, x in sec)
        judged = [x for _, x in vul if correct("vul", x[1]) and x[2].get("reasoning")]
        lhr = (sum(x[2]["reasoning"] == "Inaccurate" for x in judged) / len(judged)) if judged else None
        n = len(inst)
        extra_main = sum(x[2].get("extra_main", 0) for x in inst.values())
        extra_exp = sum(x[2].get("extra_explorer", 0) for x in inst.values())
        extra_cost = cost(extra_main, extra_exp)
        d_pc = pc - (base_pc or 0)
        table.append({
            "condition": cond, "instances": n, "pairs": len(full),
            "recall": round(recall, 3), "FPR": round(fpr, 3), "F1": round(f1, 3),
            "P-C": f"{pc}/{len(full)}", "fixed": fixed, "broken": broken, "new_FP": new_fp,
            "McNemar_p": round(mcnemar_p(fixed, broken), 4) if cond != "drea" else "",
            "LHR": round(lhr, 3) if lhr is not None else "n/a",
            "extra_main_tok/inst": round(extra_main / n) if n else 0,
            "extra_explorer_tok/inst": round(extra_exp / n) if n else 0,
            "extra_min/inst": round(sum(x[2].get("extra_seconds", 0) for x in inst.values()) / n / 60, 2) if n else 0,
            "extra_$": round(extra_cost, 2),
            "$_per_extra_correct_pair": (round(extra_cost / d_pc, 2) if d_pc > 0 else "n/a") if cond != "drea" else "",
        })

    cols = list(table[0].keys())
    print("| " + " | ".join(cols) + " |")
    print("|" + "---|" * len(cols))
    for row in table:
        print("| " + " | ".join(str(row[c]) for c in cols) + " |")
    with (args.out / f"summary_{args.model}_{args.split}.csv").open("w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=cols)
        w.writeheader()
        w.writerows(table)
    with (args.out / f"instances_{args.model}_{args.split}.csv").open("w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(per_instance[0].keys()))
        w.writeheader()
        w.writerows(per_instance)
    print(f"\nWrote {args.out}/summary_{args.model}_{args.split}.csv and instances_*.csv")
    r0_tok = [(r["r0_main"], r["r0_explorer"]) for (p, t, c), r in rows.items() if c == "drea"]
    if r0_tok:
        m = sum(a for a, _ in r0_tok) / len(r0_tok)
        e = sum(b for _, b in r0_tok) / len(r0_tok)
        print(f"DREA round 0 per instance: {m:,.0f} Planner + {e:,.0f} Explorer tokens "
              f"(${cost(m, e):.3f} at the given prices)")


if __name__ == "__main__":
    main()
