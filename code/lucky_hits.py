"""Lucky-hit rate on VERA-DREA results.

A lucky hit = the model correctly says VULNERABLE on the vulnerable version,
but with the wrong CWE or the wrong root-cause function.
LHR (per condition) = lucky hits / true positives.

Usage (from code/):
    uv run lucky_hits.py                       # all results/instances_*.csv
    uv run lucky_hits.py --split dev
    uv run lucky_hits.py --csv results/instances_deepseek-v3.2_dev.csv

Column names are auto-detected and printed; override with --id-col,
--version-col, --verdict-col, --cond-col if the guesses are wrong.
Writes results/lucky_hits_<tag>.csv (per instance) and
results/lucky_hits_summary_<tag>.csv (per condition).
"""

import argparse
import csv
import glob
import json
import os
import re
import sys
from collections import defaultdict

HERE = os.path.dirname(os.path.abspath(__file__))
DEFAULT_LABELS = os.path.join(HERE, "..", "data", "repopairbench_100.jsonl")


# ---------- helpers ----------

def pick(cols, candidates, override=None, required=True):
    if override:
        if override not in cols:
            sys.exit(f"column '{override}' not in CSV: {cols}")
        return override
    low = {c.lower(): c for c in cols}
    for cand in candidates:
        if cand in low:
            return low[cand]
    if required:
        sys.exit(f"could not find any of {candidates} in CSV columns: {cols}")
    return None


def cwe_set(value):
    """'CWE-79', ['CWE-79','CWE-89'], 'CWE-79;CWE-89', 79 -> {'79', '89'}"""
    if value is None:
        return set()
    if isinstance(value, (list, tuple, set)):
        out = set()
        for v in value:
            out |= cwe_set(v)
        return out
    return set(re.findall(r"\d+", str(value)))


def norm_func(name):
    """'pkg/mod.py:Class.method()' -> 'method'"""
    if not name:
        return ""
    s = str(name).strip().strip("`'\"")
    s = re.sub(r"\(.*\)$", "", s)          # drop (args)
    s = re.split(r"[.:/\\#]+", s)[-1]      # last segment
    return s.strip().lower()


def funcs_in(obj):
    """Collect function names from vuln_data, whatever its shape."""
    out = set()
    if isinstance(obj, dict):
        for k, v in obj.items():
            kl = k.lower()
            if isinstance(v, str) and kl in ("code_before", "code_after"):
                # RepoPairBench stores the vulnerable function's source; take its name
                m = re.search(r"^\s*(?:async\s+)?def\s+(\w+)", v, re.M)
                if m:
                    out.add(m.group(1).lower())
            elif isinstance(v, str) and ("func" in kl or "method" in kl):
                out.add(norm_func(v))
            elif isinstance(v, list) and ("func" in kl or "method" in kl) \
                    and all(isinstance(x, str) for x in v):
                out |= {norm_func(x) for x in v}
            else:
                out |= funcs_in(v)
    elif isinstance(obj, list):
        for v in obj:
            out |= funcs_in(v)
    out.discard("")
    return out


# words the pipeline's extractor sometimes grabs instead of a function name
NOT_FUNCS = {"and", "or", "the", "a", "an", "in", "of", "to", "line", "lines",
             "function", "method", "none", "null", "n/a", "na", "unknown"}


def pred_funcs(value):
    """pred_function may hold several names: 'a, b' / 'a;b' / JSON list.
    Blank or non-identifier values ('lines', 'and') give an empty set."""
    if not value:
        return set()
    s = str(value).strip()
    names = None
    if s.startswith("["):
        try:
            names = {norm_func(x) for x in json.loads(s)}
        except json.JSONDecodeError:
            pass
    if names is None:
        names = {norm_func(x) for x in re.split(r"[,;|\s]+", s)}
    return {n for n in names if re.fullmatch(r"[a-z_]\w*", n) and n not in NOT_FUNCS}


def is_vulnerable_verdict(value):
    s = str(value).strip().lower()
    return s in {"vulnerable", "vul", "1", "true", "yes", "positive"}


def is_vul_version(value):
    s = str(value).strip().lower()
    return s in {"vul", "vulnerable", "1", "true", "pre", "before"}


# ---------- main ----------

def load_labels(path):
    labels = {}
    with open(path, encoding="utf-8") as f:
        for line in f:
            if not line.strip():
                continue
            rec = json.loads(line)
            rid = str(rec.get("id") or rec.get("pair_id") or rec.get("instance_id"))
            labels[rid] = {
                "cwes": cwe_set(rec.get("cwe_ids")),
                "funcs": funcs_in(rec.get("vuln_data")),
            }
    return labels


def find_label(labels, pid):
    pid = str(pid)
    if pid in labels:
        return labels[pid]
    # CSV uses '<repo>_<hash>'; labels may use the hash, '<repo>_<hash>', or a longer hash
    keys = {pid, pid.rsplit("_", 1)[-1]}
    hits = {k for k in labels for c in keys
            if k == c or k.startswith(c) or c.startswith(k) or k.endswith("_" + c)}
    return labels[hits.pop()] if len(hits) == 1 else None


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--csv", nargs="*", help="instances CSV(s); default results/instances_*.csv")
    ap.add_argument("--split", help="only CSVs whose name contains this (e.g. dev, test)")
    ap.add_argument("--labels", default=DEFAULT_LABELS)
    ap.add_argument("--id-col"); ap.add_argument("--version-col")
    ap.add_argument("--verdict-col"); ap.add_argument("--cond-col")
    args = ap.parse_args()

    paths = args.csv or sorted(glob.glob(os.path.join(HERE, "results", "instances_*.csv")))
    if args.split:
        paths = [p for p in paths if args.split in os.path.basename(p)]
    if not paths:
        sys.exit("no instances_*.csv found (run from code/, or pass --csv)")

    labels = load_labels(args.labels)
    n_lab_funcs = sum(1 for v in labels.values() if v["funcs"])
    print(f"labels: {len(labels)} pairs, {n_lab_funcs} with root-cause functions")

    for path in paths:
        with open(path, newline="", encoding="utf-8") as f:
            rows = list(csv.DictReader(f))
        if not rows:
            continue
        cols = list(rows[0].keys())
        c_id = pick(cols, ["pair_id", "id", "pair", "instance_id"], args.id_col)
        c_ver = pick(cols, ["type", "version", "side", "variant", "label", "gt"], args.version_col)
        c_verd = pick(cols, ["final", "pred_verdict", "verdict", "pred", "prediction", "pred_label"], args.verdict_col)
        c_corr = pick(cols, ["correct"], required=False)
        c_cond = pick(cols, ["condition", "cond", "method"], args.cond_col)
        c_cwe = pick(cols, ["pred_cwe"])
        c_fn = pick(cols, ["pred_function", "pred_func"])
        print(f"\n{os.path.basename(path)}: id={c_id} version={c_ver} "
              f"verdict={c_verd} condition={c_cond}")

        out_rows, summary = [], defaultdict(lambda: defaultdict(int))
        missing = set()
        for r in rows:
            detected = (str(r[c_corr]).strip().lower() in {"1", "true", "yes"}) if c_corr \
                else is_vulnerable_verdict(r[c_verd])
            if not (is_vul_version(r[c_ver]) and detected):
                continue                      # only true positives can be lucky hits
            lab = find_label(labels, r[c_id])
            if lab is None:
                missing.add(r[c_id]); continue
            pc, pf = cwe_set(r[c_cwe]), pred_funcs(r[c_fn])
            cwe_ok = bool(pc & lab["cwes"])
            if not lab["funcs"]:
                fn_status = "no_label"
            elif not pf:
                fn_status = "not_given"      # blank/garbled pred_function: can't judge
            else:
                fn_status = "ok" if pf & lab["funcs"] else "wrong"
            lucky = (not cwe_ok) or fn_status == "wrong"      # strict
            s = summary[r[c_cond]]
            s["tp"] += 1
            s["lucky"] += lucky
            s["wrong_cwe"] += not cwe_ok
            s["wrong_func"] += fn_status == "wrong"
            s["no_pred_func"] += fn_status == "not_given"
            s["no_func_label"] += fn_status == "no_label"
            out_rows.append({"pair_id": r[c_id], "condition": r[c_cond],
                             "pred_cwe": r[c_cwe], "gt_cwe": ";".join(sorted(lab["cwes"])),
                             "pred_function": r[c_fn], "gt_functions": ";".join(sorted(lab["funcs"])),
                             "cwe_ok": cwe_ok, "func_status": fn_status, "lucky_hit": lucky})

        if missing:
            print(f"  WARNING: {len(missing)} pair ids not in labels: {sorted(missing)[:5]}")

        tag = os.path.basename(path)[len("instances_"):-len(".csv")]
        res = os.path.join(os.path.dirname(path))
        with open(os.path.join(res, f"lucky_hits_{tag}.csv"), "w", newline="") as f:
            if out_rows:
                w = csv.DictWriter(f, fieldnames=list(out_rows[0])); w.writeheader(); w.writerows(out_rows)

        hdr = ["condition", "true_positives", "lucky_hits", "lucky_hit_rate",
               "lhr_cwe_only", "wrong_cwe", "wrong_function", "no_pred_function", "no_function_label"]
        short = ["condition", "TP", "lucky", "LHR", "LHR_cwe", "badCWE", "badFn", "noPredFn", "noFnLbl"]
        print("  " + f"{short[0]:<15}" + "".join(f"{h:>9}" for h in short[1:]))
        with open(os.path.join(res, f"lucky_hits_summary_{tag}.csv"), "w", newline="") as f:
            w = csv.writer(f)
            w.writerow(hdr)
            for cond, s in sorted(summary.items()):
                tp = s["tp"]
                row = [cond, tp, s["lucky"], round(s["lucky"] / tp, 2) if tp else 0.0,
                       round(s["wrong_cwe"] / tp, 2) if tp else 0.0,
                       s["wrong_cwe"], s["wrong_func"], s["no_pred_func"], s["no_func_label"]]
                w.writerow(row)
                print("  " + f"{row[0]:<15}" + "".join(f"{v:>9}" for v in row[1:]))
        print("  LHR = wrong CWE or wrong function (strict). noPredFn = no usable "
              "pred_function (blank/garbled), not counted as lucky.")


if __name__ == "__main__":
    main()
