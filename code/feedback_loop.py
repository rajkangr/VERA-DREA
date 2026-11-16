"""VERA-DREA feedback loop: run DREA once, then K feedback rounds per condition.

How it works
------------
1. Round 0 is plain DREA (same prompts as main.py). Its log is written under
   prompt_version "drea", so it doubles as the DREA baseline.
2. For each condition (self_refine, explore, verified), we copy the round-0
   conversation into a NEW thread and send that condition's follow-up message.
   All conditions therefore start from the identical first analysis (paired
   comparison, and round 0 is paid for only once).
3. Up to K rounds per condition. A condition stops early when:
     - verified: the verifier finds no CONTRADICTED/UNRESOLVED claims, or
     - any condition: the Planner reports <revision_status>CONFIRMED.
4. Each condition gets its own JSONL log (full trace, so DREA's evaluator and
   judge score the FINAL answer) plus a <ts>.rounds.json summary with the
   verdict, revision status, audit, tokens and time for every round.

Usage
-----
  uv run feedback_loop.py gradio_00c73b6e --type vul --model deepseek-v3.2 \
      --conditions self_refine,explore,verified,filter --max-rounds 2

  (filter = verify-then-discard baseline: no feedback, no extra LLM calls)

  # DREA baseline only (with the workspace-path fix):
  uv run feedback_loop.py gradio_00c73b6e --type vul --model deepseek-v3.2 --conditions none
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import time
from datetime import datetime
from pathlib import Path
from typing import Any

from langchain_core.messages import HumanMessage
from langgraph.errors import GraphRecursionError

from core.agent_builder import build_agent
from core.prompts import get_prompt_set
from core.prompts.feedback import (
    build_explore_more,
    build_self_refine,
    build_verified,
)
from core.trace import (
    MessageTracker,
    extract_usage_entry,
    get_tool_calls,
    message_to_jsonl_entry,
    record_trace_entry,
    stringify_content,
)
from core.verdict import parse_assessment
from core import verifier as verifier_module

CONDITIONS = ("self_refine", "explore", "verified", "filter")
# filter = RepoAudit/VERA-style "verify then discard": run the verifier once on
# the round-0 answer and drop a VULNERABLE verdict if any trigger-path or
# evidence claim is CONTRADICTED. No feedback, no extra LLM calls. It answers
# "is correcting better than simply discarding?"
FILTER_FIELDS = ("trigger_path/", "evidence", "vulnerability/")
BASE_VERSION = "drea"  # round-0 prompts (unchanged DREA)
LOG_DIR = Path("logs")
DATASET_BASE_DIR = Path(os.getenv("DREA_DATASET_DIR", "../dataset"))


# ---------------------------------------------------------------------------
# Dataset helpers
# ---------------------------------------------------------------------------
def normalize_language_tag(language: str | None) -> str:
    if not language:
        return "python"
    aliases = {"py": "python", "c++": "cpp", "js": "javascript", "ts": "typescript"}
    lang = language.strip().lower()
    return aliases.get(lang, lang)


def resolve_workspace(pair_dir: Path, task_type: str, meta: dict) -> Path:
    """Repository snapshot for this task.

    build_paired_dataset.py names snapshots by commit[:12], but main.py looks
    for project_name.split("_")[1] (the item id), which does not exist. We use
    the commit stored in the meta file instead.
    """
    commit = (meta.get("tree_commit") or "")[:12]
    if commit and (pair_dir / commit).is_dir():
        return pair_dir / commit
    # Fallback: original main.py behavior, then any single snapshot dir.
    name = pair_dir.name
    legacy = pair_dir / (name.split("_")[1] if task_type == "vul" else name.split("_")[-1])
    if legacy.is_dir():
        return legacy
    raise FileNotFoundError(
        f"No repository snapshot for {task_type} in {pair_dir} "
        f"(looked for {commit or '?'} and {legacy.name}). Rebuild the dataset."
    )


# ---------------------------------------------------------------------------
# One streamed round (same logic as core.runner.repl, made reusable)
# ---------------------------------------------------------------------------
def run_round(
    agent,
    subagent_trace,
    agent_input: dict,
    thread_id: str,
    trace_data: list[dict[str, Any]],
    jsonl_path: Path,
    recursion_limit: int,
) -> dict[str, Any]:
    """Stream one Planner turn. Returns final text, tokens, tool calls, timing."""
    tracker = MessageTracker()
    start_index = len(trace_data)
    started = time.time()
    final_text = ""
    error = None
    task_calls = 0

    try:
        for chunk in agent.stream(
            agent_input,
            stream_mode="updates",
            config={
                "recursion_limit": recursion_limit,
                "configurable": {"thread_id": thread_id},
            },
        ):
            if not isinstance(chunk, dict):
                continue
            for step, data in chunk.items():
                if not isinstance(data, dict):
                    continue
                messages = data.get("messages") or []
                last_message = messages[-1] if messages else None

                for message in tracker.extract_new_messages(messages):
                    entry = message_to_jsonl_entry(message)
                    if entry and entry.get("role") != "user":
                        if entry.get("role") == "assistant" and "agent" not in entry:
                            entry["agent"] = "main"
                        record_trace_entry(entry, trace_data, jsonl_path)
                    usage = extract_usage_entry(message)
                    if usage:
                        record_trace_entry(usage, trace_data, jsonl_path)

                if step in {"agent", "model"}:
                    content = getattr(last_message, "content", None)
                    if isinstance(last_message, dict):
                        content = last_message.get("content")
                    text = stringify_content(content)
                    if text:
                        final_text = text
                    for tool_call in get_tool_calls(last_message):
                        if tool_call.get("name") == "task":
                            task_calls += 1
                            subagent_trace.set_parent_tool_call_id(
                                tool_call.get("id") or tool_call.get("tool_call_id")
                            )
    except GraphRecursionError as exc:
        error = f"GraphRecursionError: {exc}"
    except Exception as exc:  # keep going with other conditions
        error = f"{type(exc).__name__}: {exc}"
    if error:
        record_trace_entry(
            {"role": "system", "content": [{"type": "text", "content": error}],
             "timestamp": datetime.now().isoformat(timespec="microseconds")},
            trace_data, jsonl_path,
        )

    new_entries = trace_data[start_index:]
    main_tokens = sum(e.get("token_count", 0) for e in new_entries
                      if e.get("role") == "_usage" and e.get("agent") in (None, "main"))
    sub_tokens = sum(e.get("token_count", 0) for e in new_entries
                     if e.get("role") == "_usage" and e.get("agent") not in (None, "main"))
    return {
        "final_text": final_text,
        "main_tokens": main_tokens,
        "explorer_tokens": sub_tokens,
        "explore_calls": task_calls,
        "seconds": round(time.time() - started, 2),
        "error": error,
    }


def log_user(text: str, trace_data: list, jsonl_path: Path) -> None:
    record_trace_entry(
        {"role": "user", "content": [{"type": "text", "content": text}],
         "timestamp": datetime.now().isoformat(timespec="microseconds")},
        trace_data, jsonl_path,
    )


def round_summary(idx: int, run: dict, message: str | None, audit=None) -> dict:
    parsed = parse_assessment(run["final_text"])
    return {
        "round": idx,
        "verdict": parsed.verdict,
        "revision_status": parsed.revision_status,
        "revision_note": parsed.revision_note,
        "parsed": parsed.to_dict(),
        "audit_before_round": audit.to_dict() if audit is not None else None,
        "feedback_message": message,
        "main_tokens": run["main_tokens"],
        "explorer_tokens": run["explorer_tokens"],
        "explore_calls": run["explore_calls"],
        "seconds": run["seconds"],
        "error": run["error"],
        "final_text": run["final_text"],
    }


def run_filter(r0, r0_info, workspace, target_code, verify_fn, jsonl, summary_path,
               project_name, task_type, model_id, trace_data) -> Path:
    """Verify-then-discard baseline (no feedback, no extra LLM calls)."""
    started = time.time()
    parsed = parse_assessment(r0["final_text"])
    audit = verify_fn(parsed, workspace, target_code)
    bad = [c for c in audit.checks
           if c.status == "CONTRADICTED" and c.field.startswith(FILTER_FIELDS)]
    discard = parsed.verdict == "VULNERABLE" and bool(bad)
    if discard:
        reasons = "; ".join(f"[{c.claim_id}] {c.field}: {c.finding}" for c in bad)
        final_text = (
            "<security_assessment>SECURE</security_assessment>\n"
            "<security_analysis>\n<checked_operations>The VULNERABLE report was "
            "discarded by the verifier because its reasoning is contradicted by the "
            f"code: {reasons}</checked_operations>\n<validation_evidence>None; "
            "verdict produced by verify-then-discard filtering.</validation_evidence>\n"
            "</security_analysis>\n<revision_status>REVERSED</revision_status>"
        )
        record_trace_entry(
            {"role": "assistant", "agent": "main",
             "content": [{"type": "text", "content": final_text}],
             "timestamp": datetime.now().isoformat(timespec="microseconds")},
            trace_data, jsonl,
        )
    else:
        final_text = r0["final_text"]
    summary = {
        "project": project_name, "type": task_type, "model": model_id,
        "condition": "filter", "max_rounds": 0,
        "stop_reason": "discarded" if discard else "kept",
        "initial_verdict": r0_info["verdict"],
        "final_verdict": parse_assessment(final_text).verdict,
        "rounds_used": 0, "extra_main_tokens": 0, "extra_explorer_tokens": 0,
        "extra_seconds": round(time.time() - started, 2),
        "rounds": [r0_info, {"round": 1, "filter": True,
                             "audit_before_round": audit.to_dict(),
                             "final_text": final_text}],
    }
    summary_path.write_text(json.dumps(summary, indent=2), encoding="utf-8")
    print(f"[filter] {summary['initial_verdict']} -> {summary['final_verdict']} "
          f"({summary['stop_reason']}) -> {jsonl}")
    return jsonl


# ---------------------------------------------------------------------------
# Main experiment
# ---------------------------------------------------------------------------
def run_project(
    project_name: str,
    task_type: str,
    model_id: str,
    conditions: list[str],
    max_rounds: int,
    dataset_dir: Path,
    recursion_limit: int,
    verify_fn=None,
) -> dict[str, Path]:
    verify_fn = verify_fn or verifier_module.verify
    pair_dir = dataset_dir / project_name
    meta = json.loads((pair_dir / f"{task_type}_meta.json").read_text(encoding="utf-8"))
    target_code = (pair_dir / task_type).read_text(encoding="utf-8")
    workspace = resolve_workspace(pair_dir, task_type, meta)

    prompt = get_prompt_set(BASE_VERSION).user.format(
        file_path=meta["file_name"],
        code=target_code,
        language=normalize_language_tag(meta.get("language")),
    )

    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    log_base = LOG_DIR / project_name / task_type / model_id

    def paths(label: str) -> tuple[Path, Path]:
        d = log_base / label
        d.mkdir(parents=True, exist_ok=True)
        return d / f"{ts}.jsonl", d / f"{ts}.rounds.json"

    trace_data: list[dict[str, Any]] = []
    r0_jsonl, r0_summary_path = paths(BASE_VERSION)
    agent, subagent_trace = build_agent(
        workspace, trace_data, r0_jsonl, MessageTracker(),
        main_model_id=model_id, prompt_version=BASE_VERSION,
    )

    print(f"[{project_name}/{task_type}] workspace: {workspace}")
    print(f"[round 0] DREA -> {r0_jsonl}")
    log_user(prompt, trace_data, r0_jsonl)
    r0_thread = f"{ts}-r0"
    r0 = run_round(agent, subagent_trace, {"messages": [{"role": "user", "content": prompt}]},
                   r0_thread, trace_data, r0_jsonl, recursion_limit)
    r0_info = round_summary(0, r0, None)
    r0_summary_path.write_text(json.dumps(
        {"project": project_name, "type": task_type, "model": model_id,
         "condition": "drea", "rounds": [r0_info]}, indent=2), encoding="utf-8")
    print(f"[round 0] verdict={r0_info['verdict']} tokens={r0['main_tokens']}+{r0['explorer_tokens']}")
    outputs = {"drea": r0_jsonl}
    if r0["error"] or not conditions:
        return outputs

    history = agent.get_state({"configurable": {"thread_id": r0_thread}}).values["messages"]

    for cond in conditions:
        jsonl, summary_path = paths(cond)
        shutil.copyfile(r0_jsonl, jsonl)  # full trace = round 0 + feedback rounds
        if cond == "filter":
            outputs[cond] = run_filter(r0, r0_info, workspace, target_code, verify_fn,
                                       jsonl, summary_path, project_name, task_type,
                                       model_id, trace_data)
            continue
        subagent_trace._jsonl_path = jsonl  # redirect explorer logging
        thread = f"{ts}-{cond}"
        last_text = r0["final_text"]
        rounds = [r0_info]
        stop_reason = "max_rounds"

        for k in range(1, max_rounds + 1):
            parsed = parse_assessment(last_text)
            audit = None
            if cond == "verified":
                audit = verify_fn(parsed, workspace, target_code)
                if not audit.needs_attention():
                    stop_reason = "verifier_clean"
                    rounds.append({"round": k, "skipped": True, "audit_before_round": audit.to_dict()})
                    break
                message = build_verified(k, max_rounds, audit)
            elif cond == "self_refine":
                message = build_self_refine(k, max_rounds)
            elif cond == "explore":
                message = build_explore_more(k, max_rounds)
            else:
                raise ValueError(f"Unknown condition: {cond}")

            log_user(message, trace_data, jsonl)
            new_msg = HumanMessage(content=message)
            agent_input = {"messages": (list(history) + [new_msg]) if k == 1 else [new_msg]}
            run = run_round(agent, subagent_trace, agent_input, thread,
                            trace_data, jsonl, recursion_limit)
            info = round_summary(k, run, message, audit)
            rounds.append(info)
            print(f"[{cond} r{k}] verdict={info['verdict']} status={info['revision_status']} "
                  f"explore_calls={run['explore_calls']} tokens={run['main_tokens']}+{run['explorer_tokens']}")
            if run["error"]:
                stop_reason = "error"
                break
            if run["final_text"]:
                last_text = run["final_text"]
            if info["revision_status"] == "CONFIRMED":
                stop_reason = "model_confirmed"
                break

        done = [r for r in rounds if not r.get("skipped")]
        summary = {
            "project": project_name, "type": task_type, "model": model_id,
            "condition": cond, "max_rounds": max_rounds, "stop_reason": stop_reason,
            "initial_verdict": r0_info["verdict"],
            "final_verdict": parse_assessment(last_text).verdict,
            "rounds_used": len(done) - 1,
            "extra_main_tokens": sum(r["main_tokens"] for r in done[1:]),
            "extra_explorer_tokens": sum(r["explorer_tokens"] for r in done[1:]),
            "extra_seconds": round(sum(r["seconds"] for r in done[1:]), 2),
            "rounds": rounds,
        }
        summary_path.write_text(json.dumps(summary, indent=2), encoding="utf-8")
        print(f"[{cond}] {summary['initial_verdict']} -> {summary['final_verdict']} "
              f"({stop_reason}) -> {jsonl}")
        outputs[cond] = jsonl
    return outputs


def main() -> None:
    parser = argparse.ArgumentParser(description="DREA + feedback rounds (VERA-DREA experiments)")
    parser.add_argument("project_name", help="Pair directory name, e.g. gradio_00c73b6e")
    parser.add_argument("--model", required=True, help="Planner model id from config/models.json")
    parser.add_argument("--type", default="vul", choices=["vul", "sec"])
    parser.add_argument("--conditions", default="self_refine,explore,verified,filter",
                        help="Comma list of self_refine,explore,verified,filter, or 'none' for DREA only")
    parser.add_argument("--max-rounds", type=int, default=2)
    parser.add_argument("--dataset-dir", type=Path, default=DATASET_BASE_DIR)
    parser.add_argument("--recursion-limit", type=int, default=200)
    args = parser.parse_args()

    conds = [] if args.conditions.strip().lower() == "none" else [
        c.strip() for c in args.conditions.split(",") if c.strip()]
    bad = [c for c in conds if c not in CONDITIONS]
    if bad:
        parser.error(f"Unknown condition(s): {bad}. Choose from {CONDITIONS} or 'none'.")

    run_project(args.project_name, args.type, args.model, conds, args.max_rounds,
                args.dataset_dir, args.recursion_limit)


if __name__ == "__main__":
    main()
