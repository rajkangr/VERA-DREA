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
5. Robustness (added Nov 18; Nov 21: the answer is the last reply that
   contains the verdict XML, not just the last reply):
     - Missing verdict: if a reply has no parseable <security_assessment>, the
       Planner is re-asked ONCE for just the final XML (no tools). This applies
       to round 0 too, so the DREA baseline gets the same chance; the flag
       `no_verdict_before_reask` records how often it was needed.
     - API/runtime errors: a failed turn is retried ONCE on a fresh thread
       with the same conversation (GraphRecursionError is not retried).
     - Evidence gate (verified only): after the last round, the verifier runs
       on the final answer. A VULNERABLE verdict whose trigger path, evidence
       or vulnerability claims are CONTRADICTED becomes SECURE in
       `gated_verdict`. analyze.py reports it as the extra row "verified+gate",
       so the ungated result is still available.
6. Explorer budget (added Nov 23): every FEEDBACK round (all conditions) may
   spend at most --explorer-budget Explorer tokens (default 500,000). The
   check runs after each Explorer call finishes, so one call can go past it;
   once the budget is used up no new Explorer call starts, and the Planner is
   asked for its final answer without tools (logged as `budget_hit`). This
   makes `explore` and `verified` get the SAME budget, as the proposal says,
   and keeps cost per job predictable. Round 0 (the DREA baseline) is not
   capped, so it stays identical to DREA.

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
    build_format_reask,
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
GATE_FIELDS = FILTER_FIELDS  # evidence gate uses the same claim fields
RETRY_WAIT_SECONDS = int(os.getenv("DREA_RETRY_WAIT", "20"))
BASE_VERSION = "drea"  # round-0 prompts (unchanged DREA)
LOG_DIR = Path("logs")
DEFAULT_EXPLORER_BUDGET = 500_000  # Explorer tokens per feedback round (all conditions)
BUDGET_WRAPUP = (
    "The Explorer budget for this round is used up. Do not call any tools and do "
    "not start a new investigation. Based only on what you have found so far, "
    "give your final assessment now in EXACTLY the XML format from your "
    "instructions, including <revision_status> and <revision_note>."
)
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
    explorer_budget: int | None = None,
    block_tools: bool = False,
) -> dict[str, Any]:
    """Stream one Planner turn. Returns final text, tokens, tool calls, timing.

    explorer_budget: stop the turn (before any new Explorer call) once this
        turn's Explorer tokens reach it; `budget_hit` is set.
    block_tools: stop the turn as soon as the Planner tries to call the
        Explorer (used for the no-tools wrap-up after the budget is used up).
    """
    tracker = MessageTracker()
    start_index = len(trace_data)
    started = time.time()
    final_text = ""
    verdict_text = ""  # last reply that contains the verdict XML
    error = None
    task_calls = 0
    budget_hit = False
    blocked_call = False

    def explorer_tokens_so_far() -> int:
        return sum(e.get("token_count", 0) for e in trace_data[start_index:]
                   if e.get("role") == "_usage" and e.get("agent") not in (None, "main"))

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
                        if "<security_assessment>" in text:
                            verdict_text = text
                    for tool_call in get_tool_calls(last_message):
                        if tool_call.get("name") == "task":
                            if block_tools:
                                blocked_call = True
                                continue
                            task_calls += 1
                            subagent_trace.set_parent_tool_call_id(
                                tool_call.get("id") or tool_call.get("tool_call_id")
                            )
            if blocked_call:
                break  # leave the stream before the blocked Explorer call runs
            if explorer_budget is not None and explorer_tokens_so_far() >= explorer_budget:
                budget_hit = True
                break  # no new Explorer call starts after the budget is used
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
    # DeepSeek often writes the full XML report in a message that also calls
    # a tool (e.g. write_todos), then ends with a short plain-text summary.
    # The report is the answer, so use the last message that contains the
    # verdict XML; fall back to the last message (found Nov 21 in the
    # apkleaks round-0 trace: every "missing verdict" was this case).
    return {
        "final_text": verdict_text or final_text,
        "main_tokens": main_tokens,
        "explorer_tokens": sub_tokens,
        "explore_calls": task_calls,
        "seconds": round(time.time() - started, 2),
        "error": error,
        "budget_hit": budget_hit,
    }


def _merge_cost(into: dict, extra: dict) -> None:
    for key in ("main_tokens", "explorer_tokens", "explore_calls", "seconds"):
        into[key] = round(into.get(key, 0) + extra.get(key, 0), 2)


def run_turn(
    agent,
    subagent_trace,
    first_messages: list,
    retry_prior: list,
    new_message,
    thread_id: str,
    trace_data: list[dict[str, Any]],
    jsonl_path: Path,
    recursion_limit: int,
    feedback_round: bool,
    explorer_budget: int | None = None,
) -> tuple[dict[str, Any], str]:
    """One Planner turn, plus at most one retry and at most one format re-ask.

    first_messages: what to send on `thread_id` before `new_message` (the
        round-0 history for the first feedback round, else nothing because the
        thread already holds it).
    retry_prior: the full conversation before this turn, used to rebuild a
        fresh thread if the first attempt errors.
    Returns (run, thread_id_used). Tokens and time of every attempt are summed
    into `run`, so cost numbers include retries and re-asks.
    explorer_budget: cap on Explorer tokens for this turn (None = no cap; round
        0 is never capped). When it is used up, the Planner gets one no-tools
        wrap-up message asking for its final answer.
    """
    run = run_round(agent, subagent_trace,
                    {"messages": list(first_messages) + [new_message]},
                    thread_id, trace_data, jsonl_path, recursion_limit,
                    explorer_budget=explorer_budget)
    run.update(retried=False, first_error=None, reasked=False,
               no_verdict_before_reask=False, reask_error=None)
    used_thread = thread_id

    if run["error"] and not run["error"].startswith("GraphRecursionError"):
        first = run
        print(f"  ! {first['error'][:200]}  -> retrying once in {RETRY_WAIT_SECONDS}s")
        time.sleep(RETRY_WAIT_SECONDS)
        used_thread = f"{thread_id}-retry"
        run = run_round(agent, subagent_trace,
                        {"messages": list(retry_prior) + [new_message]},
                        used_thread, trace_data, jsonl_path, recursion_limit,
                        explorer_budget=explorer_budget)
        _merge_cost(run, first)
        run.update(retried=True, first_error=first["error"], reasked=False,
                   no_verdict_before_reask=False, reask_error=None)

    budget_hit = bool(run.get("budget_hit"))
    if budget_hit and not run["error"]:
        log_user(BUDGET_WRAPUP, trace_data, jsonl_path)
        wrap = run_round(agent, subagent_trace,
                         {"messages": [HumanMessage(content=BUDGET_WRAPUP)]},
                         used_thread, trace_data, jsonl_path, recursion_limit,
                         block_tools=True)
        _merge_cost(run, wrap)
        if parse_assessment(wrap["final_text"]).verdict is not None:
            run["final_text"] = wrap["final_text"]
        print(f"  $ explorer budget used up ({run['explorer_tokens']:,} tokens); "
              f"asked for the final answer -> {parse_assessment(run['final_text']).verdict}")
    run["budget_hit"] = budget_hit

    if not run["error"] and parse_assessment(run["final_text"]).verdict is None:
        run["no_verdict_before_reask"] = True
        reask = build_format_reask(feedback_round)
        log_user(reask, trace_data, jsonl_path)
        fix = run_round(agent, subagent_trace,
                        {"messages": [HumanMessage(content=reask)]},
                        used_thread, trace_data, jsonl_path, recursion_limit,
                        block_tools=True)
        _merge_cost(run, fix)
        run["reasked"] = True
        run["reask_error"] = fix["error"]
        if fix["final_text"]:
            run["final_text"] = fix["final_text"]
        print(f"  ~ no verdict; re-asked -> {parse_assessment(run['final_text']).verdict}")
    return run, used_thread


def history_of(agent, thread_id: str) -> list:
    return list(agent.get_state({"configurable": {"thread_id": thread_id}}).values.get("messages", []))


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
        "retried": run.get("retried", False),
        "first_error": run.get("first_error"),
        "reasked": run.get("reasked", False),
        "no_verdict_before_reask": run.get("no_verdict_before_reask", False),
        "reask_error": run.get("reask_error"),
        "budget_hit": run.get("budget_hit", False),
        "final_text": run["final_text"],
    }


def evidence_gate(parsed, workspace, target_code, verify_fn) -> dict:
    """Evidence gate v1 (verified condition, after the last round).

    A VULNERABLE verdict stands only if none of its trigger-path, evidence or
    vulnerability claims is CONTRADICTED by the code. Otherwise the gated
    verdict is SECURE. UNRESOLVED claims do not trigger the gate (yet): the
    placeholder verifier marks many claims UNRESOLVED, and gating on them
    would throw away true positives. Tighten once Raj's verifier is merged.
    """
    audit = verify_fn(parsed, workspace, target_code)
    bad = [c for c in audit.checks
           if c.status == "CONTRADICTED" and c.field.startswith(GATE_FIELDS)]
    blocked = parsed.verdict == "VULNERABLE" and bool(bad)
    return {
        "gated_verdict": "SECURE" if blocked else parsed.verdict,
        "blocked": blocked,
        "reasons": [f"[{c.claim_id}] {c.field}: {c.finding}" for c in bad],
        "audit": audit.to_dict(),
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
    explorer_budget: int | None = DEFAULT_EXPLORER_BUDGET,
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
    r0, r0_thread = run_turn(agent, subagent_trace, [], [], HumanMessage(content=prompt),
                             f"{ts}-r0", trace_data, r0_jsonl, recursion_limit,
                             feedback_round=False)
    r0_info = round_summary(0, r0, None)
    r0_summary_path.write_text(json.dumps(
        {"project": project_name, "type": task_type, "model": model_id,
         "condition": "drea", "rounds": [r0_info]}, indent=2), encoding="utf-8")
    print(f"[round 0] verdict={r0_info['verdict']} tokens={r0['main_tokens']}+{r0['explorer_tokens']}")
    outputs = {"drea": r0_jsonl}
    if r0["error"] or not conditions:
        return outputs

    history = history_of(agent, r0_thread)

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
            prior = list(history) if k == 1 else history_of(agent, thread)
            run, thread = run_turn(agent, subagent_trace,
                                   prior if k == 1 else [], prior, new_msg, thread,
                                   trace_data, jsonl, recursion_limit,
                                   feedback_round=True, explorer_budget=explorer_budget)
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
        gate = None
        if cond == "verified":
            gate = evidence_gate(parse_assessment(last_text), workspace, target_code, verify_fn)
        summary = {
            "project": project_name, "type": task_type, "model": model_id,
            "condition": cond, "max_rounds": max_rounds, "stop_reason": stop_reason,
            "initial_verdict": r0_info["verdict"],
            "final_verdict": parse_assessment(last_text).verdict,
            "rounds_used": len(done) - 1,
            "extra_main_tokens": sum(r["main_tokens"] for r in done[1:]),
            "extra_explorer_tokens": sum(r["explorer_tokens"] for r in done[1:]),
            "extra_seconds": round(sum(r["seconds"] for r in done[1:]), 2),
            "errors": [r["error"] for r in done[1:] if r.get("error")],
            "retried_rounds": sum(bool(r.get("retried")) for r in done[1:]),
            "reasked_rounds": sum(bool(r.get("reasked")) for r in done[1:]),
            "explorer_budget": explorer_budget,
            "budget_hit_rounds": sum(bool(r.get("budget_hit")) for r in done[1:]),
            "rounds": rounds,
        }
        if gate is not None:
            summary["gated_verdict"] = gate["gated_verdict"]
            summary["gate"] = gate
        summary_path.write_text(json.dumps(summary, indent=2), encoding="utf-8")
        gate_note = f", gate -> {gate['gated_verdict']}" if gate else ""
        print(f"[{cond}] {summary['initial_verdict']} -> {summary['final_verdict']} "
              f"({stop_reason}{gate_note}) -> {jsonl}")
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
    parser.add_argument("--explorer-budget", type=int, default=DEFAULT_EXPLORER_BUDGET,
                        help="Max Explorer tokens per feedback round, same for every "
                             "condition (0 = no cap). Round 0 is never capped.")
    args = parser.parse_args()

    conds = [] if args.conditions.strip().lower() == "none" else [
        c.strip() for c in args.conditions.split(",") if c.strip()]
    bad = [c for c in conds if c not in CONDITIONS]
    if bad:
        parser.error(f"Unknown condition(s): {bad}. Choose from {CONDITIONS} or 'none'.")

    run_project(args.project_name, args.type, args.model, conds, args.max_rounds,
                args.dataset_dir, args.recursion_limit,
                explorer_budget=args.explorer_budget or None)


if __name__ == "__main__":
    main()