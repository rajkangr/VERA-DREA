"""Smoke test: run feedback_loop end to end with FAKE models (no API keys, $0).

It builds a tiny fake repository with a path-traversal bug, scripts the
Planner's answers, and checks that every condition runs, logs, and stops for
the right reason. It also checks (added Nov 18): the format re-ask when a reply
has no verdict, one retry after an API error, the verdict parser, the
evidence gate, and that run_batch skips finished pairs. Run:

    uv run smoke_test.py
"""

from __future__ import annotations

import itertools
import json
import shutil
import tempfile
from pathlib import Path

from langchain_core.language_models.fake_chat_models import GenericFakeChatModel
from langchain_core.messages import AIMessage

import core.agent_builder as agent_builder
import feedback_loop


class FakeToolModel(GenericFakeChatModel):
    """Fake chat model that accepts bind_tools (agents call it)."""

    def bind_tools(self, tools, **kwargs):  # noqa: D401
        return self


class Script:
    """Iterator over scripted replies; an Exception item is raised once
    (simulates an API failure) and the script then continues."""

    def __init__(self, items):
        self.items = list(items)

    def __iter__(self):
        return self

    def __next__(self):
        if not self.items:
            raise StopIteration
        item = self.items.pop(0)
        if isinstance(item, Exception):
            raise item
        return item


def xml_vuln(evidence_line: str, status: str | None = None) -> str:
    tail = ""
    if status:
        tail = (f"\n<revision_status>{status}</revision_status>"
                f"\n<revision_note>test note</revision_note>")
    return f"""<security_assessment>VULNERABLE</security_assessment>
<vulnerability>
  <type>CWE-22 Path Traversal</type>
  <location>app/files.py: download()</location>
  <root_cause>User-supplied path is joined to the base directory without normalization.</root_cause>
</vulnerability>
<trigger_path>
  <source>`name` query parameter of download()</source>
  <propagation>download() passes name to build_path()</propagation>
  <sink>open(build_path(name)) reads arbitrary files</sink>
</trigger_path>
<evidence>
```python
{evidence_line}
```
</evidence>{tail}"""


def explore_call(call_id: str) -> AIMessage:
    return AIMessage(content="", tool_calls=[{
        "name": "task", "id": call_id,
        "args": {"description": "Find build_path and its callers", "subagent_type": "explore"},
    }])


def main() -> None:
    tmp = Path(tempfile.mkdtemp(prefix="drea_smoke_"))
    pair = tmp / "dataset" / "demo_deadbeef"
    snap = pair / "aaaaaaaaaaaa"
    (snap / "app").mkdir(parents=True)
    code = (
        "import os\n\nBASE = '/srv/files'\n\n"
        "def build_path(name):\n    return os.path.join(BASE, name)\n\n"
        "def download(name):\n    with open(build_path(name)) as f:\n        return f.read()\n"
    )
    (snap / "app" / "files.py").write_text(code)
    (pair / "vul").write_text(code)
    (pair / "vul_meta.json").write_text(json.dumps({
        "id": "deadbeef", "file_name": "app/files.py", "language": "python",
        "tree_commit": "aaaaaaaaaaaa" + "0" * 28, "cwe_ids": ["CWE-22"]}))

    real = "    with open(build_path(name)) as f:"
    fake = "    data = open(BASE + name).read()"  # NOT in the repo -> verifier flags it
    planner_script = [
        # round 0: explore once, then reply WITHOUT the XML verdict -> the loop
        # re-asks once, and the Planner answers with a fabricated quote
        explore_call("c0"), AIMessage(content="I think download() is vulnerable."),
        AIMessage(content=xml_vuln(fake)),
        # self_refine: r1 revises, r2 confirms
        AIMessage(content=xml_vuln(fake, "REVISED")),
        AIMessage(content=xml_vuln(fake, "CONFIRMED")),
        # explore: the first call fails (API error) -> retried once on a fresh
        # thread; then explores and confirms
        RuntimeError("simulated 502 from the API"),
        explore_call("c1"), AIMessage(content=xml_vuln(fake, "CONFIRMED")),
        # verified: r1 explores and fixes the quote; r2 should be skipped (clean)
        explore_call("c2"), AIMessage(content=xml_vuln(real, "REVISED")),
    ]
    main_llm = FakeToolModel(messages=Script(planner_script))
    sub_llm = FakeToolModel(messages=itertools.cycle(
        [AIMessage(content="build_path is defined in /app/files.py and calls os.path.join(BASE, name) with no checks.")]))
    agent_builder.build_models = lambda main_model_id=None, skip_sub=False: (main_llm, sub_llm)

    feedback_loop.LOG_DIR = tmp / "logs"
    feedback_loop.RETRY_WAIT_SECONDS = 0
    outputs = feedback_loop.run_project(
        "demo_deadbeef", "vul", "fake-model",
        ["self_refine", "explore", "verified", "filter"], max_rounds=2,
        dataset_dir=tmp / "dataset", recursion_limit=50,
    )

    expected = {"self_refine": "model_confirmed", "explore": "model_confirmed", "verified": "verifier_clean", "filter": "discarded"}
    ok = True
    for cond, stop in expected.items():
        summary = json.loads(outputs[cond].with_suffix("").with_suffix(".rounds.json").read_text())
        want = "SECURE" if cond == "filter" else "VULNERABLE"  # filter discards the flawed report
        good = summary["stop_reason"] == stop and summary["final_verdict"] == want
        ok &= good
        print(f"{'PASS' if good else 'FAIL'} {cond}: stop={summary['stop_reason']} rounds_used={summary['rounds_used']}")
    verified = json.loads(outputs["verified"].with_suffix("").with_suffix(".rounds.json").read_text())
    flagged = verified["rounds"][1]["audit_before_round"]["counts"]["CONTRADICTED"]
    print(f"{'PASS' if flagged == 1 else 'FAIL'} verifier flagged the fabricated quote ({flagged} contradicted)")
    ok &= flagged == 1
    # Round 0 had no verdict -> re-asked once, and the re-ask produced one.
    r0 = verified["rounds"][0]
    good = r0["no_verdict_before_reask"] and r0["reasked"] and r0["verdict"] == "VULNERABLE"
    print(f"{'PASS' if good else 'FAIL'} round 0 missing verdict -> re-asked -> {r0['verdict']}")
    ok &= bool(good)
    # The explore round hit an API error and was retried once.
    explore = json.loads(outputs["explore"].with_suffix("").with_suffix(".rounds.json").read_text())
    good = explore["retried_rounds"] == 1 and explore["stop_reason"] == "model_confirmed"
    print(f"{'PASS' if good else 'FAIL'} API error in explore r1 -> retried once -> {explore['stop_reason']}")
    ok &= good
    # Evidence gate: clean verified answer passes; a contradicted one is blocked.
    good = verified.get("gated_verdict") == "VULNERABLE" and not verified["gate"]["blocked"]
    from core.verdict import normalize_verdict, parse_assessment
    gate = feedback_loop.evidence_gate(parse_assessment(xml_vuln(fake)), snap, code,
                                       feedback_loop.verifier_module.verify)
    good &= gate["blocked"] and gate["gated_verdict"] == "SECURE"
    print(f"{'PASS' if good else 'FAIL'} evidence gate keeps the clean answer, blocks the fabricated one")
    ok &= bool(good)
    # Verdict parser edge cases.
    cases = {"VULNERABLE": "VULNERABLE", "NOT VULNERABLE": "SECURE", "INSECURE": "VULNERABLE",
             "**SECURE**": "SECURE", "VULNERABLE or SECURE": None, "": None}
    good = all(normalize_verdict(k) == v for k, v in cases.items())
    print(f"{'PASS' if good else 'FAIL'} verdict parser (NOT VULNERABLE -> SECURE, etc.)")
    ok &= good
    # SRR fields from the final answer.
    srr = parse_assessment(xml_vuln(real)).srr()
    good = srr["cwe"] == "CWE-22" and srr["root_cause_function"] == "download"
    print(f"{'PASS' if good else 'FAIL'} SRR fields: cwe={srr['cwe']} function={srr['root_cause_function']}")
    ok &= good
    # run_batch: this pair/type is complete and error-free -> skipped.
    import run_batch
    run_batch.HERE = tmp
    good = run_batch.already_done("demo_deadbeef", "vul", "fake-model",
                                  ["self_refine", "explore", "verified", "filter"])
    print(f"{'PASS' if good else 'FAIL'} run_batch skips a finished, error-free pair")
    ok &= good
    import subprocess, sys
    res = subprocess.run([sys.executable, "analyze.py", "--model", "fake-model",
                          "--logs", str(tmp / "logs"), "--out", str(tmp / "results")],
                         capture_output=True, text=True)
    table_ok = (res.returncode == 0 and "| verified |" in res.stdout and "| filter |" in res.stdout
                and "| verified+gate |" in res.stdout and "no_verdict_r0" in res.stdout)
    print(f"{'PASS' if table_ok else 'FAIL'} analyze.py produced the results table")
    if not table_ok:
        print(res.stdout, res.stderr)
    ok &= table_ok
    print("\nALL PASS" if ok else "\nSOME CHECKS FAILED")
    shutil.rmtree(tmp, ignore_errors=True)


if __name__ == "__main__":
    main()