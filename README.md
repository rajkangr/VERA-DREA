# VERA-DREA

Large Language Models (LLMs) frequently suffer from **"Lucky Hits"** in repository-level vulnerability detection: they flag a repository as vulnerable (`True Positive`), but fabricate the execution path or blame the wrong function/CWE.

**VERA-DREA** combines two recent frameworks into a closed self-correction loop:
1. **DREA (Decoupled Reasoning and Exploration Agents):** Separates a high-capability **Planner** agent (which formulates vulnerability hypotheses) from a lightweight **Explorer** agent (which retrieves function definitions and call-graph context across files).
2. **VERA (Vulnerability Explanation Reasoning Auditor):** Represents the Planner's explanation as a JSON **Structured Reasoning Record (SRR)** and audits each claim against the retrieved source code.
3. **Our Novel Contribution (Closed-Loop Evidence Feedback):** Instead of treating VERA as a post-hoc filter, **VERA-DREA** translates audit failures (`UNVERIFIED_ASSUMPTION`, `UNINSPECTED_CALLEE`, `HALLUCINATED_SYMBOL`, and LLM-detected contradictions) into targeted Explorer queries, retrieves the missing source code, and forces the Planner to revise or reject its initial vulnerability hypothesis.

---

## 3. Repository Structure

```text
vera_drea_mvp/
├── setup_benchmark.py       # Generates 4 multi-file Python vuln/fix pairs (8 repos)
├── vera_drea_mvp.py         # Main pipeline: AST Explorer, Planner, VERA Auditor & Evaluator
├── benchmark_data/          # Auto-generated multi-file repositories + manifest.json
│   ├── pair_01_sqli/        # CWE-89: Interprocedural SQLi with fake whitespace sanitizer
│   ├── pair_02_cmdi_lucky_hit/ # CWE-78: Decoy path check masking OS Command Injection
│   ├── pair_03_path_traversal_fp/ # CWE-22: Interprocedural Path Traversal & FP test
│   └── pair_04_ssrf/        # CWE-918: Webhook SSRF with incomplete localhost check
├── evaluation_results.json  # Full JSON logs of SRRs, audit findings, and metrics
├── README.md                # Project documentation and setup guide
└── context.md               # Complete project context for LLM handoffs
```

---

## 4. How the Code Works (`vera_drea_mvp.py`)

1. **`ASTRepoExplorer`:** Uses Python's `ast` module to parse every `.py` file in a target repository, indexing function definitions, line ranges, and interprocedural function calls (`callees`).
2. **`DREAPlanner`:** Given the entry-point file (`app.py`), outputs a machine-readable JSON **Structured Reasoning Record (SRR)**:
   - `verdict`: `"VULNERABLE"` or `"SAFE"`
   - `cwe`: e.g., `"CWE-89"`, `"CWE-78"`, `"CWE-22"`, `"CWE-918"`, or `"NONE"`
   - `root_cause_function`: The specific function containing the vulnerability sink/flaw
   - `claims`: List of specific behavioral claims about functions
   - `assumptions`: Explicit assumptions made about helper functions not yet inspected
3. **`VERAAuditor`:** Audits the initial SRR using three deterministic checks (`UNVERIFIED_ASSUMPTION`, `HALLUCINATED_SYMBOL` / `UNGROUNDED_CLAIM`, `UNINSPECTED_CALLEE`) plus an LLM consistency audit. It compiles a deduplicated list of `targeted_requests` for the `ASTRepoExplorer`.
4. **Evaluation Harness:** Runs every vulnerable/patched repository pair through three modes:
   - **`Baseline DREA`**: Initial Planner + bounded context.
   - **`Self-Refine`**: Unguided self-reflection without retrieving new code.
   - **`VERA-DREA`**: Verification-guided code retrieval + hypothesis revision.

---

## 5. Evaluation Metrics Tracked

- **Classification Accuracy:** Percentage of individual repositories (`vuln` and `patched`) correctly classified.
- **Pair-Correctness:** Strict metric requiring the detector to classify the `vuln` version as `VULNERABLE` **and** the `patched` version as `SAFE` for the same CVE/pair.
- **False Positive Rate (FPR):** Rate at which `patched` repositories are mistakenly flagged as `VULNERABLE`.
- **Lucky Hit Rate:** Percentage of True Positive predictions on `vuln` repositories that cite the wrong CWE or wrong `root_cause_function`.
- **Self-Correction Transitions:** Tracks `Predictions Corrected` (wrong $\rightarrow$ right) vs. `Predictions Regressed` (right $\rightarrow$ wrong) after feedback.
- **Computational Overhead:** Total model calls, token usage, and wall-clock latency.
