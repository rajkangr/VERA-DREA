# VERA-DREA (ECE 371H Honors Project)

Evidence-guided self-correction for repository-level vulnerability detection.

Team: Saksham Verma, Renan Solak, Tamanna Chandak, Raj Kangriwala.
Final deadline: **Mon Dec 14, 11:59 PM** (we submit by 8 PM).

Built on DREA (Sun & Meng, 2026, https://github.com/huhusmang/DREA); DREA's
original README is in `DREA_README.md`. DREA's license is not finalized
(see `LICENSE`), so keep this repository **private**.

## Research questions (from Shayan)
1. Does verification feedback improve actual **detection**, not just explanations?
2. Can it fix flawed reasoning **without new false positives**?
3. Are the gains **worth the extra compute/inference cost**?

## Conditions compared (all start from the same DREA round 0)
| Condition | What it is | Answers |
|---|---|---|
| `drea` | DREA as published (round 0) | baseline |
| `self_refine` | Self-Refine: critique + refine, no new evidence | is new evidence needed? |
| `explore` | more exploration, model picks what to check | is it just more compute? |
| `verified` | **ours**: claim-level audit + targeted Explorer requests | the method |
| `verified+gate` | ours + evidence gate (VULNERABLE needs uncontradicted evidence) | does the gate cut false positives? |
| `filter` | verify-then-discard (RepoAudit/VERA style), no feedback | is correcting better than discarding? |

## Models and OpenRouter
We run every model through **OpenRouter** (openrouter.ai): one account gives us
both models, we pay only per token, and nobody needs a GPU (a local 3B model was
too slow and too weak for repos this size). Same model choices as the DREA paper:

| Role | Model | `--model` id | Price (per 1M input tokens) |
|---|---|---|---|
| Planner + Explorer | DeepSeek V3.2 (`deepseek/deepseek-v3.2`) | `deepseek-v3.2` | about $0.26, much less with caching (we see ~90% cache hits) |
| Judge (reasoning accuracy) | GPT-4.1 (`openai/gpt-4.1`) | `gpt-4.1-judge` | about $2 |
| Backup judge (same model) | GPT-4.1 on Saksham's Azure for Students credit | `gpt-4.1-azure` | free (from the $100 student credit) |

OpenRouter stays our main provider. The Azure judge is only a way to save the
$10-15 judge cost if Microsoft approves GPT-4.1 quota on Saksham's student
account (requested Sun Nov 22). Check any model with
`uv run check_model.py <model id>` (costs a fraction of a cent).

**One shared account (Saksham's).** We keep using Saksham's OpenRouter account
and his existing key, so there is one balance and one place to see the spending.
Nobody else needs to sign up:
1. **Raj, Renan and Tamanna, by Tue Nov 24:** send Saksham your share, about
   **$28** each, so he can add it as credit. Saksham has already put in $25
   for the setup and dev runs, so everyone pays about the same. (Saksham asked
   Shayan on Sun Nov 22 whether the course can cover this; if it does, shares
   go down or get refunded.)
2. **Saksham, by Tue Nov 24 (evening):** keep using his own key for his runs. In
   OpenRouter, **Keys**, then **Create Key**, once per teammate (name it after
   them). **Credit limit:** 18 each (Saksham runs the judge). Each key can only spend its own limit, and the Activity
   page shows each person's spending. Send each key **privately (DM)**, never in
   the server channel.
3. **Everyone:** put your key in `code/.env` in BOTH `OPENROUTER_API_KEY` and
   `VLLM_API_KEY` (see `.env.example`). Never commit `.env` or paste the key anywhere.

**Budget (measured Nov 16-21):** about **$0.70 per job** on average (one job =
one pair version, with DREA round 0 plus all follow-up conditions); big repos
(Galaxy, Transformers, TensorFlow) cost $1-2.

| Part | Jobs | Cost | Who pays |
|---|---|---|---|
| Dev runs (11 pairs) | 22 | about $20 | Saksham's $25 (done Sun Nov 22) |
| Test runs, 80 pairs, with the explorer budget cap | 160 | about $70 | the shared pool: about $18 per person's 20 pairs |
| Judge (GPT-4.1) on all final answers | about 1,000 calls | about $10-15 | Saksham's Azure credit if approved, else the shared pool; run by Saksham |
| **Total** | | **about $90-105** | **about $23-28 per person** |

If the team can't cover 80 test pairs, we run 40 (about $35) and say so in the report.

## Status (Sun Nov 22)
- Pipeline runs end to end on real RepoPairBench pairs (`saksham-pipeline`).
- Fixed: verdict parsing (the answer is the message with the XML report, not
  the trailing summary; same fix in the judge), missing-verdict re-ask, API
  retry, Windows dataset build (symlinks), first evidence gate.
  Smoke test: 14 checks, ALL PASS.
- Dev results: 4 pairs complete; 7 more run on Sun Nov 22 (11 dev pairs in total,
  to save money for the test runs).
- Waiting on: Raj's verifier (`raj-verifier` branch is not pushed yet).
- Cost: about $0.70 per job (big repos $1-2). We hit the first $8 limit.
- Tamanna is away from Wed Nov 25 until Tue Dec 1; her tasks are scheduled around that.

## Who does what (with deadlines)
Everyone owns one part of the code, runs **20 of the 80 test pairs** on their
own laptop with their own key on the shared OpenRouter account, and writes one
report section.

### Raj: verifier
- [ ] **Tue Nov 24:** push branch `raj-verifier` (made from `saksham-pipeline`) with the
      MVP checks ported into `code/core/verifier.py`. Use `check_from_code()` so each
      finding has a failure code, a status and an Explorer request. General checks only,
      nothing written for one specific pair. `uv run smoke_test.py` must print ALL PASS.
- [ ] **Tue Nov 24:** send Saksham your $28 share.
- [ ] **Wed Nov 25:** put the key he DMs you in `code/.env` and run the smoke test
      (see "Models and OpenRouter").
- [ ] **Sat Nov 28:** sanitizer checks for the common Python CWEs (SQLi, command
      injection, path traversal, SSRF, XSS, deserialization); hand-check 20 verifier
      flags on the dev logs and fix false alarms.
- [ ] **Sun Nov 29 - Wed Dec 2:** test pairs 41-60 (see "Shared test runs").
- [ ] **Sat Dec 5:** draw Figure 1 (the pipeline overview: DREA round 0, verifier,
      targeted Explorer requests, evidence gate) to replace the text box in the proposal.
- [ ] **Mon Dec 7:** report section "Verifier design" (checks, failure codes, examples).

### Renan: setup, budget, TA meeting and report assembly
- [ ] **Sun Nov 22:** make a shared Google Drive folder for the logs and share it
      with everyone.
- [ ] **Tue Nov 24:** send Saksham your $28 share; collect everyone's shares and
      confirm in Discord that all three were sent.
- [ ] **Tue Nov 24:** TA meeting talking points (1 page): the dev results table, one
      fixed lucky hit, one regression, the 80 vs. 40 test-pair question. Email
      Shayan to set the exact meeting day (Nov 25-27).
- [ ] **Wed Nov 25:** set up the repo on your laptop (see Setup), smoke test ALL PASS,
      put the key Saksham DMs you in `code/.env`, and run 1 dev pair to check it works.
- [ ] **Fri Nov 27:** post each person's spending in Discord (from the Activity page
      Saksham shares).
- [ ] **Sun Nov 29 - Wed Dec 2:** test pairs 21-40.
- [ ] **Mon Dec 7:** report sections "Introduction" and "Related work"
      (DREA, VERA, RepoAudit, Self-Refine, JITVul).
- [ ] **Wed Dec 9:** assemble the full report in the ACM template on Overleaf
      (merge everyone's sections, references, figures).
- [ ] **Sun Dec 13:** final read-through; check the page limit and the template.

### Tamanna: evaluation and results (away Wed Nov 25 - Mon Nov 30)
- [ ] **Tue Nov 24:** send Saksham your $28 share.
- [ ] **Tue Nov 24:** set up the repo on your laptop (see Setup), smoke test ALL PASS.
- [ ] **Tue Nov 24:** lucky-hit rate on the dev results (a script added to `analyze.py`
      or a notebook): compare `pred_cwe` and `pred_function` in
      `code/results/instances_*.csv` with RepoPairBench's labels
      (`data/repopairbench_100.jsonl`: `cwe_ids`, `vuln_data`). Wrong CWE or wrong
      root-cause function = lucky hit. Push it on a branch `tamanna-eval`.
- [ ] **Tue Dec 1:** put the key Saksham DMs you in `code/.env`; run the smoke test.
- [ ] **Tue Dec 1 - Thu Dec 3:** test pairs 61-80.
- [ ] **Fri Dec 4:** merge everyone's logs, run `analyze.py --split test`, commit the CSVs.
- [ ] **Mon Dec 7:** report section "Results": main table, fixed/broken/new FP,
      McNemar tests, cost table, figures.

### Saksham: pipeline and method
- [x] Feedback loop, prompts, batch runner, analysis script, smoke test, Windows fixes,
      first dev runs, and the OpenRouter account (paid for setup and dev runs so far).
- [ ] **Sun Nov 22:** finish the 11 dev pairs (dev pairs 1-10 + PyDrive2).
- [ ] **Sun Nov 22:** sign up for Azure for Students, create an Azure OpenAI
      resource, and request GPT-4.1 quota (backup judge; approval takes about
      1-2 business days, maybe longer over Thanksgiving).
- [ ] **Sun Nov 22:** email Shayan: course funding for API credit, 80 vs. 40 test
      pairs, and the meeting day.
- [ ] **Mon Nov 23:** commit the dev results, and upload the dev `code/logs` as a zip
      to the shared Drive.
- [ ] **Tue Nov 24:** explorer budget cap (same token budget per round for `explore`
      and `verified`, as the proposal says).
- [ ] **Tue Nov 24 (evening):** add everyone's share as credit; create one key per
      teammate (limit 18 each) and DM it to them.
- [ ] **Wed Nov 25:** merge Raj's verifier; tune on dev pairs only (with Raj).
- [ ] **Fri Nov 27:** first GPT-4.1 judge run on the dev logs
      (`--model gpt-4.1-azure` if the quota was approved, else `gpt-4.1-judge`).
- [ ] **Sun Nov 29:** freeze the code (`git tag v1-frozen`, `git push --tags`);
      test pairs 1-20.
- [ ] **Sat Dec 5:** judge run on all test logs (from the shared Drive); upload
      the judge outputs for Tamanna's results tables.
- [ ] **Mon Dec 7:** report section "Method" (pipeline, prompts, evidence gate, conditions).

### Everyone
- [ ] Hand-check about 8 of the 30 sampled cases (Sat Dec 5): right reasoning or lucky hit?
- [ ] Read the full draft by Sat Dec 12 and leave comments on Overleaf.

## Shared test runs (after the freeze, Sun Nov 29)
Everyone runs the same frozen code on their own 20 test pairs:
```bash
git fetch --tags
git checkout v1-frozen
cd code
uv sync
uv run smoke_test.py   # must print ALL PASS
```
| Person | Command (from `code/`) |
|---|---|
| Saksham | `uv run run_batch.py --model deepseek-v3.2 --split test --start 0 --limit 20 --build --workers 2` |
| Renan | `uv run run_batch.py --model deepseek-v3.2 --split test --start 20 --limit 20 --build --workers 2` |
| Raj | `uv run run_batch.py --model deepseek-v3.2 --split test --start 40 --limit 20 --build --workers 2` |
| Tamanna | `uv run run_batch.py --model deepseek-v3.2 --split test --start 60 --limit 20 --build --workers 2` |

Tamanna starts hers on Tue Dec 1 (she is away until then); everyone else starts Sun Nov 29.

Add `--repos <folder> --dataset-dir <folder>` if you keep the data outside the repo
(recommended on Windows, e.g. `C:\vera-data\repos` and `C:\vera-data\dataset`).
Expected: `40 job(s) to run`, about 8-10 hours and $15-20. If it stops, run the same
command again: it only redoes unfinished or failed jobs. Keep the laptop plugged in
and awake, and don't close the terminal until you see `done:`.

When it finishes, zip your `code/logs` folder as `logs_<yourname>.zip` and upload
it to the shared Drive folder. Tamanna unzips all four into her `code/logs` and
runs `uv run analyze.py --model deepseek-v3.2 --split test`.

## Setup (everyone)
Needs Git and uv. uv installs Python 3.13 by itself.
```bash
git clone https://github.com/rajkangr/VERA-DREA.git
cd VERA-DREA
git checkout saksham-pipeline
cd code
uv sync
uv run smoke_test.py         # should print ALL PASS (fake models, no API keys)
```
Make your own `code/.env` from the template (git-ignored; never commit it):
Windows `copy ..\.env.example .env`, Mac `cp ../.env.example .env`.
Then put the key Saksham DMs you in it (both `OPENROUTER_API_KEY` and `VLLM_API_KEY`).

Windows: run `git config --global core.longpaths true` once, and keep `repos/` and
`dataset/` outside OneDrive (they are large).

## Run experiments (from `code/`)
```bash
# one pair, both versions, all conditions (builds the pair if missing)
uv run run_batch.py --ids 00c73b6e --build --model deepseek-v3.2 --workers 2

# dev split (20 pairs): tune prompts and the verifier here ONLY
uv run run_batch.py --split dev --build --model deepseek-v3.2 --workers 2

# results table (prices default to OpenRouter list prices)
uv run analyze.py --model deepseek-v3.2 --split dev

# reasoning accuracy / lucky hits: DREA's GPT-4.1 judge (costs money, ~$1 per 100 traces),
# then analyze.py again to fill the LHR column
uv run python -m process.eval.assess_logs --logs-root logs --model gpt-4.1-judge --dataset-dir ../dataset
```
`run_batch.py` skips work that is already done, so re-run it after a crash.
Use `feedback_loop.py` / `run_batch.py`, not DREA's `main.py`: `main.py` looks
for the repository snapshot in a folder that `build_paired_dataset.py` never creates.

Outputs: `code/logs/<pair>/<vul|sec>/<model>/<condition>/` holds a `.jsonl`
trace (scored by the judge) and a `.rounds.json` summary per run;
`code/results/` holds the CSV tables.