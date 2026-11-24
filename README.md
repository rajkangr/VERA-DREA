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

Check that a key works with `uv run check_model.py deepseek-v3.2` (costs a fraction
of a cent). We also tried Azure for Students for the judge, but the student
subscription is not allowed to create Azure OpenAI resources, so OpenRouter is the
only provider.

**One shared account (Saksham's).** We keep using Saksham's OpenRouter account
and his existing key, so there is one balance and one place to see the spending.
Nobody else needs to sign up:
1. **Raj, Renan and Tamanna, by Tue Nov 24:** send Saksham your share (see the
   budget table) so he can add it as credit. Saksham has already put in $35 for
   the setup and dev runs. (Saksham is asking Shayan whether the course can cover
   API credit; if it does, shares go down or get refunded.)
2. **Saksham, by Tue Nov 24 (evening):** keep using his own key for his runs. In
   OpenRouter, **Keys**, then **Create Key**, once per teammate (name it after
   them), with the credit limit from the budget table. Each key can only spend
   its own limit, and the Activity page shows each person's spending. Send each
   key **privately (DM)**, never in the server channel.
3. **Everyone:** put your key in `code/.env` in BOTH `OPENROUTER_API_KEY` and
   `VLLM_API_KEY` (see `.env.example`). Never commit `.env` or paste the key anywhere.

**Budget (measured Nov 16-22):** the dev runs cost **$23.43** for 11 pairs
(22 jobs; one job = one pair version with DREA round 0 plus all follow-up
conditions). Without a cap that is about **$0.90 per job**, mostly from the unguided
`explore` condition. From Nov 24 every feedback round has an **Explorer budget of
500,000 tokens** (same for all conditions, as the proposal's "same budget" design
says), which should bring it to roughly **$0.60 per job**. The first test chunk
will tell us the real number.

| Plan | Test pairs | Test jobs | Test cost | Judge | Each of Raj, Renan, Tamanna pays | Key limit per teammate |
|---|---|---|---|---|---|---|
| A (full benchmark, same as DREA) | 80 (20 each) | 160 | about $95 | about $10 | about **$31** | $25 |
| B (if the money isn't there) | 40 (10 each) | 80 | about $48 | about $8 | about **$15** | $13 |

Saksham already paid $35 (about $11.50 of it is still unused and goes toward the
test runs). **Decision on Wed Nov 25:** Plan A if all three shares for A have
arrived, otherwise Plan B, and we say so in the report.

## Status (Mon Nov 23)
- Pipeline runs end to end on real RepoPairBench pairs (`saksham-pipeline`).
- Dev runs done: **11 dev pairs** (dev pairs 1-10 + PyDrive2), all jobs OK.
- Fixed: verdict parsing (the answer is the message with the XML report, not
  the trailing summary; same fix in the judge), missing-verdict re-ask, API
  retry, Windows dataset build (symlinks), first evidence gate, and (Nov 24)
  the Explorer budget. Smoke test: 15 checks, ALL PASS.
- Waiting on: Raj's verifier (`raj-verifier` branch is not pushed yet; due Tue Nov 24).
- No TA meeting this week (short Thanksgiving week); the next check-in is after the break.
- Tamanna is away from Wed Nov 25 until Tue Dec 1; her tasks are scheduled around that.

## Who does what (with deadlines)
Everyone owns one part of the code, runs **a quarter of the test pairs** (20 in
Plan A, 10 in Plan B) on their own laptop with their own key on the shared
OpenRouter account, and writes one report section.

### Raj: verifier
- [ ] **Tue Nov 24:** push branch `raj-verifier` (made from `saksham-pipeline`) with the
      MVP checks ported into `code/core/verifier.py`. Use `check_from_code()` so each
      finding has a failure code, a status and an Explorer request. General checks only,
      nothing written for one specific pair. `uv run smoke_test.py` must print ALL PASS.
- [ ] **Tue Nov 24:** send Saksham your share (budget table).
- [ ] **Wed Nov 25:** put the key he DMs you in `code/.env` and run the smoke test
      (see "Models and OpenRouter").
- [ ] **Sat Nov 28:** sanitizer checks for the common Python CWEs (SQLi, command
      injection, path traversal, SSRF, XSS, deserialization); hand-check 20 verifier
      flags on the dev logs and fix false alarms.
- [ ] **Sun Nov 29 - Wed Dec 2:** your test pairs (see "Shared test runs").
- [ ] **Sat Dec 5:** draw Figure 1 (the pipeline overview: DREA round 0, verifier,
      targeted Explorer requests, evidence gate) to replace the text box in the proposal.
- [ ] **Mon Dec 7:** report section "Verifier design" (checks, failure codes, examples).

### Renan: setup, budget, TA check-in and report assembly
- [x] **Sun Nov 22:** shared Google Drive folder for the logs.
- [ ] **Tue Nov 24:** send Saksham your share (budget table); collect everyone's
      shares and confirm in Discord that all three were sent.
- [ ] **Mon Nov 30:** TA check-in talking points (1 page): the dev results table, one
      fixed lucky hit, one regression, the test-set size. Email Shayan to set the
      check-in day (Dec 1-4).
- [ ] **Wed Nov 25:** set up the repo on your laptop (see Setup), smoke test ALL PASS,
      put the key Saksham DMs you in `code/.env`, and run 1 dev pair to check it works.
- [ ] **Fri Nov 27:** post each person's spending in Discord (from the Activity page
      Saksham shares).
- [ ] **Sun Nov 29 - Wed Dec 2:** your test pairs (see "Shared test runs").
- [ ] **Mon Dec 7:** report sections "Introduction" and "Related work"
      (DREA, VERA, RepoAudit, Self-Refine, JITVul).
- [ ] **Wed Dec 9:** assemble the full report in the ACM template on Overleaf
      (merge everyone's sections, references, figures).
- [ ] **Sun Dec 13:** final read-through; check the page limit and the template.

### Tamanna: evaluation and results (away Wed Nov 25 - Mon Nov 30)
- [ ] **Tue Nov 24:** send Saksham your share (budget table).
- [x] **Tue Nov 24:** set up the repo on your laptop (see Setup), smoke test ALL PASS.
- [x] **Tue Nov 24:** lucky-hit rate on the dev results (a script added to `analyze.py`
      or a notebook): compare `pred_cwe` and `pred_function` in
      `code/results/instances_*.csv` with RepoPairBench's labels
      (`data/repopairbench_100.jsonl`: `cwe_ids`, `vuln_data`). Wrong CWE or wrong
      root-cause function = lucky hit. Push it on a branch `tamanna-eval`.
- [ ] **Tue Dec 1:** put the key Saksham DMs you in `code/.env`; run the smoke test.
- [ ] **Tue Dec 1 - Thu Dec 3:** your test pairs (see "Shared test runs").
- [ ] **Fri Dec 4:** merge everyone's logs, run `analyze.py --split test`, commit the CSVs.
- [ ] **Mon Dec 7:** report section "Results": main table, fixed/broken/new FP,
      McNemar tests, cost table, figures.

### Saksham: pipeline and method
- [x] Feedback loop, prompts, batch runner, analysis script, smoke test, Windows fixes,
      the OpenRouter account, and all dev runs (paid $35 so far).
- [x] **Sun Nov 22:** finished the 11 dev pairs. Tried Azure for Students for the
      judge (not allowed on student subscriptions).
- [ ] **Mon Nov 23:** commit the dev results; upload the dev `code/logs` as a zip to
      the shared Drive; email Shayan about course funding for API credit.
- [ ] **Tue Nov 24:** Explorer budget (same token budget per feedback round for every
      condition, as the proposal says); smoke test; push.
- [ ] **Tue Nov 24 (evening):** add everyone's share as credit; create one key per
      teammate (limit from the budget table) and DM it to them.
- [ ] **Wed Nov 25:** decide Plan A or B; merge Raj's verifier; tune on dev pairs only.
- [ ] **Fri Nov 27:** first GPT-4.1 judge run on the dev logs (`--model gpt-4.1-judge`).
- [ ] **Sun Nov 29:** freeze the code (`git tag v1-frozen`, `git push --tags`); start
      your test pairs.
- [ ] **Sat Dec 5:** judge run on all test logs (from the shared Drive); upload the
      judge outputs for Tamanna's results tables.
- [ ] **Mon Dec 7:** report section "Method" (pipeline, prompts, evidence gate,
      Explorer budget, conditions).

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
**Plan A (80 pairs, 20 each):**

| Person | Command (from `code/`) |
|---|---|
| Saksham | `uv run run_batch.py --model deepseek-v3.2 --split test --start 0 --limit 20 --build --workers 2` |
| Renan | `uv run run_batch.py --model deepseek-v3.2 --split test --start 20 --limit 20 --build --workers 2` |
| Raj | `uv run run_batch.py --model deepseek-v3.2 --split test --start 40 --limit 20 --build --workers 2` |
| Tamanna | `uv run run_batch.py --model deepseek-v3.2 --split test --start 60 --limit 20 --build --workers 2` |

**Plan B (40 pairs, 10 each):** the same commands with `--limit 10` and
`--start 0` (Saksham), `--start 10` (Renan), `--start 20` (Raj), `--start 30` (Tamanna).

Tamanna starts hers on Tue Dec 1 (she is away until then); everyone else starts Sun Nov 29.

Add `--repos <folder> --dataset-dir <folder>` if you keep the data outside the repo
(recommended on Windows, e.g. `C:\vera-data\repos` and `C:\vera-data\dataset`).
Expected: `40 job(s) to run` (Plan A) or `20 job(s) to run` (Plan B), about 8-10
or 4-5 hours, and about $24 or $12. If it stops, run the same
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

# every feedback round is capped at 500,000 Explorer tokens by default;
# change it with --explorer-budget N (0 = no cap; round 0 is never capped)

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
