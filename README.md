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
1. **Raj, Renan and Tamanna:** send Saksham your share (see the budget table) so he
   can add it as credit. Raj (Nov 23) and Tamanna (Nov 24) have paid; **Renan's is
   due by the end of Wed Nov 25.** Saksham has already put in $35 for the setup and
   dev runs. The course has no funding for API credit (Shayan, Nov 24).
2. **Saksham:** keeps using his own key for his runs. In OpenRouter, **Keys**, then
   **Create Key**, once per teammate (name it after them), with the credit limit
   from the budget table, created once that teammate's share has arrived. Each key
   can only spend its own limit, and the Activity page shows each person's spending.
   Send each key **privately (DM)**, never in the server channel.
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
test runs). **Decision (Nov 24): Plan A, all 80 test pairs.** The course has no
funding for API credit (Shayan, Nov 24), so we split the cost: **$31 each from Raj,
Renan and Tamanna** (by the end of Wed Nov 25). Plan B (40 pairs) is only an
emergency fallback, which
Shayan said is acceptable "with proper justification".

Free options we checked (Nov 24, from Shayan's suggestions):
- **UMass GenAI platform:** a chat interface; we found no API access, and it
  doesn't list DeepSeek V3.2 or GPT-4.1, so our pipeline can't call it.
- **Unity HPC / Google Colab:** can host open-weight models, but not DeepSeek V3.2
  (671B parameters), and Colab sessions time out long before a 10-hour run. Switching
  to a smaller model now would mean redoing the dev runs and tuning, and our results
  would no longer match DREA's setup. We keep the same model for every condition,
  as Shayan asked.

## Status (Wed Nov 25)
- Pipeline runs end to end on real RepoPairBench pairs (`saksham-pipeline`).
- Dev runs done: **11 dev pairs** (dev pairs 1-10 + PyDrive2), all jobs OK.
- Fixed: verdict parsing (the answer is the message with the XML report, not
  the trailing summary; same fix in the judge), missing-verdict re-ask, API
  retry, Windows dataset build (symlinks), first evidence gate, the Explorer
  budget, (Nov 24) the function extractor, and (Nov 25) tuning fixes #1, #3 and #4.
  Smoke test: 20 checks, ALL PASS.
- Dev results (11 pairs, `code/results/summary_deepseek-v3.2_dev.csv`): P-C (both
  versions of a pair right) is drea 4/11, self_refine 5/11, explore 4/11, verified
  3/11, verified+gate 1/11, filter 0/11. FPR: verified 0.727 vs drea 0.636. Extra
  cost over DREA: explore $17.88, verified $3.97. So right now the verifier
  conditions break more than they fix; the tuning below is about that.
- What goes wrong on the patched (`sec`) versions (Saksham read them all, Nov 24;
  spreadsheet sent to Raj): the model **sees the fix every time**, then either
  switches to a different bug (apkleaks, ParlAI, bot) or argues the fix is not
  enough (Calendarinho, chuanhuchatgpt, joblib). galaxy is our own verifier's fault:
  it said "quotes no code" for a quote inside a `<code_excerpt>` tag.
- Raj's AST verifier is pushed (`raj-verifier`, Tue Nov 24) and merged into
  `saksham-pipeline`. It has protection checks for SQL injection, command injection,
  path traversal and SSRF.
- `uv run reverify.py --split dev` re-checks the saved dev answers with the current
  verifier for free (no API calls), so we tune the verifier before paying for reruns.
- Tamanna's lucky-hit script is in (`code/lucky_hits.py`, branch `tamanna-eval`, merged
  Nov 24): dev lucky-hit rate for DREA is about 30%. She found that `pred_function` was
  blank or wrong for about a third of answers; the extractor is fixed and the instances
  CSV now also has the raw `pred_location`.
- Shares: Raj (Nov 23) and Tamanna (Nov 24) paid and have their keys. Renan: due by the end
  of Wed Nov 25; as of Wed Nov 25 he has not replied in the group chat or in DMs (see
  "If Renan doesn't respond" below).
- The dev logs are on the shared Drive (`logs_dev_saksham.zip`, Nov 24), so Raj can tune on
  the same answers.
- No course funding for API credit (Shayan, Nov 24): we run all 80 test pairs and
  split the cost (see the budget table). Shayan asked us to keep documenting individual
  contributions and to tell him about missed deadlines.
- No TA meeting this week (short Thanksgiving week); the next check-in is after the break.
- Tamanna is away from Wed Nov 25 until Tue Dec 1; her tasks are scheduled around that. Her
  OpenRouter key stays valid over the break (keys don't expire; only the $25 limit applies).

## Tuning plan (Wed Nov 25 - Sat Nov 28, dev pairs only)
Rules: tune on the **dev** pairs only (never look at test pairs before the freeze).
After every change, run the free re-check first:
`uv run reverify.py --split dev --dataset-dir C:\vera-data\dataset` (or `../dataset`).
A change is good if `broken` goes down for `verified+gate` and `filter` and no correct
answer is lost. Only then rerun 2-3 dev pairs in full (about $1-2 each).

| # | Change | File | Owner | Status |
|---|---|---|---|---|
| 1 | Verifier accepts quoted code in every format (triple-backtick and `~~~` fences, `<code_excerpt>`/`<code>` tags, backticks; strips `Line 83:` / `503<tab>` prefixes, `&lt;` entities and comments the model added), and only CONTRADICTS when most quoted lines are missing. Fixes galaxy's "quotes no code" | `core/verdict.py` (`extract_code_quotes`), `core/verifier.py` (check 1 only) | Saksham | Done Nov 25 |
| 2 | Don't flag stdlib calls or `self.`/object method calls as undefined symbols (`os.path.normpath`, `self.normpath`, `request.path_info_pop`) | `core/verifier.py` (symbol filters) | Raj | To do |
| 3 | No feedback round on a SECURE answer unless a claim is CONTRADICTED (UNRESOLVED alone is not enough); new stop reason `secure_not_contradicted`, and `reverify.py` now shows how many SECURE answers would still get a round | `feedback_loop.py` (`needs_feedback`), `reverify.py` | Saksham | Done Nov 25 |
| 4 | "Same bug" rule, in the feedback prompts only (round 0 stays plain DREA, and all three feedback conditions get the same text): if the code has a check on the path to the reported sink, give a concrete input that gets past it; don't switch bug type or sink without showing attacker input that reaches the new one | `core/prompts/feedback.py` | Saksham | Done Nov 25 |
| 5 | Add an open-redirect (CWE-601) protection check next to the XSS (CWE-79), deserialization (CWE-502) and code-injection (CWE-94/95) checks; find out why apkleaks and chuanhuchatgpt were missed even though CWE-22/78 are covered | `core/verifier.py` | Raj | Due Sat Nov 28, 6 PM |
| 6 | Write up chuanhuchatgpt (`assert` skipped under `-O`) and Calendarinho (`ALLOWED_HOSTS`) as label disagreements in the report's Limitations | report | Saksham | Before the freeze |

Raj's spreadsheet (`VERA-DREA_false_positives.xlsx`, shared Nov 25) has one row per patched
pair with the pattern and the fix that targets it.

Full reruns (move each pair's old logs out of `code/logs` first; about $1-2 per pair):
- **Wed Nov 25, after #1, #3 and #4:** galaxy (`95115f47`, fixes 1 and 3), apkleaks
  (`193c77fa`, fix 4) and bot (`0dc2e99d`, fix 4).
- **Sat Nov 28, after Raj's #2 and #5 are merged:** joblib (`1b48a788`, fix 5).

## Who does what (with deadlines)
Everyone owns one part of the code, runs **a quarter of the test pairs** (20 in
Plan A, 10 in Plan B) on their own laptop with their own key on the shared
OpenRouter account, and writes one report section.

### Raj: verifier
- [x] **Tue Nov 24:** pushed `raj-verifier` (AST checks, failure codes, Explorer requests).
- [x] **Tue Nov 24:** sent his share.
- [x] **Tue Nov 24:** agreed to merge `raj-verifier` into `saksham-pipeline`.
- [x] **Tue Nov 24:** got his OpenRouter key (limit $25).
- [ ] **Wed Nov 25:** put your key in `code/.env`; run `uv run check_model.py deepseek-v3.2`.
      Then, on `raj-verifier`, run `git merge origin/saksham-pipeline` **before** you edit
      `core/verifier.py` (fix #1 changed check 1 in that file on Nov 25), and run the smoke
      test (20 checks, ALL PASS).
- [ ] **Wed Nov 25:** get the dev runs onto your laptop for tuning: download
      `logs_dev_saksham.zip` from the shared Drive, unzip it into `code/logs`, then build
      the dev pairs (no API calls):
      `uv run run_batch.py --model deepseek-v3.2 --split dev --limit 10 --build --dry-run`
      and `uv run run_batch.py --model deepseek-v3.2 --ids 4f4ba85c --build --dry-run`.
- [ ] **Wed Nov 25 - Fri Nov 27:** tune with Saksham on the dev pairs only (see
      "Tuning plan": yours are #2 and #5). Run `uv run reverify.py --split dev` (free)
      after every verifier change: the goal is fewer `broken` for `verified+gate` and
      `filter` without losing correct answers. Hand-check 20 verifier flags in
      `results/reverify_*.csv` (start with Saksham's spreadsheet of the patched pairs)
      and fix false alarms. Push to `raj-verifier`; Saksham merges it.
- [ ] **Sat Nov 28, 6 PM:** protection checks for XSS (CWE-79), unsafe deserialization
      (CWE-502), code injection (CWE-94/95) and open redirect (CWE-601), the same way
      as the existing four; push by 6 PM so it is in the freeze.
- [ ] **Sun Nov 29 - Wed Dec 2:** your test pairs (see "Shared test runs").
- [ ] **Sat Dec 5:** draw Figure 1 (the pipeline overview: DREA round 0, verifier,
      targeted Explorer requests, evidence gate) to replace the text box in the proposal.
- [ ] **Mon Dec 7:** report section "Verifier design" (checks, failure codes, examples).

### Renan: setup, budget, TA check-in and report assembly
- [x] **Sun Nov 22:** shared Google Drive folder for the logs.
- [ ] **By Wed Nov 25:** send Saksham your share (budget table).
- [ ] **By Fri Nov 27:** set up the repo on your laptop (pull `saksham-pipeline`, `uv sync`,
      smoke test ALL PASS), put the key Saksham DMs you in `code/.env`, run
      `uv run check_model.py deepseek-v3.2`, then one cheap real run (about $0.15):
      `uv run run_batch.py --model deepseek-v3.2 --ids 193c77fa --types vul --conditions none --build --workers 1`;
      post "ready" in Discord.
- [ ] **Fri Nov 27:** post each person's spending in Discord (from the Activity page
      Saksham shares).
- [ ] **Mon Nov 30:** TA check-in talking points (1 page): the dev results table, one
      fixed lucky hit, one regression, the test-set size. Email Shayan to set the
      check-in day (Dec 1-4).
- [ ] **Sun Nov 29 - Wed Dec 2:** your test pairs (see "Shared test runs").
- [ ] **Mon Dec 7:** report sections "Introduction" and "Related work"
      (DREA, VERA, RepoAudit, Self-Refine, JITVul).
- [ ] **Wed Dec 9:** assemble the full report in the ACM template on Overleaf
      (merge everyone's sections, references, figures).
- [ ] **Sun Dec 13:** final read-through; check the page limit and the template.

### Tamanna: evaluation and results (away Wed Nov 25 - Mon Nov 30)
- [x] **Tue Nov 24:** sent her share.
- [x] **Tue Nov 24:** set up the repo on your laptop (see Setup), smoke test ALL PASS.
- [x] **Tue Nov 24:** lucky-hit rate on the dev results (a script added to `analyze.py`
      or a notebook): compare `pred_cwe` and `pred_function` in
      `code/results/instances_*.csv` with RepoPairBench's labels
      (`data/repopairbench_100.jsonl`: `cwe_ids`, `vuln_data`). Wrong CWE or wrong
      root-cause function = lucky hit. Push it on a branch `tamanna-eval`.
- [x] **Tue Nov 24:** got her OpenRouter key by DM (it stays valid over the break).
- [ ] **Tue Dec 1:** pull `saksham-pipeline`, put your key in `code/.env`; run the smoke
      test (ALL PASS) and `uv run check_model.py deepseek-v3.2`.
- [ ] **Tue Dec 1:** re-run `uv run lucky_hits.py --split dev` on the fixed instances CSV
      (Saksham re-ran it on Nov 24; check the numbers).
- [ ] **Tue Dec 1 - Thu Dec 3:** your test pairs (see "Shared test runs").
- [ ] **Fri Dec 4:** merge everyone's logs, run `analyze.py --split test`, commit the CSVs.
- [ ] **Mon Dec 7:** report section "Results": main table, fixed/broken/new FP,
      McNemar tests, cost table, figures.

### Saksham: pipeline and method
- [x] Feedback loop, prompts, batch runner, analysis script, smoke test, Windows fixes,
      the OpenRouter account, and all dev runs (paid $35 so far).
- [x] **Sun Nov 22:** finished the 11 dev pairs. Tried Azure for Students for the
      judge (not allowed on student subscriptions).
- [x] **Mon Nov 23:** Explorer budget (same token budget per feedback round for every
      condition, as the proposal says); dev results committed; emailed Shayan.
- [x] **Tue Nov 24:** Raj's key sent (limit $25).
- [x] **Tue Nov 24:** merged Raj's verifier and Tamanna's lucky-hit branch; fixed the
      function extractor Tamanna found; added `reverify.py`; rebuilt the dev tables.
- [x] **Tue Nov 24:** read the patched-pair mistakes in the dev runs (see Status) and
      sent the spreadsheet to Raj.
- [x] **Tue Nov 24:** uploaded the dev `code/logs` as `logs_dev_saksham.zip` to the shared
      Drive; emailed Shayan back; DMed Renan.
- [x] **Tue Nov 24:** added Raj's and Tamanna's shares as credit; Tamanna's key sent.
- [ ] **Renan's key:** only once his share arrives.
- [ ] **Wed Nov 25:** tuning fixes #1, #3 and #4 (see "Tuning plan"), checked with
      `reverify.py`; send Raj the false-positives spreadsheet; rerun galaxy, apkleaks and
      bot in full (about $1-2 each; move their old logs aside first).
- [ ] **Wed Nov 25 (night):** check Renan's share; if it hasn't arrived, log it as missed.
- [ ] **Before the freeze:** Limitations notes on the `assert` and `ALLOWED_HOSTS`
      label disagreements (tuning #6).
- [ ] **Fri Nov 27:** first GPT-4.1 judge run on the dev logs (`--model gpt-4.1-judge`).
- [ ] **Sat Nov 28 (evening):** merge Raj's new checks; smoke test ALL PASS; push.
- [ ] **Sun Nov 29:** freeze the code (`git tag v1-frozen`, `git push --tags`); start
      your test pairs.
- [ ] **Sat Dec 5:** judge run on all test logs (from the shared Drive); upload the
      judge outputs for Tamanna's results tables.
- [ ] **Next TA check-in (after the break):** present the pipeline and the dev results.
- [ ] **Mon Dec 7:** report section "Method" (pipeline, prompts, evidence gate,
      Explorer budget, conditions).

### If Renan doesn't respond
As of Wed Nov 25, Renan hasn't replied in the group chat or in DMs. His share is due
tonight and his setup is due Fri Nov 27.
- **Wed Nov 25, night:** if his share hasn't arrived, Saksham logs it as missed.
- **Fri Nov 27, 9 PM:** if he still hasn't paid or posted "ready", Saksham emails Shayan
  about the missed deadlines (he asked to hear about them), and his tasks move:
  - TA check-in (Mon Nov 30: talking points, emailing Shayan to set the day): Saksham.
  - His 20 test pairs (`--start 20`): the team decides in Discord on Sat Nov 28 between
    (a) Saksham, Raj and Tamanna splitting them (`--start 20 --limit 7`, `--start 27
    --limit 7`, `--start 34 --limit 6`) and his part of the cost (about $10 each), or
    (b) running 60 test pairs and explaining why in the report (Shayan said a smaller
    test set is acceptable "with proper justification").
  - His report sections (Introduction, Related work, assembling the report): split on
    Sat Nov 28 with the test pairs.
- If he comes back, he takes his tasks back from that point; the contribution log keeps
  what was missed.

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

# re-check the saved answers with the current verifier (free, no API calls)
uv run reverify.py --split dev --dataset-dir ../dataset

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
