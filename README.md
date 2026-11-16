# VERA-DREA (ECE 371H Honors Project)

Evidence-guided self-correction for repository-level vulnerability detection.

Team: Saksham Verma, Renan Solak, Tamanna Chandak, Raj Kangriwala.
Final deadline: **Dec 14, 11:59 PM**.

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
| `filter` | verify-then-discard (RepoAudit/VERA style), no feedback | is correcting better than discarding? |

## Who owns what
| Area | Owner | Main files |
|---|---|---|
| Feedback loop, prompts, experiment runs | Saksham | `code/feedback_loop.py`, `code/core/prompts/feedback.py`, `code/run_batch.py` |
| Verifier (the novel part) | Raj | `code/core/verifier.py` |
| Models, API keys/budget, Explorer serving, dataset | Renan | `code/.env`, `code/config/models.json`, `dataset/` |
| Judge, metrics, statistics, report | Tamanna | `code/analyze.py`, `code/process/eval/`, `results/` |

## Setup (everyone)
Needs Git and uv. uv installs Python 3.13 by itself.
```bash
git clone https://github.com/rajkangr/VERA-DREA.git
cd VERA-DREA/code
uv sync
uv run smoke_test.py         # should print ALL PASS (fake models, no API keys)
```
Make your own `code/.env` from the template (git-ignored; never commit it):
Windows `copy ..\.env.example .env`, Mac `cp ../.env.example .env`.

## Run experiments (from `code/`)
```bash
# one pair, both versions, all conditions (builds the pair if missing)
uv run run_batch.py --ids 00c73b6e --build --model <model_id> --workers 2

# dev split (20 pairs): tune prompts and the verifier here ONLY
uv run run_batch.py --split dev --build --model <model_id> --workers 4

# test split (80 pairs): final numbers, run once after the freeze
uv run run_batch.py --split test --build --model <model_id> --workers 6

# results table (add $ per 1M tokens to get costs)
uv run analyze.py --model <model_id> --split dev --price-main <p> --price-explorer <p>

# reasoning accuracy / lucky hits: DREA's judge, then analyze.py again
uv run python -m process.eval.assess_logs --logs-root logs --model <judge_model_id> --dataset-dir ../dataset
```
`run_batch.py` skips work that is already done, so re-run it after a crash.
Use `feedback_loop.py` / `run_batch.py`, not DREA's `main.py`: `main.py` looks
for the repository snapshot in a folder that `build_paired_dataset.py` never creates.

Outputs: `code/logs/<pair>/<vul|sec>/<model>/<condition>/` holds a `.jsonl`
trace (scored by the judge) and a `.rounds.json` summary per run;
`code/results/` holds the CSV tables.

## Git workflow
- Don't commit to `main` directly. Make a branch: `git checkout -b raj/verifier`
- Push it (`git push -u origin raj/verifier`) and open a Pull Request; one teammate reviews before merging.
- Pull often: `git checkout main`, `git pull`, then `git checkout <your-branch>` and `git merge main`.
