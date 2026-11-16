# DREA Code

This directory contains the runnable DREA implementation and baselines.

## Setup

```bash
uv sync
cp ../.env.example .env
```

Edit `.env` with your model endpoints. See `../docs/model_config.md`.

## Main Run

After reconstructing the paired dataset:

```bash
uv run main.py <project_name> \
  --dataset-dir ../dataset \
  --type vul \
  --model <model_id>
```

Use `--type sec` for the patched counterpart.

## Baselines

Function-only:

```bash
uv run run_baseline.py <item_id> \
  --dataset-path ../data/repopairbench_100.jsonl \
  --type vul \
  --model <model_id>
```

Whole-file:

```bash
uv run run_wholefile_baseline.py <item_id> \
  --dataset-path ../data/repopairbench_100.jsonl \
  --repo-cache-dir ../repos \
  --type vul \
  --model <model_id>
```

Single-agent:

```bash
uv run run_single_agent.py <item_id> \
  --dataset-path ../data/repopairbench_100.jsonl \
  --repo-cache-dir ../repos \
  --type vul \
  --model <model_id>
```
