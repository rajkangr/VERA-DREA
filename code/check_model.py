"""Send one tiny message to a model from config/models.json to check the key works.

Usage (from code/):
  uv run check_model.py deepseek-v3.2
  uv run check_model.py gpt-4.1-judge

Costs a fraction of a cent. Prints OK and the model's reply, or the error.
"""
from __future__ import annotations

import sys
from pathlib import Path

from dotenv import load_dotenv

HERE = Path(__file__).resolve().parent
load_dotenv(HERE / ".env")
sys.path.insert(0, str(HERE))

from core.model_registry import build_main_model  # noqa: E402


def main() -> int:
    if len(sys.argv) != 2:
        print(__doc__)
        return 2
    model_id = sys.argv[1]
    try:
        model = build_main_model(model_id)
        reply = model.invoke("Reply with exactly one word: ready")
    except Exception as exc:  # show the real error, e.g. a 401 or a 404
        print(f"FAIL {model_id}: {type(exc).__name__}: {exc}")
        return 1
    text = reply.content if isinstance(reply.content, str) else str(reply.content)
    print(f"OK   {model_id}: {text.strip()[:80]}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())