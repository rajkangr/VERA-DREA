#!/usr/bin/env bash
set -euo pipefail

MANIFEST="data/repopairbench_100_manifest.json"
OUTPUT="repos"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --manifest)
      MANIFEST="$2"
      shift 2
      ;;
    --output)
      OUTPUT="$2"
      shift 2
      ;;
    -h|--help)
      echo "Usage: $0 --manifest data/repopairbench_100_manifest.json --output repos"
      exit 0
      ;;
    *)
      echo "Unknown argument: $1" >&2
      exit 2
      ;;
  esac
done

if [[ ! -f "$MANIFEST" ]]; then
  echo "Manifest not found: $MANIFEST" >&2
  exit 1
fi

mkdir -p "$OUTPUT"

python3 - "$MANIFEST" <<'PY' | while IFS=$'\t' read -r repo_url; do
import json
import sys
from pathlib import Path

manifest = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
urls = set()
for item in manifest:
    commit_url = item.get("commit_url") or ""
    if "/commit/" not in commit_url:
        continue
    urls.add(commit_url.split("/commit/", 1)[0])
for url in sorted(urls):
    print(url)
PY
  path="${repo_url#https://github.com/}"
  org="${path%%/*}"
  repo="${path##*/}"
  dest="$OUTPUT/$org/$repo"

  if [[ -d "$dest/.git" ]]; then
    echo "SKIP $org/$repo"
    continue
  fi

  echo "CLONE $org/$repo"
  mkdir -p "$OUTPUT/$org"
  git clone "$repo_url" "$dest"
done
