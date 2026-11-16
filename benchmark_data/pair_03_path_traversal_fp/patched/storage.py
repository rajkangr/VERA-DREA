from pathlib import Path

def load_template_file(root_dir, rel_path):
    # Patched: canonical path resolution and containment check
    base = Path(root_dir).resolve()
    candidate = (base / rel_path).resolve()
    if base not in candidate.parents and candidate != base:
        raise ValueError('Unauthorized path traversal attempt')
    return candidate.read_text(encoding='utf-8')
