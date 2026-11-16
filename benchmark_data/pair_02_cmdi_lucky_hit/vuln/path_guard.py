import os

def resolve_export_path(base_dir, filename):
    # Completely safe path resolution
    base = os.path.realpath(base_dir)
    target = os.path.realpath(os.path.join(base, filename))
    if not target.startswith(base + os.sep):
        raise PermissionError('Path traversal blocked')
    return target
