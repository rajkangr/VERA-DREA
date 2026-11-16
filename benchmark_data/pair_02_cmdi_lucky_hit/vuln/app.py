from path_guard import resolve_export_path
from worker import run_archive_task

def export_logs_endpoint(user_Archive_name):
    # Looks like a path traversal sink at first glance
    safe_target = resolve_export_path('/var/exports', user_Archive_name)
    return run_archive_task(safe_target, user_Archive_name)
