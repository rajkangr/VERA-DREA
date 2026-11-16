import subprocess

def run_archive_task(resolved_path, label):
    # Patched: argument list with shell=False prevents command injection
    cmd = ['tar', '-czf', resolved_path, f'--label={label}', '/var/log/app']
    return subprocess.run(cmd, shell=False, capture_output=True)
