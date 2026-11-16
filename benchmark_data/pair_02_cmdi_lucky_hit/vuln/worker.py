import subprocess

def run_archive_task(resolved_path, label):
    # Actual vulnerability: unsanitized label injected into shell command
    cmd = f'tar -czf {resolved_path} --label="{label}" /var/log/app'
    return subprocess.run(cmd, shell=True, capture_output=True)
