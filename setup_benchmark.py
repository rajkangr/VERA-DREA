"""
setup_benchmark.py
Creates 4 multi-file Python vulnerability/fix pairs (8 repositories total)
modeled after RepoPairBench to test Baseline DREA, Self-Refine, and VERA-DREA.
"""

import os
import json

BENCHMARK_DIR = "benchmark_data"

PAIRS = [
    {
        "pair_id": "pair_01_sqli",
        "cwe": "CWE-89",
        "name": "Interprocedural SQL Injection with Fake Sanitizer",
        "entry_file": "app.py",
        "true_root_cause_func": "execute_user_lookup",
        "vuln_files": {
            "app.py": (
                "from security import sanitize_account_id\n"
                "from db_layer import execute_user_lookup\n\n"
                "def get_profile_Route(request_params):\n"
                "    raw_id = request_params.get('account_id', '')\n"
                "    clean_id = sanitize_account_id(raw_id)\n"
                "    return execute_user_lookup(clean_id)\n"
            ),
            "security.py": (
                "def sanitize_account_id(val):\n"
                "    # NOTE: Legacy helper only trims whitespace; does not escape SQL!\n"
                "    if val is None:\n"
                "        return ''\n"
                "    return str(val).strip()\n"
            ),
            "db_layer.py": (
                "import sqlite3\n\n"
                "def execute_user_lookup(account_id):\n"
                "    conn = sqlite3.connect('users.db')\n"
                "    cursor = conn.cursor()\n"
                "    query = f\"SELECT username, email FROM accounts WHERE id = '{account_id}'\"\n"
                "    cursor.execute(query)\n"
                "    return cursor.fetchall()\n"
            ),
        },
        "patched_files": {
            "app.py": (
                "from security import sanitize_account_id\n"
                "from db_layer import execute_user_lookup\n\n"
                "def get_profile_Route(request_params):\n"
                "    raw_id = request_params.get('account_id', '')\n"
                "    clean_id = sanitize_account_id(raw_id)\n"
                "    return execute_user_lookup(clean_id)\n"
            ),
            "security.py": (
                "def sanitize_account_id(val):\n"
                "    # Strictly enforce integer account IDs\n"
                "    if not str(val).strip().isdigit():\n"
                "        raise ValueError('Invalid non-numeric account ID')\n"
                "    return int(str(val).strip())\n"
            ),
            "db_layer.py": (
                "import sqlite3\n\n"
                "def execute_user_lookup(account_id):\n"
                "    conn = sqlite3.connect('users.db')\n"
                "    cursor = conn.cursor()\n"
                "    cursor.execute('SELECT username, email FROM accounts WHERE id = ?', (account_id,))\n"
                "    return cursor.fetchall()\n"
            ),
        },
    },
    {
        "pair_id": "pair_02_cmdi_lucky_hit",
        "cwe": "CWE-78",
        "name": "Decoy Path Check Masking OS Command Injection (Lucky Hit Trap)",
        "entry_file": "app.py",
        "true_root_cause_func": "run_archive_task",
        "vuln_files": {
            "app.py": (
                "from path_guard import resolve_export_path\n"
                "from worker import run_archive_task\n\n"
                "def export_logs_endpoint(user_Archive_name):\n"
                "    # Looks like a path traversal sink at first glance\n"
                "    safe_target = resolve_export_path('/var/exports', user_Archive_name)\n"
                "    return run_archive_task(safe_target, user_Archive_name)\n"
            ),
            "path_guard.py": (
                "import os\n\n"
                "def resolve_export_path(base_dir, filename):\n"
                "    # Completely safe path resolution\n"
                "    base = os.path.realpath(base_dir)\n"
                "    target = os.path.realpath(os.path.join(base, filename))\n"
                "    if not target.startswith(base + os.sep):\n"
                "        raise PermissionError('Path traversal blocked')\n"
                "    return target\n"
            ),
            "worker.py": (
                "import subprocess\n\n"
                "def run_archive_task(resolved_path, label):\n"
                "    # Actual vulnerability: unsanitized label injected into shell command\n"
                "    cmd = f'tar -czf {resolved_path} --label=\"{label}\" /var/log/app'\n"
                "    return subprocess.run(cmd, shell=True, capture_output=True)\n"
            ),
        },
        "patched_files": {
            "app.py": (
                "from path_guard import resolve_export_path\n"
                "from worker import run_archive_task\n\n"
                "def export_logs_endpoint(user_Archive_name):\n"
                "    safe_target = resolve_export_path('/var/exports', user_Archive_name)\n"
                "    return run_archive_task(safe_target, user_Archive_name)\n"
            ),
            "path_guard.py": (
                "import os\n\n"
                "def resolve_export_path(base_dir, filename):\n"
                "    base = os.path.realpath(base_dir)\n"
                "    target = os.path.realpath(os.path.join(base, filename))\n"
                "    if not target.startswith(base + os.sep):\n"
                "        raise PermissionError('Path traversal blocked')\n"
                "    return target\n"
            ),
            "worker.py": (
                "import subprocess\n\n"
                "def run_archive_task(resolved_path, label):\n"
                "    # Patched: argument list with shell=False prevents command injection\n"
                "    cmd = ['tar', '-czf', resolved_path, f'--label={label}', '/var/log/app']\n"
                "    return subprocess.run(cmd, shell=False, capture_output=True)\n"
            ),
        },
    },
    {
        "pair_id": "pair_03_path_traversal_fp",
        "cwe": "CWE-22",
        "name": "Interprocedural Path Traversal & False-Positive Reduction",
        "entry_file": "app.py",
        "true_root_cause_func": "load_template_file",
        "vuln_files": {
            "app.py": (
                "from storage import load_template_file\n\n"
                "def render_invoice(request_dict):\n"
                "    template_name = request_dict.get('tpl', 'default.html')\n"
                "    # Directly forwards user input to storage layer\n"
                "    content = load_template_file('/srv/templates', template_name)\n"
                "    return content\n"
            ),
            "storage.py": (
                "import os\n\n"
                "def load_template_file(root_dir, rel_path):\n"
                "    # Vulnerable: string concatenation allows ../ traversal\n"
                "    full_path = root_dir + '/' + rel_path\n"
                "    with open(full_path, 'r', encoding='utf-8') as f:\n"
                "        return f.read()\n"
            ),
        },
        "patched_files": {
            "app.py": (
                "from storage import load_template_file\n\n"
                "def render_invoice(request_dict):\n"
                "    template_name = request_dict.get('tpl', 'default.html')\n"
                "    content = load_template_file('/srv/templates', template_name)\n"
                "    return content\n"
            ),
            "storage.py": (
                "from pathlib import Path\n\n"
                "def load_template_file(root_dir, rel_path):\n"
                "    # Patched: canonical path resolution and containment check\n"
                "    base = Path(root_dir).resolve()\n"
                "    candidate = (base / rel_path).resolve()\n"
                "    if base not in candidate.parents and candidate != base:\n"
                "        raise ValueError('Unauthorized path traversal attempt')\n"
                "    return candidate.read_text(encoding='utf-8')\n"
            ),
        },
    },
    {
        "pair_id": "pair_04_ssrf",
        "cwe": "CWE-918",
        "name": "Webhook SSRF with Incomplete Loopback Blacklist",
        "entry_file": "app.py",
        "true_root_cause_func": "validate_webhook_target",
        "vuln_files": {
            "app.py": (
                "from net_utils import dispatch_webhook\n\n"
                "def register_and_ping_webhook(payload):\n"
                "    callback_url = payload.get('callback_url', '')\n"
                "    return dispatch_webhook(callback_url, {'status': 'ok'})\n"
            ),
            "net_utils.py": (
                "import urllib.request\n"
                "from url_policy import validate_webhook_target\n\n"
                "def dispatch_webhook(url, data):\n"
                "    if not validate_webhook_target(url):\n"
                "        raise ValueError('Blocked webhook URL')\n"
                "    req = urllib.request.Request(url, method='POST')\n"
                "    with urllib.request.urlopen(req, timeout=3) as resp:\n"
                "        return resp.status\n"
            ),
            "url_policy.py": (
                "from urllib.parse import urlparse\n\n"
                "def validate_webhook_target(url):\n"
                "    parsed = urlparse(url)\n"
                "    # Vulnerable: only blocks literal 'localhost', allows 127.0.0.1 and 169.254.169.254\n"
                "    if parsed.scheme not in ('http', 'https'):\n"
                "        return False\n"
                "    if parsed.hostname == 'localhost':\n"
                "        return False\n"
                "    return True\n"
            ),
        },
        "patched_files": {
            "app.py": (
                "from net_utils import dispatch_webhook\n\n"
                "def register_and_ping_webhook(payload):\n"
                "    callback_url = payload.get('callback_url', '')\n"
                "    return dispatch_webhook(callback_url, {'status': 'ok'})\n"
            ),
            "net_utils.py": (
                "import urllib.request\n"
                "from url_policy import validate_webhook_target\n\n"
                "def dispatch_webhook(url, data):\n"
                "    if not validate_webhook_target(url):\n"
                "        raise ValueError('Blocked webhook URL')\n"
                "    req = urllib.request.Request(url, method='POST')\n"
                "    with urllib.request.urlopen(req, timeout=3) as resp:\n"
                "        return resp.status\n"
            ),
            "url_policy.py": (
                "import ipaddress\n"
                "import socket\n"
                "from urllib.parse import urlparse\n\n"
                "def validate_webhook_target(url):\n"
                "    parsed = urlparse(url)\n"
                "    if parsed.scheme not in ('http', 'https') or not parsed.hostname:\n"
                "        return False\n"
                "    ip_str = socket.gethostbyname(parsed.hostname)\n"
                "    ip_obj = ipaddress.ip_address(ip_str)\n"
                "    if ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local:\n"
                "        return False\n"
                "    return True\n"
            ),
        },
    },
]


def build_benchmark():
    os.makedirs(BENCHMARK_DIR, exist_ok=True)
    manifest = []

    for item in PAIRS:
        pair_path = os.path.join(BENCHMARK_DIR, item["pair_id"])
        vuln_dir = os.path.join(pair_path, "vuln")
        patched_dir = os.path.join(pair_path, "patched")
        os.makedirs(vuln_dir, exist_ok=True)
        os.makedirs(patched_dir, exist_ok=True)

        for fname, code in item["vuln_files"].items():
            with open(os.path.join(vuln_dir, fname), "w", encoding="utf-8") as f:
                f.write(code)

        for fname, code in item["patched_files"].items():
            with open(os.path.join(patched_dir, fname), "w", encoding="utf-8") as f:
                f.write(code)

        manifest.append({
            "pair_id": item["pair_id"],
            "cwe": item["cwe"],
            "name": item["name"],
            "entry_file": item["entry_file"],
            "true_root_cause_func": item["true_root_cause_func"],
            "vuln_dir": vuln_dir,
            "patched_dir": patched_dir,
        })

    manifest_path = os.path.join(BENCHMARK_DIR, "manifest.json")
    with open(manifest_path, "w", encoding="utf-8") as f:
        json.dump(manifest, f, indent=2)

    print(f"[+] Created {len(manifest)} vulnerability/fix pairs in '{BENCHMARK_DIR}/'")


if __name__ == "__main__":
    build_benchmark()
