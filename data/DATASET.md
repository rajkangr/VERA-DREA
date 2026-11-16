# RepoPairBench 100

`repopairbench_100.jsonl` contains the 100 vulnerable/fixed function pairs used
by DREA. Each line is one JSON object with:

- `id`: short sample identifier.
- `project_name`: upstream project name.
- `repo_url`: public Git repository URL.
- `commit_hash`: fixing commit.
- `language`: source language tag.
- `cve_ids`: associated CVE identifiers.
- `cwe_ids`: associated CWE identifiers.
- `vuln_data.file_path`: target file path in the upstream repository.
- `vuln_data.code_before`: vulnerable target function before the fix.
- `vuln_data.code_after`: patched target function after the fix.

`repopairbench_100_manifest.json` is a compact manifest for browsing sample
metadata. Full repository context is not vendored in this artifact. Use
`data/scripts/clone_repos.sh` and `data/scripts/build_paired_dataset.py` to
reconstruct local repository snapshots from the public upstream repositories.

The dataset metadata is intended for research evaluation. Users are responsible
for respecting the licenses of the upstream repositories cloned during
reconstruction.
