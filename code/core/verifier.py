"""Verifier interface used by the VERA-DREA feedback loop.

>>> This is the contract between the feedback loop (Saksham) and the verifier
>>> (Raj). The loop only needs `verify(...)` to return an `AuditResult`.

Ports the deterministic AST and grounding checks from the VERA-DREA MVP
(`vera_drea_mvp.py`) into general, repository-agnostic checks using
`check_from_code()`.

Statuses (per claim):
  SUPPORTED    - code evidence confirms the claim
  CONTRADICTED - code shows the claim is false
  UNRESOLVED   - the evidence needed to check it is not available yet
  UNCHECKED    - this verifier has no check for this kind of claim
Only CONTRADICTED and UNRESOLVED claims are sent back to the Planner.

Failure types follow VERA's taxonomy (Hu et al., 2026, Table 2), adapted:
  F1 Scope / evidence integrity   (misquoted code, hallucinated symbols)
  F2 External assumption          (unchecked claims about callers/callees)
  F5 Trace incompleteness         (missing hops between source and sink)
  F6 Path fabrication             (missed protection/sanitizer on the path)
  F8 Verdict inconsistency        (verdict contradicts its own reasoning)
"""

from __future__ import annotations

import ast
import builtins
import keyword
import os
import re
import textwrap
from collections import Counter
from dataclasses import asdict, dataclass, field
from functools import lru_cache
from pathlib import Path
from typing import Any

from .verdict import (
    ParsedAssessment,
    extract_code_quotes,
    extract_cwe,
    extract_function,
)

STATUSES = ("SUPPORTED", "CONTRADICTED", "UNRESOLVED", "UNCHECKED")
SKIP_DIRS = {".git", "node_modules", ".venv", "venv", "__pycache__", "dist", "build"}

MAX_FILE_BYTES = 2_000_000
MAX_UNINSPECTED_CALLEES = 3
MAX_AMBIGUOUS_DEFS = 3  # skip ultra-generic repo names defined in >3 places


@dataclass
class ClaimCheck:
    claim_id: str
    field: str
    claim_text: str
    status: str  # one of STATUSES
    failure_type: str | None = None
    finding: str = ""
    evidence_needed: str = ""
    exploration_request: str = ""  # a concrete task for the explore subagent


@dataclass
class AuditResult:
    verdict: str | None
    checks: list[ClaimCheck] = field(default_factory=list)

    def attention_checks(self) -> list[ClaimCheck]:
        return [c for c in self.checks if c.status in ("CONTRADICTED", "UNRESOLVED")]

    def needs_attention(self) -> bool:
        return bool(self.attention_checks())

    def counts(self) -> dict[str, int]:
        counter = Counter(c.status for c in self.checks)
        return {s: counter.get(s, 0) for s in STATUSES}

    def to_dict(self) -> dict[str, Any]:
        return {
            "verdict": self.verdict,
            "counts": self.counts(),
            "checks": [asdict(c) for c in self.checks],
        }


# --------------------------------------------------------------------------
# Raj's MVP failure codes -> this interface (raj-baseline/vera_drea_mvp.py)
# --------------------------------------------------------------------------
RAJ_CODE_MAP: dict[str, dict[str, str]] = {
    "HALLUCINATED_SYMBOL": {
        "status": "CONTRADICTED",
        "failure_type": "F1 Scope / evidence integrity",
        "finding": "The claim names `{name}`, but no such function exists in the repository.",
        "evidence_needed": "The function that actually performs this step.",
        "exploration_request": "Search the repository for `{name}`. If it does not exist, find the "
                               "function that really handles this step and quote it with its file path.",
    },
    "UNGROUNDED_CLAIM": {
        "status": "UNRESOLVED",
        "failure_type": "F2 External assumption",
        "finding": "The claim relies on `{name}`, whose code was never retrieved.",
        "evidence_needed": "The source of `{name}`.",
        "exploration_request": "Read `{name}` and quote the lines that support or refute this claim.",
    },
    "UNVERIFIED_ASSUMPTION": {
        "status": "UNRESOLVED",
        "failure_type": "F2 External assumption",
        "finding": "The analysis assumes how `{name}` behaves without reading it.",
        "evidence_needed": "Whether `{name}` validates, sanitizes, or passes its input through.",
        "exploration_request": "Read `{name}` and report whether it validates, sanitizes, or passes "
                               "the tainted value through unchanged.",
    },
    "UNINSPECTED_CALLEE": {
        "status": "UNRESOLVED",
        "failure_type": "F5 Trace incompleteness",
        "finding": "Code on the trigger path calls `{name}`, which was not inspected.",
        "evidence_needed": "What `{name}` does with the tainted value.",
        "exploration_request": "Inspect `{name}` (called on the trigger path) and report whether it "
                               "changes, checks, or blocks the tainted value.",
    },
    "PROTECTION_PRESENT": {
        "status": "CONTRADICTED",
        "failure_type": "F6 Path fabrication (missed protection)",
        "finding": "`{name}` applies a protection on this path that the claim does not account for.",
        "evidence_needed": "Why the protection in `{name}` does not stop the attack, with code.",
        "exploration_request": "Read `{name}` and decide whether its check can be bypassed; quote "
                               "the exact lines. If it cannot, the path is not exploitable.",
    },
    "LLM_CONTRADICTED": {
        "status": "CONTRADICTED",
        "failure_type": "F8 Verdict inconsistency",
        "finding": "The audit model judged this claim inconsistent with the retrieved code: {name}",
        "evidence_needed": "Code that supports the claim, or a corrected claim.",
        "exploration_request": "Re-check this claim against the code and quote the lines it depends on.",
    },
}


def check_from_code(
    code: str, claim_id: str, field: str, claim_text: str, name: str
) -> ClaimCheck:
    """Build a ClaimCheck from one of Raj's MVP failure codes."""
    spec = RAJ_CODE_MAP[code]
    return ClaimCheck(
        claim_id=claim_id,
        field=field,
        claim_text=claim_text,
        status=spec["status"],
        failure_type=spec["failure_type"],
        finding=spec["finding"].format(name=name),
        evidence_needed=spec["evidence_needed"].format(name=name),
        exploration_request=spec["exploration_request"].format(name=name),
    )


# --------------------------------------------------------------------------
# Symbol filters (prevent false alarms on builtins, stdlib, and prose words)
# --------------------------------------------------------------------------
BUILTINS: frozenset[str] = frozenset(dir(builtins)) | frozenset(keyword.kwlist) | {
    "self", "cls", "args", "kwargs",
    # Common Python object/stdlib/framework methods & logging helpers
    "get", "set", "pop", "put", "add", "append", "extend", "insert", "remove",
    "clear", "copy", "keys", "values", "items", "update", "setdefault",
    "read", "readline", "readlines", "write", "writelines", "close", "flush",
    "seek", "tell", "encode", "decode", "format", "join", "split", "rsplit",
    "splitlines", "strip", "lstrip", "rstrip", "replace", "lower", "upper",
    "startswith", "endswith", "find", "rfind", "index", "count",
    "match", "search", "findall", "sub", "compile", "group", "groups",
    "system", "popen", "Popen", "run", "call", "check_output", "check_call",
    "execute", "executemany", "fetchone", "fetchall", "commit", "rollback",
    "loads", "dumps", "load", "dump", "safe_load", "literal_eval",
    "abspath", "realpath", "normpath", "basename", "dirname", "exists",
    "isfile", "isdir", "makedirs", "mkdir", "unlink", "rename", "walk",
    "resolve", "relative_to", "is_relative_to", "read_text", "write_text",
    "read_bytes", "write_bytes",
    "debug", "info", "warning", "warn", "error", "critical", "exception", "log",
    "writeln", "render", "redirect", "abort", "jsonify", "send_file",
    "reverse", "sleep", "time", "now", "isoformat", "exit", "raise_for_status",
    "__init__", "__call__", "__str__", "__repr__", "__enter__", "__exit__",
}

LOCATION_STOPWORDS: frozenset[str] = frozenset({
    "line", "lines", "file", "function", "method", "class", "module", "code",
    "script", "handler", "endpoint", "route", "view", "controller", "block",
    "body", "loop", "branch", "check", "call", "return", "input", "output",
    "path", "query", "request", "response", "the", "and", "for", "with", "from",
    "in", "at", "on", "of", "to", "by",
})

# Words indicating the Planner already analyzed why a detected protection fails.
BYPASS_KEYWORDS: tuple[str, ...] = (
    "bypass", "bypassed", "circumvent", "insufficient", "incomplete",
    "race condition", "toctou", "redirect", "rebinding", "symlink",
    "does not prevent", "fails to block", "only checks", "can still",
    "without checking", "missing check",
)


# --------------------------------------------------------------------------
# Repository AST index (cached per workspace)
# --------------------------------------------------------------------------
def _norm(s: str) -> str:
    return re.sub(r"\s+", "", s)


def _parse_ast_safe(source: str) -> ast.AST | None:
    """Parse Python source, tolerating indented method snippets."""
    if not source:
        return None
    try:
        return ast.parse(source)
    except SyntaxError:
        pass
    try:
        return ast.parse(textwrap.dedent(source))
    except SyntaxError:
        return None


def _extract_callees_from_node(node: ast.AST) -> tuple[str, ...]:
    """Return ordered unique function/method names invoked inside `node`."""
    seen: list[str] = []
    for child in ast.walk(node):
        if not isinstance(child, ast.Call):
            continue
        name: str | None = None
        if isinstance(child.func, ast.Name):
            name = child.func.id
        elif isinstance(child.func, ast.Attribute):
            name = child.func.attr
        if name and name not in seen:
            seen.append(name)
    return tuple(seen)


@dataclass(frozen=True)
class FuncInfo:
    name: str
    rel_path: str
    source: str
    norm_lines: frozenset[str]
    callees: tuple[str, ...]


@dataclass(frozen=True)
class RepoIndex:
    lines: frozenset[str]
    raw_blob: str
    functions: dict[str, tuple[FuncInfo, ...]]
    classes: frozenset[str]
    imports: frozenset[str]
    assignments: frozenset[str]


@lru_cache(maxsize=8)
def _repo_index(workspace: str) -> RepoIndex:
    lines: set[str] = set()
    chunks: list[str] = []
    funcs_mut: dict[str, list[FuncInfo]] = {}
    classes: set[str] = set()
    imports: set[str] = set()
    assignments: set[str] = set()

    for root, dirs, files in os.walk(workspace):
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
        for fname in sorted(files):
            if not fname.endswith(".py"):
                continue
            path = Path(root) / fname
            try:
                if path.stat().st_size > MAX_FILE_BYTES:
                    continue
                text = path.read_text(encoding="utf-8", errors="ignore")
            except OSError:
                continue

            chunks.append(text)
            src_lines = text.splitlines()
            for line in src_lines:
                n = _norm(line)
                if n:
                    lines.add(n)

            rel_path = os.path.relpath(path, workspace)
            tree = _parse_ast_safe(text)
            if tree is None:
                continue

            for node in ast.walk(tree):
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    start = max(0, node.lineno - 1)
                    end = getattr(node, "end_lineno", start + 1) or (start + 1)
                    func_src = "\n".join(src_lines[start:end])
                    fn_norm = frozenset(
                        n for ln in src_lines[start:end] if (n := _norm(ln))
                    )
                    info = FuncInfo(
                        name=node.name,
                        rel_path=rel_path,
                        source=func_src,
                        norm_lines=fn_norm,
                        callees=_extract_callees_from_node(node),
                    )
                    funcs_mut.setdefault(node.name, []).append(info)
                elif isinstance(node, ast.ClassDef):
                    classes.add(node.name)
                elif isinstance(node, ast.Import):
                    for alias in node.names:
                        imports.add(alias.asname or alias.name.split(".")[0])
                elif isinstance(node, ast.ImportFrom):
                    for alias in node.names:
                        if alias.name != "*":
                            imports.add(alias.asname or alias.name)
                elif isinstance(node, ast.Assign):
                    for target in node.targets:
                        if isinstance(target, ast.Name):
                            assignments.add(target.id)
                elif isinstance(node, ast.AnnAssign) and isinstance(
                    node.target, ast.Name
                ):
                    assignments.add(node.target.id)

    return RepoIndex(
        lines=frozenset(lines),
        raw_blob="\n".join(chunks),
        functions={k: tuple(v) for k, v in funcs_mut.items()},
        classes=frozenset(classes),
        imports=frozenset(imports),
        assignments=frozenset(assignments),
    )


def _extract_target_info(
    target_code: str,
) -> tuple[set[str], list[str], set[str], ast.AST | None]:
    """Parse `target_code` for defined functions, called functions, and imports."""
    defined: set[str] = set()
    called: list[str] = []
    imports: set[str] = set()

    tree = _parse_ast_safe(target_code)
    if tree is not None:
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                defined.add(node.name)
            elif isinstance(node, ast.Import):
                for alias in node.names:
                    imports.add(alias.asname or alias.name.split(".")[0])
            elif isinstance(node, ast.ImportFrom):
                for alias in node.names:
                    if alias.name != "*":
                        imports.add(alias.asname or alias.name)
            elif isinstance(node, ast.Call):
                name: str | None = None
                if isinstance(node.func, ast.Name):
                    name = node.func.id
                elif isinstance(node.func, ast.Attribute):
                    name = node.func.attr
                if name and name not in called:
                    called.append(name)
        return defined, called, imports, tree

    # Fallback if target_code snippet is truncated and fails AST parsing
    for m in re.finditer(r"^\s*(?:async\s+)?def\s+([A-Za-z_]\w*)", target_code, re.M):
        defined.add(m.group(1))
    for m in re.finditer(r"\b([A-Za-z_]\w*)\s*\(", target_code):
        name = m.group(1)
        if name not in defined and name not in called:
            called.append(name)
    return defined, called, imports, None


# --------------------------------------------------------------------------
# Quote and symbol grounding helpers
# --------------------------------------------------------------------------
def _clean_quote(quote: str) -> str:
    # Strip optional unified-diff leading +/- markers if the model pasted a diff
    return re.sub(r"^[+-]\s*", "", quote.strip())


def _quote_exists(quote: str, target_code: str, repo: RepoIndex) -> bool:
    nq = _norm(_clean_quote(quote))
    if not nq:
        return True
    if nq in _norm(target_code):
        return True
    if nq in repo.lines:
        return True
    return any(nq in line for line in repo.lines) if len(nq) >= 12 else False


def _symbol_exists_anywhere(name: str, target_code: str, repo: RepoIndex) -> bool:
    if (
        name in repo.functions
        or name in repo.classes
        or name in repo.imports
        or name in repo.assignments
    ):
        return True
    if re.search(rf"\b{re.escape(name)}\b", target_code):
        return True
    return bool(re.search(rf"\b{re.escape(name)}\b", repo.raw_blob))


def _func_is_quoted(name: str, repo: RepoIndex, all_quotes: list[str]) -> bool:
    """True if at least one non-trivial line from `name`'s definition was quoted."""
    norm_quotes = [_norm(_clean_quote(q)) for q in all_quotes]
    norm_quotes = [nq for nq in norm_quotes if len(nq) >= 6]
    if not norm_quotes:
        return False

    def_sig = f"def{name}("
    for info in repo.functions.get(name, ()):
        for nq in norm_quotes:
            if def_sig in nq:
                return True
            if nq in info.norm_lines:
                return True
            if len(nq) >= 12 and any(nq in ln for ln in info.norm_lines):
                return True
    return False


def _extract_called_symbols(text: str) -> list[tuple[str | None, str]]:
    """Extract (qualifier, func_name) pairs from `foo()` / `obj.foo()` in prose.

    `qualifier` is None for bare calls `foo()`, or the prefix before the last
    dot (e.g. `self`, `os.path`, `utils`) for attribute calls.
    """
    out: list[tuple[str | None, str]] = []
    seen: set[tuple[str | None, str]] = set()
    for m in re.finditer(
        r"\b([A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)*)\s*\(", text or ""
    ):
        full = m.group(1)
        if "." in full:
            qual, name = full.rsplit(".", 1)
        else:
            qual, name = None, full
        if len(name) < 3 or name in BUILTINS or name.lower() in LOCATION_STOPWORDS:
            continue
        item = (qual, name)
        if item not in seen:
            seen.add(item)
            out.append(item)
    return out


# --------------------------------------------------------------------------
# General MVP static protection checks (CWE-89, CWE-78, CWE-22, CWE-918)
# --------------------------------------------------------------------------
def _is_formatted_string_expr(node: ast.AST) -> bool:
    """True if AST expression builds a string dynamically (+, %, f-string, .format)."""
    if isinstance(node, ast.JoinedStr):
        return True
    if isinstance(node, ast.BinOp) and isinstance(node.op, (ast.Add, ast.Mod)):
        return True
    if (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr == "format"
    ):
        return True
    return False


def _detect_mvp_protection(cwe: str | None, source: str) -> bool:
    """Conservative, general AST check for neutralizing patterns from the MVP.

    Returns True only when an unambiguous protection for `cwe` is present in
    `source` without a co-occurring unsafe sink for the same CWE.
    """
    if not cwe or not source:
        return False
    tree = _parse_ast_safe(source)

    # CWE-89 (SQL Injection): parameterized execute(query, params) without formatting
    if cwe == "CWE-89" and tree is not None:
        has_param_exec = False
        has_unsafe_exec = False
        for node in ast.walk(tree):
            if (
                isinstance(node, ast.Call)
                and isinstance(node.func, ast.Attribute)
                and node.func.attr in ("execute", "executemany")
                and node.args
            ):
                if _is_formatted_string_expr(node.args[0]):
                    has_unsafe_exec = True
                elif len(node.args) >= 2:
                    has_param_exec = True
        return has_param_exec and not has_unsafe_exec

    # CWE-78 / CWE-77 (Command Injection): subprocess with list args and shell=False
    if cwe in ("CWE-78", "CWE-77") and tree is not None:
        has_safe_subproc = False
        has_unsafe_exec = False
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            attr = node.func.attr if isinstance(node.func, ast.Attribute) else None
            name = node.func.id if isinstance(node.func, ast.Name) else attr
            if name in ("system", "popen"):
                has_unsafe_exec = True
            elif name in ("run", "Popen", "call", "check_output", "check_call"):
                shell_kw = next((kw.value for kw in node.keywords if kw.arg == "shell"), None)
                shell_true = isinstance(shell_kw, ast.Constant) and shell_kw.value is True
                if shell_true:
                    has_unsafe_exec = True
                elif node.args and isinstance(node.args[0], (ast.List, ast.Tuple)):
                    has_safe_subproc = True
        return has_safe_subproc and not has_unsafe_exec

    # CWE-22 (Path Traversal): safe_join / send_from_directory or canonical containment
    if cwe == "CWE-22":
        if re.search(r"\b(safe_join|send_from_directory)\s*\(", source):
            return True
        has_canon = bool(re.search(r"\b(realpath|normpath)\s*\(|\.resolve\s*\(", source))
        has_contain = bool(
            re.search(r"\b(startswith|commonpath|is_relative_to)\s*\(|\.parents\b", source)
        )
        return has_canon and has_contain

    # CWE-918 (SSRF): ipaddress validation checking private/loopback/link-local ranges
    if cwe == "CWE-918":
        has_ip_mod = bool(re.search(r"\b(ipaddress|ip_address|ip_network)\b", source))
        checks = sum(
            bool(re.search(rf"\b{attr}\b", source))
            for attr in ("is_private", "is_loopback", "is_link_local", "is_reserved", "is_multicast")
        )
        return has_ip_mod and checks >= 2

    return False


# --------------------------------------------------------------------------
# Main verifier entry point
# --------------------------------------------------------------------------
def verify(
    parsed: ParsedAssessment,
    workspace: Path,
    target_code: str,
) -> AuditResult:
    """Check each claim in `parsed` against the code in `workspace`."""
    result = AuditResult(verdict=parsed.verdict)

    if parsed.verdict is None:
        result.checks.append(
            ClaimCheck(
                claim_id="C0",
                field="security_assessment",
                claim_text="(missing)",
                status="CONTRADICTED",
                failure_type="F8 Verdict inconsistency",
                finding="No <security_assessment> verdict was found in your output.",
                evidence_needed="A single VULNERABLE or SECURE verdict.",
                exploration_request=(
                    "No exploration needed; restate your final assessment in the required format."
                ),
            )
        )
        return result

    repo = _repo_index(str(workspace))
    target_defs, target_calls, target_imports, _ = _extract_target_info(target_code)

    # Collect all quoted lines across the assessment to test helper grounding
    all_quotes: list[str] = []
    for text in parsed.fields.values():
        all_quotes.extend(extract_code_quotes(text))

    flagged_symbols: set[str] = set()
    cited_repo_helpers: list[str] = []

    for claim in parsed.claims():
        check = ClaimCheck(claim.claim_id, claim.field, claim.text, "UNCHECKED")

        # ------------------------------------------------------------------
        # Check 1 (F1): Quoted code in evidence / validation_evidence
        # ------------------------------------------------------------------
        if claim.field in ("evidence", "security_analysis/validation_evidence"):
            quotes = extract_code_quotes(claim.text)
            missing = [q for q in quotes if not _quote_exists(q, target_code, repo)]
            if quotes and not missing:
                check.status = "SUPPORTED"
                check.finding = (
                    f"All {len(quotes)} quoted code line(s) were found in the repository."
                )
            elif missing:
                check.status = "CONTRADICTED"
                check.failure_type = "F1 Scope / evidence integrity"
                check.finding = (
                    f"{len(missing)} quoted line(s) do not appear in the repository, "
                    f"e.g. `{missing[0][:120]}`."
                )
                check.evidence_needed = "The exact source lines that support this evidence."
                check.exploration_request = (
                    "Find and quote, verbatim with file path and line numbers, the code "
                    f"you meant by `{missing[0][:120]}`; report if no such code exists."
                )
            else:
                check.status = "UNRESOLVED"
                check.failure_type = "F1 Scope / evidence integrity"
                check.finding = "This claim quotes no code, so it cannot be checked."
                check.evidence_needed = "Verbatim code lines supporting the claim."
                check.exploration_request = (
                    "Retrieve and quote the exact code lines this claim relies on."
                )

        # ------------------------------------------------------------------
        # Check 2 (F1 / F2): Root-cause function in vulnerability/location
        # ------------------------------------------------------------------
        elif claim.field == "vulnerability/location":
            fn = extract_function(claim.text)
            if (
                fn
                and len(fn) >= 3
                and fn not in BUILTINS
                and fn.lower() not in LOCATION_STOPWORDS
            ):
                if fn in target_defs:
                    check.status = "SUPPORTED"
                    check.finding = f"`{fn}` is defined in the target code."
                elif fn in repo.functions:
                    cited_repo_helpers.append(fn)
                    if _func_is_quoted(fn, repo, all_quotes):
                        check.status = "SUPPORTED"
                        check.finding = f"`{fn}` exists in the repository and is quoted in evidence."
                    else:
                        check = check_from_code(
                            "UNGROUNDED_CLAIM", claim.claim_id, claim.field, claim.text, fn
                        )
                        flagged_symbols.add(fn)
                elif _symbol_exists_anywhere(fn, target_code, repo):
                    check.status = "SUPPORTED"
                    check.finding = f"`{fn}` is defined or imported in the repository."
                else:
                    # Only flag HALLUCINATED_SYMBOL if explicitly formatted as a call/code symbol
                    if re.search(rf"(`{re.escape(fn)}|\b{re.escape(fn)}\s*\(|\bdef\s+{re.escape(fn)}\b)", claim.text):
                        check = check_from_code(
                            "HALLUCINATED_SYMBOL", claim.claim_id, claim.field, claim.text, fn
                        )
                        flagged_symbols.add(fn)

        # ------------------------------------------------------------------
        # Check 3 (F1 / F2): Symbols in trigger_path/* & checked_operations
        # ------------------------------------------------------------------
        elif (
            claim.field.startswith("trigger_path/")
            or claim.field == "security_analysis/checked_operations"
        ):
            calls = _extract_called_symbols(claim.text)
            hallucinated: str | None = None
            unverified: str | None = None
            grounded_count = 0

            for qual, name in calls:
                if name in target_defs:
                    grounded_count += 1
                    continue

                if name in repo.functions:
                    cited_repo_helpers.append(name)
                    if _func_is_quoted(name, repo, all_quotes):
                        grounded_count += 1
                    elif len(repo.functions[name]) <= MAX_AMBIGUOUS_DEFS:
                        if unverified is None:
                            unverified = name
                    else:
                        grounded_count += 1
                    continue

                if (
                    name in repo.classes
                    or name in repo.imports
                    or name in repo.assignments
                    or name in target_imports
                ):
                    grounded_count += 1
                    continue

                # Attribute calls on non-self objects (e.g. `requests.get()`, `etree.fromstring()`)
                # are usually external/third-party methods; don't flag as hallucinated.
                if qual is not None and qual not in ("self", "cls"):
                    continue

                if not _symbol_exists_anywhere(name, target_code, repo):
                    if hallucinated is None:
                        hallucinated = name

            if hallucinated is not None:
                check = check_from_code(
                    "HALLUCINATED_SYMBOL", claim.claim_id, claim.field, claim.text, hallucinated
                )
                flagged_symbols.add(hallucinated)
            elif unverified is not None:
                check = check_from_code(
                    "UNVERIFIED_ASSUMPTION", claim.claim_id, claim.field, claim.text, unverified
                )
                flagged_symbols.add(unverified)
            elif grounded_count > 0:
                check.status = "SUPPORTED"
                check.finding = "Named functions in this step exist in the repository and are grounded."

        result.checks.append(check)

    # ----------------------------------------------------------------------
    # Check 4 (F5): Uninspected repository callees invoked by target_code
    # ----------------------------------------------------------------------
    uninspected: list[str] = []
    for callee in target_calls:
        if (
            callee in target_defs
            or callee in BUILTINS
            or callee in flagged_symbols
            or callee not in repo.functions
        ):
            continue
        defs = repo.functions[callee]
        if len(defs) > MAX_AMBIGUOUS_DEFS:
            continue
        if _func_is_quoted(callee, repo, all_quotes):
            continue
        uninspected.append(callee)
        if len(uninspected) >= MAX_UNINSPECTED_CALLEES:
            break

    for idx, callee in enumerate(uninspected, start=1):
        defs = repo.functions[callee]
        locs = ", ".join(sorted({d.rel_path for d in defs}))
        result.checks.append(
            check_from_code(
                "UNINSPECTED_CALLEE",
                claim_id=f"U{idx}",
                field="trigger_path/callee",
                claim_text=f"Target code invokes `{callee}()` (defined in {locs}), which was not quoted in the assessment.",
                name=callee,
            )
        )

    # ----------------------------------------------------------------------
    # Check 5 (F6): General MVP protection check (VULNERABLE verdicts only)
    # ----------------------------------------------------------------------
    if parsed.verdict == "VULNERABLE":
        cwe = extract_cwe(parsed.fields.get("type"))
        rationale_blob = (
            (parsed.fields.get("root_cause") or "")
            + "\n"
            + (parsed.fields.get("evidence") or "")
        ).lower()
        discusses_bypass = any(kw in rationale_blob for kw in BYPASS_KEYWORDS)

        if cwe and not discusses_bypass:
            # Check target_code first
            if _detect_mvp_protection(cwe, target_code):
                fn_label = next(iter(sorted(target_defs)), "target function")
                result.checks.append(
                    check_from_code(
                        "PROTECTION_PRESENT",
                        claim_id="P1",
                        field="vulnerability/root_cause",
                        claim_text=parsed.fields.get("root_cause", "(no root cause)"),
                        name=fn_label,
                    )
                )
            else:
                # Check uniquely-defined cited repo helpers that were already quoted
                for helper in dict.fromkeys(cited_repo_helpers):
                    defs = repo.functions.get(helper, ())
                    if (
                        len(defs) == 1
                        and _func_is_quoted(helper, repo, all_quotes)
                        and _detect_mvp_protection(cwe, defs[0].source)
                    ):
                        result.checks.append(
                            check_from_code(
                                "PROTECTION_PRESENT",
                                claim_id="P1",
                                field="vulnerability/root_cause",
                                claim_text=parsed.fields.get("root_cause", "(no root cause)"),
                                name=helper,
                            )
                        )
                        break

    return result
