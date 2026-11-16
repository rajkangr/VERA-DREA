"""Verifier interface used by the VERA-DREA feedback loop.

>>> This is the contract between the feedback loop (Saksham) and the verifier
>>> (Raj). The loop only needs `verify(...)` to return an `AuditResult`.

`verify()` below is a PLACEHOLDER with two simple deterministic checks so the
loop can be tested end to end. Replace it with the real VERA-style checks
(AST-based edges, CWE sink/sanitizer tables, LLM checks for semantic claims).

Statuses (per claim):
  SUPPORTED    - code evidence confirms the claim
  CONTRADICTED - code shows the claim is false
  UNRESOLVED   - the evidence needed to check it is not available yet
  UNCHECKED    - this verifier has no check for this kind of claim
Only CONTRADICTED and UNRESOLVED claims are sent back to the Planner.

Failure types follow VERA's taxonomy (Hu et al., 2026, Table 2), adapted:
  F1 Scope / evidence integrity   (misquoted code, wrong variables)
  F2 External assumption          (unchecked claims about callers/callees)
  F5 Trace incompleteness         (missing hops between source and sink)
  F6 Path fabrication             (path through a branch that doesn't exist)
  F8 Verdict inconsistency        (verdict contradicts its own reasoning)
"""

from __future__ import annotations

import os
import re
from collections import Counter
from dataclasses import asdict, dataclass, field
from functools import lru_cache
from pathlib import Path
from typing import Any

from .verdict import ParsedAssessment, extract_code_quotes

STATUSES = ("SUPPORTED", "CONTRADICTED", "UNRESOLVED", "UNCHECKED")
SKIP_DIRS = {".git", "node_modules", ".venv", "venv", "__pycache__", "dist", "build"}


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
# Repository index (cached): normalized source lines of every .py file
# --------------------------------------------------------------------------
def _norm(s: str) -> str:
    return re.sub(r"\s+", "", s)


@lru_cache(maxsize=8)
def _repo_index(workspace: str) -> tuple[frozenset[str], str]:
    lines: set[str] = set()
    chunks: list[str] = []
    for root, dirs, files in os.walk(workspace):
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
        for name in files:
            if not name.endswith(".py"):
                continue
            path = Path(root) / name
            try:
                if path.stat().st_size > 2_000_000:
                    continue
                text = path.read_text(encoding="utf-8", errors="ignore")
            except OSError:
                continue
            chunks.append(text)
            for line in text.splitlines():
                n = _norm(line)
                if n:
                    lines.add(n)
    return frozenset(lines), "\n".join(chunks)


def _quote_exists(quote: str, target_code: str, workspace: Path) -> bool:
    nq = _norm(quote)
    if not nq:
        return True
    if nq in _norm(target_code):
        return True
    lines, _ = _repo_index(str(workspace))
    if nq in lines:
        return True
    return any(nq in line for line in lines) if len(nq) >= 12 else False


def _symbol_defined(name: str, workspace: Path) -> bool:
    _, blob = _repo_index(str(workspace))
    return bool(
        re.search(rf"^\s*(async\s+)?def\s+{re.escape(name)}\b", blob, re.M)
        or re.search(rf"^\s*class\s+{re.escape(name)}\b", blob, re.M)
        or re.search(rf"\b{re.escape(name)}\s*=", blob)
        or re.search(rf"import\s+.*\b{re.escape(name)}\b", blob)
    )


BUILTINS = {
    "open", "len", "str", "int", "dict", "list", "print", "isinstance",
    "getattr", "setattr", "format", "join", "split", "replace", "strip",
    "get", "read", "write", "eval", "exec", "range", "super", "type",
}


# --------------------------------------------------------------------------
# PLACEHOLDER verify(): replace with the real verifier
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
                exploration_request="No exploration needed; restate your final assessment in the required format.",
            )
        )
        return result

    for claim in parsed.claims():
        check = ClaimCheck(claim.claim_id, claim.field, claim.text, "UNCHECKED")

        # Check 1 (deterministic): quoted code must exist in the repository.
        if claim.field in ("evidence", "security_analysis/validation_evidence"):
            quotes = extract_code_quotes(claim.text)
            missing = [q for q in quotes if not _quote_exists(q, target_code, workspace)]
            if quotes and not missing:
                check.status = "SUPPORTED"
                check.finding = f"All {len(quotes)} quoted code line(s) were found in the repository."
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
                check.exploration_request = "Retrieve and quote the exact code lines this claim relies on."

        # Check 2 (deterministic): functions named in the trigger path must exist.
        elif claim.field.startswith("trigger_path/"):
            called = set(re.findall(r"\b([A-Za-z_][A-Za-z0-9_]{2,})\s*\(", claim.text))
            called -= BUILTINS
            missing = sorted(n for n in called if not _symbol_defined(n, workspace))
            if called and not missing:
                check.status = "SUPPORTED"
                check.finding = "Every function named in this step is defined or imported in the repository."
            elif missing:
                check.status = "UNRESOLVED"
                check.failure_type = "F2 External assumption"
                check.finding = (
                    "These functions are named in your trigger path but no definition "
                    f"or import was found: {', '.join(missing[:5])}."
                )
                check.evidence_needed = "Where these functions are defined, and what they do with the tainted value."
                check.exploration_request = (
                    f"Locate the definition of `{missing[0]}` (or its import source) and "
                    "report whether it validates, sanitizes, or passes through its input."
                )

        result.checks.append(check)
    return result
