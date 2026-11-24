"""Parse the Planner's XML assessment into structured fields and claims.

DREA's system prompt already forces this format:
  <security_assessment>VULNERABLE|SECURE</security_assessment>
  <vulnerability><type/><location/><root_cause/></vulnerability>
  <trigger_path><source/><propagation/><sink/></trigger_path>
  <evidence/>
or, for SECURE:
  <security_analysis><checked_operations/><validation_evidence/></security_analysis>

We split it into claims the verifier can check one by one.
"""

from __future__ import annotations

import re
from dataclasses import asdict, dataclass, field
from typing import Any

VULN_FIELDS = [
    ("type", "vulnerability/type"),
    ("location", "vulnerability/location"),
    ("root_cause", "vulnerability/root_cause"),
    ("source", "trigger_path/source"),
    ("propagation", "trigger_path/propagation"),
    ("sink", "trigger_path/sink"),
    ("evidence", "evidence"),
]
SECURE_FIELDS = [
    ("checked_operations", "security_analysis/checked_operations"),
    ("validation_evidence", "security_analysis/validation_evidence"),
]
ALL_TAGS = [name for name, _ in VULN_FIELDS + SECURE_FIELDS] + [
    "revision_status",
    "revision_note",
]


@dataclass
class Claim:
    claim_id: str  # e.g. "C3"
    field: str  # e.g. "trigger_path/source"
    text: str


@dataclass
class ParsedAssessment:
    verdict: str | None  # "VULNERABLE", "SECURE", or None if missing
    fields: dict[str, str] = field(default_factory=dict)
    revision_status: str | None = None
    revision_note: str | None = None
    raw_text: str = ""

    def claims(self) -> list[Claim]:
        spec = VULN_FIELDS if self.verdict == "VULNERABLE" else SECURE_FIELDS
        out: list[Claim] = []
        for name, label in spec:
            text = self.fields.get(name, "").strip()
            if text:
                out.append(Claim(f"C{len(out) + 1}", label, text))
        return out

    def srr(self) -> dict[str, Any]:
        """Structured Reasoning Record fields used for lucky-hit analysis.

        Derived from DREA's own XML (no prompt change), so round 0 stays the
        unmodified DREA baseline:
          cwe                  first CWE id in <type>
          root_cause_function  function named in <location>
          claims               the checkable claims (see claims())
          assumptions          trigger-path steps that name functions; the
                               verifier decides whether they were checked
        """
        vul = self.verdict == "VULNERABLE"
        claims = self.claims()
        return {
            "cwe": extract_cwe(self.fields.get("type")) if vul else None,
            "root_cause_function": extract_function(self.fields.get("location")) if vul else None,
            "location": self.fields.get("location") if vul else None,
            "claims": [asdict(c) for c in claims],
            "assumptions": [asdict(c) for c in claims
                            if c.field.startswith("trigger_path/") and "(" in c.text],
        }

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d.pop("raw_text", None)
        d["claims"] = [asdict(c) for c in self.claims()]
        d["srr"] = self.srr()
        return d


def _last_tag(text: str, tag: str) -> str | None:
    """Content of the LAST <tag>...</tag> (models sometimes repeat drafts)."""
    matches = re.findall(rf"<{tag}>(.*?)</{tag}>", text, flags=re.DOTALL | re.I)
    return matches[-1].strip() if matches else None


def normalize_verdict(raw: str | None) -> str | None:
    """Map the text inside <security_assessment> to VULNERABLE, SECURE or None.

    The old check (`"VULNERABLE" in raw`) read "NOT VULNERABLE" as VULNERABLE
    and "INSECURE" as SECURE. Now: an exact word wins; negations and
    "INSECURE" are handled; anything ambiguous (both words) is None.
    """
    words = re.sub(r"[^A-Z ]+", " ", (raw or "").upper()).split()
    text = " ".join(words)
    if text in ("VULNERABLE", "SECURE"):
        return text
    if re.search(r"\b(NOT|NON) VULNERABLE\b", text) or "NOT INSECURE" in text:
        return "SECURE"
    if re.search(r"\bNOT SECURE\b", text) or "INSECURE" in words:
        return "VULNERABLE"
    has_vul, has_sec = "VULNERABLE" in words, "SECURE" in words
    if has_vul and not has_sec:
        return "VULNERABLE"
    if has_sec and not has_vul:
        return "SECURE"
    return None


CWE_RE = re.compile(r"CWE[\s_-]*(\d+)", re.I)


def extract_cwe(type_text: str | None) -> str | None:
    """First CWE id in <type>, normalized to 'CWE-<n>'."""
    m = CWE_RE.search(type_text or "")
    return f"CWE-{int(m.group(1))}" if m else None


# Words that are not function names but often appear in <location> text.
_NOT_FUNCS = {
    "line", "lines", "file", "files", "function", "functions", "method", "methods",
    "class", "module", "view", "views", "handler", "endpoint", "route", "code", "call",
    "called", "in", "the", "and", "or", "of", "at", "to", "from", "for", "with", "via",
    "on", "by", "is", "a", "an", "inside", "within", "where", "which", "when", "then",
    "py", "python", "see", "near", "around", "approximately", "approx", "line_number",
}


def extract_function(location: str | None) -> str | None:
    """Best guess at the function named in <location>.

    Handles 'file.py: func()', 'func() in file.py', 'def func', 'Class.method',
    'function `func`', 'file.py, lines 10-20 (func)' and 'func function'.
    Returns the bare name (last part of a dotted name). Tries patterns from most
    to least specific and skips plain words such as 'lines' or 'and' (Nov 24:
    the first version returned those for about a third of the dev answers).
    """
    text = location or ""
    patterns = [
        r"\bdef\s+([A-Za-z_]\w*)",                                   # def func
        r"`([A-Za-z_][\w.]*)\s*(?:\([^`]*\))?`",                       # `func` / `func(x)`
        r"\b(?:function|method|view|handler|endpoint)\s+`?([A-Za-z_][\w.]*)",  # function func
        r"([A-Za-z_][\w.]*)\s*\(",                                     # func(
        r"\b([A-Za-z_][\w.]*)\s+(?:function|method|view|handler|endpoint)\b",  # func function
        r"\(\s*([A-Za-z_][\w.]*)\s*\)",                                # (func)
        r"\.py\s*[:,\-]{1,2}\s*([A-Za-z_][\w.]*)",                     # file.py: func
        r"::\s*([A-Za-z_][\w.]*)",                                     # file.py::func
    ]
    for pat in patterns:
        for m in re.finditer(pat, text):
            name = m.group(1).rstrip(".").split(".")[-1]
            if (len(name) >= 2 and name.lower() not in _NOT_FUNCS
                    and not name.lower().endswith("py") and not name.isdigit()):
                return name
    return None


def parse_assessment(text: str) -> ParsedAssessment:
    text = text or ""
    verdict = normalize_verdict(_last_tag(text, "security_assessment"))

    fields = {}
    for tag in ALL_TAGS:
        value = _last_tag(text, tag)
        if value is not None:
            fields[tag] = value

    status = (fields.pop("revision_status", "") or "").upper()
    status = next(
        (s for s in ("CONFIRMED", "REVISED", "REVERSED") if s in status), None
    )
    note = fields.pop("revision_note", None)
    return ParsedAssessment(
        verdict=verdict,
        fields=fields,
        revision_status=status,
        revision_note=note,
        raw_text=text,
    )


def extract_code_quotes(text: str) -> list[str]:
    """Code the Planner quoted: fenced blocks and inline `backticks`.

    Returns individual non-trivial lines, which the verifier can look up in
    the source.
    """
    quotes: list[str] = []
    for block in re.findall(r"```[\w+-]*\n(.*?)```", text or "", flags=re.DOTALL):
        quotes.extend(line for line in block.splitlines())
    for inline in re.findall(r"`([^`\n]{6,})`", text or ""):
        quotes.append(inline)
    cleaned = []
    for q in quotes:
        q = q.strip()
        q = re.sub(r"^\d+\s*[:|]\s*", "", q)  # drop "42: " / "42 | " prefixes
        if len(q) >= 6 and not q.startswith(("#", "...", "…")):
            cleaned.append(q)
    return cleaned
