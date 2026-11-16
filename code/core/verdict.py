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

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d.pop("raw_text", None)
        d["claims"] = [asdict(c) for c in self.claims()]
        return d


def _last_tag(text: str, tag: str) -> str | None:
    """Content of the LAST <tag>...</tag> (models sometimes repeat drafts)."""
    matches = re.findall(rf"<{tag}>(.*?)</{tag}>", text, flags=re.DOTALL | re.I)
    return matches[-1].strip() if matches else None


def parse_assessment(text: str) -> ParsedAssessment:
    text = text or ""
    verdict_raw = _last_tag(text, "security_assessment") or ""
    verdict_raw = verdict_raw.upper()
    if "VULNERABLE" in verdict_raw:
        verdict = "VULNERABLE"
    elif "SECURE" in verdict_raw:
        verdict = "SECURE"
    else:
        verdict = None

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
