"""Follow-up prompts for the three feedback conditions.

Every condition starts from the SAME round-0 DREA analysis (same conversation
history), then sends one of these messages as the next user turn. Only the
message differs between conditions, so differences in outcome come from the
kind of feedback, not from a different first analysis.

Conditions
----------
self_refine : Self-Refine style (Madaan et al., 2023). The Planner critiques
              and refines its own analysis using only what it has already
              seen. No new exploration. Tests feedback WITHOUT new evidence.
explore     : Unguided extra exploration. The Planner may explore more but
              chooses what to look at itself. Tests MORE EVIDENCE without
              verifier guidance (the compute/budget control).
verified    : VERA-DREA. A verifier checks each claim against the code; the
              Planner gets claim-level findings plus targeted exploration
              requests. Tests evidence-guided feedback (our method).

All three ask for the same output format, so DREA's evaluator and judge work
unchanged, plus two extra tags used for analysis:
  <revision_status>CONFIRMED | REVISED | REVERSED</revision_status>
  <revision_note>...</revision_note>
"""

from __future__ import annotations

OUTPUT_REMINDER = """
## Required output

End your response with your complete, final assessment in EXACTLY the XML format
from your instructions:
- VULNERABLE: <security_assessment>, <vulnerability> (type, location, root_cause),
  <trigger_path> (source, propagation, sink), and <evidence>.
- SECURE: <security_assessment> and <security_analysis> (checked_operations,
  validation_evidence).

Then add these two tags:
<revision_status>CONFIRMED | REVISED | REVERSED</revision_status>
  CONFIRMED = same verdict, same explanation
  REVISED   = same verdict, explanation changed (type, location, root cause, or path)
  REVERSED  = verdict changed (VULNERABLE <-> SECURE)
<revision_note>One or two sentences: what changed, and which code evidence caused it.
If nothing changed, say why your analysis holds.</revision_note>
""".strip()


# ---------------------------------------------------------------------------
# Condition 1: Self-Refine (no new evidence)
# ---------------------------------------------------------------------------
SELF_REFINE = """
## Review round {round} of {max_rounds}: critique and refine your analysis

Review the security assessment you just gave. Work in two steps.

### Step 1: Feedback
Write specific, actionable feedback on your own analysis. Check each part:
- Type: does the CWE you chose match the mechanism you describe?
- Location: did you point to the exact function and lines where the flaw is?
- Root cause: is it the specific missing or bypassed check, not a generic
  "insufficient input validation"?
- Trigger path: is every step from attacker input to the dangerous operation
  shown in code you actually read, or did you assume some steps?
- Evidence: does every quoted line exist exactly as quoted?
- Verdict: does your conclusion follow from the points above?
List each problem you find. If you find none, say so.

### Step 2: Refine
Write an improved final assessment that fixes the problems from Step 1.

Constraints:
- Use ONLY the code and evidence already in this conversation.
- Do NOT call the `task` tool or delegate to the explore subagent in this round.
- Change your verdict only if your own feedback shows it cannot be supported.

{output_reminder}
""".strip()


# ---------------------------------------------------------------------------
# Condition 2: Unguided extra exploration (budget control)
# ---------------------------------------------------------------------------
EXPLORE_MORE = """
## Review round {round} of {max_rounds}: investigate further before finalizing

Before finalizing, double-check your analysis against the repository.

- You may use the `task` tool with the `explore` subagent to gather more code
  evidence. Decide for yourself what is most worth checking.
- Then decide whether your assessment still holds.
- Change your verdict only if the evidence shows the original conclusion
  cannot be supported.

{output_reminder}
""".strip()


# ---------------------------------------------------------------------------
# Condition 3: VERA-DREA (verifier-guided, targeted exploration)
# ---------------------------------------------------------------------------
VERIFIED = """
## Verification round {round} of {max_rounds}: claim-level feedback

An independent verifier checked the claims in your last assessment against the
repository source code. The verifier does NOT know the correct answer. It only
checks whether each claim is backed by code.

Summary: {n_supported} supported, {n_contradicted} contradicted, {n_unresolved} unresolved.

### Claims that need attention
{claim_blocks}

### What to do
1. For each CONTRADICTED or UNRESOLVED claim above, delegate its suggested
   exploration to the `explore` subagent using the `task` tool. Investigate
   these specific gaps; do not restart the whole analysis.
2. Use the retrieved code to decide whether each flagged claim holds.
3. Leave claims the verifier marked SUPPORTED unchanged unless new code
   evidence contradicts them.
4. Then reach the conclusion the evidence supports:
   - CONFIRMED if the gaps resolve in favor of your assessment.
   - REVISED if your verdict stands but the type, location, root cause, or
     trigger path was wrong.
   - REVERSED if the evidence shows your verdict cannot be supported.
   Changing your answer is not the goal. A VULNERABLE verdict needs an
   evidenced path from attacker input to the dangerous operation; a SECURE
   verdict needs quoted code showing the protection.
5. Name the specific missing or bypassed check. Do not fall back on a generic
   "insufficient input validation" explanation.

{output_reminder}
""".strip()

CLAIM_BLOCK = """
[{claim_id}] {field} | {status}{failure_type}
  Your claim: {claim_text}
  Verifier finding: {finding}
  Evidence needed: {evidence_needed}
  Suggested exploration: {exploration_request}
""".strip()


def _clip(text: str, limit: int = 400) -> str:
    text = " ".join((text or "").split())
    return text if len(text) <= limit else text[: limit - 3] + "..."


def build_self_refine(round_idx: int, max_rounds: int) -> str:
    return SELF_REFINE.format(
        round=round_idx, max_rounds=max_rounds, output_reminder=OUTPUT_REMINDER
    )


def build_explore_more(round_idx: int, max_rounds: int) -> str:
    return EXPLORE_MORE.format(
        round=round_idx, max_rounds=max_rounds, output_reminder=OUTPUT_REMINDER
    )


def build_verified(round_idx: int, max_rounds: int, audit) -> str:
    """`audit` is a core.verifier.AuditResult."""
    blocks = []
    for check in audit.attention_checks():
        blocks.append(
            CLAIM_BLOCK.format(
                claim_id=check.claim_id,
                field=check.field,
                status=check.status,
                failure_type=(
                    f" | failure type: {check.failure_type}"
                    if check.failure_type
                    else ""
                ),
                claim_text=_clip(check.claim_text),
                finding=_clip(check.finding),
                evidence_needed=_clip(check.evidence_needed),
                exploration_request=_clip(check.exploration_request),
            )
        )
    counts = audit.counts()
    return VERIFIED.format(
        round=round_idx,
        max_rounds=max_rounds,
        n_supported=counts["SUPPORTED"],
        n_contradicted=counts["CONTRADICTED"],
        n_unresolved=counts["UNRESOLVED"],
        claim_blocks="\n\n".join(blocks),
        output_reminder=OUTPUT_REMINDER,
    )
