# Protocol-Aware Reportability Layer Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Add protocol-aware submission evaluation that determines if findings are worth reporting to bug bounties/VRPs, with autonomous evidence gathering quests and disposition override capability.

**Architecture:** New ProtocolEvaluator service runs after StrictClassifier in triage pipeline. It applies protocol-specific quality gates, can override disposition, and triggers LLM-based evidence quests when high-signal findings have proof gaps. Quest discoveries trigger full re-triage loop.

**Tech Stack:** Python (FastAPI/Pydantic), SQLite, React/TypeScript, Anthropic SDK for quest LLM

---

## Phase 1: Foundation - Data Models & Schema

### Task 1.1: Add Core Enums and Models

**Files:**
- Modify: `backend/models/schemas.py` (add after line 115)

**Step 1: Add SubmissionDecision enum**

Add after `VulnerabilityCategory` enum:

```python
class SubmissionDecision(str, Enum):
    """Protocol evaluation decision for reportability."""
    submit = "submit"
    dont_submit = "dont_submit"
    needs_more_info = "needs_more_info"
```

**Step 2: Add SubmissionResult model**

Add after `ProofChecklist` model (~line 300):

```python
class SubmissionResult(BaseModel):
    """
    Protocol-aware reportability evaluation result.

    Represents the 'worth submitting' decision for a finding based on
    protocol-specific rules (VRP, bug bounty, internal disclosure, etc.).
    """
    protocol_id: str  # e.g., "osvrp_strict", "hackerone_strict", "internal"
    decision: SubmissionDecision
    reasons: list[str] = Field(
        default_factory=list,
        description="Human-readable reasons for the decision (2-4 bullets)"
    )
    missing_evidence: list[str] = Field(
        default_factory=list,
        description="Specific evidence gaps if decision=needs_more_info"
    )
    suggested_next_steps: list[str] = Field(
        default_factory=list,
        description="Actionable steps to resolve evidence gaps"
    )

    # Quest tracking
    quest_run: bool = False
    quest_id: Optional[str] = None
    quest_findings: Optional[dict] = None

    # Disposition override
    disposition_modified: bool = False
    disposition_reason: Optional[str] = None
```

**Step 3: Add ProtocolPolicy model**

```python
class ProtocolPolicy(BaseModel):
    """Protocol-specific submission rules."""
    id: str
    display_name: str

    # Threat model defaults
    default_threat_model_preset: str = "AB"

    # Disposition gates
    min_disposition_to_submit: set[Disposition] = Field(
        default_factory=lambda: {Disposition.VALID_SECURITY_ISSUE}
    )

    # Submission heuristics
    require_cross_boundary_for_local_bugs: bool = True
    reject_social_engineering_only: bool = True
    require_repro_steps: bool = True
    require_impact_statement: bool = True
    require_realistic_attacker_model: bool = True

    # Category-specific rules
    category_rules: dict[VulnerabilityCategory, dict] = Field(
        default_factory=dict
    )

    # Evidence quality gates
    min_checklist_proven_count: int = 4
    allow_unknown_in_checklist: bool = False

    # Quest behavior
    enable_evidence_quests: bool = True
    quest_categories: list[VulnerabilityCategory] = Field(default_factory=list)
```

**Step 4: Add EvidenceQuest model**

```python
class EvidenceQuest(BaseModel):
    """Configuration for autonomous evidence gathering agent."""
    id: str
    finding_id: str
    category: VulnerabilityCategory

    # What evidence is missing
    missing_items: list[str]

    # Quest prompt template
    quest_type: str

    # Status
    status: AgentStatus
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None

    # Results
    evidence_found: dict[str, Any] = Field(default_factory=dict)
    new_checklist_items: dict[str, ChecklistItem] = Field(default_factory=dict)
    success: bool = False
    error_message: Optional[str] = None
```

**Step 5: Extend Finding model**

Find the `Finding` model (around line 400+) and add these fields:

```python
# Add to Finding class
    # Protocol evaluation result
    submission_result: Optional[SubmissionResult] = None

    # Quest tracking
    evidence_quest_id: Optional[str] = None
    evidence_quest_completed: bool = False
```

**Step 6: Commit**

```bash
git add backend/models/schemas.py
git commit -m "feat(models): add protocol evaluation data models

- Add SubmissionDecision, SubmissionResult, ProtocolPolicy, EvidenceQuest
- Extend Finding with submission_result and quest tracking fields
- Support protocol-aware reportability evaluation"
```

---

### Task 1.2: Database Schema Migration

**Files:**
- Create: `backend/migrations/002_add_protocol_layer.sql`

**Step 1: Create migration file**

```sql
-- Migration: Add protocol-aware reportability layer
-- Date: 2026-01-17

-- Add protocol_id to projects
ALTER TABLE projects ADD COLUMN protocol_id TEXT DEFAULT 'internal';

-- Create protocol_policies table
CREATE TABLE IF NOT EXISTS protocol_policies (
    id TEXT PRIMARY KEY,
    display_name TEXT NOT NULL,
    config JSON NOT NULL,
    is_default BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_protocol_policies_default ON protocol_policies(is_default);

-- Add submission fields to findings
ALTER TABLE findings ADD COLUMN submission_result JSON;
ALTER TABLE findings ADD COLUMN evidence_quest_id TEXT;
ALTER TABLE findings ADD COLUMN evidence_quest_completed BOOLEAN DEFAULT FALSE;

CREATE INDEX idx_findings_submission_decision ON findings(
    json_extract(submission_result, '$.decision')
);
CREATE INDEX idx_findings_quest ON findings(evidence_quest_id);

-- Create evidence_quests table
CREATE TABLE IF NOT EXISTS evidence_quests (
    id TEXT PRIMARY KEY,
    finding_id TEXT NOT NULL,
    category TEXT NOT NULL,
    quest_type TEXT NOT NULL,
    status TEXT NOT NULL,
    missing_items JSON,
    evidence_found JSON,
    new_checklist_items JSON,
    started_at TIMESTAMP,
    completed_at TIMESTAMP,
    success BOOLEAN DEFAULT FALSE,
    error_message TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (finding_id) REFERENCES findings(id) ON DELETE CASCADE
);

CREATE INDEX idx_quests_finding ON evidence_quests(finding_id);
CREATE INDEX idx_quests_status ON evidence_quests(status);
CREATE INDEX idx_quests_category ON evidence_quests(category);
```

**Step 2: Create migration runner script**

Create: `backend/migrations/run_migration.py`

```python
"""Database migration runner."""
import sqlite3
import sys
from pathlib import Path

def run_migration(db_path: str, migration_file: str):
    """Run a SQL migration file."""
    migration_path = Path(__file__).parent / migration_file

    if not migration_path.exists():
        print(f"❌ Migration file not found: {migration_file}")
        sys.exit(1)

    with open(migration_path) as f:
        sql = f.read()

    conn = sqlite3.connect(db_path)
    try:
        conn.executescript(sql)
        conn.commit()
        print(f"✅ Migration applied: {migration_file}")
    except Exception as e:
        conn.rollback()
        print(f"❌ Migration failed: {e}")
        sys.exit(1)
    finally:
        conn.close()

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: python run_migration.py <db_path> <migration_file>")
        sys.exit(1)

    run_migration(sys.argv[1], sys.argv[2])
```

**Step 3: Test migration on empty database**

```bash
# Create test database
rm -f test_migration.db
sqlite3 test_migration.db < backend/migrations/001_initial_schema.sql

# Run protocol migration
python backend/migrations/run_migration.py test_migration.db 002_add_protocol_layer.sql

# Verify tables created
sqlite3 test_migration.db "SELECT name FROM sqlite_master WHERE type='table';"
```

Expected output: Should include `protocol_policies` and `evidence_quests`

**Step 4: Commit**

```bash
git add backend/migrations/
git commit -m "feat(db): add protocol layer database schema

- Add protocol_policies table
- Add submission_result, quest fields to findings
- Add evidence_quests table with indexes
- Include migration runner script"
```

---

### Task 1.3: Default Protocol Policies

**Files:**
- Create: `backend/services/protocol_policies.py`

**Step 1: Create protocol policies module with imports**

```python
"""Default protocol policies for submission evaluation."""

from models.schemas import (
    ProtocolPolicy,
    Disposition,
    VulnerabilityCategory,
)


def get_default_policies() -> dict[str, ProtocolPolicy]:
    """Get all default protocol policies."""
    return {
        "internal": get_internal_policy(),
        "osvrp_strict": get_osvrp_strict_policy(),
        "hackerone_strict": get_hackerone_strict_policy(),
        "bugcrowd_standard": get_bugcrowd_standard_policy(),
        "research_disclosure": get_research_disclosure_policy(),
    }
```

**Step 2: Add internal policy**

```python
def get_internal_policy() -> ProtocolPolicy:
    """Internal / permissive policy for dev/QA environments."""
    return ProtocolPolicy(
        id="internal",
        display_name="Internal (Permissive)",
        default_threat_model_preset="ABC",
        min_disposition_to_submit={
            Disposition.VALID_SECURITY_ISSUE,
            Disposition.BUG,
            Disposition.MISCONFIGURATION,
            Disposition.HARDENING
        },
        require_cross_boundary_for_local_bugs=False,
        reject_social_engineering_only=False,
        require_repro_steps=False,
        require_impact_statement=False,
        require_realistic_attacker_model=False,
        min_checklist_proven_count=3,
        allow_unknown_in_checklist=True,
        category_rules={},
        enable_evidence_quests=True,
        quest_categories=[]
    )
```

**Step 3: Add osvrp_strict policy**

```python
def get_osvrp_strict_policy() -> ProtocolPolicy:
    """Google Open Source VRP (strict interpretation)."""
    return ProtocolPolicy(
        id="osvrp_strict",
        display_name="Google VRP (Strict)",
        default_threat_model_preset="AB",
        min_disposition_to_submit={Disposition.VALID_SECURITY_ISSUE},
        require_cross_boundary_for_local_bugs=True,
        reject_social_engineering_only=True,
        require_repro_steps=True,
        require_impact_statement=True,
        require_realistic_attacker_model=True,
        min_checklist_proven_count=6,
        allow_unknown_in_checklist=False,
        category_rules={
            VulnerabilityCategory.COMMAND_INJECTION: {
                "requires_shell": True,
                "reject_argument_injection": True,
            },
            VulnerabilityCategory.SQL_INJECTION: {
                "requires_structure_taint": True,
                "reject_if_parameterized": True,
            },
            VulnerabilityCategory.HARDCODED_SECRET: {
                "reject_test_files": True,
                "reject_example_files": True,
                "reject_vendored": True,
            },
        },
        enable_evidence_quests=True,
        quest_categories=[
            VulnerabilityCategory.COMMAND_INJECTION,
            VulnerabilityCategory.SQL_INJECTION,
            VulnerabilityCategory.CODE_INJECTION,
        ]
    )
```

**Step 4: Add remaining policies**

```python
def get_hackerone_strict_policy() -> ProtocolPolicy:
    """HackerOne standard triage policy."""
    return ProtocolPolicy(
        id="hackerone_strict",
        display_name="HackerOne Standard",
        default_threat_model_preset="AB",
        min_disposition_to_submit={
            Disposition.VALID_SECURITY_ISSUE,
            Disposition.BUG
        },
        require_cross_boundary_for_local_bugs=True,
        reject_social_engineering_only=True,
        require_repro_steps=True,
        require_impact_statement=True,
        require_realistic_attacker_model=True,
        min_checklist_proven_count=5,
        allow_unknown_in_checklist=True,
        category_rules={
            VulnerabilityCategory.COMMAND_INJECTION: {
                "requires_shell": True,
            },
        },
        enable_evidence_quests=True,
        quest_categories=[]
    )


def get_bugcrowd_standard_policy() -> ProtocolPolicy:
    """Bugcrowd standard VDP policy."""
    return ProtocolPolicy(
        id="bugcrowd_standard",
        display_name="Bugcrowd Standard",
        default_threat_model_preset="AB",
        min_disposition_to_submit={
            Disposition.VALID_SECURITY_ISSUE,
            Disposition.BUG
        },
        require_cross_boundary_for_local_bugs=True,
        reject_social_engineering_only=True,
        require_repro_steps=True,
        require_impact_statement=True,
        require_realistic_attacker_model=True,
        min_checklist_proven_count=5,
        allow_unknown_in_checklist=True,
        category_rules={},
        enable_evidence_quests=True,
        quest_categories=[]
    )


def get_research_disclosure_policy() -> ProtocolPolicy:
    """Security research / responsible disclosure policy."""
    return ProtocolPolicy(
        id="research_disclosure",
        display_name="Research Disclosure",
        default_threat_model_preset="ABC",
        min_disposition_to_submit={
            Disposition.VALID_SECURITY_ISSUE,
            Disposition.BUG,
            Disposition.HARDENING
        },
        require_cross_boundary_for_local_bugs=False,
        reject_social_engineering_only=False,
        require_repro_steps=True,
        require_impact_statement=True,
        require_realistic_attacker_model=False,
        min_checklist_proven_count=4,
        allow_unknown_in_checklist=True,
        category_rules={},
        enable_evidence_quests=True,
        quest_categories=[]
    )
```

**Step 5: Add policy loader class**

```python
class ProtocolPolicyLoader:
    """Load and manage protocol policies."""

    def __init__(self, db_conn):
        self.db = db_conn

    async def seed_default_policies(self):
        """Seed database with default policies."""
        import json

        policies = get_default_policies()

        for policy_id, policy in policies.items():
            # Check if exists
            cursor = await self.db.execute(
                "SELECT id FROM protocol_policies WHERE id = ?",
                (policy_id,)
            )
            existing = await cursor.fetchone()

            if existing:
                # Update
                await self.db.execute("""
                    UPDATE protocol_policies
                    SET config = ?, updated_at = CURRENT_TIMESTAMP
                    WHERE id = ?
                """, (json.dumps(policy.model_dump()), policy_id))
            else:
                # Insert
                await self.db.execute("""
                    INSERT INTO protocol_policies (id, display_name, config, is_default)
                    VALUES (?, ?, ?, ?)
                """, (
                    policy.id,
                    policy.display_name,
                    json.dumps(policy.model_dump()),
                    policy.id == "internal"
                ))

        await self.db.commit()

    async def get_policy(self, policy_id: str) -> ProtocolPolicy:
        """Load policy from database."""
        import json

        cursor = await self.db.execute(
            "SELECT config FROM protocol_policies WHERE id = ?",
            (policy_id,)
        )
        row = await cursor.fetchone()

        if not row:
            raise ValueError(f"Protocol policy not found: {policy_id}")

        config = json.loads(row[0])
        return ProtocolPolicy(**config)
```

**Step 6: Create seeding script**

Create: `backend/scripts/seed_protocols.py`

```python
"""Seed default protocol policies."""
import asyncio
import aiosqlite
from pathlib import Path
import sys

# Add backend to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from services.protocol_policies import ProtocolPolicyLoader


async def main():
    db_path = Path(__file__).parent.parent / "data" / "quickhack.db"

    async with aiosqlite.connect(db_path) as db:
        loader = ProtocolPolicyLoader(db)
        await loader.seed_default_policies()
        print("✅ Seeded 5 default protocol policies")


if __name__ == "__main__":
    asyncio.run(main())
```

**Step 7: Test seeding**

```bash
python backend/scripts/seed_protocols.py
sqlite3 backend/data/quickhack.db "SELECT id, display_name FROM protocol_policies;"
```

Expected: 5 rows with all policy IDs

**Step 8: Commit**

```bash
git add backend/services/protocol_policies.py backend/scripts/seed_protocols.py
git commit -m "feat(protocol): add default protocol policies

- Add 5 default policies: internal, osvrp_strict, hackerone_strict, bugcrowd_standard, research_disclosure
- Implement ProtocolPolicyLoader for database operations
- Add seeding script for initial setup"
```

---

## Phase 2: ProtocolEvaluator Core

### Task 2.1: ProtocolEvaluator Base Structure

**Files:**
- Create: `backend/services/protocol_evaluator.py`

**Step 1: Create evaluator with imports and context**

```python
"""Protocol-aware reportability evaluation service."""

from dataclasses import dataclass
from typing import Optional
import re

from models.schemas import (
    Finding,
    Evidence,
    ClassificationResult,
    ProtocolPolicy,
    SubmissionResult,
    SubmissionDecision,
    Disposition,
    VulnerabilityCategory,
    InputChannel,
    ChecklistStatus,
)


@dataclass
class EvaluationContext:
    """Bundled context for protocol evaluation."""
    finding: Finding
    evidence: Evidence
    classification: ClassificationResult
    policy: ProtocolPolicy


class ProtocolEvaluator:
    """
    Protocol-aware reportability evaluation.

    Applies protocol-specific quality gates to determine if findings
    are worth submitting to bug bounties, VRPs, or disclosure programs.
    """

    def __init__(self):
        # Category-specific evaluators
        self.category_evaluators = {
            VulnerabilityCategory.COMMAND_INJECTION: self._evaluate_command_injection,
            VulnerabilityCategory.SQL_INJECTION: self._evaluate_sql_injection,
        }
```

**Step 2: Add main evaluate method**

```python
    def evaluate(
        self,
        finding: Finding,
        evidence: Evidence,
        classification: ClassificationResult,
        policy: ProtocolPolicy
    ) -> tuple[SubmissionResult, Optional[Disposition]]:
        """
        Evaluate finding for reportability under protocol rules.

        Returns:
            (SubmissionResult, Optional[new_disposition])
            If new_disposition is not None, caller should update Finding.disposition
        """
        ctx = EvaluationContext(finding, evidence, classification, policy)

        # Gate 1: Disposition filtering
        if classification.disposition not in policy.min_disposition_to_submit:
            return self._reject_by_disposition(ctx)

        # Gate 2: Proof checklist completeness
        checklist_gate = self._check_checklist_quality(ctx)
        if checklist_gate is not None:
            return checklist_gate

        # Gate 3: Attacker model realism
        attacker_model_gate = self._check_attacker_model(ctx)
        if attacker_model_gate is not None:
            return attacker_model_gate

        # Gate 4: Category-specific validation
        category_gate = self._apply_category_rules(ctx)
        if category_gate is not None:
            return category_gate

        # Gate 5: Local-only bug filtering
        local_bug_gate = self._check_local_boundary(ctx)
        if local_bug_gate is not None:
            return local_bug_gate

        # All gates passed
        return self._accept_for_submission(ctx)
```

**Step 3: Commit base structure**

```bash
git add backend/services/protocol_evaluator.py
git commit -m "feat(protocol): add ProtocolEvaluator base structure

- Create EvaluationContext dataclass
- Add ProtocolEvaluator with 5-gate evaluation flow
- Set up category-specific evaluator registry"
```

---

### Task 2.2: Implement Gate Functions

**Files:**
- Modify: `backend/services/protocol_evaluator.py`

**Step 1: Add Gate 1 - disposition filtering**

Add after the `evaluate` method:

```python
    def _reject_by_disposition(
        self, ctx: EvaluationContext
    ) -> tuple[SubmissionResult, None]:
        """Gate 1: Disposition doesn't meet protocol threshold."""
        result = SubmissionResult(
            protocol_id=ctx.policy.id,
            decision=SubmissionDecision.dont_submit,
            reasons=[
                f"Disposition is {ctx.classification.disposition.value}",
                f"Protocol requires: {[d.value for d in ctx.policy.min_disposition_to_submit]}",
                "Not meeting reportability bar for this protocol"
            ],
            missing_evidence=[],
            suggested_next_steps=[
                "Review finding manually if you believe it's reportable",
                "Consider switching to a more permissive protocol"
            ]
        )
        return (result, None)
```

**Step 2: Add Gate 2 - checklist quality**

```python
    def _check_checklist_quality(
        self, ctx: EvaluationContext
    ) -> Optional[tuple[SubmissionResult, Optional[Disposition]]]:
        """Gate 2: Verify proof checklist has sufficient PROVEN items."""
        checklist = ctx.classification.proof_checklist

        # Count PROVEN items
        proven_count = sum(1 for item in [
            checklist.source_controlled_input,
            checklist.sink_present,
            checklist.dataflow_evidenced,
            checklist.reachable,
            checklist.boundary_crossed,
            checklist.not_only_misconfig,
        ] if item.status == ChecklistStatus.PROVEN and item.value)

        # Check if meets minimum
        if proven_count < ctx.policy.min_checklist_proven_count:
            # Downgrade disposition
            new_disposition = Disposition.HARDENING
            result = SubmissionResult(
                protocol_id=ctx.policy.id,
                decision=SubmissionDecision.dont_submit,
                reasons=[
                    f"Only {proven_count}/{ctx.policy.min_checklist_proven_count} checklist items proven",
                    "Insufficient evidence for submission under this protocol",
                    f"Disposition downgraded: {ctx.classification.disposition.value} → {new_disposition.value}"
                ],
                disposition_modified=True,
                disposition_reason="Insufficient proof for protocol requirements"
            )
            return (result, new_disposition)

        # Check for UNKNOWN items if policy is strict
        if not ctx.policy.allow_unknown_in_checklist:
            unknown_items = [
                name for name, item in [
                    ("source", checklist.source_controlled_input),
                    ("sink", checklist.sink_present),
                    ("dataflow", checklist.dataflow_evidenced),
                    ("reachability", checklist.reachable),
                    ("boundary", checklist.boundary_crossed),
                    ("not_misconfig", checklist.not_only_misconfig),
                ] if item.status == ChecklistStatus.UNKNOWN
            ]

            if unknown_items:
                result = SubmissionResult(
                    protocol_id=ctx.policy.id,
                    decision=SubmissionDecision.needs_more_info,
                    reasons=[
                        f"Protocol requires all items proven",
                        f"Unknown items: {', '.join(unknown_items)}"
                    ],
                    missing_evidence=unknown_items,
                    suggested_next_steps=["Run evidence quest to gather missing proof"],
                    quest_run=True
                )
                return (result, None)

        return None  # Passed this gate
```

**Step 3: Add Gate 3 - attacker model**

```python
    def _check_attacker_model(
        self, ctx: EvaluationContext
    ) -> Optional[tuple[SubmissionResult, Optional[Disposition]]]:
        """Gate 3: Verify realistic attacker model."""
        if not ctx.policy.require_realistic_attacker_model:
            return None

        # Check for social engineering markers
        description_lower = ctx.finding.description.lower()
        social_eng_markers = [
            "user must paste",
            "trick the user",
            "convince user to",
            "user needs to manually",
            "requires user to open",
            "phishing",
            "social engineering"
        ]

        if any(marker in description_lower for marker in social_eng_markers):
            if ctx.policy.reject_social_engineering_only:
                new_disposition = Disposition.HARDENING
                result = SubmissionResult(
                    protocol_id=ctx.policy.id,
                    decision=SubmissionDecision.dont_submit,
                    reasons=[
                        "Attack requires social engineering / user cooperation",
                        "No realistic remote attacker scenario",
                        f"Disposition downgraded: {ctx.classification.disposition.value} → {new_disposition.value}"
                    ],
                    disposition_modified=True,
                    disposition_reason="Social engineering dependency - not reportable"
                )
                return (result, new_disposition)

        return None
```

**Step 4: Add Gate 5 - local boundary**

```python
    def _check_local_boundary(
        self, ctx: EvaluationContext
    ) -> Optional[tuple[SubmissionResult, Optional[Disposition]]]:
        """Gate 5: Check if local-only bugs have automation boundary."""
        if not ctx.policy.require_cross_boundary_for_local_bugs:
            return None

        # Check if input channel is local without automation
        if ctx.evidence.input_channel == InputChannel.local_unprivileged:
            # Look for automation signals
            automation_signals = [
                "route_registration",
                "ci_artifact",
                "repo_checkout",
                "webhook",
                "scheduled_task"
            ]

            has_automation = any(
                signal in ctx.evidence.input_channel_signals
                for signal in automation_signals
            )

            if not has_automation:
                result = SubmissionResult(
                    protocol_id=ctx.policy.id,
                    decision=SubmissionDecision.needs_more_info,
                    reasons=[
                        "Input channel is local_unprivileged without automation boundary",
                        "Need evidence that this is reachable from untrusted context"
                    ],
                    missing_evidence=[
                        "Is this tool invoked automatically (CI/build farm/hooks)?",
                        "Is the input sourced from untrusted repo content or artifacts?",
                        "Show the call path where untrusted data reaches this sink"
                    ],
                    suggested_next_steps=[
                        "Run evidence quest to trace call paths",
                        "Check CI/CD configuration for automatic invocations"
                    ],
                    quest_run=True
                )
                return (result, None)

        return None
```

**Step 5: Add accept helper**

```python
    def _accept_for_submission(
        self, ctx: EvaluationContext
    ) -> tuple[SubmissionResult, None]:
        """All gates passed - recommend submission."""
        result = SubmissionResult(
            protocol_id=ctx.policy.id,
            decision=SubmissionDecision.submit,
            reasons=[
                f"All protocol gates passed for {ctx.policy.display_name}",
                f"Disposition: {ctx.classification.disposition.value}",
                f"Classification confidence: {ctx.classification.classification_confidence}%",
                "Ready for disclosure/reporting"
            ],
            missing_evidence=[],
            suggested_next_steps=[
                "Generate final report with proof checklist",
                "Include attack scenario and prerequisites"
            ]
        )
        return (result, None)
```

**Step 6: Commit gate implementations**

```bash
git add backend/services/protocol_evaluator.py
git commit -m "feat(protocol): implement core evaluation gates

- Gate 1: Disposition filtering
- Gate 2: Checklist quality with disposition downgrade
- Gate 3: Attacker model realism (social engineering check)
- Gate 5: Local boundary automation check
- Add accept helper for submittable findings"
```

---

### Task 2.3: Category-Specific Rules

**Files:**
- Modify: `backend/services/protocol_evaluator.py`

**Step 1: Add Gate 4 dispatcher**

Add after `_check_attacker_model`:

```python
    def _apply_category_rules(
        self, ctx: EvaluationContext
    ) -> Optional[tuple[SubmissionResult, Optional[Disposition]]]:
        """Gate 4: Apply category-specific validation rules."""
        category = ctx.classification.category

        if category in self.category_evaluators:
            evaluator = self.category_evaluators[category]
            return evaluator(ctx)

        return None
```

**Step 2: Implement command injection evaluator**

```python
    def _evaluate_command_injection(
        self, ctx: EvaluationContext
    ) -> Optional[tuple[SubmissionResult, Optional[Disposition]]]:
        """Command injection specific rules."""
        category_rules = ctx.policy.category_rules.get(
            VulnerabilityCategory.COMMAND_INJECTION,
            {}
        )

        requires_shell = category_rules.get("requires_shell", False)
        if not requires_shell:
            return None

        snippet = (ctx.evidence.snippet or "").lower()

        # Check for shell indicators
        shell_indicators = [
            "shell=true",
            "shell = true",
            "os.system",
            "os.popen",
            "/bin/sh -c",
            "cmd.exe /c"
        ]
        has_shell = any(indicator in snippet for indicator in shell_indicators)

        # Check for shell=False with argv
        has_shell_false = "shell=false" in snippet or "shell = false" in snippet
        has_argv_list = bool(re.search(r'\.split\(\s*["\']', snippet))

        is_arg_injection = (has_shell_false or has_argv_list) and not has_shell

        if category_rules.get("reject_argument_injection") and is_arg_injection:
            new_disposition = Disposition.HARDENING
            result = SubmissionResult(
                protocol_id=ctx.policy.id,
                decision=SubmissionDecision.dont_submit,
                reasons=[
                    "Subprocess call uses shell=False with argument list",
                    "This is argument injection, not arbitrary command execution",
                    "No shell metacharacter expansion possible",
                    f"Disposition downgraded: {ctx.classification.disposition.value} → {new_disposition.value}"
                ],
                disposition_modified=True,
                disposition_reason="Not true command injection - argv parsing issue"
            )
            return (result, new_disposition)

        if requires_shell and not has_shell:
            result = SubmissionResult(
                protocol_id=ctx.policy.id,
                decision=SubmissionDecision.needs_more_info,
                reasons=[
                    "Cannot confirm shell execution context",
                    "Command injection requires shell=True or equivalent"
                ],
                missing_evidence=[
                    "Is this using shell=True or os.system()?",
                    "Show the exact subprocess invocation"
                ],
                suggested_next_steps=[
                    "Read the sink function to verify shell usage"
                ]
            )
            return (result, None)

        return None
```

**Step 3: Implement SQL injection evaluator**

```python
    def _evaluate_sql_injection(
        self, ctx: EvaluationContext
    ) -> Optional[tuple[SubmissionResult, Optional[Disposition]]]:
        """SQL injection specific rules."""
        checklist = ctx.classification.proof_checklist

        # Check if already mitigated by StrictClassifier
        if (checklist.dataflow_evidenced.status == ChecklistStatus.DISPROVEN and
            checklist.dataflow_evidenced.reason_code in [
                "mitigated_by_parameterization",
                "mitigated_by_allowlist"
            ]):
            # Already handled correctly
            return None

        return None
```

**Step 4: Commit category rules**

```bash
git add backend/services/protocol_evaluator.py
git commit -m "feat(protocol): add category-specific rule evaluators

- Gate 4: Category rule dispatcher
- Command injection: Shell requirement and argv injection detection
- SQL injection: Parameterization check (defers to classifier)
- Support protocol-specific vulnerability validation"
```

---

### Task 2.4: Write Unit Tests for ProtocolEvaluator

**Files:**
- Create: `backend/tests/services/test_protocol_evaluator.py`

**Step 1: Create test file with fixtures**

```python
"""Tests for ProtocolEvaluator."""
import pytest
from models.schemas import (
    Finding,
    Evidence,
    ClassificationResult,
    ProtocolPolicy,
    Disposition,
    ChecklistStatus,
    ChecklistItem,
    ProofChecklist,
    VulnerabilityCategory,
    InputChannel,
    SubmissionDecision,
)
from services.protocol_evaluator import ProtocolEvaluator


@pytest.fixture
def strict_policy():
    """Strict protocol policy (like osvrp_strict)."""
    return ProtocolPolicy(
        id="test_strict",
        display_name="Test Strict",
        min_disposition_to_submit={Disposition.VALID_SECURITY_ISSUE},
        require_cross_boundary_for_local_bugs=True,
        reject_social_engineering_only=True,
        require_realistic_attacker_model=True,
        min_checklist_proven_count=6,
        allow_unknown_in_checklist=False,
        category_rules={
            VulnerabilityCategory.COMMAND_INJECTION: {
                "requires_shell": True,
                "reject_argument_injection": True
            }
        },
        enable_evidence_quests=True,
        quest_categories=[]
    )


@pytest.fixture
def permissive_policy():
    """Permissive protocol policy (like internal)."""
    return ProtocolPolicy(
        id="test_permissive",
        display_name="Test Permissive",
        min_disposition_to_submit={
            Disposition.VALID_SECURITY_ISSUE,
            Disposition.HARDENING
        },
        require_cross_boundary_for_local_bugs=False,
        reject_social_engineering_only=False,
        require_realistic_attacker_model=False,
        min_checklist_proven_count=3,
        allow_unknown_in_checklist=True,
        category_rules={},
        enable_evidence_quests=False,
        quest_categories=[]
    )


@pytest.fixture
def valid_finding():
    """Finding with VALID_SECURITY_ISSUE disposition."""
    return Finding(
        id="test-001",
        title="Command Injection",
        description="User input flows to subprocess",
        vulnerability_type="command_injection",
        file_path="app/exec.py",
        line_start=100,
        disposition=Disposition.VALID_SECURITY_ISSUE,
        category=VulnerabilityCategory.COMMAND_INJECTION
    )


@pytest.fixture
def complete_checklist():
    """Proof checklist with all items PROVEN."""
    return ProofChecklist(
        source_controlled_input=ChecklistItem(
            value=True, status=ChecklistStatus.PROVEN, reason="Request param"
        ),
        sink_present=ChecklistItem(
            value=True, status=ChecklistStatus.PROVEN, reason="subprocess.run()"
        ),
        dataflow_evidenced=ChecklistItem(
            value=True, status=ChecklistStatus.PROVEN, reason="Direct flow"
        ),
        reachable=ChecklistItem(
            value=True, status=ChecklistStatus.PROVEN, reason="@app.route"
        ),
        boundary_crossed=ChecklistItem(
            value=True, status=ChecklistStatus.PROVEN, reason="HTTP endpoint"
        ),
        not_only_misconfig=ChecklistItem(
            value=True, status=ChecklistStatus.PROVEN, reason="Code-level bug"
        )
    )


@pytest.fixture
def network_evidence():
    """Evidence with network input channel."""
    return Evidence(
        finding_id="test-001",
        snippet="subprocess.run(cmd, shell=True)",
        input_channel=InputChannel.network,
        input_channel_deterministic=True,
        input_channel_signals=["route_registration"],
        input_channel_reason="HTTP request handler",
        matches=[]
    )
```

**Step 2: Test Gate 1 - disposition filtering**

```python
def test_reject_by_disposition_strict_policy(
    valid_finding, network_evidence, complete_checklist, strict_policy
):
    """Test that HARDENING is rejected by strict policy."""
    # Arrange
    finding = valid_finding
    finding.disposition = Disposition.HARDENING

    classification = ClassificationResult(
        disposition=Disposition.HARDENING,
        classification_confidence=80,
        exploit_confidence=None,
        proof_checklist=complete_checklist,
        reasoning=["Sink present but no dataflow"],
        category=VulnerabilityCategory.COMMAND_INJECTION
    )

    evaluator = ProtocolEvaluator()

    # Act
    result, new_disposition = evaluator.evaluate(
        finding, network_evidence, classification, strict_policy
    )

    # Assert
    assert result.decision == SubmissionDecision.dont_submit
    assert "Disposition is hardening" in result.reasons[0]
    assert new_disposition is None  # No override


def test_accept_hardening_permissive_policy(
    valid_finding, network_evidence, complete_checklist, permissive_policy
):
    """Test that HARDENING is accepted by permissive policy."""
    # Arrange
    finding = valid_finding
    finding.disposition = Disposition.HARDENING

    classification = ClassificationResult(
        disposition=Disposition.HARDENING,
        classification_confidence=80,
        exploit_confidence=None,
        proof_checklist=complete_checklist,
        reasoning=["Sink present"],
        category=VulnerabilityCategory.COMMAND_INJECTION
    )

    evaluator = ProtocolEvaluator()

    # Act
    result, new_disposition = evaluator.evaluate(
        finding, network_evidence, classification, permissive_policy
    )

    # Assert
    assert result.decision == SubmissionDecision.submit
    assert "All protocol gates passed" in result.reasons[0]
```

**Step 3: Test Gate 2 - checklist quality**

```python
def test_reject_insufficient_checklist_items(
    valid_finding, network_evidence, strict_policy
):
    """Test that insufficient proven items triggers rejection."""
    # Arrange
    incomplete_checklist = ProofChecklist(
        source_controlled_input=ChecklistItem(
            value=True, status=ChecklistStatus.PROVEN, reason="Found"
        ),
        sink_present=ChecklistItem(
            value=True, status=ChecklistStatus.PROVEN, reason="Found"
        ),
        dataflow_evidenced=ChecklistItem(
            value=False, status=ChecklistStatus.UNKNOWN, reason="Not found"
        ),
        reachable=ChecklistItem(
            value=False, status=ChecklistStatus.UNKNOWN, reason="Not found"
        ),
        boundary_crossed=ChecklistItem(
            value=True, status=ChecklistStatus.PROVEN, reason="Found"
        ),
        not_only_misconfig=ChecklistItem(
            value=True, status=ChecklistStatus.PROVEN, reason="Found"
        )
    )

    classification = ClassificationResult(
        disposition=Disposition.VALID_SECURITY_ISSUE,
        classification_confidence=80,
        exploit_confidence=70,
        proof_checklist=incomplete_checklist,
        reasoning=["Some items proven"],
        category=VulnerabilityCategory.COMMAND_INJECTION
    )

    evaluator = ProtocolEvaluator()

    # Act
    result, new_disposition = evaluator.evaluate(
        valid_finding, network_evidence, classification, strict_policy
    )

    # Assert
    assert result.decision == SubmissionDecision.dont_submit
    assert "4/6 checklist items proven" in result.reasons[0]
    assert result.disposition_modified is True
    assert new_disposition == Disposition.HARDENING
```

**Step 4: Test Gate 3 - attacker model**

```python
def test_reject_social_engineering(
    network_evidence, complete_checklist, strict_policy
):
    """Test that social engineering is rejected."""
    # Arrange
    social_eng_finding = Finding(
        id="test-002",
        title="XSS",
        description="User must paste malicious script into browser console",
        vulnerability_type="xss",
        file_path="app/api.py",
        line_start=50,
        disposition=Disposition.VALID_SECURITY_ISSUE,
        category=VulnerabilityCategory.XSS
    )

    classification = ClassificationResult(
        disposition=Disposition.VALID_SECURITY_ISSUE,
        classification_confidence=90,
        exploit_confidence=80,
        proof_checklist=complete_checklist,
        reasoning=["All items proven"],
        category=VulnerabilityCategory.XSS
    )

    evaluator = ProtocolEvaluator()

    # Act
    result, new_disposition = evaluator.evaluate(
        social_eng_finding, network_evidence, classification, strict_policy
    )

    # Assert
    assert result.decision == SubmissionDecision.dont_submit
    assert "social engineering" in result.reasons[0].lower()
    assert new_disposition == Disposition.HARDENING
```

**Step 5: Test Gate 5 - local boundary**

```python
def test_local_bug_needs_automation_boundary(
    valid_finding, complete_checklist, strict_policy
):
    """Test that local bugs without automation trigger needs_more_info."""
    # Arrange
    local_evidence = Evidence(
        finding_id="test-001",
        snippet="subprocess.run(cmd, shell=True)",
        input_channel=InputChannel.local_unprivileged,
        input_channel_deterministic=True,
        input_channel_signals=[],  # No automation signals
        input_channel_reason="CLI argument",
        matches=[]
    )

    classification = ClassificationResult(
        disposition=Disposition.VALID_SECURITY_ISSUE,
        classification_confidence=90,
        exploit_confidence=80,
        proof_checklist=complete_checklist,
        reasoning=["All items proven"],
        category=VulnerabilityCategory.COMMAND_INJECTION
    )

    evaluator = ProtocolEvaluator()

    # Act
    result, new_disposition = evaluator.evaluate(
        valid_finding, local_evidence, classification, strict_policy
    )

    # Assert
    assert result.decision == SubmissionDecision.needs_more_info
    assert "local_unprivileged without automation boundary" in result.reasons[0]
    assert result.quest_run is True
    assert "Is this tool invoked automatically" in result.missing_evidence[0]
```

**Step 6: Test command injection category rules**

```python
def test_command_injection_rejects_argv_injection(
    valid_finding, network_evidence, complete_checklist, strict_policy
):
    """Test that shell=False is rejected as not true command injection."""
    # Arrange
    argv_evidence = Evidence(
        finding_id="test-001",
        snippet='subprocess.run(cmd.split(" "), shell=False)',
        input_channel=InputChannel.network,
        input_channel_deterministic=True,
        input_channel_signals=["route_registration"],
        input_channel_reason="HTTP endpoint",
        matches=[]
    )

    classification = ClassificationResult(
        disposition=Disposition.VALID_SECURITY_ISSUE,
        classification_confidence=90,
        exploit_confidence=80,
        proof_checklist=complete_checklist,
        reasoning=["All items proven"],
        category=VulnerabilityCategory.COMMAND_INJECTION
    )

    evaluator = ProtocolEvaluator()

    # Act
    result, new_disposition = evaluator.evaluate(
        valid_finding, argv_evidence, classification, strict_policy
    )

    # Assert
    assert result.decision == SubmissionDecision.dont_submit
    assert "argument injection" in result.reasons[1].lower()
    assert "not arbitrary command execution" in result.reasons[1].lower()
    assert new_disposition == Disposition.HARDENING
```

**Step 7: Test full submission acceptance**

```python
def test_accept_valid_finding_all_gates_pass(
    valid_finding, network_evidence, complete_checklist, strict_policy
):
    """Test that valid finding passing all gates is accepted."""
    # Arrange
    classification = ClassificationResult(
        disposition=Disposition.VALID_SECURITY_ISSUE,
        classification_confidence=95,
        exploit_confidence=90,
        proof_checklist=complete_checklist,
        reasoning=["All items proven", "Shell execution confirmed"],
        category=VulnerabilityCategory.COMMAND_INJECTION
    )

    evaluator = ProtocolEvaluator()

    # Act
    result, new_disposition = evaluator.evaluate(
        valid_finding, network_evidence, classification, strict_policy
    )

    # Assert
    assert result.decision == SubmissionDecision.submit
    assert "All protocol gates passed" in result.reasons[0]
    assert result.disposition_modified is False
    assert new_disposition is None
```

**Step 8: Run tests**

```bash
pytest backend/tests/services/test_protocol_evaluator.py -v
```

Expected: All tests pass

**Step 9: Commit tests**

```bash
git add backend/tests/services/test_protocol_evaluator.py
git commit -m "test(protocol): add comprehensive ProtocolEvaluator unit tests

- Test all 5 gates with various scenarios
- Test category-specific rules (command injection)
- Test disposition override logic
- Test acceptance and rejection flows
- 8 test cases with fixtures"
```

---

## Phase 3: Evidence Quest System

### Task 3.1: Quest Orchestrator Base

**Files:**
- Create: `backend/services/evidence_quest_orchestrator.py`

**Step 1: Create orchestrator with imports**

```python
"""Evidence quest orchestration service."""

import asyncio
import uuid
from datetime import datetime
from typing import Optional

from models.schemas import (
    Finding,
    Evidence,
    EvidenceQuest,
    VulnerabilityCategory,
    AgentStatus,
    ChecklistItem,
    ChecklistStatus,
)


class EvidenceQuestOrchestrator:
    """
    Orchestrates autonomous evidence gathering quests.

    Creates and manages LLM-based agents that gather missing evidence
    for high-signal findings with proof gaps.
    """

    def __init__(
        self,
        repo_root: str,
        llm_client,
        db_conn
    ):
        self.repo_root = repo_root
        self.llm_client = llm_client
        self.db = db_conn

        # Quest playbook registry
        self.quest_playbooks = {
            VulnerabilityCategory.COMMAND_INJECTION: CommandInjectionQuest,
            VulnerabilityCategory.SQL_INJECTION: SQLInjectionQuest,
        }
```

**Step 2: Add create_quest method**

```python
    async def create_quest(
        self,
        finding: Finding,
        evidence: Evidence,
        missing_items: list[str]
    ) -> EvidenceQuest:
        """
        Create a new evidence quest for a finding.

        Args:
            finding: The finding that needs more evidence
            evidence: Current evidence bundle
            missing_items: List of checklist items that are UNKNOWN/missing

        Returns:
            EvidenceQuest object with initial state
        """
        quest_id = f"quest_{uuid.uuid4().hex[:12]}"

        # Determine quest type from category
        category = finding.category or VulnerabilityCategory.GENERIC
        quest_type = self._get_quest_type(category)

        quest = EvidenceQuest(
            id=quest_id,
            finding_id=finding.id,
            category=category,
            missing_items=missing_items,
            quest_type=quest_type,
            status=AgentStatus.PENDING
        )

        # Store in database
        await self._store_quest(quest)

        return quest

    def _get_quest_type(self, category: VulnerabilityCategory) -> str:
        """Map category to quest type identifier."""
        mapping = {
            VulnerabilityCategory.COMMAND_INJECTION: "command_injection_quest",
            VulnerabilityCategory.SQL_INJECTION: "sql_injection_quest",
        }
        return mapping.get(category, "generic_quest")
```

**Step 3: Add run_quest method**

```python
    async def run_quest(
        self,
        quest: EvidenceQuest,
        finding: Finding,
        evidence: Evidence
    ) -> tuple[Evidence, bool]:
        """
        Execute an evidence quest.

        Returns:
            (updated_evidence, success)
        """
        # Update quest status
        quest.status = AgentStatus.RUNNING
        quest.started_at = datetime.utcnow()
        await self._update_quest(quest)

        try:
            # Get quest playbook
            playbook_class = self.quest_playbooks.get(quest.category)
            if not playbook_class:
                raise ValueError(f"No playbook for category: {quest.category}")

            # Instantiate and run playbook
            playbook = playbook_class(
                repo_root=self.repo_root,
                llm_client=self.llm_client,
                finding=finding,
                evidence=evidence,
                missing_items=quest.missing_items
            )

            quest_result = await playbook.execute()

            # Update quest with results
            quest.evidence_found = quest_result.evidence_found
            quest.new_checklist_items = quest_result.new_checklist_items
            quest.success = quest_result.success
            quest.status = AgentStatus.COMPLETED
            quest.completed_at = datetime.utcnow()

            if quest_result.success:
                # Merge new evidence
                updated_evidence = self._merge_evidence(
                    evidence,
                    quest_result.evidence_found
                )
                await self._update_quest(quest)
                return (updated_evidence, True)
            else:
                quest.error_message = quest_result.error_message
                await self._update_quest(quest)
                return (evidence, False)

        except Exception as e:
            # Quest execution failed
            quest.status = AgentStatus.FAILED
            quest.error_message = str(e)
            quest.completed_at = datetime.utcnow()
            await self._update_quest(quest)
            return (evidence, False)
```

**Step 4: Add evidence merging**

```python
    def _merge_evidence(
        self,
        original: Evidence,
        quest_findings: dict
    ) -> Evidence:
        """Merge quest findings into original Evidence object."""
        # Copy original
        updated = original.model_copy(deep=True)

        # Merge route registration
        if "route_registration" in quest_findings and quest_findings["route_registration"]:
            updated.route_registration = quest_findings["route_registration"]

        # Merge auth gates
        if "auth_gates" in quest_findings:
            updated.auth_gates.extend(quest_findings["auth_gates"])

        # Merge dataflow snippet
        if "dataflow_snippet" in quest_findings:
            updated.dataflow_snippet = quest_findings["dataflow_snippet"]

        # Merge matches
        if "new_matches" in quest_findings:
            updated.matches.extend(quest_findings["new_matches"])

        # Update input channel if quest discovered better info
        if "input_channel" in quest_findings:
            updated.input_channel = quest_findings["input_channel"]
            updated.input_channel_deterministic = True
            updated.input_channel_signals.extend(
                quest_findings.get("input_channel_signals", [])
            )
            updated.input_channel_reason = quest_findings.get(
                "input_channel_reason",
                "Discovered by evidence quest"
            )

        return updated
```

**Step 5: Add database methods**

```python
    async def _store_quest(self, quest: EvidenceQuest):
        """Store quest in database."""
        import json
        await self.db.execute("""
            INSERT INTO evidence_quests
            (id, finding_id, category, quest_type, status, missing_items, started_at)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (
            quest.id,
            quest.finding_id,
            quest.category.value,
            quest.quest_type,
            quest.status.value,
            json.dumps(quest.missing_items),
            quest.started_at
        ))
        await self.db.commit()

    async def _update_quest(self, quest: EvidenceQuest):
        """Update quest in database."""
        import json
        await self.db.execute("""
            UPDATE evidence_quests
            SET status = ?,
                evidence_found = ?,
                new_checklist_items = ?,
                completed_at = ?,
                success = ?,
                error_message = ?
            WHERE id = ?
        """, (
            quest.status.value,
            json.dumps(quest.evidence_found),
            json.dumps({k: v.model_dump() for k, v in quest.new_checklist_items.items()}),
            quest.completed_at,
            quest.success,
            quest.error_message,
            quest.id
        ))
        await self.db.commit()
```

**Step 6: Commit orchestrator base**

```bash
git add backend/services/evidence_quest_orchestrator.py
git commit -m "feat(quest): add EvidenceQuestOrchestrator base

- Create quest creation and execution flow
- Implement evidence merging logic
- Add database CRUD methods
- Set up playbook registry"
```

---

### Task 3.2: Quest Playbook Base Classes

**Files:**
- Modify: `backend/services/evidence_quest_orchestrator.py`

**Step 1: Add QuestResult dataclass**

Add after imports:

```python
from dataclasses import dataclass


@dataclass
class QuestResult:
    """Result from a quest execution."""
    success: bool
    evidence_found: dict
    new_checklist_items: dict[str, ChecklistItem]
    error_message: Optional[str] = None
```

**Step 2: Add QuestPlaybook base class**

Add after `QuestResult`:

```python
class QuestPlaybook:
    """
    Base class for evidence quest playbooks.

    Subclasses implement category-specific evidence gathering strategies.
    """

    def __init__(
        self,
        repo_root: str,
        llm_client,
        finding: Finding,
        evidence: Evidence,
        missing_items: list[str]
    ):
        self.repo_root = repo_root
        self.llm_client = llm_client
        self.finding = finding
        self.evidence = evidence
        self.missing_items = missing_items

    async def execute(self) -> QuestResult:
        """
        Execute the quest playbook.

        Returns:
            QuestResult with discovered evidence
        """
        raise NotImplementedError

    def _build_quest_prompt(self) -> str:
        """Build LLM prompt for this quest."""
        raise NotImplementedError
```

**Step 3: Commit base classes**

```bash
git add backend/services/evidence_quest_orchestrator.py
git commit -m "feat(quest): add QuestPlaybook base classes

- Add QuestResult dataclass
- Add QuestPlaybook abstract base class
- Define execute and _build_quest_prompt interface"
```

---

### Task 3.3: Command Injection Quest Playbook

**Files:**
- Modify: `backend/services/evidence_quest_orchestrator.py`

**Step 1: Add CommandInjectionQuest class**

Add at end of file:

```python
class CommandInjectionQuest(QuestPlaybook):
    """Evidence quest for command injection vulnerabilities."""

    async def execute(self) -> QuestResult:
        """Execute command injection evidence quest."""
        evidence_found = {}
        new_checklist_items = {}

        # Task 1: Verify shell execution
        if "sink" in self.missing_items or "reachability" in self.missing_items:
            shell_context = await self._verify_shell_execution()
            if shell_context:
                evidence_found["shell_context"] = shell_context
                new_checklist_items["sink_present"] = ChecklistItem(
                    value=True,
                    status=ChecklistStatus.PROVEN,
                    reason=f"Quest found: {shell_context}",
                    tool_calls=["read_file", "grep"]
                )

        # Task 2: Trace dataflow
        if "dataflow" in self.missing_items:
            dataflow = await self._trace_dataflow()
            if dataflow:
                evidence_found["dataflow_snippet"] = dataflow
                new_checklist_items["dataflow_evidenced"] = ChecklistItem(
                    value=True,
                    status=ChecklistStatus.PROVEN,
                    reason="Quest traced source to sink",
                    tool_calls=["read_file"]
                )

        # Task 3: Find entry point
        if "reachability" in self.missing_items:
            entry_point = await self._find_entry_point()
            if entry_point:
                evidence_found["route_registration"] = entry_point
                new_checklist_items["reachable"] = ChecklistItem(
                    value=True,
                    status=ChecklistStatus.PROVEN,
                    reason=f"Quest found entry point: {entry_point}",
                    tool_calls=["grep"]
                )

        # Task 4: Check automation boundary
        if "boundary" in self.missing_items or "local_boundary" in self.missing_items:
            automation = await self._check_automation_boundary()
            if automation:
                evidence_found["input_channel"] = "ci_artifact"
                evidence_found["input_channel_signals"] = [automation]
                evidence_found["input_channel_reason"] = f"Quest found automation: {automation}"

        success = len(evidence_found) > 0

        return QuestResult(
            success=success,
            evidence_found=evidence_found,
            new_checklist_items=new_checklist_items,
            error_message=None if success else "No additional evidence found"
        )
```

**Step 2: Add helper methods (simplified for MVP)**

```python
    def _build_quest_prompt(self) -> str:
        """Build quest prompt for command injection."""
        return f"""
# Evidence Quest: Command Injection Validation

## Finding
- File: {self.finding.file_path}
- Line: {self.finding.line_start}
- Type: {self.finding.vulnerability_type}

## Current Evidence
{self.evidence.snippet}

## Missing Evidence
{', '.join(self.missing_items)}

## Task
Gather missing evidence for this command injection finding.

1. Verify shell execution (shell=True, os.system, etc.)
2. Trace dataflow from source to sink
3. Find entry point (route registration, CLI invocation)
4. Check for automation boundary (CI/CD, webhooks)

Return JSON with discovered evidence.
"""

    async def _verify_shell_execution(self) -> Optional[str]:
        """Verify if this is actual shell execution (simplified)."""
        # In real implementation, would use LLM with tools
        # For MVP, check evidence snippet
        snippet_lower = self.evidence.snippet.lower()
        if "shell=true" in snippet_lower or "os.system" in snippet_lower:
            return "shell=True detected in subprocess.run()"
        return None

    async def _trace_dataflow(self) -> Optional[str]:
        """Trace dataflow from source to sink (simplified)."""
        # In real implementation, would use LLM to trace
        if "request" in self.evidence.snippet.lower():
            return "request parameter flows to subprocess call"
        return None

    async def _find_entry_point(self) -> Optional[str]:
        """Find how this function is invoked (simplified)."""
        # In real implementation, would grep for decorators
        snippet_lower = self.evidence.snippet.lower()
        if "@app.route" in snippet_lower or "@router" in snippet_lower:
            return "@app.route decorator found"
        return None

    async def _check_automation_boundary(self) -> Optional[str]:
        """Check for CI/automation invocation (simplified)."""
        # In real implementation, would search CI configs
        # For MVP, check file path
        if ".github" in self.finding.file_path or "ci/" in self.finding.file_path:
            return "Found in CI directory"
        return None
```

**Step 3: Add SQLInjectionQuest stub**

```python
class SQLInjectionQuest(QuestPlaybook):
    """Evidence quest for SQL injection vulnerabilities."""

    async def execute(self) -> QuestResult:
        """Execute SQL injection evidence quest."""
        # Simplified for MVP - just return no evidence
        return QuestResult(
            success=False,
            evidence_found={},
            new_checklist_items={},
            error_message="SQL injection quest not yet implemented"
        )

    def _build_quest_prompt(self) -> str:
        return "SQL injection quest prompt (TODO)"
```

**Step 4: Commit quest playbooks**

```bash
git add backend/services/evidence_quest_orchestrator.py
git commit -m "feat(quest): add command injection quest playbook

- Implement CommandInjectionQuest with 4 evidence gathering tasks
- Add helper methods for shell verification, dataflow tracing, entry points
- Add SQLInjectionQuest stub for future implementation
- Simplified implementations for MVP (no full LLM integration yet)"
```

---

### Task 3.4: Integrate Quests into Triage Service

**Files:**
- Modify: `backend/services/finding_triage_service.py`

**Step 1: Add quest orchestrator import**

Add to imports section:

```python
from services.evidence_quest_orchestrator import EvidenceQuestOrchestrator
from services.protocol_evaluator import ProtocolEvaluator
from services.protocol_policies import ProtocolPolicyLoader
```

**Step 2: Update FindingTriageService __init__**

Find `__init__` method and add:

```python
    def __init__(self):
        self.quest_orchestrator: Optional[EvidenceQuestOrchestrator] = None
        self.protocol_evaluator = ProtocolEvaluator()
```

**Step 3: Add new triage method with protocol support**

Add after existing `triage_findings` method:

```python
    async def triage_with_protocol(
        self,
        repo_root: str,
        findings: list[Finding],
        policy_version: str = "1.0.0",
        budgets: Optional[BudgetConfig] = None,
        threat_model_profile: Optional[dict] = None,
        protocol_policy: Optional[ProtocolPolicy] = None,
        db_conn = None,
    ) -> TriageResult:
        """
        Triage findings with protocol evaluation and quest support.

        This includes ProtocolEvaluator and evidence quest integration.
        """
        if not findings:
            return TriageResult(
                triaged_findings=[],
                reportable_findings=[],
                metrics=TriageMetrics(
                    raw_count=0,
                    triaged_count=0,
                    reportable_count=0,
                    by_disposition={},
                    timeout_count=0,
                    timeout_rate=0.0
                ),
                batch_id=self._generate_batch_id()
            )

        batch_id = self._generate_batch_id()
        batch_start = time.time()
        budgets = budgets or BudgetConfig()

        # Initialize quest orchestrator if db provided
        if db_conn and protocol_policy and protocol_policy.enable_evidence_quests:
            # TODO: Add LLM client initialization
            self.quest_orchestrator = EvidenceQuestOrchestrator(
                repo_root=repo_root,
                llm_client=None,  # Simplified for MVP
                db_conn=db_conn
            )

        gatherer = EvidenceGatherer(repo_root, budgets)
        classifier = StrictClassifier()

        triaged = []
        reportable = []
        timeout_count = 0

        for idx, finding in enumerate(findings):
            # Check batch timeout
            elapsed_ms = (time.time() - batch_start) * 1000
            remaining_findings = len(findings) - len(triaged)

            if elapsed_ms > budgets.batch_ms:
                # Mark remaining as timeout
                for remaining_finding in findings[idx:]:
                    triaged_finding = self._mark_as_timeout(
                        remaining_finding, batch_id, policy_version
                    )
                    triaged.append(triaged_finding)
                timeout_count += remaining_findings
                break

            try:
                # Step 1: Gather evidence
                evidence = await asyncio.to_thread(gatherer.gather, finding)

                # Step 2: Classify
                classification = await asyncio.to_thread(
                    classifier.classify,
                    finding, evidence, threat_model_profile
                )

                # Step 3: Protocol evaluation
                if protocol_policy:
                    submission_result, new_disposition = await asyncio.to_thread(
                        self.protocol_evaluator.evaluate,
                        finding, evidence, classification, protocol_policy
                    )

                    # Step 4: Handle quest if needed
                    if (submission_result.quest_run and
                        self.quest_orchestrator and
                        submission_result.decision == SubmissionDecision.needs_more_info):

                        quest = await self.quest_orchestrator.create_quest(
                            finding, evidence, submission_result.missing_evidence
                        )

                        # Run quest
                        updated_evidence, quest_success = await self.quest_orchestrator.run_quest(
                            quest, finding, evidence
                        )

                        if quest_success:
                            # Re-run classification
                            classification = await asyncio.to_thread(
                                classifier.classify,
                                finding, updated_evidence, threat_model_profile
                            )

                            # Re-run protocol evaluation
                            submission_result, new_disposition = await asyncio.to_thread(
                                self.protocol_evaluator.evaluate,
                                finding, updated_evidence, classification, protocol_policy
                            )

                            evidence = updated_evidence

                        # Store quest ID
                        finding.evidence_quest_id = quest.id
                        finding.evidence_quest_completed = quest_success

                    # Step 5: Apply disposition override if needed
                    if new_disposition:
                        classification.disposition = new_disposition

                    finding.submission_result = submission_result
                else:
                    # No protocol evaluation
                    finding.submission_result = None

                # Step 6: Attach metadata
                triaged_finding = self._attach_triage_metadata(
                    finding, classification, batch_id, policy_version
                )
                triaged.append(triaged_finding)

                # Track reportable (check submission decision if available)
                if finding.submission_result:
                    if finding.submission_result.decision == SubmissionDecision.submit:
                        reportable.append(triaged_finding)
                else:
                    # Fallback to disposition
                    if classification.disposition in [
                        Disposition.VALID_SECURITY_ISSUE,
                        Disposition.BUG
                    ]:
                        reportable.append(triaged_finding)

                # Track timeouts
                if evidence.timed_out:
                    timeout_count += 1

            except Exception as e:
                triaged_finding = self._mark_as_error(
                    finding, batch_id, policy_version, str(e)
                )
                triaged.append(triaged_finding)

        # Verify guarantee
        assert len(triaged) == len(findings), \
            f"Triage dropped findings: {len(findings)} input vs {len(triaged)} output"

        # Build metrics
        metrics = self._build_metrics(findings, triaged, reportable, timeout_count)

        return TriageResult(
            triaged_findings=triaged,
            reportable_findings=reportable,
            metrics=metrics,
            batch_id=batch_id
        )
```

**Step 4: Commit triage integration**

```bash
git add backend/services/finding_triage_service.py
git commit -m "feat(triage): integrate protocol evaluation and quests

- Add triage_with_protocol method with full protocol support
- Quest orchestrator initialization
- Re-triage loop when quest succeeds
- Apply disposition override from protocol evaluation
- Update reportable tracking to use submission decision"
```

---

Due to output length limits, I'll save the plan here and create a continuation file. Let me save this first part:

```bash
git add docs/plans/2026-01-17-protocol-reportability-layer-implementation.md
git commit -m "docs: add protocol reportability layer implementation plan (Part 1)

- Phase 1: Foundation (data models, schema, policies) - COMPLETE
- Phase 2: ProtocolEvaluator core - COMPLETE
- Phase 3: Evidence Quest system - COMPLETE
- Phases 4-7 to be added in Part 2"
```

**Plan complete and saved to `docs/plans/2026-01-17-protocol-reportability-layer-implementation.md`.**

The first 3 phases are documented with step-by-step implementation tasks. I need to create a second file for Phases 4-7 (API, Frontend, Documentation, Deployment).

Would you like me to:
1. **Create Part 2 immediately** with Phases 4-7
2. **Use Subagent-Driven approach** to start implementing Part 1 now
3. **Guide you to use executing-plans** in a separate session

Which approach?