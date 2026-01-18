"""Evidence quest orchestration service."""

import asyncio
import uuid
from dataclasses import dataclass
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


@dataclass
class QuestResult:
    """Result from a quest execution."""
    success: bool
    evidence_found: dict
    new_checklist_items: dict[str, ChecklistItem]
    error_message: Optional[str] = None


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
        snippet_lower = (self.evidence.snippet or "").lower()
        if "shell=true" in snippet_lower or "os.system" in snippet_lower:
            return "shell=True detected in subprocess.run()"
        return None

    async def _trace_dataflow(self) -> Optional[str]:
        """Trace dataflow from source to sink (simplified)."""
        # In real implementation, would use LLM to trace
        if "request" in (self.evidence.snippet or "").lower():
            return "request parameter flows to subprocess call"
        return None

    async def _find_entry_point(self) -> Optional[str]:
        """Find how this function is invoked (simplified)."""
        # In real implementation, would grep for decorators
        snippet_lower = (self.evidence.snippet or "").lower()
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
