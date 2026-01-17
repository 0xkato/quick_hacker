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


# Placeholder imports - will be implemented in Tasks 3.2-3.3
class CommandInjectionQuest:
    """Placeholder for Task 3.3."""
    def __init__(self, repo_root, llm_client, finding, evidence, missing_items):
        pass
    async def execute(self):
        from dataclasses import dataclass
        @dataclass
        class QuestResult:
            success: bool = False
            evidence_found: dict = None
            new_checklist_items: dict = None
            error_message: str = "Not yet implemented"
        return QuestResult()


class SQLInjectionQuest:
    """Placeholder for Task 3.3."""
    def __init__(self, repo_root, llm_client, finding, evidence, missing_items):
        pass
    async def execute(self):
        from dataclasses import dataclass
        @dataclass
        class QuestResult:
            success: bool = False
            evidence_found: dict = None
            new_checklist_items: dict = None
            error_message: str = "Not yet implemented"
        return QuestResult()
