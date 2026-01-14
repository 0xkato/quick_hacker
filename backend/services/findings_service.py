"""
Findings Service - Database persistence for security findings.

Ensures findings are saved to PostgreSQL/SQLite database for durability
across restarts and page refreshes.
"""

from typing import List, Optional
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from database.connection import get_session
from database.models import Finding as DBFinding
from models.schemas import Finding, Severity


class FindingsService:
    """
    Service for persisting and retrieving security findings.

    Findings are saved to the database when created, ensuring they survive:
    - Page refreshes
    - Server restarts
    - Agent process termination
    """

    async def save_finding(self, finding: Finding) -> DBFinding:
        """
        Save a finding to the database.

        Args:
            finding: Pydantic Finding model from agent

        Returns:
            Database Finding model

        Raises:
            Exception: If database save fails
        """
        async with get_session() as session:
            # Convert Pydantic model to SQLAlchemy model
            db_finding = DBFinding(
                id=finding.id,
                agent_id=finding.agent_id,
                repo_id=finding.repo_id,
                severity=finding.severity.value if isinstance(finding.severity, Severity) else finding.severity,
                title=finding.title,
                description=finding.description,
                file_path=finding.file_path or "",
                line_start=finding.line_start or 0,
                line_end=finding.line_end,
                code_snippet=finding.code_snippet,
                vulnerable_code=finding.vulnerable_code,
                vulnerability_type=finding.vulnerability_type or "Unknown",
                cwe_id=finding.cwe_id,
                attack_scenario=finding.attack_scenario,
                proof_of_concept=finding.proof_of_concept,
                recommended_fix=finding.recommended_fix,
                confidence=finding.confidence or 0.8,
                source_trace=finding.source_trace,
                created_at=finding.created_at,
                metadata_=finding.metadata or {},
            )

            # Check if finding already exists (prevent duplicates)
            existing = await session.get(DBFinding, finding.id)
            if existing:
                # Update existing finding
                for key, value in db_finding.__dict__.items():
                    if not key.startswith('_'):
                        setattr(existing, key, value)
                await session.commit()
                await session.refresh(existing)
                return existing
            else:
                # Create new finding
                session.add(db_finding)
                await session.commit()
                await session.refresh(db_finding)
                return db_finding

    async def get_findings_by_agent(self, agent_id: str) -> List[Finding]:
        """
        Get all findings for a specific agent.

        Args:
            agent_id: Agent identifier

        Returns:
            List of Pydantic Finding models
        """
        async with get_session() as session:
            result = await session.execute(
                select(DBFinding).where(DBFinding.agent_id == agent_id)
            )
            db_findings = result.scalars().all()

            # Convert to Pydantic models
            return [self._to_pydantic(f) for f in db_findings]

    async def get_findings_by_repo(self, repo_id: str) -> List[Finding]:
        """
        Get all findings for a specific repository.

        Args:
            repo_id: Repository/project identifier

        Returns:
            List of Pydantic Finding models
        """
        async with get_session() as session:
            result = await session.execute(
                select(DBFinding).where(DBFinding.repo_id == repo_id)
            )
            db_findings = result.scalars().all()

            return [self._to_pydantic(f) for f in db_findings]

    async def get_finding_by_id(self, finding_id: str) -> Optional[Finding]:
        """
        Get a specific finding by ID.

        Args:
            finding_id: Finding identifier

        Returns:
            Pydantic Finding model or None if not found
        """
        async with get_session() as session:
            db_finding = await session.get(DBFinding, finding_id)
            if not db_finding:
                return None
            return self._to_pydantic(db_finding)

    async def delete_findings_by_agent(self, agent_id: str) -> int:
        """
        Delete all findings for a specific agent.

        Args:
            agent_id: Agent identifier

        Returns:
            Number of findings deleted
        """
        async with get_session() as session:
            result = await session.execute(
                select(DBFinding).where(DBFinding.agent_id == agent_id)
            )
            findings = result.scalars().all()
            count = len(findings)

            for finding in findings:
                await session.delete(finding)

            await session.commit()
            return count

    def _to_pydantic(self, db_finding: DBFinding) -> Finding:
        """
        Convert SQLAlchemy model to Pydantic model.

        Args:
            db_finding: Database Finding model

        Returns:
            Pydantic Finding model
        """
        return Finding(
            id=db_finding.id,
            agent_id=db_finding.agent_id,
            repo_id=db_finding.repo_id,
            severity=Severity(db_finding.severity),
            title=db_finding.title,
            description=db_finding.description,
            file_path=db_finding.file_path,
            line_start=db_finding.line_start,
            line_end=db_finding.line_end,
            code_snippet=db_finding.code_snippet,
            vulnerable_code=db_finding.vulnerable_code,
            vulnerability_type=db_finding.vulnerability_type,
            cwe_id=db_finding.cwe_id,
            attack_scenario=db_finding.attack_scenario,
            proof_of_concept=db_finding.proof_of_concept,
            recommended_fix=db_finding.recommended_fix,
            confidence=db_finding.confidence,
            source_trace=db_finding.source_trace,
            created_at=db_finding.created_at,
            metadata=db_finding.metadata_,
        )


# Global singleton instance
findings_service = FindingsService()
