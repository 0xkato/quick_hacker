"""
Scan Service - Database persistence for scan/agent records.

Ensures scan records survive server restarts so completed scans remain
visible alongside their findings. Follows the FindingsService pattern.
"""

from datetime import datetime
from typing import List, Optional

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from database.connection import get_session
from database.models import Scan as DBScan
from models.schemas import Agent, AgentStatus, AgentType, ProviderConfig, ProviderType


class ScanService:
    """Service for persisting and retrieving scan records."""

    async def save_scan(self, agent: Agent) -> DBScan:
        """Save or update a scan record (upsert).

        Strips API keys from provider_config before storing.
        """
        async with get_session() as session:
            # Sanitize provider config — only store provider + model
            provider_dict = {}
            if agent.provider_config:
                provider_val = agent.provider_config.provider
                provider_dict = {
                    "provider": provider_val.value if hasattr(provider_val, 'value') else str(provider_val),
                    "model": agent.provider_config.model or "unknown",
                }

            status_val = agent.status.value if hasattr(agent.status, 'value') else str(agent.status)
            agent_type_val = agent.agent_type.value if hasattr(agent.agent_type, 'value') else str(agent.agent_type)

            existing = await session.get(DBScan, agent.id)
            if existing:
                existing.status = status_val
                existing.name = agent.name
                existing.started_at = agent.started_at
                existing.completed_at = agent.completed_at
                existing.files_analyzed = agent.files_analyzed or 0
                existing.findings_count = agent.findings_count or 0
                existing.error_message = agent.error_message
                await session.commit()
                await session.refresh(existing)
                return existing

            db_scan = DBScan(
                id=agent.id,
                repo_id=agent.repo_id,
                name=agent.name,
                agent_type=agent_type_val,
                status=status_val,
                provider_config=provider_dict,
                scan_tier=agent.scan_tier,
                time_budget_seconds=agent.time_budget_seconds,
                custom_prompt=agent.custom_prompt,
                target_files=agent.target_files,
                focus_areas=agent.focus_areas,
                created_at=agent.created_at or datetime.utcnow(),
                started_at=agent.started_at,
                completed_at=agent.completed_at,
                files_analyzed=agent.files_analyzed or 0,
                findings_count=agent.findings_count or 0,
                error_message=agent.error_message,
            )
            session.add(db_scan)
            await session.commit()
            await session.refresh(db_scan)
            return db_scan

    async def update_status(
        self,
        scan_id: str,
        status: str,
        started_at: Optional[datetime] = None,
        completed_at: Optional[datetime] = None,
        files_analyzed: Optional[int] = None,
        findings_count: Optional[int] = None,
        error_message: Optional[str] = None,
    ) -> Optional[DBScan]:
        """Lightweight status + progress update."""
        async with get_session() as session:
            db_scan = await session.get(DBScan, scan_id)
            if not db_scan:
                return None
            db_scan.status = status
            if started_at is not None:
                db_scan.started_at = started_at
            if completed_at is not None:
                db_scan.completed_at = completed_at
            if files_analyzed is not None:
                db_scan.files_analyzed = files_analyzed
            if findings_count is not None:
                db_scan.findings_count = findings_count
            if error_message is not None:
                db_scan.error_message = error_message
            await session.commit()
            await session.refresh(db_scan)
            return db_scan

    async def get_scan(self, scan_id: str) -> Optional[Agent]:
        """Get a single scan as Agent schema."""
        async with get_session() as session:
            db_scan = await session.get(DBScan, scan_id)
            if not db_scan:
                return None
            return self._to_agent_schema(db_scan)

    async def list_scans(
        self,
        repo_id: Optional[str] = None,
        status: Optional[str] = None,
    ) -> List[Agent]:
        """List scans with optional filtering."""
        async with get_session() as session:
            query = select(DBScan)
            if repo_id:
                query = query.where(DBScan.repo_id == repo_id)
            if status:
                query = query.where(DBScan.status == status)
            query = query.order_by(DBScan.created_at.desc())
            result = await session.execute(query)
            return [self._to_agent_schema(s) for s in result.scalars().all()]

    async def delete_scan(self, scan_id: str) -> bool:
        """Delete a scan record."""
        async with get_session() as session:
            db_scan = await session.get(DBScan, scan_id)
            if not db_scan:
                return False
            await session.delete(db_scan)
            await session.commit()
            return True

    def _to_agent_schema(self, db_scan: DBScan) -> Agent:
        """Convert DB model to Agent Pydantic schema."""
        provider_data = db_scan.provider_config or {}
        provider_str = provider_data.get("provider", "anthropic")

        # Try to convert provider string to ProviderType enum
        try:
            provider_type = ProviderType(provider_str)
        except (ValueError, KeyError):
            provider_type = provider_str

        # Try to convert agent_type string to AgentType enum
        try:
            agent_type = AgentType(db_scan.agent_type)
        except (ValueError, KeyError):
            agent_type = db_scan.agent_type

        # Try to convert status string to AgentStatus enum
        try:
            status = AgentStatus(db_scan.status)
        except (ValueError, KeyError):
            status = db_scan.status

        return Agent(
            id=db_scan.id,
            repo_id=db_scan.repo_id,
            name=db_scan.name,
            agent_type=agent_type,
            status=status,
            provider_config=ProviderConfig(
                provider=provider_type,
                model=provider_data.get("model", "unknown"),
            ),
            scan_tier=db_scan.scan_tier,
            time_budget_seconds=db_scan.time_budget_seconds,
            custom_prompt=db_scan.custom_prompt,
            target_files=db_scan.target_files,
            focus_areas=db_scan.focus_areas,
            created_at=db_scan.created_at,
            started_at=db_scan.started_at,
            completed_at=db_scan.completed_at,
            files_analyzed=db_scan.files_analyzed or 0,
            findings_count=db_scan.findings_count or 0,
            error_message=db_scan.error_message,
        )


# Global singleton
scan_service = ScanService()
