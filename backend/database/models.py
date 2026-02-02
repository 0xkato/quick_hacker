"""Database models for user authentication, API keys, and triage system."""
import uuid
from datetime import datetime
from typing import Optional, Any

from sqlalchemy import String, DateTime, Boolean, ForeignKey, Text, Index, Integer, Float, JSON
from sqlalchemy.orm import Mapped, mapped_column, relationship
from sqlalchemy.dialects.postgresql import UUID, JSONB

from .connection import Base


class User(Base):
    """User account model."""
    __tablename__ = "users"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4
    )
    username: Mapped[str] = mapped_column(
        String(50),
        unique=True,
        nullable=False,
        index=True
    )
    email: Mapped[str] = mapped_column(
        String(255),
        unique=True,
        nullable=False,
        index=True
    )
    password_hash: Mapped[str] = mapped_column(String(255), nullable=False)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    is_admin: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime,
        default=datetime.utcnow,
        nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime,
        default=datetime.utcnow,
        onupdate=datetime.utcnow,
        nullable=False
    )

    # Relationships
    api_keys: Mapped[list["UserAPIKey"]] = relationship(
        "UserAPIKey",
        back_populates="user",
        cascade="all, delete-orphan"
    )

    def __repr__(self) -> str:
        return f"<User(id={self.id}, username={self.username})>"


class UserAPIKey(Base):
    """User's LLM provider API keys."""
    __tablename__ = "user_api_keys"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4
    )
    user_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False
    )
    provider: Mapped[str] = mapped_column(
        String(50),
        nullable=False
    )  # anthropic, openai, ollama
    api_key_encrypted: Mapped[str] = mapped_column(Text, nullable=False)
    is_valid: Mapped[Optional[bool]] = mapped_column(Boolean, nullable=True)
    last_validated_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime,
        default=datetime.utcnow,
        nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime,
        default=datetime.utcnow,
        onupdate=datetime.utcnow,
        nullable=False
    )

    # Relationships
    user: Mapped["User"] = relationship("User", back_populates="api_keys")

    # Composite unique constraint
    __table_args__ = (
        Index("ix_user_provider", "user_id", "provider", unique=True),
    )

    def __repr__(self) -> str:
        return f"<UserAPIKey(id={self.id}, provider={self.provider})>"


class Finding(Base):
    """Security finding with triage metadata."""
    __tablename__ = "findings"

    # Core finding fields
    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    agent_id: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    repo_id: Mapped[str] = mapped_column(String(64), nullable=False)
    severity: Mapped[str] = mapped_column(String(20), nullable=False)
    title: Mapped[str] = mapped_column(Text, nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False)
    file_path: Mapped[str] = mapped_column(Text, nullable=False)
    line_start: Mapped[int] = mapped_column(Integer, nullable=False)
    line_end: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    code_snippet: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    vulnerable_code: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    vulnerability_type: Mapped[str] = mapped_column(String(128), nullable=False)
    cwe_id: Mapped[Optional[str]] = mapped_column(String(20), nullable=True)
    attack_scenario: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    proof_of_concept: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    recommended_fix: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    # Confidence score (0.0-1.0). Note: For equality comparisons, use tolerance
    # or compare against rounded values. New code should prefer classification_confidence
    # (integer 0-100) for triage-related confidence scores.
    confidence: Mapped[float] = mapped_column(Float, nullable=False)
    source_trace: Mapped[Optional[dict]] = mapped_column(JSONB, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime,
        default=datetime.utcnow,
        nullable=False
    )
    metadata_: Mapped[dict] = mapped_column("metadata", JSONB, default=dict, nullable=False)

    # Classification gate fields (legacy)
    classification: Mapped[Optional[str]] = mapped_column(String(32), nullable=True)
    config_dependent: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    config_flag: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)
    default_secure: Mapped[Optional[bool]] = mapped_column(Boolean, nullable=True)
    contradiction_present: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    fix_type: Mapped[str] = mapped_column(String(20), default="code", nullable=False)
    classification_reasoning: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    # Triage fields (new)
    batch_id: Mapped[Optional[str]] = mapped_column(String(32), nullable=True, index=True)
    disposition: Mapped[Optional[str]] = mapped_column(String(32), nullable=True, index=True)
    classification_confidence: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    exploit_confidence: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    proof_checklist: Mapped[Optional[dict]] = mapped_column(JSONB, nullable=True)
    reasoning: Mapped[Optional[list]] = mapped_column(JSONB, nullable=True)
    triage_policy_version: Mapped[Optional[str]] = mapped_column(String(16), nullable=True)
    triaged_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    category: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)

    # Protocol layer fields
    submission_result: Mapped[Optional[dict]] = mapped_column(JSONB, nullable=True)
    evidence_quest_id: Mapped[Optional[str]] = mapped_column(String(64), nullable=True, index=True)
    evidence_quest_completed: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)

    # Relationships
    evidence_blobs: Mapped[list["EvidenceBlob"]] = relationship(
        "EvidenceBlob",
        back_populates="finding",
        cascade="all, delete-orphan"
    )

    # Composite indexes
    __table_args__ = (
        Index("idx_findings_agent_disposition", "agent_id", "disposition"),
        Index("idx_findings_agent_triaged_at", "agent_id", "triaged_at"),
    )

    def __repr__(self) -> str:
        return f"<Finding(id={self.id}, title={self.title[:50]}, disposition={self.disposition})>"


class EvidenceBlob(Base):
    """Evidence snippet gathered during triage."""
    __tablename__ = "evidence_blobs"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    finding_id: Mapped[str] = mapped_column(
        String(64),
        ForeignKey("findings.id", ondelete="CASCADE"),
        nullable=False,
        index=True
    )
    evidence_type: Mapped[str] = mapped_column(String(32), nullable=False, index=True)
    file_path: Mapped[Optional[str]] = mapped_column(String(512), nullable=True)
    line_number: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    snippet: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    match_type: Mapped[Optional[str]] = mapped_column(String(32), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime,
        default=datetime.utcnow,
        nullable=False
    )

    # Relationship
    finding: Mapped["Finding"] = relationship("Finding", back_populates="evidence_blobs")

    def __repr__(self) -> str:
        return f"<EvidenceBlob(id={self.id}, type={self.evidence_type}, match_type={self.match_type})>"


class ProtocolPolicy(Base):
    """Protocol policy configuration for submission evaluation."""
    __tablename__ = "protocol_policies"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    display_name: Mapped[str] = mapped_column(String(128), nullable=False)
    config: Mapped[dict] = mapped_column(JSONB, nullable=False)
    is_default: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime,
        default=datetime.utcnow,
        nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime,
        default=datetime.utcnow,
        onupdate=datetime.utcnow,
        nullable=False
    )

    def __repr__(self) -> str:
        return f"<ProtocolPolicy(id={self.id}, display_name={self.display_name})>"


class EvidenceQuest(Base):
    """Evidence gathering quest for findings."""
    __tablename__ = "evidence_quests"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    finding_id: Mapped[str] = mapped_column(
        String(64),
        ForeignKey("findings.id", ondelete="CASCADE"),
        nullable=False,
        index=True
    )
    category: Mapped[str] = mapped_column(String(64), nullable=False)
    quest_type: Mapped[str] = mapped_column(String(64), nullable=False)
    status: Mapped[str] = mapped_column(String(32), nullable=False, index=True)
    missing_items: Mapped[Optional[list]] = mapped_column(JSONB, nullable=True)
    evidence_found: Mapped[Optional[dict]] = mapped_column(JSONB, nullable=True)
    new_checklist_items: Mapped[Optional[dict]] = mapped_column(JSONB, nullable=True)
    started_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    completed_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    success: Mapped[Optional[bool]] = mapped_column(Boolean, nullable=True)
    error_message: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime,
        default=datetime.utcnow,
        nullable=False
    )

    def __repr__(self) -> str:
        return f"<EvidenceQuest(id={self.id}, finding_id={self.finding_id}, status={self.status})>"
