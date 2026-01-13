# Time-Tiered Audit System Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Replace the agent-type-based architecture with a unified time-based audit system that forces deep, coverage-driven security reviews.

**Architecture:** Single unified agent driven by time tiers (Quick/Medium/Deep/Ultra/Evil). File prioritization via sink detection + connectivity scoring. Two-phase system: system-driven initially, then LLM-driven after tier breadth coverage. Database-backed state persistence for resume capability.

**Tech Stack:** Python/FastAPI, SQLAlchemy, Pydantic, React/TypeScript, WebSocket

---

## Task 1: Add TimeTier Enum and Update Schemas

**Files:**
- Modify: `backend/models/schemas.py:28-36`

**Step 1: Add TimeTier enum after AgentType**

Add the new enum after line 36:

```python
class TimeTier(str, Enum):
    """Time-based audit tiers."""
    QUICK = "quick"      # 10 minutes
    MEDIUM = "medium"    # 30 minutes
    DEEP = "deep"        # 1 hour
    ULTRA = "ultra"      # 3 hours
    EVIL = "evil"        # 24 hours
```

**Step 2: Add RiskTier enum for vulnerability classification**

```python
class RiskTier(str, Enum):
    """Vulnerability risk tiers with weights."""
    S = "S"  # 100 - Memory safety, pre-auth RCE, authn bypass
    A = "A"  # 80 - Code-exec injections, file write, SQLi w/ write
    B = "B"  # 60 - SSRF, read-only injection, path traversal
    C = "C"  # 40 - XSS, CSRF, clickjacking, open redirect
    D = "D"  # 20 - Info disclosure, security headers, logging
    E = "E"  # 10 - Hygiene, non-exploitable misconfigs

RISK_TIER_WEIGHTS = {
    RiskTier.S: 100,
    RiskTier.A: 80,
    RiskTier.B: 60,
    RiskTier.C: 40,
    RiskTier.D: 20,
    RiskTier.E: 10,
}
```

**Step 3: Add AuditPhase enum**

```python
class AuditPhase(str, Enum):
    """Phase of the time-tiered audit."""
    SYSTEM_DRIVEN = "system_driven"
    LLM_DRIVEN = "llm_driven"
```

**Step 4: Add time tier to AgentCreateRequest**

Modify `AgentCreateRequest` class to add:

```python
    # Time-tiered audit configuration
    time_tier: Optional[TimeTier] = None  # If set, uses time-tiered audit
```

**Step 5: Commit**

```bash
git add backend/models/schemas.py
git commit -m "feat: add TimeTier, RiskTier, and AuditPhase enums

Add foundation enums for time-tiered audit system:
- TimeTier: quick/medium/deep/ultra/evil with durations
- RiskTier: S/A/B/C/D/E vulnerability classification
- AuditPhase: system_driven/llm_driven transition tracking

Co-Authored-By: Claude Opus 4.5 <noreply@anthropic.com>"
```

---

## Task 2: Create Database Models for Audit Sessions

**Files:**
- Modify: `backend/database/models.py`
- Modify: `backend/database/__init__.py`

**Step 1: Add AuditSession model**

Add to `backend/database/models.py`:

```python
from sqlalchemy import JSON, Integer, Float


class AuditSession(Base):
    """Persistent state for time-tiered audit sessions."""
    __tablename__ = "audit_sessions"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4
    )
    agent_id: Mapped[str] = mapped_column(String(12), unique=True, nullable=False, index=True)
    repo_id: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    time_tier: Mapped[str] = mapped_column(String(20), nullable=False)

    # Timing
    start_time: Mapped[datetime] = mapped_column(DateTime, nullable=False)
    elapsed_seconds: Mapped[float] = mapped_column(Float, default=0.0, nullable=False)
    time_limit_seconds: Mapped[int] = mapped_column(Integer, nullable=False)

    # Phase tracking
    current_phase: Mapped[str] = mapped_column(String(20), default="system_driven", nullable=False)
    files_analyzed: Mapped[list] = mapped_column(JSON, default=list, nullable=False)
    tiers_covered: Mapped[list] = mapped_column(JSON, default=list, nullable=False)

    # Counters
    consecutive_nothing_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    recommendation_batch_size: Mapped[int] = mapped_column(Integer, default=2, nullable=False)

    # LLM state
    attack_surface_map: Mapped[list] = mapped_column(JSON, default=list, nullable=False)
    trust_boundaries: Mapped[list] = mapped_column(JSON, default=list, nullable=False)
    open_questions: Mapped[list] = mapped_column(JSON, default=list, nullable=False)
    high_risk_areas_reviewed: Mapped[list] = mapped_column(JSON, default=list, nullable=False)

    # Conversation history
    conversation_history: Mapped[list] = mapped_column(JSON, default=list, nullable=False)

    # Queue
    pending_files: Mapped[list] = mapped_column(JSON, default=list, nullable=False)

    # Status
    status: Mapped[str] = mapped_column(String(20), default="running", nullable=False)

    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)

    # Relationship to findings
    findings: Mapped[list["AuditFinding"]] = relationship(
        "AuditFinding",
        back_populates="session",
        cascade="all, delete-orphan"
    )


class AuditFinding(Base):
    """Mutable findings with revision history."""
    __tablename__ = "audit_findings"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4
    )
    session_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("audit_sessions.id", ondelete="CASCADE"),
        nullable=False
    )
    finding_id: Mapped[str] = mapped_column(String(12), nullable=False, index=True)

    # Core finding data
    title: Mapped[str] = mapped_column(String(500), nullable=False)
    evidence: Mapped[list] = mapped_column(JSON, default=list, nullable=False)
    risk_tier: Mapped[str] = mapped_column(String(5), nullable=False)
    impact: Mapped[str] = mapped_column(Text, nullable=True)
    preconditions: Mapped[list] = mapped_column(JSON, default=list, nullable=False)
    recommendations: Mapped[list] = mapped_column(JSON, default=list, nullable=False)

    # Mutation tracking
    status: Mapped[str] = mapped_column(String(20), default="active", nullable=False)
    confidence: Mapped[float] = mapped_column(Float, default=0.5, nullable=False)

    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)

    # Relationships
    session: Mapped["AuditSession"] = relationship("AuditSession", back_populates="findings")
    revisions: Mapped[list["FindingRevision"]] = relationship(
        "FindingRevision",
        back_populates="finding",
        cascade="all, delete-orphan",
        order_by="FindingRevision.created_at"
    )


class FindingRevision(Base):
    """Revision history for mutable findings."""
    __tablename__ = "finding_revisions"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4
    )
    finding_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("audit_findings.id", ondelete="CASCADE"),
        nullable=False
    )

    field_changes: Mapped[dict] = mapped_column(JSON, nullable=False)
    reason: Mapped[str] = mapped_column(Text, nullable=True)

    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, nullable=False)

    # Relationship
    finding: Mapped["AuditFinding"] = relationship("AuditFinding", back_populates="revisions")
```

**Step 2: Update __init__.py exports**

```python
from .connection import get_db, engine, AsyncSessionLocal, init_db
from .models import Base, User, UserAPIKey, AuditSession, AuditFinding, FindingRevision

__all__ = [
    "get_db", "engine", "AsyncSessionLocal", "init_db", "Base",
    "User", "UserAPIKey", "AuditSession", "AuditFinding", "FindingRevision"
]
```

**Step 3: Commit**

```bash
git add backend/database/models.py backend/database/__init__.py
git commit -m "feat: add database models for audit session persistence

Add SQLAlchemy models:
- AuditSession: full state persistence for resume capability
- AuditFinding: mutable findings with status tracking
- FindingRevision: revision history for finding mutations

Co-Authored-By: Claude Opus 4.5 <noreply@anthropic.com>"
```

---

## Task 3: Create File Prioritizer Service

**Files:**
- Create: `backend/services/file_prioritizer.py`

**Step 1: Create the file prioritizer service**

```python
"""File prioritization service for time-tiered audits.

Prioritizes files based on:
1. Sink tier weights (S=100, A=80, B=60, C=40, D=20, E=10)
2. Connectivity (imports by/from other files)
3. Entry point bonuses (routes, controllers, handlers)
"""

import os
import re
from dataclasses import dataclass, field
from typing import Optional
from pathlib import Path

from models.schemas import RiskTier, RISK_TIER_WEIGHTS


@dataclass
class DetectedSink:
    """A detected sink in a file."""
    file_path: str
    line_number: int
    sink_type: str
    risk_tier: RiskTier
    pattern_matched: str
    code_snippet: str


@dataclass
class FileScore:
    """Prioritization score for a file."""
    file_path: str
    total_score: float
    max_sink_weight: int = 0
    sink_count: int = 0
    sinks: list[DetectedSink] = field(default_factory=list)
    import_count: int = 0
    imported_by_count: int = 0
    sensitive_imports: list[str] = field(default_factory=list)
    is_entry_point: bool = False
    reason: str = ""


# Sink detection patterns by tier
SINK_PATTERNS = {
    RiskTier.S: [
        # Memory safety (mainly for C/C++/Rust unsafe)
        (r'\bunsafe\s*\{', "unsafe_block"),
        (r'\bstrcpy\s*\(', "strcpy"),
        (r'\bsprintf\s*\(', "sprintf"),
        (r'\bgets\s*\(', "gets"),
        # Pre-auth RCE patterns
        (r'@app\.route.*methods.*POST.*\n[^@]*(?:eval|exec|subprocess)', "pre_auth_rce"),
    ],
    RiskTier.A: [
        # Deserialization
        (r'\bpickle\.loads?\s*\(', "pickle_deserialize"),
        (r'\byaml\.(?:unsafe_)?load\s*\(', "yaml_load"),
        (r'\bjson\.loads?\s*\([^)]*\brequest\b', "json_deserialize_request"),
        (r'ObjectInputStream', "java_deserialize"),
        (r'unserialize\s*\(', "php_unserialize"),
        # Code execution
        (r'\beval\s*\(', "eval"),
        (r'\bexec\s*\(', "exec"),
        (r'\bcompile\s*\([^)]+\)\s*\)', "compile_exec"),
        # Command injection
        (r'\bsubprocess\.(?:run|call|Popen|check_output)\s*\([^)]*shell\s*=\s*True', "subprocess_shell"),
        (r'\bos\.system\s*\(', "os_system"),
        (r'\bos\.popen\s*\(', "os_popen"),
        (r'child_process\.exec\s*\(', "child_process_exec"),
        # Template injection
        (r'render_template_string\s*\(', "ssti"),
        (r'\.render\s*\([^)]*\+', "template_concat"),
        (r'Jinja2\s*\([^)]*autoescape\s*=\s*False', "jinja_no_escape"),
        # SQL with write
        (r'(?:INSERT|UPDATE|DELETE|DROP|CREATE|ALTER)\s+.*\+.*(?:request|input|param)', "sql_write"),
    ],
    RiskTier.B: [
        # SSRF
        (r'requests\.(?:get|post|put|delete|head|patch)\s*\([^)]*(?:request|input|param|url)', "ssrf"),
        (r'urllib\.(?:request\.)?urlopen\s*\(', "urllib_ssrf"),
        (r'http\.client\.HTTP', "http_client"),
        (r'fetch\s*\([^)]*(?:req|input|param)', "fetch_ssrf"),
        # Read-only SQL injection
        (r'(?:SELECT|FROM|WHERE)\s+.*["\']?\s*\+\s*', "sqli_read"),
        (r'\.query\s*\([^)]*\+', "sqli_query"),
        (r'\.execute\s*\([^)]*%', "sqli_format"),
        (r'\.raw\s*\([^)]*\+', "sqli_raw"),
        # Path traversal / LFI
        (r'open\s*\([^)]*(?:request|input|param|filename)', "lfi"),
        (r'(?:send_file|send_from_directory)\s*\([^)]*(?:request|input)', "path_traversal"),
        (r'\.\./', "dot_dot_slash"),
        # XXE
        (r'etree\.parse\s*\(', "xxe_parse"),
        (r'XMLParser\s*\(', "xxe_parser"),
        (r'xml\.dom\.minidom', "xxe_minidom"),
    ],
    RiskTier.C: [
        # XSS
        (r'innerHTML\s*=', "xss_innerhtml"),
        (r'document\.write\s*\(', "xss_document_write"),
        (r'\.html\s*\([^)]*(?:request|input|param)', "xss_jquery_html"),
        (r'\|\s*safe\b', "xss_safe_filter"),
        (r'dangerouslySetInnerHTML', "xss_react_dangerous"),
        # CSRF (missing protection)
        (r'@csrf_exempt', "csrf_exempt"),
        (r'csrf\s*:\s*false', "csrf_disabled"),
        # Open redirect
        (r'redirect\s*\([^)]*(?:request|input|param|url|next)', "open_redirect"),
        (r'location\s*=\s*[^;]*(?:request|input|param)', "open_redirect_js"),
        # Header injection
        (r'\.set_header\s*\([^)]*(?:request|input)', "header_injection"),
        (r'response\.headers\[[^]]*\]\s*=\s*[^;]*(?:request|input)', "header_injection"),
    ],
    RiskTier.D: [
        # Info disclosure
        (r'(?:print|console\.log|logger\.debug)\s*\([^)]*(?:password|secret|key|token)', "info_leak_log"),
        (r'DEBUG\s*=\s*True', "debug_enabled"),
        (r'\.env\b', "env_exposure"),
        # Missing security headers
        (r'X-Frame-Options', "missing_xframe"),  # Inverse - check if NOT present
        (r'Content-Security-Policy', "missing_csp"),
    ],
    RiskTier.E: [
        # Weak crypto
        (r'\bMD5\s*\(', "weak_hash_md5"),
        (r'\bSHA1\s*\(', "weak_hash_sha1"),
        (r'DES\b', "weak_cipher_des"),
        # Hardcoded secrets (likely false positives)
        (r'(?:password|secret|key)\s*=\s*["\'][^"\']+["\']', "hardcoded_secret"),
    ],
}

# Sensitive imports that indicate security-critical code
SENSITIVE_IMPORTS = [
    "subprocess", "os", "sys", "pickle", "yaml", "json",
    "sqlite3", "psycopg2", "mysql", "pymongo", "sqlalchemy",
    "cryptography", "hashlib", "hmac", "secrets",
    "jwt", "oauth", "auth", "session", "cookie",
    "requests", "urllib", "http", "socket",
    "jinja2", "mako", "template",
    "xml", "lxml", "etree",
]

# Entry point directory patterns
ENTRY_POINT_PATTERNS = [
    r'/routes?/',
    r'/api/',
    r'/controllers?/',
    r'/handlers?/',
    r'/views?/',
    r'/endpoints?/',
    r'/routers?/',
]


class FilePrioritizer:
    """Prioritizes files for security review based on sink detection and connectivity."""

    def __init__(self, repo_path: str):
        self.repo_path = repo_path
        self._file_contents: dict[str, str] = {}
        self._import_graph: dict[str, set[str]] = {}  # file -> files it imports
        self._imported_by: dict[str, set[str]] = {}   # file -> files that import it

    def scan_repository(self) -> list[FileScore]:
        """Scan entire repository and return prioritized file list."""
        # Collect all source files
        source_files = self._collect_source_files()

        # Build import graph
        self._build_import_graph(source_files)

        # Score each file
        scores: list[FileScore] = []
        for file_path in source_files:
            score = self._score_file(file_path)
            if score.total_score > 0:
                scores.append(score)

        # Sort by score descending
        scores.sort(key=lambda s: s.total_score, reverse=True)

        return scores

    def get_files_by_tier(self, scores: list[FileScore]) -> dict[RiskTier, list[FileScore]]:
        """Group scored files by their highest risk tier."""
        by_tier: dict[RiskTier, list[FileScore]] = {tier: [] for tier in RiskTier}

        for score in scores:
            if score.sinks:
                highest_tier = min(score.sinks, key=lambda s: RISK_TIER_WEIGHTS[s.risk_tier]).risk_tier
                by_tier[highest_tier].append(score)

        return by_tier

    def _collect_source_files(self) -> list[str]:
        """Collect all source code files in the repository."""
        extensions = {'.py', '.js', '.ts', '.jsx', '.tsx', '.java', '.go', '.php', '.rb', '.rs', '.c', '.cpp', '.h'}
        source_files = []

        for root, dirs, files in os.walk(self.repo_path):
            # Skip common non-source directories
            dirs[:] = [d for d in dirs if d not in {
                'node_modules', '.git', '__pycache__', 'venv', '.venv',
                'dist', 'build', 'target', '.next', 'vendor'
            }]

            for file in files:
                ext = os.path.splitext(file)[1].lower()
                if ext in extensions:
                    full_path = os.path.join(root, file)
                    rel_path = os.path.relpath(full_path, self.repo_path)
                    source_files.append(rel_path)

        return source_files

    def _get_file_content(self, file_path: str) -> str:
        """Get file content, cached."""
        if file_path not in self._file_contents:
            full_path = os.path.join(self.repo_path, file_path)
            try:
                with open(full_path, 'r', encoding='utf-8', errors='ignore') as f:
                    self._file_contents[file_path] = f.read()
            except Exception:
                self._file_contents[file_path] = ""
        return self._file_contents[file_path]

    def _build_import_graph(self, files: list[str]) -> None:
        """Build import/dependency graph between files."""
        for file_path in files:
            content = self._get_file_content(file_path)
            imports = self._extract_imports(content, file_path)
            self._import_graph[file_path] = imports

            for imported in imports:
                if imported not in self._imported_by:
                    self._imported_by[imported] = set()
                self._imported_by[imported].add(file_path)

    def _extract_imports(self, content: str, file_path: str) -> set[str]:
        """Extract imported file paths from content."""
        imports = set()

        # Python imports
        for match in re.finditer(r'^(?:from|import)\s+([\w.]+)', content, re.MULTILINE):
            module = match.group(1).replace('.', '/')
            imports.add(module)

        # JavaScript/TypeScript imports
        for match in re.finditer(r'(?:import|require)\s*\(?[\'"]([^"\']+)["\']', content):
            imports.add(match.group(1))

        return imports

    def _score_file(self, file_path: str) -> FileScore:
        """Calculate priority score for a single file."""
        content = self._get_file_content(file_path)

        score = FileScore(file_path=file_path, total_score=0)

        # Detect sinks
        for tier, patterns in SINK_PATTERNS.items():
            for pattern, sink_type in patterns:
                for match in re.finditer(pattern, content, re.IGNORECASE | re.MULTILINE):
                    line_num = content[:match.start()].count('\n') + 1
                    lines = content.split('\n')
                    snippet = lines[max(0, line_num-2):min(len(lines), line_num+2)]

                    sink = DetectedSink(
                        file_path=file_path,
                        line_number=line_num,
                        sink_type=sink_type,
                        risk_tier=tier,
                        pattern_matched=pattern,
                        code_snippet='\n'.join(snippet)
                    )
                    score.sinks.append(sink)

                    weight = RISK_TIER_WEIGHTS[tier]
                    if weight > score.max_sink_weight:
                        score.max_sink_weight = weight
                    score.sink_count += 1

        # Check sensitive imports
        for sensitive in SENSITIVE_IMPORTS:
            if re.search(rf'\b{sensitive}\b', content, re.IGNORECASE):
                score.sensitive_imports.append(sensitive)

        # Check if entry point
        for pattern in ENTRY_POINT_PATTERNS:
            if re.search(pattern, file_path, re.IGNORECASE):
                score.is_entry_point = True
                break

        # Get connectivity scores
        score.import_count = len(self._import_graph.get(file_path, set()))
        score.imported_by_count = len(self._imported_by.get(file_path, set()))

        # Calculate total score
        score.total_score = (
            score.max_sink_weight +
            (score.imported_by_count * 2) +
            (len(score.sensitive_imports) * 10) +
            (20 if score.is_entry_point else 0)
        )

        # Build reason string
        reasons = []
        if score.sinks:
            tier_counts = {}
            for sink in score.sinks:
                tier_counts[sink.risk_tier.value] = tier_counts.get(sink.risk_tier.value, 0) + 1
            reasons.append(f"Sinks: {tier_counts}")
        if score.sensitive_imports:
            reasons.append(f"Sensitive imports: {score.sensitive_imports[:3]}")
        if score.is_entry_point:
            reasons.append("Entry point")
        if score.imported_by_count > 0:
            reasons.append(f"Imported by {score.imported_by_count} files")

        score.reason = "; ".join(reasons)

        return score


# Singleton instance
_prioritizer: Optional[FilePrioritizer] = None


def get_prioritizer(repo_path: str) -> FilePrioritizer:
    """Get or create file prioritizer for a repository."""
    global _prioritizer
    if _prioritizer is None or _prioritizer.repo_path != repo_path:
        _prioritizer = FilePrioritizer(repo_path)
    return _prioritizer
```

**Step 2: Commit**

```bash
git add backend/services/file_prioritizer.py
git commit -m "feat: add file prioritizer service for sink detection

Implements file prioritization based on:
- Sink tier weights (S=100 to E=10)
- Connectivity scoring (imports/imported-by)
- Entry point detection
- Sensitive import detection

Patterns cover: deserialization, code exec, SQLi, SSRF,
XSS, path traversal, and more across all risk tiers.

Co-Authored-By: Claude Opus 4.5 <noreply@anthropic.com>"
```

---

## Task 4: Create Audit State Manager Service

**Files:**
- Create: `backend/services/audit_state_manager.py`

**Step 1: Create the audit state manager**

```python
"""Audit state manager for time-tiered audit persistence.

Handles:
- Session creation and persistence
- State updates after each round
- Resume capability
- Finding mutations with revision tracking
"""

import uuid
from datetime import datetime
from typing import Optional
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from database.models import AuditSession, AuditFinding, FindingRevision
from models.schemas import TimeTier, AuditPhase


# Time limits in seconds for each tier
TIME_LIMITS = {
    TimeTier.QUICK: 10 * 60,      # 10 minutes
    TimeTier.MEDIUM: 30 * 60,     # 30 minutes
    TimeTier.DEEP: 60 * 60,       # 1 hour
    TimeTier.ULTRA: 3 * 60 * 60,  # 3 hours
    TimeTier.EVIL: 24 * 60 * 60,  # 24 hours
}

# Patience thresholds (consecutive "nothing" before early exit)
PATIENCE_THRESHOLDS = {
    TimeTier.QUICK: 3,
    TimeTier.MEDIUM: 5,
    TimeTier.DEEP: 7,
    TimeTier.ULTRA: 10,
    TimeTier.EVIL: 15,
}


class AuditStateManager:
    """Manages persistent state for time-tiered audits."""

    def __init__(self, db: AsyncSession):
        self.db = db

    async def create_session(
        self,
        agent_id: str,
        repo_id: str,
        time_tier: TimeTier,
    ) -> AuditSession:
        """Create a new audit session."""
        session = AuditSession(
            agent_id=agent_id,
            repo_id=repo_id,
            time_tier=time_tier.value,
            start_time=datetime.utcnow(),
            elapsed_seconds=0.0,
            time_limit_seconds=TIME_LIMITS[time_tier],
            current_phase=AuditPhase.SYSTEM_DRIVEN.value,
            files_analyzed=[],
            tiers_covered=[],
            consecutive_nothing_count=0,
            recommendation_batch_size=2,
            attack_surface_map=[],
            trust_boundaries=[],
            open_questions=[],
            high_risk_areas_reviewed=[],
            conversation_history=[],
            pending_files=[],
            status="running",
        )
        self.db.add(session)
        await self.db.commit()
        await self.db.refresh(session)
        return session

    async def get_session(self, agent_id: str) -> Optional[AuditSession]:
        """Get session by agent ID."""
        result = await self.db.execute(
            select(AuditSession).where(AuditSession.agent_id == agent_id)
        )
        return result.scalar_one_or_none()

    async def update_session(
        self,
        agent_id: str,
        **updates
    ) -> Optional[AuditSession]:
        """Update session state."""
        session = await self.get_session(agent_id)
        if not session:
            return None

        for key, value in updates.items():
            if hasattr(session, key):
                setattr(session, key, value)

        session.updated_at = datetime.utcnow()
        await self.db.commit()
        await self.db.refresh(session)
        return session

    async def record_file_analyzed(
        self,
        agent_id: str,
        file_path: str,
        risk_tier: Optional[str] = None,
    ) -> Optional[AuditSession]:
        """Record that a file has been analyzed."""
        session = await self.get_session(agent_id)
        if not session:
            return None

        # Add to files analyzed
        files = list(session.files_analyzed)
        if file_path not in files:
            files.append(file_path)
            session.files_analyzed = files

        # Track tier coverage for phase transition
        if risk_tier:
            tiers = list(session.tiers_covered)
            if risk_tier not in tiers:
                tiers.append(risk_tier)
                session.tiers_covered = tiers

        await self.db.commit()
        await self.db.refresh(session)
        return session

    async def check_phase_transition(self, agent_id: str) -> bool:
        """Check if should transition from system-driven to LLM-driven.

        Transition when:
        - At least one file from each detected tier has been analyzed, OR
        - 10 files total analyzed
        """
        session = await self.get_session(agent_id)
        if not session:
            return False

        if session.current_phase == AuditPhase.LLM_DRIVEN.value:
            return False  # Already transitioned

        files_analyzed = len(session.files_analyzed)
        tiers_covered = len(session.tiers_covered)

        # Transition after 10 files or all detected tiers covered
        # (we'll check detected tiers from pending_files)
        if files_analyzed >= 10:
            session.current_phase = AuditPhase.LLM_DRIVEN.value
            await self.db.commit()
            return True

        # Check if we've covered all detected tiers
        detected_tiers = set()
        for pf in session.pending_files:
            if isinstance(pf, dict) and 'risk_tier' in pf:
                detected_tiers.add(pf['risk_tier'])

        if detected_tiers and set(session.tiers_covered) >= detected_tiers:
            session.current_phase = AuditPhase.LLM_DRIVEN.value
            await self.db.commit()
            return True

        return False

    async def increment_nothing_count(self, agent_id: str) -> tuple[int, bool]:
        """Increment consecutive nothing count. Returns (count, should_exit)."""
        session = await self.get_session(agent_id)
        if not session:
            return 0, False

        session.consecutive_nothing_count += 1
        await self.db.commit()

        threshold = PATIENCE_THRESHOLDS.get(
            TimeTier(session.time_tier),
            7
        )
        should_exit = session.consecutive_nothing_count >= threshold

        return session.consecutive_nothing_count, should_exit

    async def reset_nothing_count(self, agent_id: str) -> None:
        """Reset consecutive nothing count (found something)."""
        session = await self.get_session(agent_id)
        if session:
            session.consecutive_nothing_count = 0
            await self.db.commit()

    async def double_batch_size(self, agent_id: str) -> int:
        """Double recommendation batch size (capped at 64)."""
        session = await self.get_session(agent_id)
        if not session:
            return 2

        new_size = min(session.recommendation_batch_size * 2, 64)
        session.recommendation_batch_size = new_size
        await self.db.commit()

        return new_size

    async def add_finding(
        self,
        agent_id: str,
        finding_id: str,
        title: str,
        evidence: list[str],
        risk_tier: str,
        impact: str,
        preconditions: list[str],
        recommendations: list[str],
        confidence: float = 0.5,
    ) -> Optional[AuditFinding]:
        """Add a new finding to the session."""
        session = await self.get_session(agent_id)
        if not session:
            return None

        finding = AuditFinding(
            session_id=session.id,
            finding_id=finding_id,
            title=title,
            evidence=evidence,
            risk_tier=risk_tier,
            impact=impact,
            preconditions=preconditions,
            recommendations=recommendations,
            status="active",
            confidence=confidence,
        )
        self.db.add(finding)
        await self.db.commit()
        await self.db.refresh(finding)

        # Reset nothing count since we found something
        await self.reset_nothing_count(agent_id)

        return finding

    async def update_finding(
        self,
        finding_id: str,
        reason: str,
        **updates
    ) -> Optional[AuditFinding]:
        """Update a finding and record revision."""
        result = await self.db.execute(
            select(AuditFinding).where(AuditFinding.finding_id == finding_id)
        )
        finding = result.scalar_one_or_none()
        if not finding:
            return None

        # Record changes
        field_changes = {}
        for key, new_value in updates.items():
            if hasattr(finding, key):
                old_value = getattr(finding, key)
                if old_value != new_value:
                    field_changes[key] = {"old": old_value, "new": new_value}
                    setattr(finding, key, new_value)

        if field_changes:
            revision = FindingRevision(
                finding_id=finding.id,
                field_changes=field_changes,
                reason=reason,
            )
            self.db.add(revision)
            finding.updated_at = datetime.utcnow()
            await self.db.commit()
            await self.db.refresh(finding)

        return finding

    async def get_time_remaining(self, agent_id: str) -> float:
        """Get remaining time in seconds."""
        session = await self.get_session(agent_id)
        if not session:
            return 0.0

        return max(0.0, session.time_limit_seconds - session.elapsed_seconds)

    async def update_elapsed_time(self, agent_id: str, elapsed: float) -> bool:
        """Update elapsed time. Returns True if time limit reached."""
        session = await self.get_session(agent_id)
        if not session:
            return True

        session.elapsed_seconds = elapsed
        await self.db.commit()

        return elapsed >= session.time_limit_seconds

    async def save_conversation_history(
        self,
        agent_id: str,
        history: list[dict],
    ) -> None:
        """Save LLM conversation history for resume."""
        session = await self.get_session(agent_id)
        if session:
            session.conversation_history = history
            await self.db.commit()

    async def save_llm_state(
        self,
        agent_id: str,
        attack_surface_map: list,
        trust_boundaries: list,
        open_questions: list,
        high_risk_areas_reviewed: list,
    ) -> None:
        """Save LLM analysis state for resume."""
        session = await self.get_session(agent_id)
        if session:
            session.attack_surface_map = attack_surface_map
            session.trust_boundaries = trust_boundaries
            session.open_questions = open_questions
            session.high_risk_areas_reviewed = high_risk_areas_reviewed
            await self.db.commit()

    async def complete_session(self, agent_id: str, status: str = "completed") -> None:
        """Mark session as complete."""
        session = await self.get_session(agent_id)
        if session:
            session.status = status
            await self.db.commit()
```

**Step 2: Commit**

```bash
git add backend/services/audit_state_manager.py
git commit -m "feat: add audit state manager for session persistence

Implements:
- Session creation with time tier configuration
- State updates after each analysis round
- Phase transition detection (system -> LLM driven)
- Finding mutations with revision history
- Patience threshold tracking for early exit
- Batch size doubling (2->4->8...->64)
- Resume capability via conversation history

Co-Authored-By: Claude Opus 4.5 <noreply@anthropic.com>"
```

---

## Task 5: Create Core Prompt Template

**Files:**
- Create: `backend/prompts/time_tiered_prompt.py`

**Step 1: Create the prompt template**

```python
"""Core prompt template for time-tiered security audits.

This prompt enforces deep, coverage-driven audits through:
- Non-negotiable completion rules
- Depth Expansion Protocol (DEP)
- File doubling policy
- Structured JSON output
"""

from models.schemas import TimeTier, AuditPhase


def get_time_tiered_system_prompt() -> str:
    """Get the core system prompt for time-tiered audits."""
    return '''You are the Security Audit Brain for an automated, authorized, defensive vulnerability research pipeline.

NON-NEGOTIABLE RULES
- Never claim the audit is complete unless the Completion Criteria are satisfied (below).
- If you feel "there's nothing else to do," that is a trigger to run the Depth Expansion Protocol, NOT a reason to stop.
- If the context provider/API assistant says "no more files" or returns empty context, you must assume coverage is insufficient and request more context using the doubling policy (up to 64 files) and/or change what you ask for (targeted file patterns).
- Do NOT produce exploit payloads, step-by-step attack instructions, or operational guidance for attacking real systems. Focus on defensive findings, reasoning, and remediation.
- Operate only on provided artifacts and authorized scope.

ENVIRONMENT / INTERFACE
- You receive code/config/docs as "files" plus any tool summaries.
- You can request more context by returning a structured response with:
  - status = NEED_MORE_CONTEXT
  - next_batch_size (doubling up to 64)
  - requested_paths / requested_file_types / requested_search_terms
  - why (explicit gaps)
(If your platform uses a tool call, express the same intent in the tool's expected format.)

PRIMARY OBJECTIVE
Perform a deep, coverage-driven security audit of the available system artifacts. Your job is to:
1) Build a precise "attack surface + trust boundary" map,
2) Identify high-risk vulnerability candidates and insecure patterns,
3) Propose defensive mitigations and confirm what evidence supports each claim,
4) Explicitly identify what you still do NOT know and request the minimum additional context to resolve it.

DEPTH EXPANSION PROTOCOL (DEP) — RUN THIS WHENEVER YOU'RE ABOUT TO STOP
When you think you're done, or when you receive "no more context," you MUST do the following:

DEP-1: Coverage Checklist (must explicitly answer each)
A) Entry points: HTTP routes/controllers, RPC, message queues, cron/jobs, CLI commands, webhooks
B) AuthN/AuthZ: session/token verification, middleware, RBAC/ABAC checks, object-level authorization
C) Data flows: user input → parsing/validation → business logic → sinks (DB, filesystem, network, templates)
D) Secrets & trust: config files, env usage, key handling, signing/verifying logic, credential loading
E) Dangerous primitives: deserialization, template rendering, shell/process execution, file upload/write
F) Dependencies & supply chain: lockfiles, vendored libs, update mechanisms, CI/CD scripts
G) Logging/telemetry: sensitive data exposure, audit logging completeness
H) Multi-tenancy boundaries (if applicable): tenant scoping, row-level checks, org/user isolation
I) Error handling: exception paths, fallback logic, debug/admin modes

DEP-2: "Shallow Audit Detector"
If ANY of these are true, you are not allowed to conclude:
- You have not identified at least 5 concrete entry points and their authorization model (or explicitly stated why you can't).
- You cannot name the primary data stores and where queries are built.
- You have not examined the auth/session/token verification code path.
- You have not examined file/network/template/deserialization touchpoints (or proven they don't exist).
- Your findings list is generic (e.g., "check for SQLi") instead of evidence-based (file/function-level).

DEP-3: Targeted Context Requests (be specific)
If gaps exist, request additional context by naming:
- Exact file paths if known, otherwise patterns (e.g., *auth*, *middleware*, *routes*, *controllers*, *db*, *orm*, *queries*, *serialization*, *templates*, *uploads*, *storage*, *config*, *docker*, *k8s*, *ci*, *terraform*)
- Specific symbols to search for (e.g., "jwt", "token", "verify", "deserialize", "render", "exec", "spawn", "eval", "pickle", "yaml", "xml", "template", "upload", "path", "join", "SELECT", "query")
- The reason each requested item matters.

FILE DOUBLING POLICY
- If you need more context, set next_batch_size = min(current_batch_size * 2, max_batch_size).
- If current_batch_size is unknown, assume 4 for the first request.
- If the API returns "no more files" but DEP indicates gaps, request again with:
  (a) the doubled batch size AND
  (b) a targeted list of paths/patterns and search terms.
- Stop increasing at 64 files. If still missing critical items after max_batch_size, return status = INSUFFICIENT_CONTEXT with a prioritized list of what is missing.

COMPLETION CRITERIA (only then you may conclude AUDIT_COMPLETE)
You may conclude only if:
- DEP-1 checklist is fully addressed with evidence OR explicit proof of absence.
- You produced an attack-surface map and trust-boundary assumptions.
- Each high-risk finding includes: evidence (file/function), impact, preconditions, and remediation.
- You enumerated remaining unknowns (if any) and why they don't block conclusions.

OUTPUT FORMAT (always respond in this JSON shape)
{
  "status": "IN_PROGRESS | NEED_MORE_CONTEXT | AUDIT_COMPLETE | INSUFFICIENT_CONTEXT",
  "current_batch_size": <int>,
  "next_batch_size": <int or null>,
  "audit_state": {
    "attack_surface_map": [ ... ],
    "trust_boundaries": [ ... ],
    "high_risk_areas_reviewed": [ ... ],
    "open_questions": [ ... ]
  },
  "findings": [
    {
      "id": "<stable short id>",
      "title": "<specific>",
      "evidence": ["file:path:line_or_symbol", "..."],
      "risk_tier": "S|A|B|C|D|E",
      "impact": "<defensive impact description>",
      "preconditions": ["..."],
      "recommendations": ["..."]
    }
  ],
  "context_request": {
    "requested_paths": [ ... ],
    "requested_file_types": [ ... ],
    "requested_search_terms": [ ... ],
    "why": "<what gap this resolves>"
  },
  "files_to_investigate": [
    "<file paths you want to look at next based on your analysis>"
  ]
}

Remember: "I'm done" is not a valid stopping condition. Only the Completion Criteria are.'''


def format_variables_block(
    time_tier: TimeTier,
    time_remaining_seconds: float,
    current_phase: AuditPhase,
    files_analyzed_count: int,
    tiers_covered: list[str],
    consecutive_nothing_count: int,
    patience_threshold: int,
    current_batch_size: int,
    repo_language_stack: list[str],
    target_surface: str,
) -> str:
    """Format the dynamic variables block for injection."""
    time_remaining_human = _format_duration(time_remaining_seconds)

    return f'''VARIABLES (current state)
- time_tier: {time_tier.value}
- time_remaining_seconds: {time_remaining_seconds:.0f}
- time_remaining_human: {time_remaining_human}
- current_phase: {current_phase.value}
- files_analyzed_count: {files_analyzed_count}
- tiers_covered: {tiers_covered}
- consecutive_nothing_count: {consecutive_nothing_count}
- patience_threshold: {patience_threshold}
- current_batch_size: {current_batch_size}
- max_batch_size: 64
- vulnerability_tier_weights: {{S:100, A:80, B:60, C:40, D:20, E:10}}
- repo_language_stack: {repo_language_stack}
- target_surface: {target_surface}'''


def format_recommended_files_block(
    files: list[dict],
    phase: AuditPhase,
) -> str:
    """Format the recommended files block."""
    if not files:
        return "No additional files flagged for investigation."

    if phase == AuditPhase.SYSTEM_DRIVEN:
        header = "The following files have been flagged for investigation based on sink detection and connectivity analysis:"
    else:
        header = "System fallback suggestions (you may also suggest files based on your accumulated context):"

    lines = [header, ""]
    for i, f in enumerate(files, 1):
        lines.append(f"{i}. {f.get('file_path', 'unknown')} (score: {f.get('score', 0):.0f})")
        if f.get('reason'):
            lines.append(f"   - {f['reason']}")
        if f.get('sinks'):
            for sink in f['sinks'][:3]:
                lines.append(f"   - {sink.get('risk_tier', '?')}-tier sink: {sink.get('sink_type', 'unknown')} at line {sink.get('line_number', '?')}")
        lines.append("")

    return "\n".join(lines)


def format_llm_steering_block() -> str:
    """Format the LLM steering prompt for phase 2."""
    return '''You are now in LLM-driven phase. Based on your accumulated context:
- What files should we investigate next?
- What patterns or connections have you noticed?
- What areas remain under-explored?

Include your file suggestions in the "files_to_investigate" field of your response.'''


def _format_duration(seconds: float) -> str:
    """Format seconds as human-readable duration."""
    if seconds < 60:
        return f"{seconds:.0f} seconds"
    elif seconds < 3600:
        mins = seconds / 60
        return f"{mins:.0f} minutes"
    else:
        hours = seconds / 3600
        mins = (seconds % 3600) / 60
        if mins > 0:
            return f"{hours:.0f}h {mins:.0f}m"
        return f"{hours:.0f} hours"
```

**Step 2: Commit**

```bash
git add backend/prompts/time_tiered_prompt.py
git commit -m "feat: add core prompt template for time-tiered audits

Implements the Security Audit Brain prompt with:
- Non-negotiable completion rules
- Depth Expansion Protocol (DEP) with 9-point coverage checklist
- Shallow Audit Detector to prevent premature completion
- File doubling policy (2->4->8...->64)
- Structured JSON output format
- Dynamic variable injection
- Phase-aware file recommendation formatting

Co-Authored-By: Claude Opus 4.5 <noreply@anthropic.com>"
```

---

## Task 6: Create Time-Tiered Agent

**Files:**
- Create: `backend/agents/time_tiered_agent.py`

**Step 1: Create the unified time-tiered agent**

```python
"""Time-tiered security audit agent.

Unified agent that replaces all previous agent types with a single
time-based architecture. Duration is the only variable - all audits
use the same deep, coverage-driven methodology.
"""

import asyncio
import json
import time
import uuid
from datetime import datetime
from typing import Optional, Callable

from sqlalchemy.ext.asyncio import AsyncSession

from agents.base_agent import BaseAgent
from database import get_db
from models.schemas import (
    AgentCreateRequest,
    AgentStatus,
    AgentType,
    Finding,
    FindingCreate,
    Severity,
    TimeTier,
    AuditPhase,
    WSMessage,
    WSMessageType,
)
from providers import Message
from prompts.time_tiered_prompt import (
    get_time_tiered_system_prompt,
    format_variables_block,
    format_recommended_files_block,
    format_llm_steering_block,
)
from services.file_prioritizer import FilePrioritizer, FileScore
from services.audit_state_manager import (
    AuditStateManager,
    TIME_LIMITS,
    PATIENCE_THRESHOLDS,
)


class TimeTieredAgent(BaseAgent):
    """Time-tiered security audit agent."""

    agent_type: AgentType = AgentType.DEEP_AUDIT  # For compatibility

    def __init__(
        self,
        request: AgentCreateRequest,
        repo_path: str,
        on_message: Optional[Callable[[WSMessage], None]] = None,
        db: Optional[AsyncSession] = None,
    ):
        super().__init__(request, repo_path, on_message)

        self.time_tier = request.time_tier or TimeTier.MEDIUM
        self.time_limit = TIME_LIMITS[self.time_tier]
        self.patience_threshold = PATIENCE_THRESHOLDS[self.time_tier]

        self._db = db
        self._state_manager: Optional[AuditStateManager] = None
        self._prioritizer: Optional[FilePrioritizer] = None
        self._start_time: Optional[float] = None
        self._file_scores: list[FileScore] = []
        self._current_phase = AuditPhase.SYSTEM_DRIVEN
        self._conversation_history: list[dict] = []
        self._batch_size = 2
        self._nothing_count = 0

        # LLM state
        self._attack_surface_map: list = []
        self._trust_boundaries: list = []
        self._open_questions: list = []
        self._high_risk_areas: list = []

        # Update name to reflect tier
        self.name = f"audit_{self.time_tier.value}_{self.id}"

    async def _init_state_manager(self) -> None:
        """Initialize state manager with database session."""
        if self._state_manager is None:
            # Get database session
            async for db in get_db():
                self._db = db
                self._state_manager = AuditStateManager(db)
                break

    async def analyze(self) -> None:
        """Run the time-tiered audit loop."""
        await self._init_state_manager()

        # Initialize
        self._start_time = time.time()
        self._prioritizer = FilePrioritizer(self.repo_path)

        await self.emit_log(f"Starting {self.time_tier.value} tier audit ({self._format_duration(self.time_limit)})")

        # Create persistent session
        if self._state_manager:
            await self._state_manager.create_session(
                agent_id=self.id,
                repo_id=self.repo_id,
                time_tier=self.time_tier,
            )

        # Initial file scan
        await self.emit_log("Scanning repository for security-relevant files...")
        self._file_scores = self._prioritizer.scan_repository()
        await self.emit_log(f"Found {len(self._file_scores)} files with security relevance")

        # Group by tier for initial recommendations
        files_by_tier = self._prioritizer.get_files_by_tier(self._file_scores)
        tier_counts = {t.value: len(files) for t, files in files_by_tier.items() if files}
        await self.emit_log(f"Files by risk tier: {tier_counts}")

        # Main audit loop
        while not self._should_stop():
            elapsed = time.time() - self._start_time
            remaining = self.time_limit - elapsed

            # Update progress
            await self.emit_progress(
                current=int(elapsed),
                total=self.time_limit,
                file=f"{self._format_duration(remaining)} remaining"
            )

            # Get next batch of files to recommend
            recommended = self._get_next_recommendations()

            # Build prompt
            prompt = self._build_audit_prompt(recommended, elapsed, remaining)

            # Send to LLM
            response = await self._call_llm(prompt)

            # Parse response
            parsed = self._parse_response(response)

            # Update state based on response
            await self._process_response(parsed)

            # Check for phase transition
            if self._state_manager:
                transitioned = await self._state_manager.check_phase_transition(self.id)
                if transitioned:
                    self._current_phase = AuditPhase.LLM_DRIVEN
                    await self.emit_log("Transitioned to LLM-driven phase")

            # Brief pause to prevent tight loop
            await asyncio.sleep(0.5)

        # Final status
        if self._nothing_count >= self.patience_threshold:
            await self.emit_log(f"Audit ended: exhaustion threshold reached ({self._nothing_count}/{self.patience_threshold})")
        else:
            await self.emit_log(f"Audit ended: time limit reached")

        # Complete session
        if self._state_manager:
            await self._state_manager.complete_session(self.id)

    def _should_stop(self) -> bool:
        """Check if audit should stop."""
        if self._cancelled:
            return True

        elapsed = time.time() - self._start_time
        if elapsed >= self.time_limit:
            return True

        if self._nothing_count >= self.patience_threshold:
            return True

        return False

    def _get_next_recommendations(self) -> list[dict]:
        """Get next batch of file recommendations."""
        analyzed = set(self.processed_files)

        # Filter to unanalyzed files
        remaining = [f for f in self._file_scores if f.file_path not in analyzed]

        # Take top N based on current batch size
        batch = remaining[:self._batch_size]

        return [
            {
                "file_path": f.file_path,
                "score": f.total_score,
                "reason": f.reason,
                "sinks": [
                    {
                        "risk_tier": s.risk_tier.value,
                        "sink_type": s.sink_type,
                        "line_number": s.line_number,
                    }
                    for s in f.sinks[:5]
                ]
            }
            for f in batch
        ]

    def _build_audit_prompt(
        self,
        recommended_files: list[dict],
        elapsed: float,
        remaining: float,
    ) -> str:
        """Build the full audit prompt with dynamic context."""
        parts = [get_time_tiered_system_prompt()]

        # Add variables
        parts.append("\n\n" + format_variables_block(
            time_tier=self.time_tier,
            time_remaining_seconds=remaining,
            current_phase=self._current_phase,
            files_analyzed_count=len(self.processed_files),
            tiers_covered=list(set(
                s.risk_tier.value
                for f in self._file_scores
                if f.file_path in self.processed_files
                for s in f.sinks
            )),
            consecutive_nothing_count=self._nothing_count,
            patience_threshold=self.patience_threshold,
            current_batch_size=self._batch_size,
            repo_language_stack=self._detect_languages(),
            target_surface="api/web",  # TODO: detect from repo
        ))

        # Add recommended files
        parts.append("\n\n" + format_recommended_files_block(
            recommended_files,
            self._current_phase,
        ))

        # Add LLM steering in phase 2
        if self._current_phase == AuditPhase.LLM_DRIVEN:
            parts.append("\n\n" + format_llm_steering_block())

        # Add file contents for analysis
        if recommended_files:
            parts.append("\n\n=== FILES FOR ANALYSIS ===\n")
            for rf in recommended_files[:3]:  # Limit to 3 files per round
                content = self._read_file(rf["file_path"])
                if content:
                    parts.append(f"\n--- {rf['file_path']} ---\n")
                    parts.append(content[:10000])  # Truncate very long files

        return "\n".join(parts)

    async def _call_llm(self, prompt: str) -> str:
        """Call LLM and return response."""
        messages = list(self._conversation_history)
        messages.append({"role": "user", "content": prompt})

        full_response = ""
        async for chunk in self.provider.generate_stream(
            [Message(role=m["role"], content=m["content"]) for m in messages],
            system=None,  # System prompt is included in user message
        ):
            full_response += chunk.content
            if chunk.is_complete:
                break

        # Update conversation history
        self._conversation_history.append({"role": "user", "content": prompt})
        self._conversation_history.append({"role": "assistant", "content": full_response})

        # Persist history
        if self._state_manager:
            await self._state_manager.save_conversation_history(
                self.id,
                self._conversation_history,
            )

        return full_response

    def _parse_response(self, response: str) -> dict:
        """Parse LLM JSON response."""
        # Try to extract JSON from response
        try:
            # Find JSON block
            start = response.find('{')
            end = response.rfind('}') + 1
            if start >= 0 and end > start:
                json_str = response[start:end]
                return json.loads(json_str)
        except json.JSONDecodeError:
            pass

        # Return empty structure if parsing fails
        return {
            "status": "IN_PROGRESS",
            "findings": [],
            "audit_state": {},
            "context_request": {},
            "files_to_investigate": [],
        }

    async def _process_response(self, parsed: dict) -> None:
        """Process parsed LLM response."""
        status = parsed.get("status", "IN_PROGRESS")

        # Update LLM state
        audit_state = parsed.get("audit_state", {})
        self._attack_surface_map = audit_state.get("attack_surface_map", self._attack_surface_map)
        self._trust_boundaries = audit_state.get("trust_boundaries", self._trust_boundaries)
        self._open_questions = audit_state.get("open_questions", self._open_questions)
        self._high_risk_areas = audit_state.get("high_risk_areas_reviewed", self._high_risk_areas)

        # Persist LLM state
        if self._state_manager:
            await self._state_manager.save_llm_state(
                self.id,
                self._attack_surface_map,
                self._trust_boundaries,
                self._open_questions,
                self._high_risk_areas,
            )

        # Process findings
        findings = parsed.get("findings", [])
        for f in findings:
            await self._emit_finding(f)

        # Handle status
        if status == "NEED_MORE_CONTEXT":
            # Double batch size
            self._batch_size = min(self._batch_size * 2, 64)
            if self._state_manager:
                await self._state_manager.double_batch_size(self.id)
            await self.emit_log(f"Increasing batch size to {self._batch_size}")

            # Reset nothing count
            self._nothing_count = 0
            if self._state_manager:
                await self._state_manager.reset_nothing_count(self.id)

        elif status == "AUDIT_COMPLETE":
            # Check if this is premature
            if not findings and not parsed.get("files_to_investigate"):
                self._nothing_count += 1
                if self._state_manager:
                    count, _ = await self._state_manager.increment_nothing_count(self.id)
                    self._nothing_count = count
                await self.emit_log(f"No new findings or files suggested ({self._nothing_count}/{self.patience_threshold})")
            else:
                self._nothing_count = 0
                if self._state_manager:
                    await self._state_manager.reset_nothing_count(self.id)

        else:  # IN_PROGRESS or INSUFFICIENT_CONTEXT
            if findings or parsed.get("files_to_investigate"):
                self._nothing_count = 0
                if self._state_manager:
                    await self._state_manager.reset_nothing_count(self.id)

        # Mark analyzed files
        context_request = parsed.get("context_request", {})
        for path in context_request.get("requested_paths", []):
            if path not in self.processed_files:
                self.processed_files.append(path)
                if self._state_manager:
                    # Determine risk tier from our file scores
                    tier = None
                    for fs in self._file_scores:
                        if fs.file_path == path and fs.sinks:
                            tier = fs.sinks[0].risk_tier.value
                            break
                    await self._state_manager.record_file_analyzed(self.id, path, tier)

        # Process LLM file suggestions (phase 2)
        llm_suggestions = parsed.get("files_to_investigate", [])
        if llm_suggestions and self._current_phase == AuditPhase.LLM_DRIVEN:
            # Boost priority of LLM-suggested files
            for suggestion in llm_suggestions:
                for fs in self._file_scores:
                    if fs.file_path == suggestion or suggestion in fs.file_path:
                        fs.total_score += 50  # Bonus for LLM suggestion
            # Re-sort
            self._file_scores.sort(key=lambda s: s.total_score, reverse=True)

    async def _emit_finding(self, finding_data: dict) -> None:
        """Emit a finding from LLM response."""
        finding_id = finding_data.get("id", str(uuid.uuid4())[:8])

        # Check if this is an update to existing finding
        existing = next((f for f in self.findings if f.id == finding_id), None)

        # Map risk tier to severity
        risk_tier = finding_data.get("risk_tier", "C")
        severity_map = {"S": "critical", "A": "critical", "B": "high", "C": "medium", "D": "low", "E": "info"}
        severity = Severity(severity_map.get(risk_tier, "medium"))

        if existing:
            # Update existing finding
            # ... mutation logic would go here
            await self.emit(WSMessageType.FINDING, {
                "action": "updated",
                "finding": existing.model_dump(),
            })
        else:
            # Create new finding
            evidence = finding_data.get("evidence", [])
            file_path = evidence[0].split(":")[0] if evidence else "unknown"
            line_start = 1
            if evidence and ":" in evidence[0]:
                try:
                    line_start = int(evidence[0].split(":")[1])
                except (ValueError, IndexError):
                    pass

            finding_create = FindingCreate(
                severity=severity,
                title=finding_data.get("title", "Unknown Issue"),
                description=finding_data.get("impact", ""),
                file_path=file_path,
                line_start=line_start,
                vulnerability_type=f"{risk_tier}-tier finding",
                attack_scenario="; ".join(finding_data.get("preconditions", [])),
                recommended_fix="; ".join(finding_data.get("recommendations", [])),
                confidence=0.8,
            )

            finding = self.add_finding(finding_create)
            await self.emit_finding(finding)

            # Persist to database
            if self._state_manager:
                await self._state_manager.add_finding(
                    agent_id=self.id,
                    finding_id=finding.id,
                    title=finding.title,
                    evidence=evidence,
                    risk_tier=risk_tier,
                    impact=finding_data.get("impact", ""),
                    preconditions=finding_data.get("preconditions", []),
                    recommendations=finding_data.get("recommendations", []),
                    confidence=0.8,
                )

    def _read_file(self, file_path: str) -> Optional[str]:
        """Read file content from repository."""
        import os
        full_path = os.path.join(self.repo_path, file_path)
        try:
            with open(full_path, 'r', encoding='utf-8', errors='ignore') as f:
                return f.read()
        except Exception:
            return None

    def _detect_languages(self) -> list[str]:
        """Detect programming languages from analyzed files."""
        ext_to_lang = {
            '.py': 'Python', '.js': 'JavaScript', '.ts': 'TypeScript',
            '.java': 'Java', '.go': 'Go', '.php': 'PHP', '.rb': 'Ruby',
        }
        langs = set()
        for fs in self._file_scores:
            for ext, lang in ext_to_lang.items():
                if fs.file_path.endswith(ext):
                    langs.add(lang)
        return list(langs)

    def _format_duration(self, seconds: float) -> str:
        """Format seconds as human-readable duration."""
        if seconds < 60:
            return f"{seconds:.0f}s"
        elif seconds < 3600:
            return f"{seconds/60:.0f}m"
        else:
            hours = seconds / 3600
            mins = (seconds % 3600) / 60
            return f"{hours:.0f}h {mins:.0f}m"
```

**Step 2: Commit**

```bash
git add backend/agents/time_tiered_agent.py
git commit -m "feat: add time-tiered security audit agent

Unified agent implementing time-based audit architecture:
- Configurable time tiers (quick/medium/deep/ultra/evil)
- Two-phase system: system-driven then LLM-driven
- Geometric batch size expansion (2->4->8...->64)
- Patience threshold for early exit
- Database-backed state persistence
- File prioritization via sink detection + connectivity
- LLM state tracking (attack surface, trust boundaries)
- Finding emission with mutation support

Co-Authored-By: Claude Opus 4.5 <noreply@anthropic.com>"
```

---

## Task 7: Update Agent Orchestrator

**Files:**
- Modify: `backend/services/agent_orchestrator.py`

**Step 1: Add TimeTieredAgent to imports**

Add to imports section:

```python
from agents.time_tiered_agent import TimeTieredAgent
from models.schemas import TimeTier
```

**Step 2: Update create_agent method**

In `create_agent` method, add time tier routing before the agent class lookup:

```python
        # Route to time-tiered agent if time_tier is specified
        if request.time_tier:
            agent = TimeTieredAgent(
                request=request,
                repo_path=repo_path,
                on_message=self._broadcast_message,
            )

            async with self._lock:
                self._agents[agent.id] = agent
                self._findings[agent.id] = []

            return agent.to_schema()

        # Legacy: Create agent instance based on type
        agent_class = AGENT_CLASSES.get(request.agent_type)
```

**Step 3: Commit**

```bash
git add backend/services/agent_orchestrator.py
git commit -m "feat: route time-tier requests to TimeTieredAgent

Add routing logic to create_agent() that checks for time_tier
in request and routes to TimeTieredAgent. Legacy agent types
continue to work for backwards compatibility.

Co-Authored-By: Claude Opus 4.5 <noreply@anthropic.com>"
```

---

## Task 8: Update Frontend Types

**Files:**
- Modify: `frontend/types/index.ts`

**Step 1: Add TimeTier type**

After the AgentType definition:

```typescript
export type TimeTier = 'quick' | 'medium' | 'deep' | 'ultra' | 'evil';

export type AuditPhase = 'system_driven' | 'llm_driven';

export type RiskTier = 'S' | 'A' | 'B' | 'C' | 'D' | 'E';
```

**Step 2: Update AgentCreateRequest**

Add time_tier to the interface:

```typescript
export interface AgentCreateRequest {
  repo_id: string;
  agent_type: AgentType;
  time_tier?: TimeTier;  // Add this
  // ... rest of fields
}
```

**Step 3: Update Agent interface**

Add time-related fields:

```typescript
export interface Agent {
  // ... existing fields
  time_tier?: TimeTier;
  time_remaining?: number;
  current_phase?: AuditPhase;
}
```

**Step 4: Add TimeTierInfo interface**

```typescript
export interface TimeTierInfo {
  value: TimeTier;
  label: string;
  duration: string;
  durationSeconds: number;
  description: string;
}

export const TIME_TIERS: TimeTierInfo[] = [
  { value: 'quick', label: 'Quick', duration: '10 min', durationSeconds: 600, description: 'Fast triage scan' },
  { value: 'medium', label: 'Medium', duration: '30 min', durationSeconds: 1800, description: 'Standard review' },
  { value: 'deep', label: 'Deep', duration: '1 hr', durationSeconds: 3600, description: 'Full coverage' },
  { value: 'ultra', label: 'Ultra', duration: '3 hr', durationSeconds: 10800, description: 'Comprehensive audit' },
  { value: 'evil', label: 'Evil', duration: '24 hr', durationSeconds: 86400, description: 'Maximum depth' },
];
```

**Step 5: Commit**

```bash
git add frontend/types/index.ts
git commit -m "feat: add frontend types for time-tiered audits

Add TypeScript types:
- TimeTier union type
- AuditPhase for tracking system/LLM-driven phases
- RiskTier for vulnerability classification
- TimeTierInfo with duration metadata
- TIME_TIERS constant array
- Updated AgentCreateRequest and Agent interfaces

Co-Authored-By: Claude Opus 4.5 <noreply@anthropic.com>"
```

---

## Task 9: Update AgentManager Component

**Files:**
- Modify: `frontend/components/AgentPanel/AgentManager.tsx`

**Step 1: Replace AGENT_TYPES with TIME_TIERS**

Replace lines 33-70:

```typescript
import { Clock, Zap, Search, Layers, Skull } from 'lucide-react';
import type { TimeTier } from '@/types';
import { TIME_TIERS } from '@/types';

const TIME_TIER_ICONS: Record<TimeTier, React.ReactNode> = {
  quick: <Zap className="w-4 h-4" />,
  medium: <Clock className="w-4 h-4" />,
  deep: <Search className="w-4 h-4" />,
  ultra: <Layers className="w-4 h-4" />,
  evil: <Skull className="w-4 h-4" />,
};
```

**Step 2: Update CreateAgentModal state**

Change:

```typescript
const [timeTier, setTimeTier] = useState<TimeTier>('medium');
```

**Step 3: Update agent type selector in form**

Replace the Agent Type section with:

```typescript
{/* Time Tier */}
<div>
  <label className="block text-vsc-xs text-vsc-text-muted mb-2 uppercase tracking-wider">
    Audit Duration
  </label>
  <div className="grid grid-cols-5 gap-1.5">
    {TIME_TIERS.map((tier) => (
      <button
        key={tier.value}
        type="button"
        onClick={() => setTimeTier(tier.value)}
        className={clsx(
          'p-2 rounded border text-left transition-colors',
          timeTier === tier.value
            ? 'border-vsc-accent bg-vsc-accent/10'
            : 'border-vsc-border-subtle hover:border-vsc-border bg-vsc-input'
        )}
      >
        <div className="flex items-center gap-2 mb-1 text-vsc-text">
          {TIME_TIER_ICONS[tier.value]}
          <span className="text-vsc-sm font-medium">{tier.label}</span>
        </div>
        <p className="text-vsc-xs text-vsc-text-muted">{tier.duration}</p>
      </button>
    ))}
  </div>
</div>
```

**Step 4: Update handleSubmit**

Update the request object:

```typescript
const request: AgentCreateRequest = {
  repo_id: repoId,
  agent_type: 'deep_audit',  // Default for compatibility
  time_tier: timeTier,
  provider_config: {
    provider,
    model,
    api_key: apiKey || undefined,
  },
  custom_prompt: customPrompt || undefined,
};
```

**Step 5: Update AgentCard to show time remaining**

In the progress section, update to show time:

```typescript
{/* Progress section - show time for time-tiered agents */}
{progress && isRunning && (
  <div className="mb-3">
    <div className="progress-bar mb-1.5">
      <div
        className="progress-bar-fill"
        style={{ width: `${(progress.current / progress.total) * 100}%` }}
      />
    </div>
    <div className="flex justify-between text-vsc-xs text-vsc-text-muted">
      {agent.time_tier ? (
        <>
          <span>{formatDuration(progress.total - progress.current)} remaining</span>
          <span>{Math.round((progress.current / progress.total) * 100)}%</span>
        </>
      ) : (
        <>
          <span>{progress.current}/{progress.total} files</span>
          <span>{Math.round((progress.current / progress.total) * 100)}%</span>
        </>
      )}
    </div>
  </div>
)}
```

Add helper function:

```typescript
const formatDuration = (seconds: number): string => {
  if (seconds < 60) return `${Math.round(seconds)}s`;
  if (seconds < 3600) return `${Math.round(seconds / 60)}m`;
  const hours = Math.floor(seconds / 3600);
  const mins = Math.round((seconds % 3600) / 60);
  return mins > 0 ? `${hours}h ${mins}m` : `${hours}h`;
};
```

**Step 6: Commit**

```bash
git add frontend/components/AgentPanel/AgentManager.tsx
git commit -m "feat: update AgentManager to use time tiers

Replace agent type selector with time tier selector:
- 5 time tiers: Quick (10m), Medium (30m), Deep (1h), Ultra (3h), Evil (24h)
- Icons for each tier (Zap, Clock, Search, Layers, Skull)
- Progress bar shows time remaining instead of file count
- Duration formatting helper function

Co-Authored-By: Claude Opus 4.5 <noreply@anthropic.com>"
```

---

## Task 10: Final Integration and Testing

**Step 1: Run database migration**

```bash
cd /Users/0xkato/Desktop/Hobby/claude_apps/quick_hack/backend
python -c "
import asyncio
from database import init_db
asyncio.run(init_db())
print('Database tables created successfully')
"
```

**Step 2: Run backend to verify no import errors**

```bash
cd /Users/0xkato/Desktop/Hobby/claude_apps/quick_hack/backend
python -c "
from agents.time_tiered_agent import TimeTieredAgent
from services.file_prioritizer import FilePrioritizer
from services.audit_state_manager import AuditStateManager
from prompts.time_tiered_prompt import get_time_tiered_system_prompt
print('All imports successful')
"
```

**Step 3: Build frontend to verify TypeScript**

```bash
cd /Users/0xkato/Desktop/Hobby/claude_apps/quick_hack/frontend
npm run build
```

**Step 4: Final commit**

```bash
git add -A
git commit -m "feat: complete time-tiered audit system implementation

Full implementation of time-based security audit architecture:

Backend:
- TimeTier, RiskTier, AuditPhase enums
- Database models (AuditSession, AuditFinding, FindingRevision)
- File prioritizer with sink detection + connectivity scoring
- Audit state manager for session persistence
- Core prompt template with DEP and completion criteria
- TimeTieredAgent unified agent
- Orchestrator routing

Frontend:
- TypeScript types for time tiers
- Updated AgentManager with tier selector
- Time-based progress display

This replaces the previous agent-type-based architecture with a
unified time-based model where duration is the only variable.

Co-Authored-By: Claude Opus 4.5 <noreply@anthropic.com>"
```

---

Plan complete and saved to `docs/plans/2026-01-10-time-tiered-implementation.md`.

**Two execution options:**

**1. Subagent-Driven (this session)** - I dispatch fresh subagent per task, review between tasks, fast iteration

**2. Parallel Session (separate)** - Open new session with executing-plans, batch execution with checkpoints

Which approach?
