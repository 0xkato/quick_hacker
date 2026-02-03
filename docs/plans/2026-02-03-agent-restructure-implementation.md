# Agent Architecture Restructure Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Restructure agent system with Foundation-first approach, specialist routing, and Devil's Advocate pushing.

**Architecture:** Multi-phase system where Foundation agents build context before hunting, signals route through Decider → Family Coordinator → Specialists, with Arbiter for disagreements and Devil's Advocate pushing at all levels.

**Tech Stack:** Python 3.11+, asyncio, existing ReactAgent infrastructure, Markdown prompts

**Reference Design:** `docs/plans/2026-02-03-agent-restructure-design.md`

---

## Phase 1: Foundation Context Data Model

### Task 1.1: Create Foundation Context Schema

**Files:**
- Create: `backend/agents/deep_audit/foundation.py`
- Test: `backend/tests/agents/deep_audit/test_foundation.py`

**Step 1: Write the failing test**

```python
# backend/tests/agents/deep_audit/test_foundation.py
import pytest
from agents.deep_audit.foundation import (
    FoundationContext,
    RepoProfile,
    ScopeMap,
    ThreatModel,
    TrustBoundary,
    AttackerCapability,
)


class TestFoundationContext:
    def test_foundation_context_creation(self):
        """Foundation context can be created with all components."""
        repo_profile = RepoProfile(
            languages=["C++", "Python"],
            frameworks=["gRPC"],
            build_system="Bazel",
            entry_point_files=["src/main.cc"],
        )
        scope_map = ScopeMap(
            security_critical=["crypto/", "auth/"],
            test_code=["test/", "*_test.cc"],
            vendor_code=["third_party/"],
            generated_code=["build/gen/"],
        )
        threat_model = ThreatModel(
            trust_boundaries=[
                TrustBoundary(name="network", description="External network access")
            ],
            attacker_capabilities=[
                AttackerCapability.NETWORK_ACCESS,
                AttackerCapability.UNAUTHENTICATED,
            ],
            in_scope_paths=["src/", "api/"],
            out_of_scope_paths=["internal_tools/"],
            out_of_scope_reasons={"internal_tools/": "Admin-only, requires VPN"},
        )

        context = FoundationContext(
            repo_profile=repo_profile,
            scope_map=scope_map,
            threat_model=threat_model,
        )

        assert context.repo_profile.languages == ["C++", "Python"]
        assert "crypto/" in context.scope_map.security_critical
        assert AttackerCapability.NETWORK_ACCESS in context.threat_model.attacker_capabilities

    def test_foundation_context_to_prompt_injection(self):
        """Foundation context can be serialized for prompt injection."""
        context = FoundationContext(
            repo_profile=RepoProfile(languages=["Python"], frameworks=[], build_system="pip", entry_point_files=[]),
            scope_map=ScopeMap(security_critical=[], test_code=["tests/"], vendor_code=[], generated_code=[]),
            threat_model=ThreatModel(
                trust_boundaries=[],
                attacker_capabilities=[AttackerCapability.NETWORK_ACCESS],
                in_scope_paths=["src/"],
                out_of_scope_paths=[],
                out_of_scope_reasons={},
            ),
        )

        prompt_text = context.to_prompt_context()

        assert "Python" in prompt_text
        assert "tests/" in prompt_text
        assert "NETWORK_ACCESS" in prompt_text

    def test_is_path_in_scope(self):
        """Foundation context can determine if path is in scope."""
        context = FoundationContext(
            repo_profile=RepoProfile(languages=[], frameworks=[], build_system="", entry_point_files=[]),
            scope_map=ScopeMap(
                security_critical=["src/"],
                test_code=["tests/", "*_test.py"],
                vendor_code=["vendor/"],
                generated_code=[],
            ),
            threat_model=ThreatModel(
                trust_boundaries=[],
                attacker_capabilities=[],
                in_scope_paths=["src/", "api/"],
                out_of_scope_paths=["internal/"],
                out_of_scope_reasons={},
            ),
        )

        assert context.is_in_scope("src/handler.py") == True
        assert context.is_in_scope("tests/test_handler.py") == False  # Test code
        assert context.is_in_scope("vendor/lib.py") == False  # Vendor
        assert context.is_in_scope("internal/admin.py") == False  # Out of scope
```

**Step 2: Run test to verify it fails**

```bash
cd backend && python -m pytest tests/agents/deep_audit/test_foundation.py -v
```
Expected: FAIL with "ModuleNotFoundError: No module named 'agents.deep_audit.foundation'"

**Step 3: Write minimal implementation**

```python
# backend/agents/deep_audit/foundation.py
"""Foundation Context - shared context built before vulnerability hunting."""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from fnmatch import fnmatch
from typing import Any


class AttackerCapability(Enum):
    """Attacker capabilities from threat model."""
    NETWORK_ACCESS = "network_access"
    UNAUTHENTICATED = "unauthenticated"
    AUTHENTICATED_USER = "authenticated_user"
    AUTHENTICATED_ADMIN = "authenticated_admin"
    LOCAL_ACCESS = "local_access"
    INSIDER = "insider"


@dataclass
class TrustBoundary:
    """A boundary between trust zones."""
    name: str
    description: str
    entry_points: list[str] = field(default_factory=list)


@dataclass
class RepoProfile:
    """Repository profile from RepoProfiler."""
    languages: list[str]
    frameworks: list[str]
    build_system: str
    entry_point_files: list[str]
    total_files: int = 0
    total_lines: int = 0
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class ScopeMap:
    """Scope mapping from ScopeMapper."""
    security_critical: list[str]  # Paths/patterns for security-critical code
    test_code: list[str]  # Paths/patterns for test code
    vendor_code: list[str]  # Paths/patterns for vendor/third-party
    generated_code: list[str]  # Paths/patterns for generated code
    module_purposes: dict[str, str] = field(default_factory=dict)  # path -> purpose


@dataclass
class ThreatModel:
    """Threat model from ThreatModeler."""
    trust_boundaries: list[TrustBoundary]
    attacker_capabilities: list[AttackerCapability]
    in_scope_paths: list[str]
    out_of_scope_paths: list[str]
    out_of_scope_reasons: dict[str, str]  # path -> reason
    assumptions: list[str] = field(default_factory=list)


@dataclass
class FoundationContext:
    """Complete foundation context built before hunting."""
    repo_profile: RepoProfile
    scope_map: ScopeMap
    threat_model: ThreatModel

    def _matches_any_pattern(self, path: str, patterns: list[str]) -> bool:
        """Check if path matches any of the patterns."""
        for pattern in patterns:
            if pattern.endswith("/"):
                # Directory pattern
                if path.startswith(pattern) or f"/{pattern}" in f"/{path}":
                    return True
            elif "*" in pattern:
                # Glob pattern
                if fnmatch(path, pattern) or fnmatch(path.split("/")[-1], pattern):
                    return True
            else:
                # Exact match or prefix
                if path == pattern or path.startswith(pattern):
                    return True
        return False

    def is_in_scope(self, path: str) -> bool:
        """Determine if a file path is in scope for analysis."""
        # Check exclusions first
        if self._matches_any_pattern(path, self.scope_map.test_code):
            return False
        if self._matches_any_pattern(path, self.scope_map.vendor_code):
            return False
        if self._matches_any_pattern(path, self.scope_map.generated_code):
            return False
        if self._matches_any_pattern(path, self.threat_model.out_of_scope_paths):
            return False

        # If in_scope_paths is specified, path must match
        if self.threat_model.in_scope_paths:
            return self._matches_any_pattern(path, self.threat_model.in_scope_paths)

        return True

    def is_security_critical(self, path: str) -> bool:
        """Check if path is in security-critical area."""
        return self._matches_any_pattern(path, self.scope_map.security_critical)

    def to_prompt_context(self) -> str:
        """Serialize to text for prompt injection."""
        lines = [
            "## Foundation Context",
            "",
            "### Repository Profile",
            f"- Languages: {', '.join(self.repo_profile.languages) or 'Unknown'}",
            f"- Frameworks: {', '.join(self.repo_profile.frameworks) or 'None detected'}",
            f"- Build System: {self.repo_profile.build_system or 'Unknown'}",
            "",
            "### Scope Map",
            f"- Security Critical: {', '.join(self.scope_map.security_critical) or 'Not specified'}",
            f"- Test Code (IGNORE): {', '.join(self.scope_map.test_code) or 'None'}",
            f"- Vendor Code (IGNORE): {', '.join(self.scope_map.vendor_code) or 'None'}",
            "",
            "### Threat Model",
            f"- Attacker Capabilities: {', '.join(c.value for c in self.threat_model.attacker_capabilities) or 'Not specified'}",
            f"- In Scope: {', '.join(self.threat_model.in_scope_paths) or 'All paths'}",
            f"- Out of Scope: {', '.join(self.threat_model.out_of_scope_paths) or 'None'}",
        ]

        if self.threat_model.trust_boundaries:
            lines.append("")
            lines.append("### Trust Boundaries")
            for boundary in self.threat_model.trust_boundaries:
                lines.append(f"- {boundary.name}: {boundary.description}")

        return "\n".join(lines)

    def to_dict(self) -> dict[str, Any]:
        """Serialize to dictionary for JSON storage."""
        return {
            "repo_profile": {
                "languages": self.repo_profile.languages,
                "frameworks": self.repo_profile.frameworks,
                "build_system": self.repo_profile.build_system,
                "entry_point_files": self.repo_profile.entry_point_files,
                "total_files": self.repo_profile.total_files,
                "total_lines": self.repo_profile.total_lines,
                "metadata": self.repo_profile.metadata,
            },
            "scope_map": {
                "security_critical": self.scope_map.security_critical,
                "test_code": self.scope_map.test_code,
                "vendor_code": self.scope_map.vendor_code,
                "generated_code": self.scope_map.generated_code,
                "module_purposes": self.scope_map.module_purposes,
            },
            "threat_model": {
                "trust_boundaries": [
                    {"name": b.name, "description": b.description, "entry_points": b.entry_points}
                    for b in self.threat_model.trust_boundaries
                ],
                "attacker_capabilities": [c.value for c in self.threat_model.attacker_capabilities],
                "in_scope_paths": self.threat_model.in_scope_paths,
                "out_of_scope_paths": self.threat_model.out_of_scope_paths,
                "out_of_scope_reasons": self.threat_model.out_of_scope_reasons,
                "assumptions": self.threat_model.assumptions,
            },
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "FoundationContext":
        """Deserialize from dictionary."""
        rp = data["repo_profile"]
        sm = data["scope_map"]
        tm = data["threat_model"]

        return cls(
            repo_profile=RepoProfile(
                languages=rp["languages"],
                frameworks=rp["frameworks"],
                build_system=rp["build_system"],
                entry_point_files=rp["entry_point_files"],
                total_files=rp.get("total_files", 0),
                total_lines=rp.get("total_lines", 0),
                metadata=rp.get("metadata", {}),
            ),
            scope_map=ScopeMap(
                security_critical=sm["security_critical"],
                test_code=sm["test_code"],
                vendor_code=sm["vendor_code"],
                generated_code=sm.get("generated_code", []),
                module_purposes=sm.get("module_purposes", {}),
            ),
            threat_model=ThreatModel(
                trust_boundaries=[
                    TrustBoundary(name=b["name"], description=b["description"], entry_points=b.get("entry_points", []))
                    for b in tm["trust_boundaries"]
                ],
                attacker_capabilities=[AttackerCapability(c) for c in tm["attacker_capabilities"]],
                in_scope_paths=tm["in_scope_paths"],
                out_of_scope_paths=tm["out_of_scope_paths"],
                out_of_scope_reasons=tm.get("out_of_scope_reasons", {}),
                assumptions=tm.get("assumptions", []),
            ),
        )
```

**Step 4: Run test to verify it passes**

```bash
cd backend && python -m pytest tests/agents/deep_audit/test_foundation.py -v
```
Expected: PASS

**Step 5: Commit**

```bash
git add backend/agents/deep_audit/foundation.py backend/tests/agents/deep_audit/test_foundation.py
git commit -m "feat: add Foundation Context data model for restructured agent architecture"
```

---

### Task 1.2: Create Suspicious Signal Schema

**Files:**
- Modify: `backend/agents/deep_audit/foundation.py`
- Test: `backend/tests/agents/deep_audit/test_foundation.py`

**Step 1: Add failing test for Signal schema**

```python
# Add to backend/tests/agents/deep_audit/test_foundation.py

from agents.deep_audit.foundation import (
    SuspiciousSignal,
    SignalCategory,
    SignalSeverity,
)


class TestSuspiciousSignal:
    def test_signal_creation(self):
        """Suspicious signal can be created with required fields."""
        signal = SuspiciousSignal(
            signal_id="sig-001",
            category=SignalCategory.COMMAND_INJECTION,
            severity=SignalSeverity.HIGH,
            file_path="src/api/execute.py",
            line_start=45,
            code_snippet="os.system(user_input)",
            why_suspicious="User-controlled string flows to os.system()",
            entry_point_trace=["POST /api/run", "handle_run()", "os.system()"],
        )

        assert signal.signal_id == "sig-001"
        assert signal.category == SignalCategory.COMMAND_INJECTION
        assert signal.severity == SignalSeverity.HIGH
        assert len(signal.entry_point_trace) == 3

    def test_signal_to_specialist_context(self):
        """Signal can be formatted for specialist consumption."""
        signal = SuspiciousSignal(
            signal_id="sig-001",
            category=SignalCategory.SQL_INJECTION,
            severity=SignalSeverity.CRITICAL,
            file_path="src/db/query.py",
            line_start=100,
            code_snippet="cursor.execute(f'SELECT * FROM {table}')",
            why_suspicious="String interpolation in SQL query",
            entry_point_trace=["GET /api/data", "get_data()", "execute()"],
        )

        context = signal.to_specialist_context()

        assert "sig-001" in context
        assert "SQL_INJECTION" in context
        assert "src/db/query.py:100" in context
        assert "String interpolation" in context
```

**Step 2: Run test to verify it fails**

```bash
cd backend && python -m pytest tests/agents/deep_audit/test_foundation.py::TestSuspiciousSignal -v
```
Expected: FAIL

**Step 3: Add Signal implementation to foundation.py**

```python
# Add to backend/agents/deep_audit/foundation.py (after existing classes)

class SignalCategory(Enum):
    """Categories of suspicious signals."""
    # Memory Safety
    BUFFER_OVERFLOW = "buffer_overflow"
    USE_AFTER_FREE = "use_after_free"
    DOUBLE_FREE = "double_free"
    UNINITIALIZED_MEMORY = "uninitialized_memory"
    INTEGER_OVERFLOW = "integer_overflow"
    FORMAT_STRING = "format_string"
    TYPE_CONFUSION = "type_confusion"
    UNSAFE_FFI = "unsafe_ffi"

    # Injection
    SQL_INJECTION = "sql_injection"
    NOSQL_INJECTION = "nosql_injection"
    COMMAND_INJECTION = "command_injection"
    TEMPLATE_INJECTION = "template_injection"
    EXPRESSION_INJECTION = "expression_injection"
    LDAP_INJECTION = "ldap_injection"
    XPATH_INJECTION = "xpath_injection"
    CRLF_INJECTION = "crlf_injection"
    LOG_INJECTION = "log_injection"
    EMAIL_INJECTION = "email_injection"

    # Web
    SSRF = "ssrf"
    REQUEST_SMUGGLING = "request_smuggling"
    CACHE_POISONING = "cache_poisoning"
    HOST_HEADER_INJECTION = "host_header_injection"
    XSS = "xss"
    PROTOTYPE_POLLUTION = "prototype_pollution"
    CLICKJACKING = "clickjacking"

    # Deserialization/Parsing
    UNSAFE_DESERIALIZATION = "unsafe_deserialization"
    XXE = "xxe"
    ZIP_SLIP = "zip_slip"
    REDOS = "redos"
    PATH_TRAVERSAL = "path_traversal"

    # Auth
    AUTH_BYPASS = "auth_bypass"
    SESSION_FIXATION = "session_fixation"
    CSRF = "csrf"
    IDOR = "idor"
    PRIVILEGE_ESCALATION = "privilege_escalation"

    # Crypto
    CRYPTO_MISUSE = "crypto_misuse"
    WEAK_RANDOMNESS = "weak_randomness"
    SECRETS_EXPOSURE = "secrets_exposure"

    # Other
    RACE_CONDITION = "race_condition"
    RESOURCE_EXHAUSTION = "resource_exhaustion"
    SENSITIVE_DATA_EXPOSURE = "sensitive_data_exposure"
    MASS_ASSIGNMENT = "mass_assignment"

    # Generic
    UNKNOWN = "unknown"


class SignalSeverity(Enum):
    """Severity of suspicious signal."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


@dataclass
class SuspiciousSignal:
    """A suspicious pattern identified by Hunters, not yet verified."""
    signal_id: str
    category: SignalCategory
    severity: SignalSeverity
    file_path: str
    line_start: int
    code_snippet: str
    why_suspicious: str
    entry_point_trace: list[str]

    line_end: int | None = None
    sink_function: str | None = None
    related_signals: list[str] = field(default_factory=list)
    hunter_notes: str | None = None
    foundation_context_summary: str | None = None

    def to_specialist_context(self) -> str:
        """Format signal for specialist agent consumption."""
        lines = [
            f"## Signal: {self.signal_id}",
            "",
            f"**Category:** {self.category.value.upper()}",
            f"**Severity:** {self.severity.value.upper()}",
            f"**Location:** {self.file_path}:{self.line_start}",
            "",
            "**Code:**",
            "```",
            self.code_snippet,
            "```",
            "",
            f"**Why Suspicious:** {self.why_suspicious}",
            "",
            "**Entry Point Trace:**",
        ]
        for i, step in enumerate(self.entry_point_trace):
            lines.append(f"  {i + 1}. {step}")

        if self.sink_function:
            lines.append(f"\n**Sink Function:** {self.sink_function}")

        if self.hunter_notes:
            lines.append(f"\n**Hunter Notes:** {self.hunter_notes}")

        return "\n".join(lines)

    def to_dict(self) -> dict[str, Any]:
        """Serialize to dictionary."""
        return {
            "signal_id": self.signal_id,
            "category": self.category.value,
            "severity": self.severity.value,
            "file_path": self.file_path,
            "line_start": self.line_start,
            "line_end": self.line_end,
            "code_snippet": self.code_snippet,
            "why_suspicious": self.why_suspicious,
            "entry_point_trace": self.entry_point_trace,
            "sink_function": self.sink_function,
            "related_signals": self.related_signals,
            "hunter_notes": self.hunter_notes,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "SuspiciousSignal":
        """Deserialize from dictionary."""
        return cls(
            signal_id=data["signal_id"],
            category=SignalCategory(data["category"]),
            severity=SignalSeverity(data["severity"]),
            file_path=data["file_path"],
            line_start=data["line_start"],
            line_end=data.get("line_end"),
            code_snippet=data["code_snippet"],
            why_suspicious=data["why_suspicious"],
            entry_point_trace=data["entry_point_trace"],
            sink_function=data.get("sink_function"),
            related_signals=data.get("related_signals", []),
            hunter_notes=data.get("hunter_notes"),
        )
```

**Step 4: Run test to verify it passes**

```bash
cd backend && python -m pytest tests/agents/deep_audit/test_foundation.py -v
```
Expected: PASS

**Step 5: Commit**

```bash
git add backend/agents/deep_audit/foundation.py backend/tests/agents/deep_audit/test_foundation.py
git commit -m "feat: add SuspiciousSignal schema for hunter output"
```

---

## Phase 2: Specialist Family Infrastructure

### Task 2.1: Create Specialist Family Registry

**Files:**
- Create: `backend/agents/deep_audit/specialists/__init__.py`
- Create: `backend/agents/deep_audit/specialists/registry.py`
- Test: `backend/tests/agents/deep_audit/test_specialist_registry.py`

**Step 1: Write failing test**

```python
# backend/tests/agents/deep_audit/test_specialist_registry.py
import pytest
from agents.deep_audit.specialists.registry import (
    SpecialistFamily,
    SpecialistRegistry,
    get_family_for_signal,
    get_specialists_for_signal,
)
from agents.deep_audit.foundation import SignalCategory


class TestSpecialistRegistry:
    def test_family_enum_has_14_families(self):
        """There are exactly 14 specialist families."""
        assert len(SpecialistFamily) == 14

    def test_get_family_for_sql_injection(self):
        """SQL injection routes to Injection family."""
        family = get_family_for_signal(SignalCategory.SQL_INJECTION)
        assert family == SpecialistFamily.INJECTION

    def test_get_family_for_buffer_overflow(self):
        """Buffer overflow routes to Memory Safety family."""
        family = get_family_for_signal(SignalCategory.BUFFER_OVERFLOW)
        assert family == SpecialistFamily.MEMORY_SAFETY

    def test_get_specialists_for_sql_injection(self):
        """SQL injection signal returns SQL Injection Auditor."""
        specialists = get_specialists_for_signal(SignalCategory.SQL_INJECTION)
        assert "sql_injection_auditor" in specialists

    def test_get_specialists_for_memory_copy(self):
        """Buffer overflow can match multiple memory specialists."""
        specialists = get_specialists_for_signal(SignalCategory.BUFFER_OVERFLOW)
        assert "oob_read_write_auditor" in specialists

    def test_registry_has_all_specialists(self):
        """Registry contains all 64 specialists."""
        registry = SpecialistRegistry()
        assert len(registry.all_specialists) == 64
```

**Step 2: Run test to verify it fails**

```bash
cd backend && python -m pytest tests/agents/deep_audit/test_specialist_registry.py -v
```
Expected: FAIL

**Step 3: Write implementation**

```python
# backend/agents/deep_audit/specialists/__init__.py
"""Specialist agents for deep vulnerability verification."""
from .registry import (
    SpecialistFamily,
    SpecialistRegistry,
    get_family_for_signal,
    get_specialists_for_signal,
)

__all__ = [
    "SpecialistFamily",
    "SpecialistRegistry",
    "get_family_for_signal",
    "get_specialists_for_signal",
]
```

```python
# backend/agents/deep_audit/specialists/registry.py
"""Specialist family and routing registry."""
from __future__ import annotations

from enum import Enum
from dataclasses import dataclass, field
from typing import Any

from agents.deep_audit.foundation import SignalCategory


class SpecialistFamily(Enum):
    """The 14 specialist families."""
    MEMORY_SAFETY = "memory_safety"
    INJECTION = "injection"
    WEB_EDGE_CASES = "web_edge_cases"
    BROWSER_CLIENT = "browser_client"
    DESERIALIZATION_PARSING = "deserialization_parsing"
    FILE_SYSTEM = "file_system"
    AUTHN_SESSION = "authn_session"
    AUTHZ_BUSINESS_LOGIC = "authz_business_logic"
    CRYPTO_SECRETS = "crypto_secrets"
    INFRASTRUCTURE = "infrastructure"
    SUPPLY_CHAIN = "supply_chain"
    CONCURRENCY = "concurrency"
    DATA_EXPOSURE = "data_exposure"
    API_DESIGN = "api_design"


@dataclass
class SpecialistInfo:
    """Information about a specialist."""
    id: str
    name: str
    family: SpecialistFamily
    triggers: list[SignalCategory]
    proficiency: str
    prompt_template: str | None = None


# Signal category to family mapping
CATEGORY_TO_FAMILY: dict[SignalCategory, SpecialistFamily] = {
    # Memory Safety
    SignalCategory.BUFFER_OVERFLOW: SpecialistFamily.MEMORY_SAFETY,
    SignalCategory.USE_AFTER_FREE: SpecialistFamily.MEMORY_SAFETY,
    SignalCategory.DOUBLE_FREE: SpecialistFamily.MEMORY_SAFETY,
    SignalCategory.UNINITIALIZED_MEMORY: SpecialistFamily.MEMORY_SAFETY,
    SignalCategory.INTEGER_OVERFLOW: SpecialistFamily.MEMORY_SAFETY,
    SignalCategory.FORMAT_STRING: SpecialistFamily.MEMORY_SAFETY,
    SignalCategory.TYPE_CONFUSION: SpecialistFamily.MEMORY_SAFETY,
    SignalCategory.UNSAFE_FFI: SpecialistFamily.MEMORY_SAFETY,

    # Injection
    SignalCategory.SQL_INJECTION: SpecialistFamily.INJECTION,
    SignalCategory.NOSQL_INJECTION: SpecialistFamily.INJECTION,
    SignalCategory.COMMAND_INJECTION: SpecialistFamily.INJECTION,
    SignalCategory.TEMPLATE_INJECTION: SpecialistFamily.INJECTION,
    SignalCategory.EXPRESSION_INJECTION: SpecialistFamily.INJECTION,
    SignalCategory.LDAP_INJECTION: SpecialistFamily.INJECTION,
    SignalCategory.XPATH_INJECTION: SpecialistFamily.INJECTION,
    SignalCategory.CRLF_INJECTION: SpecialistFamily.INJECTION,
    SignalCategory.LOG_INJECTION: SpecialistFamily.INJECTION,
    SignalCategory.EMAIL_INJECTION: SpecialistFamily.INJECTION,

    # Web Edge Cases
    SignalCategory.SSRF: SpecialistFamily.WEB_EDGE_CASES,
    SignalCategory.REQUEST_SMUGGLING: SpecialistFamily.WEB_EDGE_CASES,
    SignalCategory.CACHE_POISONING: SpecialistFamily.WEB_EDGE_CASES,
    SignalCategory.HOST_HEADER_INJECTION: SpecialistFamily.WEB_EDGE_CASES,

    # Browser/Client
    SignalCategory.XSS: SpecialistFamily.BROWSER_CLIENT,
    SignalCategory.PROTOTYPE_POLLUTION: SpecialistFamily.BROWSER_CLIENT,
    SignalCategory.CLICKJACKING: SpecialistFamily.BROWSER_CLIENT,

    # Deserialization/Parsing
    SignalCategory.UNSAFE_DESERIALIZATION: SpecialistFamily.DESERIALIZATION_PARSING,
    SignalCategory.XXE: SpecialistFamily.DESERIALIZATION_PARSING,
    SignalCategory.ZIP_SLIP: SpecialistFamily.DESERIALIZATION_PARSING,
    SignalCategory.REDOS: SpecialistFamily.DESERIALIZATION_PARSING,

    # File System
    SignalCategory.PATH_TRAVERSAL: SpecialistFamily.FILE_SYSTEM,

    # Auth
    SignalCategory.AUTH_BYPASS: SpecialistFamily.AUTHN_SESSION,
    SignalCategory.SESSION_FIXATION: SpecialistFamily.AUTHN_SESSION,
    SignalCategory.CSRF: SpecialistFamily.AUTHN_SESSION,

    # AuthZ/Business Logic
    SignalCategory.IDOR: SpecialistFamily.AUTHZ_BUSINESS_LOGIC,
    SignalCategory.PRIVILEGE_ESCALATION: SpecialistFamily.AUTHZ_BUSINESS_LOGIC,

    # Crypto
    SignalCategory.CRYPTO_MISUSE: SpecialistFamily.CRYPTO_SECRETS,
    SignalCategory.WEAK_RANDOMNESS: SpecialistFamily.CRYPTO_SECRETS,
    SignalCategory.SECRETS_EXPOSURE: SpecialistFamily.CRYPTO_SECRETS,

    # Concurrency
    SignalCategory.RACE_CONDITION: SpecialistFamily.CONCURRENCY,
    SignalCategory.RESOURCE_EXHAUSTION: SpecialistFamily.CONCURRENCY,

    # Data Exposure
    SignalCategory.SENSITIVE_DATA_EXPOSURE: SpecialistFamily.DATA_EXPOSURE,

    # API Design
    SignalCategory.MASS_ASSIGNMENT: SpecialistFamily.API_DESIGN,

    # Unknown -> default to Injection for analysis
    SignalCategory.UNKNOWN: SpecialistFamily.INJECTION,
}


# All 64 specialists
ALL_SPECIALISTS: list[SpecialistInfo] = [
    # Memory Safety (8)
    SpecialistInfo("oob_read_write_auditor", "OOB Read/Write Auditor", SpecialistFamily.MEMORY_SAFETY,
                   [SignalCategory.BUFFER_OVERFLOW], "C/C++ memory model, bounds reasoning, struct layout"),
    SpecialistInfo("use_after_free_auditor", "Use-After-Free Auditor", SpecialistFamily.MEMORY_SAFETY,
                   [SignalCategory.USE_AFTER_FREE], "Lifetime/ownership tracing, allocator behavior"),
    SpecialistInfo("double_free_auditor", "Double-Free/Invalid-Free Auditor", SpecialistFamily.MEMORY_SAFETY,
                   [SignalCategory.DOUBLE_FREE], "Heap lifecycle, error-handling paths, RAII"),
    SpecialistInfo("uninit_memory_auditor", "Uninitialized Memory Auditor", SpecialistFamily.MEMORY_SAFETY,
                   [SignalCategory.UNINITIALIZED_MEMORY], "Compiler behavior, struct padding, serialization"),
    SpecialistInfo("integer_overflow_auditor", "Integer Overflow/Underflow Auditor", SpecialistFamily.MEMORY_SAFETY,
                   [SignalCategory.INTEGER_OVERFLOW], "Signed/unsigned hazards, truncation, cast chains"),
    SpecialistInfo("format_string_auditor", "Format String Auditor", SpecialistFamily.MEMORY_SAFETY,
                   [SignalCategory.FORMAT_STRING], "Format specifiers, variadic pitfalls"),
    SpecialistInfo("type_confusion_auditor", "Type Confusion Auditor", SpecialistFamily.MEMORY_SAFETY,
                   [SignalCategory.TYPE_CONFUSION], "RTTI/vtables, object layout, deserialization"),
    SpecialistInfo("unsafe_ffi_auditor", "Unsafe FFI Boundary Auditor", SpecialistFamily.MEMORY_SAFETY,
                   [SignalCategory.UNSAFE_FFI], "Cross-language ABI, ownership transfer"),

    # Injection (10)
    SpecialistInfo("sql_injection_auditor", "SQL Injection Auditor", SpecialistFamily.INJECTION,
                   [SignalCategory.SQL_INJECTION], "Parameterization patterns, ORM escape hatches"),
    SpecialistInfo("nosql_injection_auditor", "NoSQL Injection Auditor", SpecialistFamily.INJECTION,
                   [SignalCategory.NOSQL_INJECTION], "Operator injection, query object merging"),
    SpecialistInfo("command_injection_auditor", "OS Command Injection Auditor", SpecialistFamily.INJECTION,
                   [SignalCategory.COMMAND_INJECTION], "Shell parsing hazards, argument vector safety"),
    SpecialistInfo("template_injection_auditor", "Template Injection (SSTI) Auditor", SpecialistFamily.INJECTION,
                   [SignalCategory.TEMPLATE_INJECTION], "Template engine capabilities, sandbox escapes"),
    SpecialistInfo("expression_injection_auditor", "Expression/Eval Injection Auditor", SpecialistFamily.INJECTION,
                   [SignalCategory.EXPRESSION_INJECTION], "Language runtime behavior, sandbox boundaries"),
    SpecialistInfo("ldap_injection_auditor", "LDAP Injection Auditor", SpecialistFamily.INJECTION,
                   [SignalCategory.LDAP_INJECTION], "Escaping rules, filter grammar"),
    SpecialistInfo("xpath_injection_auditor", "XPath/XQuery Injection Auditor", SpecialistFamily.INJECTION,
                   [SignalCategory.XPATH_INJECTION], "XML query syntax, escaping"),
    SpecialistInfo("crlf_injection_auditor", "CRLF/Header Injection Auditor", SpecialistFamily.INJECTION,
                   [SignalCategory.CRLF_INJECTION], "HTTP header rules, framework mitigations"),
    SpecialistInfo("log_injection_auditor", "Log Injection/Forgery Auditor", SpecialistFamily.INJECTION,
                   [SignalCategory.LOG_INJECTION], "Log formats, downstream parser risks"),
    SpecialistInfo("email_injection_auditor", "Email/SMTP Injection Auditor", SpecialistFamily.INJECTION,
                   [SignalCategory.EMAIL_INJECTION], "MIME/header rules, newline handling"),

    # Web Edge Cases (4)
    SpecialistInfo("ssrf_auditor", "SSRF Auditor", SpecialistFamily.WEB_EDGE_CASES,
                   [SignalCategory.SSRF], "URL parsing pitfalls, allowlist/bypass patterns"),
    SpecialistInfo("request_smuggling_auditor", "Request Smuggling Auditor", SpecialistFamily.WEB_EDGE_CASES,
                   [SignalCategory.REQUEST_SMUGGLING], "Proxy chains, RFC edge-cases"),
    SpecialistInfo("cache_poisoning_auditor", "Cache Poisoning/Deception Auditor", SpecialistFamily.WEB_EDGE_CASES,
                   [SignalCategory.CACHE_POISONING], "Cache key composition, Vary headers"),
    SpecialistInfo("host_header_auditor", "Host Header Injection Auditor", SpecialistFamily.WEB_EDGE_CASES,
                   [SignalCategory.HOST_HEADER_INJECTION], "Reverse proxy headers, canonical host"),

    # Browser/Client (4)
    SpecialistInfo("xss_auditor", "XSS Auditor (Reflected/Stored/DOM)", SpecialistFamily.BROWSER_CLIENT,
                   [SignalCategory.XSS], "Context-aware escaping, CSP, DOM sinks"),
    SpecialistInfo("prototype_pollution_auditor", "Prototype Pollution Auditor", SpecialistFamily.BROWSER_CLIENT,
                   [SignalCategory.PROTOTYPE_POLLUTION], "JS object model, __proto__ hazards"),
    SpecialistInfo("clickjacking_auditor", "Clickjacking/UI Redress Auditor", SpecialistFamily.BROWSER_CLIENT,
                   [SignalCategory.CLICKJACKING], "Frame headers, CSP frame-ancestors"),
    SpecialistInfo("csp_auditor", "CSP/Frontend Hardening Auditor", SpecialistFamily.BROWSER_CLIENT,
                   [], "CSP directives, practical deployment"),

    # Deserialization/Parsing (6)
    SpecialistInfo("unsafe_deser_auditor", "Unsafe Deserialization Auditor", SpecialistFamily.DESERIALIZATION_PARSING,
                   [SignalCategory.UNSAFE_DESERIALIZATION], "Language-specific gadget risks"),
    SpecialistInfo("parser_differential_auditor", "Parser Differential Auditor", SpecialistFamily.DESERIALIZATION_PARSING,
                   [], "Canonicalization, encoding transformations"),
    SpecialistInfo("xxe_auditor", "XXE/XML Security Auditor", SpecialistFamily.DESERIALIZATION_PARSING,
                   [SignalCategory.XXE], "External entity rules, secure parser settings"),
    SpecialistInfo("zip_slip_auditor", "Zip Slip/Archive Traversal Auditor", SpecialistFamily.DESERIALIZATION_PARSING,
                   [SignalCategory.ZIP_SLIP], "Path normalization, symlink hazards"),
    SpecialistInfo("redos_auditor", "ReDoS Auditor", SpecialistFamily.DESERIALIZATION_PARSING,
                   [SignalCategory.REDOS], "Catastrophic backtracking patterns"),
    SpecialistInfo("file_parser_auditor", "File Parser Attack Surface Auditor", SpecialistFamily.DESERIALIZATION_PARSING,
                   [], "Parser sandboxing, memory-safety exposure"),

    # File System (4)
    SpecialistInfo("path_traversal_auditor", "Path Traversal Auditor", SpecialistFamily.FILE_SYSTEM,
                   [SignalCategory.PATH_TRAVERSAL], "Normalization pitfalls, encoding tricks"),
    SpecialistInfo("file_upload_auditor", "Insecure File Upload Auditor", SpecialistFamily.FILE_SYSTEM,
                   [], "Validation strategies, storage paths"),
    SpecialistInfo("symlink_toctou_auditor", "Symlink/TOCTOU Auditor", SpecialistFamily.FILE_SYSTEM,
                   [], "Race windows, atomic file operations"),
    SpecialistInfo("temp_file_auditor", "Insecure Temp File/Permissions Auditor", SpecialistFamily.FILE_SYSTEM,
                   [], "OS-level secure temp APIs"),

    # AuthN/Session (5)
    SpecialistInfo("authn_bypass_auditor", "AuthN Bypass Auditor", SpecialistFamily.AUTHN_SESSION,
                   [SignalCategory.AUTH_BYPASS], "Framework auth stacks, middleware ordering"),
    SpecialistInfo("session_mgmt_auditor", "Session Management Auditor", SpecialistFamily.AUTHN_SESSION,
                   [SignalCategory.SESSION_FIXATION], "Fixation, rotation, cookie flags"),
    SpecialistInfo("csrf_auditor", "CSRF Auditor", SpecialistFamily.AUTHN_SESSION,
                   [SignalCategory.CSRF], "CSRF token patterns, SameSite behavior"),
    SpecialistInfo("oauth_auditor", "OAuth/OIDC/SSO Flow Auditor", SpecialistFamily.AUTHN_SESSION,
                   [], "Protocol invariants, state/nonce validation"),
    SpecialistInfo("jwt_auditor", "JWT/Token Validation Auditor", SpecialistFamily.AUTHN_SESSION,
                   [], "Algorithm/key handling, claim validation"),

    # AuthZ/Business Logic (5)
    SpecialistInfo("idor_auditor", "Broken Access Control/IDOR Auditor", SpecialistFamily.AUTHZ_BUSINESS_LOGIC,
                   [SignalCategory.IDOR], "Ownership checks, tenant scoping"),
    SpecialistInfo("priv_esc_auditor", "Privilege Escalation Auditor", SpecialistFamily.AUTHZ_BUSINESS_LOGIC,
                   [SignalCategory.PRIVILEGE_ESCALATION], "Role/permission graph reasoning"),
    SpecialistInfo("multi_tenant_auditor", "Multi-Tenant Isolation Auditor", SpecialistFamily.AUTHZ_BUSINESS_LOGIC,
                   [], "Tenant boundary enforcement"),
    SpecialistInfo("workflow_bypass_auditor", "Workflow/Business Logic Bypass Auditor", SpecialistFamily.AUTHZ_BUSINESS_LOGIC,
                   [], "State transition integrity, replay"),
    SpecialistInfo("rate_limit_auditor", "Rate Limit/Abuse Controls Auditor", SpecialistFamily.AUTHZ_BUSINESS_LOGIC,
                   [], "Throttling placement, bypass vectors"),

    # Crypto/Secrets (4)
    SpecialistInfo("crypto_misuse_auditor", "Crypto Misuse Auditor", SpecialistFamily.CRYPTO_SECRETS,
                   [SignalCategory.CRYPTO_MISUSE], "Correct primitives, modes, IV/nonce rules"),
    SpecialistInfo("randomness_auditor", "Randomness/Token Generation Auditor", SpecialistFamily.CRYPTO_SECRETS,
                   [SignalCategory.WEAK_RANDOMNESS], "CSPRNG usage, entropy assumptions"),
    SpecialistInfo("secrets_handling_auditor", "Secrets Handling Auditor", SpecialistFamily.CRYPTO_SECRETS,
                   [SignalCategory.SECRETS_EXPOSURE], "Secret lifecycle, leakage in logs"),
    SpecialistInfo("tls_auditor", "TLS/Certificate Validation Auditor", SpecialistFamily.CRYPTO_SECRETS,
                   [], "Hostname verification, trust store handling"),

    # Infrastructure (4)
    SpecialistInfo("insecure_config_auditor", "Insecure Configuration Auditor", SpecialistFamily.INFRASTRUCTURE,
                   [], "Secure baseline per framework"),
    SpecialistInfo("container_auditor", "Container/Sandbox Boundary Auditor", SpecialistFamily.INFRASTRUCTURE,
                   [], "Container hardening concepts"),
    SpecialistInfo("k8s_auditor", "Kubernetes Manifest Auditor", SpecialistFamily.INFRASTRUCTURE,
                   [], "RBAC scoping, secret mounting"),
    SpecialistInfo("cicd_auditor", "CI/CD Pipeline Security Auditor", SpecialistFamily.INFRASTRUCTURE,
                   [], "Token exposure, untrusted PR execution"),

    # Supply Chain (3)
    SpecialistInfo("dependency_risk_auditor", "Dependency Risk Auditor", SpecialistFamily.SUPPLY_CHAIN,
                   [], "SBOM reading, risky package patterns"),
    SpecialistInfo("dependency_confusion_auditor", "Dependency Confusion/Typosquatting Auditor", SpecialistFamily.SUPPLY_CHAIN,
                   [], "Package ecosystem behaviors"),
    SpecialistInfo("plugin_auditor", "Plugin/Extension System Auditor", SpecialistFamily.SUPPLY_CHAIN,
                   [], "Sandboxing, trust model"),

    # Concurrency (2)
    SpecialistInfo("race_condition_auditor", "Race Condition Auditor", SpecialistFamily.CONCURRENCY,
                   [SignalCategory.RACE_CONDITION], "Atomicity, idempotency, locking"),
    SpecialistInfo("dos_auditor", "DoS/Resource Exhaustion Auditor", SpecialistFamily.CONCURRENCY,
                   [SignalCategory.RESOURCE_EXHAUSTION], "Input size limits, streaming vs buffering"),

    # Data Exposure (2)
    SpecialistInfo("sensitive_data_auditor", "Sensitive Data Exposure Auditor", SpecialistFamily.DATA_EXPOSURE,
                   [SignalCategory.SENSITIVE_DATA_EXPOSURE], "Data classification, redaction"),
    SpecialistInfo("token_in_url_auditor", "Access Token/PII in URL Auditor", SpecialistFamily.DATA_EXPOSURE,
                   [], "Referrer leakage, proxy logs"),

    # API Design (3)
    SpecialistInfo("mass_assignment_auditor", "Mass Assignment/Over-posting Auditor", SpecialistFamily.API_DESIGN,
                   [SignalCategory.MASS_ASSIGNMENT], "Framework binding rules"),
    SpecialistInfo("param_pollution_auditor", "Parameter Pollution/Ambiguity Auditor", SpecialistFamily.API_DESIGN,
                   [], "Framework parsing order"),
    SpecialistInfo("graphql_auditor", "GraphQL Security Auditor", SpecialistFamily.API_DESIGN,
                   [], "Introspection controls, complexity limits"),
]


class SpecialistRegistry:
    """Registry of all specialists."""

    def __init__(self):
        self._specialists_by_id: dict[str, SpecialistInfo] = {
            s.id: s for s in ALL_SPECIALISTS
        }
        self._specialists_by_family: dict[SpecialistFamily, list[SpecialistInfo]] = {}
        for s in ALL_SPECIALISTS:
            if s.family not in self._specialists_by_family:
                self._specialists_by_family[s.family] = []
            self._specialists_by_family[s.family].append(s)

    @property
    def all_specialists(self) -> list[SpecialistInfo]:
        """Get all registered specialists."""
        return ALL_SPECIALISTS

    def get_by_id(self, specialist_id: str) -> SpecialistInfo | None:
        """Get specialist by ID."""
        return self._specialists_by_id.get(specialist_id)

    def get_by_family(self, family: SpecialistFamily) -> list[SpecialistInfo]:
        """Get all specialists in a family."""
        return self._specialists_by_family.get(family, [])

    def get_for_category(self, category: SignalCategory) -> list[SpecialistInfo]:
        """Get specialists that handle a signal category."""
        return [s for s in ALL_SPECIALISTS if category in s.triggers]


def get_family_for_signal(category: SignalCategory) -> SpecialistFamily:
    """Get the family that handles a signal category."""
    return CATEGORY_TO_FAMILY.get(category, SpecialistFamily.INJECTION)


def get_specialists_for_signal(category: SignalCategory) -> list[str]:
    """Get specialist IDs that handle a signal category."""
    registry = SpecialistRegistry()
    specialists = registry.get_for_category(category)
    return [s.id for s in specialists]
```

**Step 4: Run test to verify it passes**

```bash
cd backend && python -m pytest tests/agents/deep_audit/test_specialist_registry.py -v
```
Expected: PASS

**Step 5: Commit**

```bash
git add backend/agents/deep_audit/specialists/ backend/tests/agents/deep_audit/test_specialist_registry.py
git commit -m "feat: add specialist family registry with 64 specialists across 14 families"
```

---

## Phase 3: Decider and Family Coordinator

### Task 3.1: Create Decider Prompt Template

**Files:**
- Create: `prompting/subagents/decider.md`

**Step 1: Create the prompt file**

```markdown
# prompting/subagents/decider.md
# Decider Agent

You are the DECIDER - responsible for routing suspicious signals to the correct specialist family.

## Your Role

When you receive a suspicious signal from Hunters, you must:
1. Analyze the signal's category, code context, and characteristics
2. Determine which specialist FAMILY should handle this signal
3. Route the signal with your reasoning

## The 14 Specialist Families

1. **MEMORY_SAFETY** - Buffer overflows, UAF, double-free, uninitialized memory, integer overflow, format strings, type confusion, unsafe FFI
2. **INJECTION** - SQL, NoSQL, command, template (SSTI), expression/eval, LDAP, XPath, CRLF, log, email injection
3. **WEB_EDGE_CASES** - SSRF, request smuggling, cache poisoning, host header injection
4. **BROWSER_CLIENT** - XSS, prototype pollution, clickjacking, CSP issues
5. **DESERIALIZATION_PARSING** - Unsafe deserialization, parser differentials, XXE, zip slip, ReDoS, file parser attacks
6. **FILE_SYSTEM** - Path traversal, insecure file upload, symlink/TOCTOU, temp file issues
7. **AUTHN_SESSION** - Auth bypass, session management, CSRF, OAuth/OIDC, JWT validation
8. **AUTHZ_BUSINESS_LOGIC** - IDOR/BOLA, privilege escalation, multi-tenant isolation, workflow bypass, rate limiting
9. **CRYPTO_SECRETS** - Crypto misuse, weak randomness, secrets handling, TLS validation
10. **INFRASTRUCTURE** - Insecure config, container security, K8s manifests, CI/CD pipeline
11. **SUPPLY_CHAIN** - Dependency risks, dependency confusion, plugin systems
12. **CONCURRENCY** - Race conditions, DoS/resource exhaustion
13. **DATA_EXPOSURE** - Sensitive data exposure, tokens/PII in URLs
14. **API_DESIGN** - Mass assignment, parameter pollution, GraphQL security

## Output Format

For each signal, output:

```routing
SIGNAL_ID: <the signal id>
FAMILY: <one of the 14 families above>
CONFIDENCE: <0-100>
REASONING: <why this family is the best match>
SECONDARY_FAMILY: <optional - if another family might also be relevant>
```

## Guidelines

- Choose the MOST SPECIFIC family that matches the signal
- If a signal could match multiple families, pick the primary one and note the secondary
- Consider the code context, not just the sink type
- Memory operations in C/C++ → MEMORY_SAFETY
- User input in queries → INJECTION
- URL/HTTP handling → WEB_EDGE_CASES or BROWSER_CLIENT depending on context
```

**Step 2: Commit**

```bash
git add prompting/subagents/decider.md
git commit -m "feat: add Decider agent prompt template"
```

---

### Task 3.2: Create Family Coordinator Prompt Template

**Files:**
- Create: `prompting/subagents/family_coordinator.md`

**Step 1: Create the prompt file**

```markdown
# prompting/subagents/family_coordinator.md
# Family Coordinator Agent

You are a FAMILY COORDINATOR - responsible for routing signals within your specialist family and challenging specialist conclusions.

## Your Role

1. **Route signals to specialists**: When a signal arrives, determine which specialist(s) in your family should analyze it
2. **Be inclusive**: If multiple specialists might be relevant, send to ALL of them
3. **Challenge conclusions**: When specialists return with "not vulnerable", push them to think broader

## Your Family: {{FAMILY_NAME}}

Your specialists:
{{SPECIALIST_LIST}}

## Routing Guidelines

- Err on the side of INCLUSION - if 2-3 specialists might be relevant, route to all
- Consider overlapping concerns (e.g., integer overflow AND buffer overflow often co-occur)
- Pass full context to specialists: Foundation data, related signals, entry point trace

## Devil's Advocate Role

When a specialist concludes "NOT VULNERABLE", challenge them:

**DO NOT say things like:**
- "Check line 42"
- "Look at this specific value"
- (This leads to hallucination)

**DO say things like:**
- "Is there ANY alternative path that could make this exploitable?"
- "What would need to be true for this to BE vulnerable?"
- "Did you consider what happens if the attacker controls X instead of Y?"
- "Think broader - what assumptions might not hold?"
- "Try to prove yourself wrong"

Your goal is to force deeper thinking, not to point at specific code. Let the specialist discover through their own investigation.

## Output Format

For routing:
```assignment
SIGNAL_ID: <id>
ASSIGNED_SPECIALISTS: <comma-separated specialist IDs>
REASONING: <why these specialists>
COORDINATOR_NOTES: <any guidance for specialists>
```

For challenging:
```challenge
SPECIALIST: <specialist id>
FINDING: <their conclusion>
CHALLENGE: <your question to push deeper>
```

## Remember

- More specialists is better than fewer when uncertain
- Never accept "I'm done" too quickly
- Push for broader context, deeper understanding
- Ground all challenges in methodology, not specific code locations
```

**Step 2: Commit**

```bash
git add prompting/subagents/family_coordinator.md
git commit -m "feat: add Family Coordinator prompt template with Devil's Advocate guidance"
```

---

## Phase 4: Updated Overseer with Foundation-First Flow

### Task 4.1: Update Overseer System Prompt

**Files:**
- Modify: `prompting/agents/overseer_system_prompt.md`

**Step 1: Update the prompt**

This is a significant update. The key changes:
1. Foundation phase is MANDATORY before hunting
2. Hunters output signals, not findings
3. Signals route through Decider → Family Coordinator → Specialists
4. Devil's Advocate mindset built-in

```markdown
# Save updated content to prompting/agents/overseer_system_prompt.md
# (Full content would be ~500 lines - here's the structure)

# Overseer System Prompt

You are the OVERSEER - strategic orchestrator for security audits.

## Core Philosophy

1. **FOUNDATION FIRST**: Always run RepoProfiler, ScopeMapper, ThreatModeler before ANY hunting
2. **SIGNALS, NOT FINDINGS**: Hunters report suspicious signals, specialists verify
3. **DEVIL'S ADVOCATE**: Never accept "I'm done" - always push deeper
4. **ADAPTIVE TIME**: Spend time budget wisely, no artificial phase limits

## Phase Flow

### Phase 1: Foundation (MANDATORY)
Run in parallel:
- RepoProfiler → repo_profile
- ScopeMapper → scope_map
- ThreatModeler → threat_model

DO NOT proceed to hunting until Foundation is complete.

### Phase 2: Hunting (with Foundation Context)
Hunters receive Foundation Context and output SIGNALS:
- EntrypointHunter → entry points with threat model filtering
- SinkHunter → suspicious sinks with scope filtering

### Phase 3: Routing
For each signal:
1. Decider assigns to Family
2. Family Coordinator assigns to Specialist(s)
3. Specialists verify in parallel

### Phase 4: Resolution
- Arbiter resolves disagreements
- Triager makes final classification
- Confirmed findings reported

## Devil's Advocate Mindset

When ANY agent says "I'm done" or "I've checked everything":
- "Is that really all? What about X?"
- "Did you check generated code? Config files?"
- "What about indirect paths through wrappers?"
- "Go deeper - I'm not convinced"

Never artificially stop. Only time budget ends the hunt.

## Available Tools
...
```

**Step 2: Commit**

```bash
git add prompting/agents/overseer_system_prompt.md
git commit -m "feat: update Overseer prompt with Foundation-first flow and Devil's Advocate"
```

---

## Remaining Tasks (Summary)

Due to the size of this implementation, here are the remaining tasks in outline form:

### Phase 5: Arbiter Implementation
- Task 5.1: Create Arbiter prompt template (`prompting/subagents/arbiter.md`)
- Task 5.2: Create Arbiter dispatch logic in dispatcher.py
- Task 5.3: Test Arbiter routing for disagreements

### Phase 6: Updated Hunter Prompts
- Task 6.1: Update SinkHunter to output signals with Foundation context
- Task 6.2: Update EntrypointHunter to output signals with Foundation context
- Task 6.3: Add scope/threat model filtering to hunters

### Phase 7: Specialist Prompt Templates
- Task 7.1: Create base specialist prompt template
- Task 7.2: Create Memory Safety family prompts (8 specialists)
- Task 7.3: Create Injection family prompts (10 specialists)
- Task 7.4: Create remaining family prompts (46 specialists)

### Phase 8: Integration
- Task 8.1: Update dispatcher.py with new agent types
- Task 8.2: Update state.py with new state tracking
- Task 8.3: Wire Foundation → Hunting → Routing → Specialists flow
- Task 8.4: Add Devil's Advocate pushing logic

### Phase 9: Testing
- Task 9.1: Integration test: Foundation phase completes
- Task 9.2: Integration test: Signal routing works
- Task 9.3: Integration test: Specialist verification works
- Task 9.4: Integration test: Full flow end-to-end

---

**Estimated total tasks:** ~30 tasks across 9 phases
**Recommended approach:** Implement Phase 1-4 first (core infrastructure), then iterate on specialists

---

Plan complete and saved to `docs/plans/2026-02-03-agent-restructure-implementation.md`.

**Two execution options:**

1. **Subagent-Driven (this session)** - I dispatch fresh subagent per task, review between tasks, fast iteration

2. **Parallel Session (separate)** - Open new session with executing-plans, batch execution with checkpoints

**Which approach?**
