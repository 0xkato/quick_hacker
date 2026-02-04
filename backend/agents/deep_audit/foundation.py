"""
Foundation Context Schema for Deep Audit Agent Architecture.

The FoundationContext is built BEFORE any vulnerability hunting begins and is
injected into all downstream agents (Hunters, Specialists, etc.). It provides:
- Repository profile (languages, frameworks, build system)
- Scope map (what code is security-critical, test, vendor)
- Threat model (attacker capabilities, trust boundaries, in/out of scope)
"""

from dataclasses import dataclass, field
from enum import Enum
from fnmatch import fnmatch
from typing import Any


class AttackerCapability(Enum):
    """Defines what an attacker can do in the threat model."""
    NETWORK_ACCESS = "network_access"
    UNAUTHENTICATED = "unauthenticated"
    AUTHENTICATED_USER = "authenticated_user"
    AUTHENTICATED_ADMIN = "authenticated_admin"
    LOCAL_ACCESS = "local_access"
    INSIDER = "insider"


@dataclass
class TrustBoundary:
    """Represents a boundary between trust zones in the application."""
    name: str
    description: str
    entry_points: list[str] = field(default_factory=list)


@dataclass
class RepoProfile:
    """Profile of the repository being audited."""
    languages: list[str]
    frameworks: list[str]
    build_system: str
    entry_point_files: list[str]
    total_files: int = 0
    total_lines: int = 0
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class ScopeMap:
    """Maps different categories of code in the repository."""
    security_critical: list[str]  # Paths/patterns for security-critical code
    test_code: list[str]  # Paths/patterns for test code
    vendor_code: list[str]  # Paths/patterns for third-party/vendor code
    generated_code: list[str]  # Paths/patterns for generated code
    module_purposes: dict[str, str] = field(default_factory=dict)  # module -> purpose description


@dataclass
class ThreatModel:
    """Defines the threat model for the security audit."""
    trust_boundaries: list[TrustBoundary]
    attacker_capabilities: list[AttackerCapability]
    in_scope_paths: list[str]
    out_of_scope_paths: list[str]
    out_of_scope_reasons: dict[str, str]  # path -> reason
    assumptions: list[str] = field(default_factory=list)


@dataclass
class FoundationContext:
    """
    Complete foundation context for the security audit.

    Built during the Foundation Phase by RepoProfiler, ScopeMapper, and ThreatModeler.
    Written to /memories/foundation/context.md for all downstream agents to read.

    The context enables agents to:
    - Filter out test/vendor/generated code (is_in_scope)
    - Prioritize security-critical paths (is_security_critical)
    - Understand the threat model and attacker capabilities
    - Make informed decisions about vulnerability severity

    Attributes:
        repo_profile: Languages, frameworks, build system, entry points
        scope_map: Security-critical vs test/vendor/generated code paths
        threat_model: Trust boundaries, attacker capabilities, in/out of scope

    Example:
        >>> ctx = FoundationContext.from_dict(foundation_data)
        >>> if ctx.is_in_scope("src/api/auth.py"):
        ...     # Analyze this file
        >>> # Context is written to /memories/foundation/context.md
        >>> # Agents read it using: Read("/memories/foundation/context.md")
    """
    repo_profile: RepoProfile
    scope_map: ScopeMap
    threat_model: ThreatModel

    def _matches_any_pattern(self, path: str, patterns: list[str]) -> bool:
        """Check if path matches any of the given patterns (glob or prefix)."""
        for pattern in patterns:
            # Handle glob patterns
            if "*" in pattern:
                if fnmatch(path, pattern) or fnmatch(path.split("/")[-1], pattern):
                    return True
            # Handle directory patterns (ending with /)
            elif pattern.endswith("/"):
                # Directory pattern - match anywhere in path
                if path.startswith(pattern) or f"/{pattern}" in f"/{path}":
                    return True
            # Handle prefix patterns (directory paths)
            elif path.startswith(pattern):
                return True
        return False

    def is_in_scope(self, path: str) -> bool:
        """
        Determine if a path is in scope for security analysis.

        A path is OUT of scope if:
        - It matches test_code patterns
        - It matches vendor_code patterns
        - It matches generated_code patterns
        - It's explicitly in out_of_scope_paths

        A path is IN scope if it's not excluded by the above rules.
        """
        # Check exclusions first
        if self._matches_any_pattern(path, self.scope_map.test_code):
            return False
        if self._matches_any_pattern(path, self.scope_map.vendor_code):
            return False
        if self._matches_any_pattern(path, self.scope_map.generated_code):
            return False
        if self._matches_any_pattern(path, self.threat_model.out_of_scope_paths):
            return False

        return True

    def is_security_critical(self, path: str) -> bool:
        """Check if a path is in security-critical code areas."""
        return self._matches_any_pattern(path, self.scope_map.security_critical)

    def to_prompt_context(self) -> str:
        """
        Serialize the foundation context for injection into agent prompts.

        Returns a human-readable string representation suitable for LLM consumption.
        """
        lines = []

        # Repository Profile
        lines.append("## Repository Profile")
        lines.append(f"Languages: {', '.join(self.repo_profile.languages) or 'Not specified'}")
        lines.append(f"Frameworks: {', '.join(self.repo_profile.frameworks) or 'None'}")
        lines.append(f"Build System: {self.repo_profile.build_system or 'Not specified'}")
        if self.repo_profile.entry_point_files:
            lines.append(f"Entry Points: {', '.join(self.repo_profile.entry_point_files)}")
        lines.append("")

        # Scope Map
        lines.append("## Scope Map")
        if self.scope_map.security_critical:
            lines.append(f"Security-Critical Areas: {', '.join(self.scope_map.security_critical)}")
        if self.scope_map.test_code:
            lines.append(f"Test Code (excluded): {', '.join(self.scope_map.test_code)}")
        if self.scope_map.vendor_code:
            lines.append(f"Vendor Code (excluded): {', '.join(self.scope_map.vendor_code)}")
        if self.scope_map.generated_code:
            lines.append(f"Generated Code (excluded): {', '.join(self.scope_map.generated_code)}")
        lines.append("")

        # Threat Model
        lines.append("## Threat Model")
        if self.threat_model.attacker_capabilities:
            capabilities = [cap.name for cap in self.threat_model.attacker_capabilities]
            lines.append(f"Attacker Capabilities: {', '.join(capabilities)}")
        if self.threat_model.trust_boundaries:
            lines.append("Trust Boundaries:")
            for boundary in self.threat_model.trust_boundaries:
                lines.append(f"  - {boundary.name}: {boundary.description}")
        if self.threat_model.in_scope_paths:
            lines.append(f"In-Scope Paths: {', '.join(self.threat_model.in_scope_paths)}")
        if self.threat_model.out_of_scope_paths:
            lines.append(f"Out-of-Scope Paths: {', '.join(self.threat_model.out_of_scope_paths)}")
        if self.threat_model.assumptions:
            lines.append("Assumptions:")
            for assumption in self.threat_model.assumptions:
                lines.append(f"  - {assumption}")

        return "\n".join(lines)

    def to_dict(self) -> dict[str, Any]:
        """Convert the foundation context to a dictionary for serialization."""
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
                    {
                        "name": tb.name,
                        "description": tb.description,
                        "entry_points": tb.entry_points,
                    }
                    for tb in self.threat_model.trust_boundaries
                ],
                "attacker_capabilities": [cap.value for cap in self.threat_model.attacker_capabilities],
                "in_scope_paths": self.threat_model.in_scope_paths,
                "out_of_scope_paths": self.threat_model.out_of_scope_paths,
                "out_of_scope_reasons": self.threat_model.out_of_scope_reasons,
                "assumptions": self.threat_model.assumptions,
            },
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "FoundationContext":
        """Create a FoundationContext from a dictionary."""
        repo_data = data["repo_profile"]
        repo_profile = RepoProfile(
            languages=repo_data["languages"],
            frameworks=repo_data["frameworks"],
            build_system=repo_data["build_system"],
            entry_point_files=repo_data["entry_point_files"],
            total_files=repo_data.get("total_files", 0),
            total_lines=repo_data.get("total_lines", 0),
            metadata=repo_data.get("metadata", {}),
        )

        scope_data = data["scope_map"]
        scope_map = ScopeMap(
            security_critical=scope_data["security_critical"],
            test_code=scope_data["test_code"],
            vendor_code=scope_data["vendor_code"],
            generated_code=scope_data["generated_code"],
            module_purposes=scope_data.get("module_purposes", {}),
        )

        threat_data = data["threat_model"]

        # Parse attacker capabilities, skipping unknown values
        # Agents may return capabilities not in our predefined enum
        valid_capabilities = {cap.value for cap in AttackerCapability}
        parsed_capabilities = []
        for cap in threat_data.get("attacker_capabilities", []):
            if cap in valid_capabilities:
                parsed_capabilities.append(AttackerCapability(cap))
            else:
                # Try to map to closest known capability
                cap_lower = cap.lower()
                if "network" in cap_lower or "remote" in cap_lower:
                    parsed_capabilities.append(AttackerCapability.NETWORK_ACCESS)
                elif "unauth" in cap_lower or "anonymous" in cap_lower:
                    parsed_capabilities.append(AttackerCapability.UNAUTHENTICATED)
                elif "admin" in cap_lower:
                    parsed_capabilities.append(AttackerCapability.AUTHENTICATED_ADMIN)
                elif "auth" in cap_lower or "user" in cap_lower:
                    parsed_capabilities.append(AttackerCapability.AUTHENTICATED_USER)
                elif "local" in cap_lower:
                    parsed_capabilities.append(AttackerCapability.LOCAL_ACCESS)
                elif "insider" in cap_lower or "internal" in cap_lower:
                    parsed_capabilities.append(AttackerCapability.INSIDER)
                else:
                    print(f"[Foundation] Unknown attacker capability '{cap}', skipping")

        # Deduplicate capabilities
        parsed_capabilities = list(set(parsed_capabilities))

        threat_model = ThreatModel(
            trust_boundaries=[
                TrustBoundary(
                    name=tb["name"],
                    description=tb["description"],
                    entry_points=tb.get("entry_points", []),
                )
                for tb in threat_data.get("trust_boundaries", [])
            ],
            attacker_capabilities=parsed_capabilities,
            in_scope_paths=threat_data.get("in_scope_paths", []),
            out_of_scope_paths=threat_data.get("out_of_scope_paths", []),
            out_of_scope_reasons=threat_data.get("out_of_scope_reasons", {}),
            assumptions=threat_data.get("assumptions", []),
        )

        return cls(
            repo_profile=repo_profile,
            scope_map=scope_map,
            threat_model=threat_model,
        )


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
