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

    Built during the Foundation phase and injected into all downstream agents.
    """
    repo_profile: RepoProfile
    scope_map: ScopeMap
    threat_model: ThreatModel

    def _matches_any_pattern(self, path: str, patterns: list[str]) -> bool:
        """Check if path matches any of the given patterns (glob or prefix)."""
        for pattern in patterns:
            # Handle glob patterns
            if "*" in pattern:
                if fnmatch(path, pattern):
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
        threat_model = ThreatModel(
            trust_boundaries=[
                TrustBoundary(
                    name=tb["name"],
                    description=tb["description"],
                    entry_points=tb.get("entry_points", []),
                )
                for tb in threat_data["trust_boundaries"]
            ],
            attacker_capabilities=[
                AttackerCapability(cap) for cap in threat_data["attacker_capabilities"]
            ],
            in_scope_paths=threat_data["in_scope_paths"],
            out_of_scope_paths=threat_data["out_of_scope_paths"],
            out_of_scope_reasons=threat_data.get("out_of_scope_reasons", {}),
            assumptions=threat_data.get("assumptions", []),
        )

        return cls(
            repo_profile=repo_profile,
            scope_map=scope_map,
            threat_model=threat_model,
        )
