"""
Skills loader for Deep Audit specialist agents.

Loads vulnerability-specific methodology files (skills) and injects them
into specialist prompts to improve detection accuracy and reduce false positives.

Skills are markdown files containing:
- Step-by-step methodology for finding the vulnerability class
- Decision tree for classification (VULNERABLE/HARDENED/SAFE/BY_DESIGN)
- Real-world examples with vulnerable and fixed code
- Common false positive patterns

Usage:
    >>> from agents.deep_audit.skills_loader import SkillsLoader
    >>> loader = SkillsLoader()
    >>> skill = loader.load_for_specialist("sql_injection_auditor")
    >>> if skill:
    ...     prompt = f"{base_prompt}\\n\\n## Detection Methodology\\n{skill}"
"""

import logging
from pathlib import Path
from typing import Optional

from agents.deep_audit.foundation import SignalCategory

logger = logging.getLogger(__name__)

# Directory containing skill files, relative to this module
SKILLS_DIR = Path(__file__).parent / "skills"


# Maps specialist_id -> skill file path (relative to SKILLS_DIR)
SPECIALIST_SKILL_MAP: dict[str, str] = {
    # Memory Safety (8)
    "oob_read_write_auditor": "memory/buffer_overflow.md",
    "use_after_free_auditor": "memory/use_after_free.md",
    "double_free_auditor": "memory/double_free.md",
    "uninit_memory_auditor": "memory/uninitialized_memory.md",
    "integer_overflow_auditor": "memory/integer_overflow.md",
    "format_string_auditor": "memory/format_string.md",
    "type_confusion_auditor": "memory/type_confusion.md",
    "unsafe_ffi_auditor": "memory/unsafe_ffi.md",

    # Injection (10)
    "sql_injection_auditor": "injection/sql_injection.md",
    "nosql_injection_auditor": "injection/nosql_injection.md",
    "command_injection_auditor": "injection/command_injection.md",
    "template_injection_auditor": "injection/template_injection.md",
    "expression_injection_auditor": "injection/expression_injection.md",
    "ldap_injection_auditor": "injection/ldap_injection.md",
    "xpath_injection_auditor": "injection/xpath_injection.md",
    "crlf_injection_auditor": "injection/crlf_injection.md",
    "log_injection_auditor": "injection/log_injection.md",
    "email_injection_auditor": "injection/email_injection.md",

    # Web Edge Cases (4)
    "ssrf_auditor": "web/ssrf.md",
    "request_smuggling_auditor": "web/request_smuggling.md",
    "cache_poisoning_auditor": "web/cache_poisoning.md",
    "host_header_auditor": "web/host_header_injection.md",

    # Browser/Client (4)
    "xss_auditor": "browser/xss.md",
    "prototype_pollution_auditor": "browser/prototype_pollution.md",
    "clickjacking_auditor": "browser/clickjacking.md",
    "csp_auditor": "browser/csp_issues.md",

    # Deserialization/Parsing (6)
    "unsafe_deser_auditor": "deserialization/unsafe_deserialization.md",
    "parser_differential_auditor": "deserialization/parser_differential.md",
    "xxe_auditor": "deserialization/xxe.md",
    "zip_slip_auditor": "deserialization/zip_slip.md",
    "redos_auditor": "deserialization/redos.md",
    "file_parser_auditor": "deserialization/file_parser.md",

    # File System (4)
    "path_traversal_auditor": "web/path_traversal.md",
    "file_upload_auditor": "filesystem/file_upload.md",
    "symlink_toctou_auditor": "filesystem/symlink_toctou.md",
    "temp_file_auditor": "filesystem/temp_file.md",

    # AuthN/Session (5)
    "authn_bypass_auditor": "auth/auth_bypass.md",
    "session_mgmt_auditor": "session/session_management.md",
    "csrf_auditor": "session/csrf.md",
    "oauth_auditor": "session/oauth.md",
    "jwt_auditor": "session/jwt.md",

    # AuthZ/Business Logic (5)
    "idor_auditor": "auth/idor.md",
    "priv_esc_auditor": "auth/privilege_escalation.md",
    "multi_tenant_auditor": "auth/multi_tenant_isolation.md",
    "workflow_bypass_auditor": "auth/workflow_bypass.md",
    "rate_limit_auditor": "auth/rate_limit_bypass.md",

    # Crypto/Secrets (4)
    "crypto_misuse_auditor": "crypto/crypto_misuse.md",
    "randomness_auditor": "crypto/weak_randomness.md",
    "secrets_handling_auditor": "crypto/secrets_handling.md",
    "tls_auditor": "crypto/tls_configuration.md",

    # Infrastructure (4)
    "insecure_config_auditor": "infrastructure/insecure_configuration.md",
    "container_auditor": "infrastructure/container_security.md",
    "k8s_auditor": "infrastructure/kubernetes_security.md",
    "cicd_auditor": "infrastructure/cicd_security.md",

    # Supply Chain (3)
    "dependency_risk_auditor": "supply_chain/dependency_risk.md",
    "dependency_confusion_auditor": "supply_chain/dependency_confusion.md",
    "plugin_auditor": "supply_chain/plugin_extension.md",

    # Concurrency (2)
    "race_condition_auditor": "concurrency/race_condition.md",
    "dos_auditor": "concurrency/dos_resource_exhaustion.md",

    # Data Exposure (2)
    "sensitive_data_auditor": "data_exposure/sensitive_data_exposure.md",
    "token_in_url_auditor": "data_exposure/token_in_url.md",

    # API Design (3)
    "mass_assignment_auditor": "api_design/mass_assignment.md",
    "param_pollution_auditor": "api_design/parameter_pollution.md",
    "graphql_auditor": "api_design/graphql_security.md",
}


# Maps SignalCategory -> skill file path (for hunters and other non-specialist agents)
CATEGORY_SKILL_MAP: dict[SignalCategory, str] = {
    # Memory Safety
    SignalCategory.BUFFER_OVERFLOW: "memory/buffer_overflow.md",
    SignalCategory.USE_AFTER_FREE: "memory/use_after_free.md",
    SignalCategory.DOUBLE_FREE: "memory/double_free.md",
    SignalCategory.UNINITIALIZED_MEMORY: "memory/uninitialized_memory.md",
    SignalCategory.INTEGER_OVERFLOW: "memory/integer_overflow.md",
    SignalCategory.FORMAT_STRING: "memory/format_string.md",
    SignalCategory.TYPE_CONFUSION: "memory/type_confusion.md",
    SignalCategory.UNSAFE_FFI: "memory/unsafe_ffi.md",

    # Injection
    SignalCategory.SQL_INJECTION: "injection/sql_injection.md",
    SignalCategory.NOSQL_INJECTION: "injection/nosql_injection.md",
    SignalCategory.COMMAND_INJECTION: "injection/command_injection.md",
    SignalCategory.TEMPLATE_INJECTION: "injection/template_injection.md",
    SignalCategory.EXPRESSION_INJECTION: "injection/expression_injection.md",
    SignalCategory.LDAP_INJECTION: "injection/ldap_injection.md",
    SignalCategory.XPATH_INJECTION: "injection/xpath_injection.md",
    SignalCategory.CRLF_INJECTION: "injection/crlf_injection.md",
    SignalCategory.LOG_INJECTION: "injection/log_injection.md",
    SignalCategory.EMAIL_INJECTION: "injection/email_injection.md",

    # Web
    SignalCategory.SSRF: "web/ssrf.md",
    SignalCategory.REQUEST_SMUGGLING: "web/request_smuggling.md",
    SignalCategory.CACHE_POISONING: "web/cache_poisoning.md",
    SignalCategory.HOST_HEADER_INJECTION: "web/host_header_injection.md",
    SignalCategory.PATH_TRAVERSAL: "web/path_traversal.md",

    # Browser
    SignalCategory.XSS: "browser/xss.md",
    SignalCategory.PROTOTYPE_POLLUTION: "browser/prototype_pollution.md",
    SignalCategory.CLICKJACKING: "browser/clickjacking.md",

    # Deserialization
    SignalCategory.UNSAFE_DESERIALIZATION: "deserialization/unsafe_deserialization.md",
    SignalCategory.XXE: "deserialization/xxe.md",
    SignalCategory.ZIP_SLIP: "deserialization/zip_slip.md",
    SignalCategory.REDOS: "deserialization/redos.md",

    # Auth
    SignalCategory.AUTH_BYPASS: "auth/auth_bypass.md",
    SignalCategory.SESSION_FIXATION: "session/session_management.md",
    SignalCategory.CSRF: "session/csrf.md",
    SignalCategory.IDOR: "auth/idor.md",
    SignalCategory.PRIVILEGE_ESCALATION: "auth/privilege_escalation.md",

    # Crypto
    SignalCategory.CRYPTO_MISUSE: "crypto/crypto_misuse.md",
    SignalCategory.WEAK_RANDOMNESS: "crypto/weak_randomness.md",
    SignalCategory.SECRETS_EXPOSURE: "crypto/secrets_handling.md",

    # Other
    SignalCategory.RACE_CONDITION: "concurrency/race_condition.md",
    SignalCategory.RESOURCE_EXHAUSTION: "concurrency/dos_resource_exhaustion.md",
    SignalCategory.SENSITIVE_DATA_EXPOSURE: "data_exposure/sensitive_data_exposure.md",
    SignalCategory.MASS_ASSIGNMENT: "api_design/mass_assignment.md",
}


class SkillsLoader:
    """Loads skill files for specialist agents.

    Caches loaded skills in memory to avoid repeated disk reads
    within a single scan session.
    """

    def __init__(self, skills_dir: Optional[Path] = None) -> None:
        self._skills_dir = skills_dir or SKILLS_DIR
        self._cache: dict[str, str] = {}

    def _load_file(self, relative_path: str) -> Optional[str]:
        """Load a skill file from disk, using cache."""
        if relative_path in self._cache:
            return self._cache[relative_path]

        file_path = self._skills_dir / relative_path
        if not file_path.is_file():
            logger.debug("Skill file not found: %s", file_path)
            return None

        try:
            content = file_path.read_text(encoding="utf-8")
            self._cache[relative_path] = content
            return content
        except OSError as e:
            logger.warning("Failed to read skill file %s: %s", file_path, e)
            return None

    def load_for_specialist(self, specialist_id: str) -> Optional[str]:
        """Load the skill file for a given specialist.

        Args:
            specialist_id: The specialist's ID (e.g. "sql_injection_auditor")

        Returns:
            Skill file content as string, or None if no skill exists.
        """
        relative_path = SPECIALIST_SKILL_MAP.get(specialist_id)
        if not relative_path:
            logger.debug("No skill mapping for specialist: %s", specialist_id)
            return None
        return self._load_file(relative_path)

    def load_for_category(self, category: SignalCategory) -> Optional[str]:
        """Load the skill file for a given signal category.

        Args:
            category: The SignalCategory enum value

        Returns:
            Skill file content as string, or None if no skill exists.
        """
        relative_path = CATEGORY_SKILL_MAP.get(category)
        if not relative_path:
            logger.debug("No skill mapping for category: %s", category)
            return None
        return self._load_file(relative_path)

    def load_for_category_name(self, category_name: str) -> Optional[str]:
        """Load skill by category name string (convenience for prompt assembly).

        Args:
            category_name: Category name as string (e.g. "SQL_INJECTION")

        Returns:
            Skill file content as string, or None.
        """
        try:
            category = SignalCategory[category_name]
        except KeyError:
            logger.debug("Unknown category name: %s", category_name)
            return None
        return self.load_for_category(category)

    def clear_cache(self) -> None:
        """Clear the in-memory skill cache."""
        self._cache.clear()

    @property
    def available_skills(self) -> list[str]:
        """List all available skill files on disk."""
        if not self._skills_dir.is_dir():
            return []
        return sorted(
            str(p.relative_to(self._skills_dir))
            for p in self._skills_dir.rglob("*.md")
        )
