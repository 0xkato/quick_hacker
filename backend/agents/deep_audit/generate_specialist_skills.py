#!/usr/bin/env python3
"""Generate Claude Code plugin SKILL.md files from existing specialist content.

Merges each specialist's skill file (detection methodology) and prompt file
(domain expertise) into a single SKILL.md for Claude Code's native skill system.

Output: specialist_plugin/skills/<skill-name>/SKILL.md

Usage:
    python3 generate_specialist_skills.py
    # Or from backend/:
    python3 -m agents.deep_audit.generate_specialist_skills
"""

import os
from pathlib import Path

# Base directories
SCRIPT_DIR = Path(__file__).resolve().parent
SKILLS_DIR = SCRIPT_DIR / "skills"
PROMPTS_DIR = SCRIPT_DIR.parents[2] / "prompting"
OUTPUT_DIR = SCRIPT_DIR / "specialist_plugin" / "skills"

# specialist_id -> (skill_path, prompt_path, description)
# skill_path relative to SKILLS_DIR, prompt_path relative to PROMPTS_DIR
SPECIALISTS = {
    # Memory Safety (8)
    "oob_read_write_auditor": (
        "memory/buffer_overflow.md",
        "specialists/memory_safety/oob_read_write.md",
        "Detection methodology for out-of-bounds read/write and buffer overflow vulnerabilities",
    ),
    "use_after_free_auditor": (
        "memory/use_after_free.md",
        "specialists/memory_safety/use_after_free.md",
        "Detection methodology for use-after-free and dangling pointer vulnerabilities",
    ),
    "double_free_auditor": (
        "memory/double_free.md",
        "specialists/memory_safety/double_free.md",
        "Detection methodology for double-free and repeated deallocation bugs",
    ),
    "uninit_memory_auditor": (
        "memory/uninitialized_memory.md",
        "specialists/memory_safety/uninit_memory.md",
        "Detection methodology for uninitialized memory reads and information disclosure",
    ),
    "integer_overflow_auditor": (
        "memory/integer_overflow.md",
        "specialists/memory_safety/integer_overflow.md",
        "Detection methodology for integer overflows, underflows, and truncation",
    ),
    "format_string_auditor": (
        "memory/format_string.md",
        "specialists/memory_safety/format_string.md",
        "Detection methodology for format string vulnerabilities",
    ),
    "type_confusion_auditor": (
        "memory/type_confusion.md",
        "specialists/memory_safety/type_confusion.md",
        "Detection methodology for type confusion vulnerabilities",
    ),
    "unsafe_ffi_auditor": (
        "memory/unsafe_ffi.md",
        "specialists/memory_safety/unsafe_ffi.md",
        "Detection methodology for unsafe FFI boundary vulnerabilities",
    ),
    # Injection (10)
    "sql_injection_auditor": (
        "injection/sql_injection.md",
        "specialists/injection/sql_injection.md",
        "Detection methodology for SQL injection vulnerabilities",
    ),
    "nosql_injection_auditor": (
        "injection/nosql_injection.md",
        "specialists/injection/nosql_injection.md",
        "Detection methodology for NoSQL injection vulnerabilities",
    ),
    "command_injection_auditor": (
        "injection/command_injection.md",
        "specialists/injection/command_injection.md",
        "Detection methodology for OS command injection vulnerabilities",
    ),
    "template_injection_auditor": (
        "injection/template_injection.md",
        "specialists/injection/template_injection.md",
        "Detection methodology for server-side template injection",
    ),
    "expression_injection_auditor": (
        "injection/expression_injection.md",
        "specialists/injection/expression_injection.md",
        "Detection methodology for expression language injection",
    ),
    "ldap_injection_auditor": (
        "injection/ldap_injection.md",
        "specialists/injection/ldap_injection.md",
        "Detection methodology for LDAP injection vulnerabilities",
    ),
    "xpath_injection_auditor": (
        "injection/xpath_injection.md",
        "specialists/injection/xpath_injection.md",
        "Detection methodology for XPath injection vulnerabilities",
    ),
    "crlf_injection_auditor": (
        "injection/crlf_injection.md",
        "specialists/injection/crlf_injection.md",
        "Detection methodology for CRLF injection and response splitting",
    ),
    "log_injection_auditor": (
        "injection/log_injection.md",
        "specialists/injection/log_injection.md",
        "Detection methodology for log injection and log forging",
    ),
    "email_injection_auditor": (
        "injection/email_injection.md",
        "specialists/injection/email_injection.md",
        "Detection methodology for email header injection",
    ),
    # Web Edge Cases (4)
    "ssrf_auditor": (
        "web/ssrf.md",
        "specialists/web_edge_cases/ssrf.md",
        "Detection methodology for server-side request forgery",
    ),
    "request_smuggling_auditor": (
        "web/request_smuggling.md",
        "specialists/web_edge_cases/request_smuggling.md",
        "Detection methodology for HTTP request smuggling",
    ),
    "cache_poisoning_auditor": (
        "web/cache_poisoning.md",
        "specialists/web_edge_cases/cache_poisoning.md",
        "Detection methodology for web cache poisoning",
    ),
    "host_header_auditor": (
        "web/host_header_injection.md",
        "specialists/web_edge_cases/host_header.md",
        "Detection methodology for Host header injection",
    ),
    # Browser/Client (4)
    "xss_auditor": (
        "browser/xss.md",
        "specialists/browser_client/xss.md",
        "Detection methodology for cross-site scripting vulnerabilities",
    ),
    "prototype_pollution_auditor": (
        "browser/prototype_pollution.md",
        "specialists/browser_client/prototype_pollution.md",
        "Detection methodology for JavaScript prototype pollution",
    ),
    "clickjacking_auditor": (
        "browser/clickjacking.md",
        "specialists/browser_client/clickjacking.md",
        "Detection methodology for clickjacking and UI redressing",
    ),
    "csp_auditor": (
        "browser/csp_issues.md",
        "specialists/browser_client/csp.md",
        "Detection methodology for Content Security Policy bypasses",
    ),
    # Deserialization/Parsing (6)
    "unsafe_deser_auditor": (
        "deserialization/unsafe_deserialization.md",
        "specialists/deserialization_parsing/unsafe_deserialization.md",
        "Detection methodology for insecure deserialization vulnerabilities",
    ),
    "parser_differential_auditor": (
        "deserialization/parser_differential.md",
        "specialists/deserialization_parsing/parser_differential.md",
        "Detection methodology for parser differential vulnerabilities",
    ),
    "xxe_auditor": (
        "deserialization/xxe.md",
        "specialists/deserialization_parsing/xxe.md",
        "Detection methodology for XML External Entity injection",
    ),
    "zip_slip_auditor": (
        "deserialization/zip_slip.md",
        "specialists/deserialization_parsing/zip_slip.md",
        "Detection methodology for archive extraction path traversal",
    ),
    "redos_auditor": (
        "deserialization/redos.md",
        "specialists/deserialization_parsing/redos.md",
        "Detection methodology for Regular Expression Denial of Service",
    ),
    "file_parser_auditor": (
        "deserialization/file_parser.md",
        "specialists/deserialization_parsing/file_parser.md",
        "Detection methodology for file format parser vulnerabilities",
    ),
    # File System (4)
    "path_traversal_auditor": (
        "web/path_traversal.md",
        "specialists/file_system/path_traversal.md",
        "Detection methodology for directory traversal and LFI",
    ),
    "file_upload_auditor": (
        "filesystem/file_upload.md",
        "specialists/file_system/file_upload.md",
        "Detection methodology for unrestricted file upload",
    ),
    "symlink_toctou_auditor": (
        "filesystem/symlink_toctou.md",
        "specialists/file_system/symlink_toctou.md",
        "Detection methodology for symlink attacks and TOCTOU races",
    ),
    "temp_file_auditor": (
        "filesystem/temp_file.md",
        "specialists/file_system/temp_file.md",
        "Detection methodology for insecure temporary file creation",
    ),
    # AuthN/Session (5)
    "authn_bypass_auditor": (
        "auth/auth_bypass.md",
        "specialists/authn_session/authn_bypass.md",
        "Detection methodology for authentication bypass vulnerabilities",
    ),
    "session_mgmt_auditor": (
        "session/session_management.md",
        "specialists/authn_session/session_management.md",
        "Detection methodology for session management vulnerabilities",
    ),
    "csrf_auditor": (
        "session/csrf.md",
        "specialists/authn_session/csrf.md",
        "Detection methodology for cross-site request forgery",
    ),
    "oauth_auditor": (
        "session/oauth.md",
        "specialists/authn_session/oauth.md",
        "Detection methodology for OAuth/OIDC vulnerabilities",
    ),
    "jwt_auditor": (
        "session/jwt.md",
        "specialists/authn_session/jwt.md",
        "Detection methodology for JWT vulnerabilities",
    ),
    # AuthZ/Business Logic (5)
    "idor_auditor": (
        "auth/idor.md",
        "specialists/authz_business_logic/idor.md",
        "Detection methodology for Insecure Direct Object Reference",
    ),
    "priv_esc_auditor": (
        "auth/privilege_escalation.md",
        "specialists/authz_business_logic/privilege_escalation.md",
        "Detection methodology for privilege escalation vulnerabilities",
    ),
    "multi_tenant_auditor": (
        "auth/multi_tenant_isolation.md",
        "specialists/authz_business_logic/multi_tenant.md",
        "Detection methodology for multi-tenant isolation failures",
    ),
    "workflow_bypass_auditor": (
        "auth/workflow_bypass.md",
        "specialists/authz_business_logic/workflow_bypass.md",
        "Detection methodology for business logic workflow bypass",
    ),
    "rate_limit_auditor": (
        "auth/rate_limit_bypass.md",
        "specialists/authz_business_logic/rate_limit.md",
        "Detection methodology for rate limiting bypass",
    ),
    # Crypto/Secrets (4)
    "crypto_misuse_auditor": (
        "crypto/crypto_misuse.md",
        "specialists/crypto_secrets/crypto_misuse.md",
        "Detection methodology for cryptographic implementation flaws",
    ),
    "randomness_auditor": (
        "crypto/weak_randomness.md",
        "specialists/crypto_secrets/randomness.md",
        "Detection methodology for weak PRNG and predictable tokens",
    ),
    "secrets_handling_auditor": (
        "crypto/secrets_handling.md",
        "specialists/crypto_secrets/secrets_handling.md",
        "Detection methodology for hardcoded secrets and insecure storage",
    ),
    "tls_auditor": (
        "crypto/tls_configuration.md",
        "specialists/crypto_secrets/tls.md",
        "Detection methodology for TLS/SSL configuration weaknesses",
    ),
    # Infrastructure (4)
    "insecure_config_auditor": (
        "infrastructure/insecure_configuration.md",
        "specialists/infrastructure/insecure_config.md",
        "Detection methodology for security misconfigurations",
    ),
    "container_auditor": (
        "infrastructure/container_security.md",
        "specialists/infrastructure/container.md",
        "Detection methodology for container security issues",
    ),
    "k8s_auditor": (
        "infrastructure/kubernetes_security.md",
        "specialists/infrastructure/kubernetes.md",
        "Detection methodology for Kubernetes security misconfigurations",
    ),
    "cicd_auditor": (
        "infrastructure/cicd_security.md",
        "specialists/infrastructure/cicd.md",
        "Detection methodology for CI/CD pipeline vulnerabilities",
    ),
    # Supply Chain (3)
    "dependency_risk_auditor": (
        "supply_chain/dependency_risk.md",
        "specialists/supply_chain/dependency_risk.md",
        "Detection methodology for dependency vulnerability assessment",
    ),
    "dependency_confusion_auditor": (
        "supply_chain/dependency_confusion.md",
        "specialists/supply_chain/dependency_confusion.md",
        "Detection methodology for dependency confusion attacks",
    ),
    "plugin_auditor": (
        "supply_chain/plugin_extension.md",
        "specialists/supply_chain/plugin.md",
        "Detection methodology for plugin and extension security",
    ),
    # Concurrency (2)
    "race_condition_auditor": (
        "concurrency/race_condition.md",
        "specialists/concurrency/race_condition.md",
        "Detection methodology for race conditions and TOCTOU",
    ),
    "dos_auditor": (
        "concurrency/dos_resource_exhaustion.md",
        "specialists/concurrency/dos.md",
        "Detection methodology for denial of service and resource exhaustion",
    ),
    # Data Exposure (2)
    "sensitive_data_auditor": (
        "data_exposure/sensitive_data_exposure.md",
        "specialists/data_exposure/sensitive_data.md",
        "Detection methodology for sensitive data exposure",
    ),
    "token_in_url_auditor": (
        "data_exposure/token_in_url.md",
        "specialists/data_exposure/token_in_url.md",
        "Detection methodology for tokens leaked in URLs",
    ),
    # API Design (3)
    "mass_assignment_auditor": (
        "api_design/mass_assignment.md",
        "specialists/api_design/mass_assignment.md",
        "Detection methodology for mass assignment vulnerabilities",
    ),
    "param_pollution_auditor": (
        "api_design/parameter_pollution.md",
        "specialists/api_design/parameter_pollution.md",
        "Detection methodology for HTTP parameter pollution",
    ),
    "graphql_auditor": (
        "api_design/graphql_security.md",
        "specialists/api_design/graphql.md",
        "Detection methodology for GraphQL security issues",
    ),
}


def specialist_id_to_skill_name(specialist_id: str) -> str:
    """Convert specialist_id to Claude Code skill name (kebab-case)."""
    return specialist_id.replace("_auditor", "").replace("_", "-") + "-audit"


def generate_skill_md(
    skill_name: str,
    description: str,
    prompt_content: str,
    skill_content: str,
) -> str:
    """Generate SKILL.md content with YAML frontmatter."""
    return f"""---
name: {skill_name}
description: {description}
---

# Domain Expertise

{prompt_content.strip()}

---

# Detection Methodology

{skill_content.strip()}
"""


def main() -> None:
    """Generate all specialist SKILL.md files."""
    # Ensure output directory exists
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

    generated = 0
    errors = []

    for specialist_id, (skill_path, prompt_path, description) in SPECIALISTS.items():
        skill_name = specialist_id_to_skill_name(specialist_id)
        skill_dir = OUTPUT_DIR / skill_name
        skill_dir.mkdir(parents=True, exist_ok=True)

        # Read skill file (detection methodology)
        skill_file = SKILLS_DIR / skill_path
        if not skill_file.is_file():
            errors.append(f"  MISSING skill: {skill_file}")
            continue
        skill_content = skill_file.read_text(encoding="utf-8")

        # Read prompt file (domain expertise)
        prompt_file = PROMPTS_DIR / prompt_path
        if not prompt_file.is_file():
            errors.append(f"  MISSING prompt: {prompt_file}")
            continue
        prompt_content = prompt_file.read_text(encoding="utf-8")

        # Generate merged SKILL.md
        merged = generate_skill_md(skill_name, description, prompt_content, skill_content)
        output_file = skill_dir / "SKILL.md"
        output_file.write_text(merged, encoding="utf-8")

        generated += 1
        print(f"  {skill_name}/SKILL.md ({len(merged):,} chars)")

    print(f"\nGenerated: {generated}/{len(SPECIALISTS)} SKILL.md files")
    print(f"Output: {OUTPUT_DIR}")

    if errors:
        print(f"\nErrors ({len(errors)}):")
        for e in errors:
            print(e)
        raise SystemExit(1)


if __name__ == "__main__":
    main()
