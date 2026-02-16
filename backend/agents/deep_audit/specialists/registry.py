"""
Specialist Family Registry for Deep Audit.

This registry maps vulnerability signal categories to specialist families and
individual specialist agents. Contains 64 specialists organized into 14 families.

Routing Flow:
1. SinkHunter/EntrypointHunter find signals with a category (e.g., SQL_INJECTION)
2. Decider calls get_family_for_signal() to route to a family (e.g., INJECTION)
3. FamilyCoordinator calls get_specialists_for_signal() to assign specialists
4. Specialists analyze signals and return verdicts

Families:
- MEMORY_SAFETY: Buffer overflow, use-after-free, integer overflow (8 specialists)
- INJECTION: SQL, command, template, LDAP injection (10 specialists)
- WEB_EDGE_CASES: SSRF, request smuggling, cache poisoning (4 specialists)
- BROWSER_CLIENT: XSS, prototype pollution, clickjacking (4 specialists)
- DESERIALIZATION_PARSING: Unsafe deserialization, XXE, zip slip (6 specialists)
- FILE_SYSTEM: Path traversal, file upload, symlink attacks (4 specialists)
- AUTHN_SESSION: Auth bypass, session fixation, CSRF, OAuth, JWT (5 specialists)
- AUTHZ_BUSINESS_LOGIC: IDOR, privilege escalation, workflow bypass (5 specialists)
- CRYPTO_SECRETS: Crypto misuse, weak randomness, secrets exposure (4 specialists)
- INFRASTRUCTURE: Container, Kubernetes, CI/CD security (4 specialists)
- SUPPLY_CHAIN: Dependency confusion, plugin security (3 specialists)
- CONCURRENCY: Race conditions, resource exhaustion (2 specialists)
- DATA_EXPOSURE: Sensitive data exposure, tokens in URLs (2 specialists)
- API_DESIGN: Mass assignment, parameter pollution, GraphQL (3 specialists)

Usage:
    >>> from agents.deep_audit.specialists.registry import get_family_for_signal
    >>> family = get_family_for_signal(SignalCategory.SQL_INJECTION)
    >>> # family == SpecialistFamily.INJECTION

Adding a New Specialist:
1. Add SpecialistInfo to ALL_SPECIALISTS list
2. Map new SignalCategory to family in CATEGORY_TO_FAMILY dict
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Optional

from agents.deep_audit.foundation import SignalCategory


class SpecialistFamily(Enum):
    """14 specialist families for vulnerability verification."""
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
    """Information about a specialist agent."""
    id: str
    name: str
    family: SpecialistFamily
    triggers: list[SignalCategory]
    proficiency: str
    prompt_template: Optional[str] = None


# Mapping from SignalCategory to SpecialistFamily
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
    SignalCategory.PATH_TRAVERSAL: SpecialistFamily.FILE_SYSTEM,

    # Auth
    SignalCategory.AUTH_BYPASS: SpecialistFamily.AUTHN_SESSION,
    SignalCategory.SESSION_FIXATION: SpecialistFamily.AUTHN_SESSION,
    SignalCategory.CSRF: SpecialistFamily.AUTHN_SESSION,
    SignalCategory.IDOR: SpecialistFamily.AUTHZ_BUSINESS_LOGIC,
    SignalCategory.PRIVILEGE_ESCALATION: SpecialistFamily.AUTHZ_BUSINESS_LOGIC,

    # Crypto
    SignalCategory.CRYPTO_MISUSE: SpecialistFamily.CRYPTO_SECRETS,
    SignalCategory.WEAK_RANDOMNESS: SpecialistFamily.CRYPTO_SECRETS,
    SignalCategory.SECRETS_EXPOSURE: SpecialistFamily.CRYPTO_SECRETS,

    # Other
    SignalCategory.RACE_CONDITION: SpecialistFamily.CONCURRENCY,
    SignalCategory.RESOURCE_EXHAUSTION: SpecialistFamily.CONCURRENCY,
    SignalCategory.SENSITIVE_DATA_EXPOSURE: SpecialistFamily.DATA_EXPOSURE,
    SignalCategory.MASS_ASSIGNMENT: SpecialistFamily.API_DESIGN,

    # Generic - routes to API_DESIGN as catchall
    SignalCategory.UNKNOWN: SpecialistFamily.API_DESIGN,
}


# All 64 specialists organized by family
ALL_SPECIALISTS: list[SpecialistInfo] = [
    # Memory Safety (8)
    SpecialistInfo(
        id="oob_read_write_auditor",
        name="Out-of-Bounds Read/Write Auditor",
        family=SpecialistFamily.MEMORY_SAFETY,
        triggers=[SignalCategory.BUFFER_OVERFLOW],
        proficiency="Expert at identifying buffer overflows, heap/stack OOB reads and writes, and bounds-checking failures in C/C++/Rust unsafe code.",
    ),
    SpecialistInfo(
        id="use_after_free_auditor",
        name="Use-After-Free Auditor",
        family=SpecialistFamily.MEMORY_SAFETY,
        triggers=[SignalCategory.USE_AFTER_FREE],
        proficiency="Expert at detecting use-after-free vulnerabilities, dangling pointers, and object lifetime issues.",
    ),
    SpecialistInfo(
        id="double_free_auditor",
        name="Double-Free Auditor",
        family=SpecialistFamily.MEMORY_SAFETY,
        triggers=[SignalCategory.DOUBLE_FREE],
        proficiency="Expert at identifying double-free bugs and memory corruption from repeated deallocation.",
    ),
    SpecialistInfo(
        id="uninit_memory_auditor",
        name="Uninitialized Memory Auditor",
        family=SpecialistFamily.MEMORY_SAFETY,
        triggers=[SignalCategory.UNINITIALIZED_MEMORY],
        proficiency="Expert at finding uninitialized memory reads and information disclosure via memory remnants.",
    ),
    SpecialistInfo(
        id="integer_overflow_auditor",
        name="Integer Overflow Auditor",
        family=SpecialistFamily.MEMORY_SAFETY,
        triggers=[SignalCategory.INTEGER_OVERFLOW],
        proficiency="Expert at detecting integer overflows, underflows, and truncation that leads to security issues.",
    ),
    SpecialistInfo(
        id="format_string_auditor",
        name="Format String Auditor",
        family=SpecialistFamily.MEMORY_SAFETY,
        triggers=[SignalCategory.FORMAT_STRING],
        proficiency="Expert at identifying format string vulnerabilities in printf-family functions.",
    ),
    SpecialistInfo(
        id="type_confusion_auditor",
        name="Type Confusion Auditor",
        family=SpecialistFamily.MEMORY_SAFETY,
        triggers=[SignalCategory.TYPE_CONFUSION],
        proficiency="Expert at detecting type confusion vulnerabilities in C++, JavaScript, and other languages.",
    ),
    SpecialistInfo(
        id="unsafe_ffi_auditor",
        name="Unsafe FFI Auditor",
        family=SpecialistFamily.MEMORY_SAFETY,
        triggers=[SignalCategory.UNSAFE_FFI],
        proficiency="Expert at auditing unsafe foreign function interface calls between safe and unsafe code boundaries.",
    ),

    # Injection (10)
    SpecialistInfo(
        id="sql_injection_auditor",
        name="SQL Injection Auditor",
        family=SpecialistFamily.INJECTION,
        triggers=[SignalCategory.SQL_INJECTION],
        proficiency="Expert at detecting SQL injection via string concatenation, improper parameterization, and ORM bypasses.",
    ),
    SpecialistInfo(
        id="nosql_injection_auditor",
        name="NoSQL Injection Auditor",
        family=SpecialistFamily.INJECTION,
        triggers=[SignalCategory.NOSQL_INJECTION],
        proficiency="Expert at finding NoSQL injection in MongoDB, Redis, and other document/key-value stores.",
    ),
    SpecialistInfo(
        id="command_injection_auditor",
        name="Command Injection Auditor",
        family=SpecialistFamily.INJECTION,
        triggers=[SignalCategory.COMMAND_INJECTION],
        proficiency="Expert at detecting OS command injection via shell execution, subprocess calls, and system() invocations.",
    ),
    SpecialistInfo(
        id="template_injection_auditor",
        name="Template Injection Auditor",
        family=SpecialistFamily.INJECTION,
        triggers=[SignalCategory.TEMPLATE_INJECTION],
        proficiency="Expert at finding SSTI vulnerabilities in Jinja2, Freemarker, Velocity, and other template engines.",
    ),
    SpecialistInfo(
        id="expression_injection_auditor",
        name="Expression Injection Auditor",
        family=SpecialistFamily.INJECTION,
        triggers=[SignalCategory.EXPRESSION_INJECTION],
        proficiency="Expert at detecting EL injection, SpEL injection, and dynamic expression evaluation vulnerabilities.",
    ),
    SpecialistInfo(
        id="ldap_injection_auditor",
        name="LDAP Injection Auditor",
        family=SpecialistFamily.INJECTION,
        triggers=[SignalCategory.LDAP_INJECTION],
        proficiency="Expert at identifying LDAP injection in directory service queries and authentication flows.",
    ),
    SpecialistInfo(
        id="xpath_injection_auditor",
        name="XPath Injection Auditor",
        family=SpecialistFamily.INJECTION,
        triggers=[SignalCategory.XPATH_INJECTION],
        proficiency="Expert at detecting XPath injection in XML document queries.",
    ),
    SpecialistInfo(
        id="crlf_injection_auditor",
        name="CRLF Injection Auditor",
        family=SpecialistFamily.INJECTION,
        triggers=[SignalCategory.CRLF_INJECTION],
        proficiency="Expert at finding HTTP header injection and response splitting via CRLF sequences.",
    ),
    SpecialistInfo(
        id="log_injection_auditor",
        name="Log Injection Auditor",
        family=SpecialistFamily.INJECTION,
        triggers=[SignalCategory.LOG_INJECTION],
        proficiency="Expert at detecting log injection and log forging vulnerabilities that enable log poisoning.",
    ),
    SpecialistInfo(
        id="email_injection_auditor",
        name="Email Injection Auditor",
        family=SpecialistFamily.INJECTION,
        triggers=[SignalCategory.EMAIL_INJECTION],
        proficiency="Expert at identifying email header injection for spam relay and phishing attacks.",
    ),

    # Web Edge Cases (4)
    SpecialistInfo(
        id="ssrf_auditor",
        name="SSRF Auditor",
        family=SpecialistFamily.WEB_EDGE_CASES,
        triggers=[SignalCategory.SSRF],
        proficiency="Expert at detecting server-side request forgery including DNS rebinding, protocol smuggling, and cloud metadata access.",
    ),
    SpecialistInfo(
        id="request_smuggling_auditor",
        name="Request Smuggling Auditor",
        family=SpecialistFamily.WEB_EDGE_CASES,
        triggers=[SignalCategory.REQUEST_SMUGGLING],
        proficiency="Expert at finding HTTP request smuggling via CL.TE, TE.CL, and HTTP/2 desync attacks.",
    ),
    SpecialistInfo(
        id="cache_poisoning_auditor",
        name="Cache Poisoning Auditor",
        family=SpecialistFamily.WEB_EDGE_CASES,
        triggers=[SignalCategory.CACHE_POISONING],
        proficiency="Expert at detecting web cache poisoning and deception attacks.",
    ),
    SpecialistInfo(
        id="host_header_auditor",
        name="Host Header Injection Auditor",
        family=SpecialistFamily.WEB_EDGE_CASES,
        triggers=[SignalCategory.HOST_HEADER_INJECTION],
        proficiency="Expert at identifying Host header injection for password reset poisoning and cache poisoning.",
    ),

    # Browser/Client (4)
    SpecialistInfo(
        id="xss_auditor",
        name="XSS Auditor",
        family=SpecialistFamily.BROWSER_CLIENT,
        triggers=[SignalCategory.XSS],
        proficiency="Expert at detecting reflected, stored, and DOM-based XSS including mutation XSS and filter bypasses.",
    ),
    SpecialistInfo(
        id="prototype_pollution_auditor",
        name="Prototype Pollution Auditor",
        family=SpecialistFamily.BROWSER_CLIENT,
        triggers=[SignalCategory.PROTOTYPE_POLLUTION],
        proficiency="Expert at finding prototype pollution in JavaScript via __proto__, constructor, and Object.assign patterns.",
    ),
    SpecialistInfo(
        id="clickjacking_auditor",
        name="Clickjacking Auditor",
        family=SpecialistFamily.BROWSER_CLIENT,
        triggers=[SignalCategory.CLICKJACKING],
        proficiency="Expert at detecting clickjacking vulnerabilities and missing frame-busting protections.",
    ),
    SpecialistInfo(
        id="csp_auditor",
        name="CSP Auditor",
        family=SpecialistFamily.BROWSER_CLIENT,
        triggers=[SignalCategory.XSS],  # CSP issues often relate to XSS
        proficiency="Expert at auditing Content Security Policy configurations for bypasses and weaknesses.",
    ),

    # Deserialization/Parsing (6)
    SpecialistInfo(
        id="unsafe_deser_auditor",
        name="Unsafe Deserialization Auditor",
        family=SpecialistFamily.DESERIALIZATION_PARSING,
        triggers=[SignalCategory.UNSAFE_DESERIALIZATION],
        proficiency="Expert at detecting insecure deserialization in Java, PHP, Python pickle, .NET, and Ruby.",
    ),
    SpecialistInfo(
        id="parser_differential_auditor",
        name="Parser Differential Auditor",
        family=SpecialistFamily.DESERIALIZATION_PARSING,
        triggers=[SignalCategory.UNSAFE_DESERIALIZATION],
        proficiency="Expert at finding parser differential vulnerabilities where different components parse data differently.",
    ),
    SpecialistInfo(
        id="xxe_auditor",
        name="XXE Auditor",
        family=SpecialistFamily.DESERIALIZATION_PARSING,
        triggers=[SignalCategory.XXE],
        proficiency="Expert at detecting XML External Entity injection including blind XXE and parameter entity attacks.",
    ),
    SpecialistInfo(
        id="zip_slip_auditor",
        name="Zip Slip Auditor",
        family=SpecialistFamily.DESERIALIZATION_PARSING,
        triggers=[SignalCategory.ZIP_SLIP],
        proficiency="Expert at finding archive extraction vulnerabilities (zip slip) allowing path traversal during extraction.",
    ),
    SpecialistInfo(
        id="redos_auditor",
        name="ReDoS Auditor",
        family=SpecialistFamily.DESERIALIZATION_PARSING,
        triggers=[SignalCategory.REDOS],
        proficiency="Expert at detecting Regular Expression Denial of Service via catastrophic backtracking.",
    ),
    SpecialistInfo(
        id="file_parser_auditor",
        name="File Parser Auditor",
        family=SpecialistFamily.DESERIALIZATION_PARSING,
        triggers=[SignalCategory.UNSAFE_DESERIALIZATION],
        proficiency="Expert at auditing file format parsers (PDF, image, office) for memory corruption and code execution.",
    ),

    # File System (4)
    SpecialistInfo(
        id="path_traversal_auditor",
        name="Path Traversal Auditor",
        family=SpecialistFamily.FILE_SYSTEM,
        triggers=[SignalCategory.PATH_TRAVERSAL],
        proficiency="Expert at detecting directory traversal and local file inclusion vulnerabilities.",
    ),
    SpecialistInfo(
        id="file_upload_auditor",
        name="File Upload Auditor",
        family=SpecialistFamily.FILE_SYSTEM,
        triggers=[SignalCategory.PATH_TRAVERSAL],
        proficiency="Expert at finding unrestricted file upload vulnerabilities enabling code execution.",
    ),
    SpecialistInfo(
        id="symlink_toctou_auditor",
        name="Symlink/TOCTOU Auditor",
        family=SpecialistFamily.FILE_SYSTEM,
        triggers=[SignalCategory.RACE_CONDITION, SignalCategory.PATH_TRAVERSAL],
        proficiency="Expert at detecting symlink attacks and time-of-check to time-of-use race conditions.",
    ),
    SpecialistInfo(
        id="temp_file_auditor",
        name="Temp File Auditor",
        family=SpecialistFamily.FILE_SYSTEM,
        triggers=[SignalCategory.PATH_TRAVERSAL, SignalCategory.RACE_CONDITION],
        proficiency="Expert at finding insecure temporary file creation leading to privilege escalation.",
    ),

    # AuthN/Session (5)
    SpecialistInfo(
        id="authn_bypass_auditor",
        name="Authentication Bypass Auditor",
        family=SpecialistFamily.AUTHN_SESSION,
        triggers=[SignalCategory.AUTH_BYPASS],
        proficiency="Expert at detecting authentication bypass via logic flaws, default credentials, and broken authentication.",
    ),
    SpecialistInfo(
        id="session_mgmt_auditor",
        name="Session Management Auditor",
        family=SpecialistFamily.AUTHN_SESSION,
        triggers=[SignalCategory.SESSION_FIXATION],
        proficiency="Expert at finding session fixation, session hijacking, and insecure session token generation.",
    ),
    SpecialistInfo(
        id="csrf_auditor",
        name="CSRF Auditor",
        family=SpecialistFamily.AUTHN_SESSION,
        triggers=[SignalCategory.CSRF],
        proficiency="Expert at detecting cross-site request forgery and token bypass techniques.",
    ),
    SpecialistInfo(
        id="oauth_auditor",
        name="OAuth Auditor",
        family=SpecialistFamily.AUTHN_SESSION,
        triggers=[SignalCategory.AUTH_BYPASS],
        proficiency="Expert at finding OAuth/OIDC misconfigurations including redirect_uri bypass and token leakage.",
    ),
    SpecialistInfo(
        id="jwt_auditor",
        name="JWT Auditor",
        family=SpecialistFamily.AUTHN_SESSION,
        triggers=[SignalCategory.AUTH_BYPASS, SignalCategory.CRYPTO_MISUSE],
        proficiency="Expert at detecting JWT vulnerabilities including algorithm confusion, key confusion, and signature bypass.",
    ),

    # AuthZ/Business Logic (5)
    SpecialistInfo(
        id="idor_auditor",
        name="IDOR Auditor",
        family=SpecialistFamily.AUTHZ_BUSINESS_LOGIC,
        triggers=[SignalCategory.IDOR],
        proficiency="Expert at finding Insecure Direct Object Reference vulnerabilities in API endpoints.",
    ),
    SpecialistInfo(
        id="priv_esc_auditor",
        name="Privilege Escalation Auditor",
        family=SpecialistFamily.AUTHZ_BUSINESS_LOGIC,
        triggers=[SignalCategory.PRIVILEGE_ESCALATION],
        proficiency="Expert at detecting horizontal and vertical privilege escalation via authorization flaws.",
    ),
    SpecialistInfo(
        id="multi_tenant_auditor",
        name="Multi-Tenant Isolation Auditor",
        family=SpecialistFamily.AUTHZ_BUSINESS_LOGIC,
        triggers=[SignalCategory.IDOR, SignalCategory.PRIVILEGE_ESCALATION],
        proficiency="Expert at finding tenant isolation failures in multi-tenant SaaS applications.",
    ),
    SpecialistInfo(
        id="workflow_bypass_auditor",
        name="Workflow Bypass Auditor",
        family=SpecialistFamily.AUTHZ_BUSINESS_LOGIC,
        triggers=[SignalCategory.AUTH_BYPASS, SignalCategory.PRIVILEGE_ESCALATION],
        proficiency="Expert at detecting business logic flaws that allow skipping workflow steps or state transitions.",
    ),
    SpecialistInfo(
        id="rate_limit_auditor",
        name="Rate Limit Bypass Auditor",
        family=SpecialistFamily.AUTHZ_BUSINESS_LOGIC,
        triggers=[SignalCategory.RESOURCE_EXHAUSTION],
        proficiency="Expert at finding rate limiting bypasses for brute force and resource abuse.",
    ),

    # Crypto/Secrets (4)
    SpecialistInfo(
        id="crypto_misuse_auditor",
        name="Crypto Misuse Auditor",
        family=SpecialistFamily.CRYPTO_SECRETS,
        triggers=[SignalCategory.CRYPTO_MISUSE],
        proficiency="Expert at detecting weak ciphers, improper modes, padding oracle, and cryptographic implementation flaws.",
    ),
    SpecialistInfo(
        id="randomness_auditor",
        name="Randomness Auditor",
        family=SpecialistFamily.CRYPTO_SECRETS,
        triggers=[SignalCategory.WEAK_RANDOMNESS],
        proficiency="Expert at finding weak PRNG usage, predictable tokens, and insufficient entropy.",
    ),
    SpecialistInfo(
        id="secrets_handling_auditor",
        name="Secrets Handling Auditor",
        family=SpecialistFamily.CRYPTO_SECRETS,
        triggers=[SignalCategory.SECRETS_EXPOSURE],
        proficiency="Expert at detecting hardcoded secrets, insecure secret storage, and secrets in logs/URLs.",
    ),
    SpecialistInfo(
        id="tls_auditor",
        name="TLS Configuration Auditor",
        family=SpecialistFamily.CRYPTO_SECRETS,
        triggers=[SignalCategory.CRYPTO_MISUSE],
        proficiency="Expert at auditing TLS/SSL configurations for weak protocols, ciphers, and certificate issues.",
    ),

    # Infrastructure (4)
    SpecialistInfo(
        id="insecure_config_auditor",
        name="Insecure Configuration Auditor",
        family=SpecialistFamily.INFRASTRUCTURE,
        triggers=[SignalCategory.SECRETS_EXPOSURE],
        proficiency="Expert at finding security misconfigurations in application and infrastructure settings.",
    ),
    SpecialistInfo(
        id="container_auditor",
        name="Container Security Auditor",
        family=SpecialistFamily.INFRASTRUCTURE,
        triggers=[SignalCategory.PRIVILEGE_ESCALATION],
        proficiency="Expert at detecting Docker/container security issues including escape vectors and privileged containers.",
    ),
    SpecialistInfo(
        id="k8s_auditor",
        name="Kubernetes Security Auditor",
        family=SpecialistFamily.INFRASTRUCTURE,
        triggers=[SignalCategory.PRIVILEGE_ESCALATION, SignalCategory.SECRETS_EXPOSURE],
        proficiency="Expert at finding Kubernetes misconfigurations, RBAC issues, and pod security violations.",
    ),
    SpecialistInfo(
        id="cicd_auditor",
        name="CI/CD Security Auditor",
        family=SpecialistFamily.INFRASTRUCTURE,
        triggers=[SignalCategory.COMMAND_INJECTION, SignalCategory.SECRETS_EXPOSURE],
        proficiency="Expert at detecting CI/CD pipeline vulnerabilities including poisoned pipelines and secrets exposure.",
    ),

    # Supply Chain (3)
    SpecialistInfo(
        id="dependency_risk_auditor",
        name="Dependency Risk Auditor",
        family=SpecialistFamily.SUPPLY_CHAIN,
        triggers=[SignalCategory.UNKNOWN],
        proficiency="Expert at assessing dependency vulnerabilities and transitive risk in package ecosystems.",
    ),
    SpecialistInfo(
        id="dependency_confusion_auditor",
        name="Dependency Confusion Auditor",
        family=SpecialistFamily.SUPPLY_CHAIN,
        triggers=[SignalCategory.UNKNOWN],
        proficiency="Expert at detecting dependency confusion and namespace hijacking attacks.",
    ),
    SpecialistInfo(
        id="plugin_auditor",
        name="Plugin/Extension Auditor",
        family=SpecialistFamily.SUPPLY_CHAIN,
        triggers=[SignalCategory.UNKNOWN],
        proficiency="Expert at auditing plugin systems and extension mechanisms for sandbox escapes.",
    ),

    # Concurrency (2)
    SpecialistInfo(
        id="race_condition_auditor",
        name="Race Condition Auditor",
        family=SpecialistFamily.CONCURRENCY,
        triggers=[SignalCategory.RACE_CONDITION],
        proficiency="Expert at detecting race conditions, TOCTOU, and double-spend vulnerabilities.",
    ),
    SpecialistInfo(
        id="dos_auditor",
        name="DoS/Resource Exhaustion Auditor",
        family=SpecialistFamily.CONCURRENCY,
        triggers=[SignalCategory.RESOURCE_EXHAUSTION],
        proficiency="Expert at finding denial of service vectors including algorithmic complexity and resource exhaustion.",
    ),

    # Data Exposure (2)
    SpecialistInfo(
        id="sensitive_data_auditor",
        name="Sensitive Data Exposure Auditor",
        family=SpecialistFamily.DATA_EXPOSURE,
        triggers=[SignalCategory.SENSITIVE_DATA_EXPOSURE],
        proficiency="Expert at detecting PII leakage, verbose errors, and unintended data exposure.",
    ),
    SpecialistInfo(
        id="token_in_url_auditor",
        name="Token in URL Auditor",
        family=SpecialistFamily.DATA_EXPOSURE,
        triggers=[SignalCategory.SENSITIVE_DATA_EXPOSURE, SignalCategory.SECRETS_EXPOSURE],
        proficiency="Expert at finding sensitive tokens in URLs, referrer leakage, and history/cache exposure.",
    ),

    # API Design (3)
    SpecialistInfo(
        id="mass_assignment_auditor",
        name="Mass Assignment Auditor",
        family=SpecialistFamily.API_DESIGN,
        triggers=[SignalCategory.MASS_ASSIGNMENT],
        proficiency="Expert at detecting mass assignment and auto-binding vulnerabilities in frameworks.",
    ),
    SpecialistInfo(
        id="param_pollution_auditor",
        name="Parameter Pollution Auditor",
        family=SpecialistFamily.API_DESIGN,
        triggers=[SignalCategory.MASS_ASSIGNMENT],
        proficiency="Expert at finding HTTP parameter pollution and array parameter abuse.",
    ),
    SpecialistInfo(
        id="graphql_auditor",
        name="GraphQL Security Auditor",
        family=SpecialistFamily.API_DESIGN,
        triggers=[SignalCategory.IDOR, SignalCategory.RESOURCE_EXHAUSTION],
        proficiency="Expert at auditing GraphQL APIs for introspection leaks, batching abuse, and authorization bypass.",
    ),
]


class SpecialistRegistry:
    """Registry for accessing specialist information."""

    def __init__(self) -> None:
        self._by_id: dict[str, SpecialistInfo] = {s.id: s for s in ALL_SPECIALISTS}
        self._by_family: dict[SpecialistFamily, list[SpecialistInfo]] = {}
        for specialist in ALL_SPECIALISTS:
            if specialist.family not in self._by_family:
                self._by_family[specialist.family] = []
            self._by_family[specialist.family].append(specialist)

    @property
    def all_specialists(self) -> list[SpecialistInfo]:
        """Return all registered specialists."""
        return ALL_SPECIALISTS

    def get_by_id(self, specialist_id: str) -> Optional[SpecialistInfo]:
        """Get a specialist by its ID."""
        return self._by_id.get(specialist_id)

    def get_by_family(self, family: SpecialistFamily) -> list[SpecialistInfo]:
        """Get all specialists in a family."""
        return self._by_family.get(family, [])

    def get_for_category(self, category: SignalCategory) -> list[SpecialistInfo]:
        """Get all specialists that handle a given signal category."""
        return [s for s in ALL_SPECIALISTS if category in s.triggers]

    def find_best_specialist_for_category(self, category_str: str) -> Optional[SpecialistInfo]:
        """Fuzzy-match a category string to the best specialist.

        Used as fallback when SignalCategory enum parsing fails.
        Tries matching against specialist IDs and proficiency descriptions.

        Args:
            category_str: Normalized category string (lowercase, underscored)

        Returns:
            Best matching SpecialistInfo or None
        """
        # Try matching against specialist IDs first (most specific)
        for specialist in ALL_SPECIALISTS:
            if category_str in specialist.id or specialist.id.replace("_auditor", "") in category_str:
                return specialist
        # Try matching against proficiency descriptions (broader)
        for specialist in ALL_SPECIALISTS:
            if category_str.replace("_", " ") in specialist.proficiency.lower():
                return specialist
        return None


def get_family_for_signal(category: SignalCategory) -> SpecialistFamily:
    """
    Get the specialist family responsible for a signal category.

    Used by the Decider to route signals to the correct family.
    """
    return CATEGORY_TO_FAMILY.get(category, SpecialistFamily.API_DESIGN)


def get_specialists_for_signal(category: SignalCategory) -> list[str]:
    """
    Get specialist IDs that handle a given signal category.

    Used by Family Coordinators to assign specific specialists.
    """
    return [s.id for s in ALL_SPECIALISTS if category in s.triggers]
