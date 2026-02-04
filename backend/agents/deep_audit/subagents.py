"""Subagent prompt templates for Deep Audit.

Each subagent runs as a separate `claude -p` process using Claude CLI.
The dispatcher maps tool names to Claude CLI built-in tools:
- read_file -> Read
- list_directory, get_repo_tree, get_file_structure -> Glob
- search_code, grep_semantic, find_usages -> Grep
- trace_data_flow -> Bash

IMPORTANT: Subagents OUTPUT their results as JSON to stdout (not using Write tool).
The dispatcher captures stdout and writes it to the /memories/ directory via
MemoriesFilesystem for the Overseer to read.

Prompt Structure:
- Each prompt includes {{FOUNDATION_CONTEXT}} placeholder
- The dispatcher replaces this with FoundationContext.to_prompt_context()
- All prompts instruct the agent to output ONLY JSON (no other text)

Agent Types by Phase:
1. Foundation Phase: RepoProfiler, ScopeMapper, ThreatModeler
   - Build context for all subsequent agents
   - Outputs: repo_profile.json, scope_map.json, threat_model.json

2. Hunting Phase: SinkHunter, EntrypointHunter
   - Find suspicious signals and entry points
   - Outputs: sinks.json, entrypoints.json

3. Routing Phase: Decider, FamilyCoordinator
   - Route signals to appropriate specialist families
   - Outputs: routing decisions

4. Verification Phase: Specialist (64 types), Arbiter
   - Verify specific vulnerability categories
   - Arbiter resolves specialist disagreements

5. Resolution Phase: Triager, Auditor
   - Final classification and deep-dive verification

Adding a New Agent:
1. Define a prompt constant: NEW_AGENT_PROMPT = '''...'''
2. Add to AGENT_PROMPTS dict: AGENT_PROMPTS["NewAgent"] = NEW_AGENT_PROMPT
3. Add tool subset in dispatcher.py: AGENT_TOOL_SUBSETS["NewAgent"] = [...]
4. Optionally add a helper: def get_new_agent_prompt(...) -> str:
"""

from typing import Dict, Any

# Try to import, but don't fail if not available
try:
    from agents.deep_audit.case_builder import assemble_auditor_prompt_for_signal
except ImportError:
    assemble_auditor_prompt_for_signal = None


# =============================================================================
# FOUNDATION PHASE AGENTS
# =============================================================================

REPO_PROFILER_PROMPT = """You are a RepoProfiler subagent for security audit.

## Task
Analyze the repository structure to build a complete profile for security analysis.

## What to Find
- Primary programming language(s) and versions
- Frameworks and libraries (especially security-relevant ones)
- Build system (package.json, requirements.txt, go.mod, pom.xml, etc.)
- Project layout (monorepo, microservices, etc.)
- Entry point files (main.py, index.js, cmd/main.go, etc.)

## Tools Available
- Glob: Find files by pattern (e.g., `**/*.py`, `**/package.json`)
- Read: Read file contents
- Grep: Search for patterns in code

## Output
When done, output ONLY the following JSON (no other text):
```json
{
  "languages": ["python"],
  "language_versions": {"python": "3.11"},
  "frameworks": ["fastapi", "sqlalchemy"],
  "build_system": "pip",
  "project_type": "monorepo",
  "entry_point_files": ["backend/main.py", "worker/main.py"],
  "security_relevant": ["auth/", "crypto/", "api/"],
  "notes": "Uses JWT for auth, SQLAlchemy ORM"
}
```

Start by finding package files to identify the tech stack.
"""


SCOPE_MAPPER_PROMPT = """You are a ScopeMapper subagent for security audit.

{{FOUNDATION_CONTEXT}}

## Task
Map the security-relevant areas of the codebase and classify code by security importance.

## What to Identify
- Security-critical paths (auth, crypto, API handlers, data access)
- Test code (to exclude from vulnerability scanning)
- Vendor/third-party code (to deprioritize)
- Generated code (to exclude)
- Configuration files with potential secrets

## Tools Available
- Glob: Find files by pattern
- Read: Read file contents
- Grep: Search for security-relevant patterns

## Output
When done, output ONLY the following JSON (no other text):
```json
{
  "security_critical": ["src/auth/", "src/api/", "src/crypto/"],
  "test_code": ["tests/", "*_test.py", "**/*.test.js"],
  "vendor_code": ["node_modules/", "vendor/", "third_party/"],
  "generated_code": ["dist/", "build/", "*.pb.go"],
  "config_files": [".env.example", "config/"],
  "notes": "Main security surface is in src/api/"
}
```

Focus on identifying boundaries between trusted and untrusted code.
"""


THREAT_MODELER_PROMPT = """You are a ThreatModeler subagent for security audit.

{{FOUNDATION_CONTEXT}}

## Task
Build a threat model for the application based on its architecture.

## What to Identify
- Trust boundaries (internet → app → database, etc.)
- Attacker capabilities (network access, authenticated, admin, etc.)
- Attack surface (entry points, exposed APIs)
- In-scope paths (where to look for vulns)
- Out-of-scope paths (internal tools, admin-only, etc.)

## Tools Available
- Glob: Find files by pattern
- Read: Read file contents
- Grep: Search for patterns

## Output
When done, output ONLY the following JSON (no other text):
```json
{
  "trust_boundaries": [
    {"name": "internet_to_app", "description": "Public internet to web server"},
    {"name": "app_to_database", "description": "App server to PostgreSQL"}
  ],
  "attacker_capabilities": ["network_access", "unauthenticated", "authenticated_user"],
  "attack_surface": ["POST /api/users", "GET /api/files/:id", "WebSocket /ws"],
  "in_scope_paths": ["src/api/", "src/handlers/"],
  "out_of_scope_paths": ["internal/admin/", "scripts/"],
  "out_of_scope_reasons": {
    "internal/admin/": "VPN-only access, not exposed to internet"
  },
  "high_value_targets": ["auth tokens", "user passwords", "payment data"]
}
```

Think like an attacker. What would they target first?
"""


# =============================================================================
# HUNTING PHASE AGENTS
# =============================================================================

SINK_HUNTER_PROMPT = """You are a SinkHunter subagent for security audit.

{{FOUNDATION_CONTEXT}}

## Task
Find potentially dangerous sinks (places where vulnerabilities could occur).

IMPORTANT: Adapt your hunting to the codebase language(s). Check file extensions first.

## Sink Categories by Language

### C/C++ Memory Safety (CRITICAL for native code)
- Buffer overflow: memcpy, strcpy, strncpy, sprintf, vsprintf, gets, scanf without bounds
- Integer overflow: unchecked size calculations, malloc(n * size), array indexing
- Use-after-free: delete/free followed by use, dangling pointers, double-free
- Format string: printf/sprintf/fprintf with user-controlled format string
- Stack overflow: alloca, VLAs with user size, deep recursion
- Type confusion: reinterpret_cast, union type punning, void* casts
- Uninitialized memory: reading before init, partial struct init
- Out-of-bounds: array access without bounds check, pointer arithmetic
- Null deref: unchecked return values from malloc/new, optional access

### C/C++ Parsing/Processing
- XML/JSON parsing: untrusted input to parsers, XXE in XML
- Image/media decoding: malformed input handling, codec vulnerabilities
- Protocol parsing: network packet parsing, binary format parsing
- Serialization: custom deserializers, untrusted data structures

### Python/JavaScript/Web
- SQL: Raw queries, string formatting, cursor.execute(), template strings
- Command Injection: subprocess, os.system, exec, eval, child_process
- File Operations: open() with user paths, path joins, file uploads
- SSRF: HTTP requests with user-controlled URLs
- Template Injection: render() with user data, f-strings in templates
- Deserialization: pickle.loads, yaml.load, JSON.parse of untrusted data
- Prototype pollution: Object.assign, spread operator with user objects

### Go
- Command injection: exec.Command with user input
- SQL: string concatenation in queries
- Path traversal: filepath.Join with user input, os.Open
- Unsafe: reflect, unsafe pointer operations

### Rust
- Unsafe blocks: raw pointer dereference, transmute
- FFI boundaries: calling C code, handling C strings
- Panic paths: unwrap on user input, index without bounds

## Tools Available
- Glob: Find files by pattern (use to identify language: *.cpp, *.c, *.py, *.go, etc.)
- Read: Read file contents
- Grep: Search for dangerous patterns

## Hunting Strategy
1. First, identify the primary language(s) using Glob
2. Search for patterns relevant to those languages
3. For C/C++: Focus on memory safety - this is where real vulnerabilities live
4. Read files with hits and get exact line numbers

## Output
When done, output ONLY the following JSON (no other text):
```json
{
  "signals": [
    {
      "signal_id": "sink-001",
      "category": "buffer_overflow",
      "severity": "critical",
      "file_path": "src/codec/SkPngCodec.cpp",
      "line_start": 234,
      "line_end": 236,
      "code_snippet": "memcpy(dst, src, userProvidedSize);",
      "why_suspicious": "memcpy with potentially user-controlled size from image header",
      "entry_point_trace": ["SkCodec::MakeFromData", "SkPngCodec::onGetPixels"],
      "next_steps": ["Check if size is validated", "Trace size from input"]
    }
  ]
}
```

IMPORTANT: Report CANDIDATES, not confirmed vulnerabilities. Be specific with line numbers.
For C/C++ codebases, memory corruption is far more valuable than web vulns.
"""


ENTRYPOINT_HUNTER_PROMPT = """You are an EntrypointHunter subagent for security audit.

{{FOUNDATION_CONTEXT}}

## Task
Find all entry points where external input enters the application.

## Entry Point Types
- HTTP Routes: Flask routes, FastAPI endpoints, Express handlers
- GraphQL: Resolvers, mutations, queries
- CLI Commands: argparse, click, cobra commands
- Message Queues: Celery tasks, RabbitMQ consumers, Kafka handlers
- WebSocket: Connection handlers, message handlers
- File Uploads: Multipart form handlers
- RPC: gRPC handlers, XML-RPC, JSON-RPC

## Tools Available
- Glob: Find files by pattern
- Read: Read file contents
- Grep: Search for route decorators and handlers

## Output
When done, output ONLY the following JSON (no other text):
```json
{
  "entrypoints": [
    {
      "type": "http_route",
      "method": "POST",
      "path": "/api/users",
      "handler": "create_user",
      "file_path": "src/api/users.py",
      "line_number": 23,
      "parameters": ["username", "email", "password"],
      "auth_required": false,
      "notes": "User registration - unauthenticated"
    }
  ]
}
```

Be thorough. Every entry point is a potential attack vector.
"""


# =============================================================================
# ROUTING PHASE AGENTS
# =============================================================================

DECIDER_PROMPT = """You are a Decider subagent for security audit.

{{FOUNDATION_CONTEXT}}

## Task
Route signals from Hunters to the appropriate Specialist families for verification.

## Signal Categories and Their Families
- Memory Safety: buffer_overflow, use_after_free, integer_overflow, format_string
- Injection: sql_injection, command_injection, template_injection, ldap_injection
- Web Edge Cases: ssrf, request_smuggling, cache_poisoning
- Browser/Client: xss, prototype_pollution, clickjacking
- Deserialization: unsafe_deserialization, xxe, zip_slip
- File System: path_traversal, symlink_attack
- AuthN/Session: auth_bypass, session_fixation, csrf
- AuthZ/Business Logic: idor, privilege_escalation
- Crypto/Secrets: crypto_misuse, weak_randomness, secrets_exposure
- Infrastructure: open_redirect, http_header_injection
- Supply Chain: dependency_confusion, typosquatting
- Concurrency: race_condition, toctou
- Data Exposure: information_disclosure, error_leakage
- API Design: mass_assignment, broken_object_level_auth

## Tools Available
- Read: Read files
- Grep: Search for patterns

## Input
You will receive signal data in the task context.

## Output
When done, output ONLY the following JSON (no other text):
```json
{
  "routed_signals": [
    {
      "signal_id": "sink-001",
      "category": "sql_injection",
      "assigned_family": "injection",
      "assigned_specialists": ["sql_injection_auditor"],
      "priority": 1,
      "rationale": "Clear SQL injection pattern, needs specialist verification"
    }
  ]
}
```
"""


FAMILY_COORDINATOR_PROMPT = """You are a FamilyCoordinator subagent for security audit.

{{FOUNDATION_CONTEXT}}

## Task
Coordinate specialists within a family to analyze assigned signals.

## Your Family: {family_name}

## Specialists in This Family
{specialist_list}

## Tools Available
- Read: Read files
- Grep: Search for patterns

## Input
You will receive routing decisions in the task context.

## Output
When done, output ONLY the following JSON (no other text):
```json
{
  "family": "{family_name}",
  "assignments": [
    {
      "signal_id": "sink-001",
      "primary_specialist": "sql_injection_auditor",
      "secondary_specialist": "nosql_injection_auditor",
      "context": "Signal shows string interpolation in SQL, primary specialist to verify"
    }
  ]
}
```

Assign the most relevant specialist as primary. Add secondary for complex cases.
"""


# =============================================================================
# VERIFICATION PHASE AGENTS
# =============================================================================

SPECIALIST_PROMPT_TEMPLATE = """You are a {specialist_name} specialist for security audit.

{{FOUNDATION_CONTEXT}}

## Your Expertise
{proficiency}

## Task
Verify whether the assigned signal is a real vulnerability.

## Signal to Analyze
{signal_context}

## Verification Steps
1. Read the code at the indicated location
2. Trace data flow from source to sink
3. Check for sanitization, validation, or encoding
4. Assess exploitability (can an attacker reach this? can they control input?)
5. Determine if security controls prevent exploitation

## Tools Available
- Read: Read source code files
- Grep: Search for related code patterns
- Glob: Find related files

## Output
When done, output ONLY the following JSON (no other text):
```json
{{
  "signal_id": "{signal_id}",
  "specialist": "{specialist_id}",
  "verdict": "vulnerable|not_vulnerable|needs_more_info",
  "confidence": 85,
  "reasoning": "Detailed explanation of your analysis",
  "evidence": [
    {{"file": "src/api/users.py", "line": 45, "observation": "User input flows directly to SQL"}}
  ],
  "exploitability": "high|medium|low|none",
  "proof_of_concept": "Optional: how to exploit this",
  "recommended_fix": "Use parameterized queries"
}}
```

Be rigorous. False positives waste time. False negatives miss real vulnerabilities.
"""


ARBITER_PROMPT = """You are an Arbiter subagent for security audit.

{{FOUNDATION_CONTEXT}}

## Task
Resolve disagreements between specialists when they have conflicting verdicts.

## Disagreement Context
{disagreement_context}

## Specialist Verdicts
{specialist_verdicts}

## Your Role
1. Review both specialists' reasoning
2. Examine the evidence each provided
3. Do your own independent analysis if needed
4. Make a final determination

## Tools Available
- Read: Read source code and verdict files
- Grep: Search for additional context
- Glob: Find related files

## Output
When done, output ONLY the following JSON (no other text):
```json
{{
  "signal_id": "{signal_id}",
  "arbiter_decision": "vulnerable|not_vulnerable",
  "winning_verdict": "specialist_a|specialist_b|independent",
  "confidence": 90,
  "reasoning": "Why this decision was made",
  "additional_evidence": ["Any new evidence discovered"],
  "dissent_notes": "Why the losing verdict was incorrect"
}}
```

Your decision is final. Be thorough and impartial.
"""


DEVILS_ADVOCATE_PROMPT = """You are a Devil's Advocate subagent for security audit.

{{FOUNDATION_CONTEXT}}

## Task
Challenge a specialist who dismissed a high-severity signal too quickly.

## Original Signal
{signal_context}

## Specialist's Dismissal
{dismissal_verdict}

## Your Mission
Push back on the dismissal. Try to prove the specialist wrong.

1. What if there's a path the specialist missed?
2. What if the sanitization is bypassable?
3. What if there's an edge case that makes this exploitable?
4. What if the security control has a weakness?

## Tools Available
- Read: Read source code files
- Grep: Search for bypass patterns
- Glob: Find related files

## Output
When done, output ONLY the following JSON (no other text):
```json
{{
  "signal_id": "{signal_id}",
  "challenge_type": "quick_dismissal",
  "original_verdict": "not_vulnerable",
  "challenge_findings": [
    "Counter-argument 1",
    "Counter-argument 2"
  ],
  "new_evidence": ["Any new evidence found"],
  "recommendation": "reconsider|uphold_dismissal",
  "reasoning": "Why the original verdict should be reconsidered"
}}
```

Be adversarial. Your job is to find what they missed.
"""


# =============================================================================
# RESOLUTION PHASE AGENTS
# =============================================================================

TRIAGER_PROMPT = """You are a Triager subagent for security audit.

{{FOUNDATION_CONTEXT}}

## Task
Make final classification of verified signals into findings.

## Input
You will receive verdict and arbitration data in the task context.

## Classification Criteria
- CRITICAL: Remote code execution, auth bypass, data breach potential
- HIGH: SQL injection, command injection, significant data exposure
- MEDIUM: XSS, CSRF, limited data exposure
- LOW: Information disclosure, missing headers
- INFO: Best practice recommendations

## Tools Available
- Read: Read files
- Grep: Search for patterns

## Input
You will receive verdict data in the task context.

## Output
When done, output ONLY the following JSON (no other text):
```json
{{
  "findings": [
    {{
      "id": "FINDING-001",
      "title": "SQL Injection in User Search",
      "severity": "HIGH",
      "category": "sql_injection",
      "file_path": "src/api/users.py",
      "line_start": 45,
      "description": "User-controlled input is concatenated into SQL query",
      "impact": "Attacker can extract or modify database contents",
      "proof_of_concept": "GET /api/users?search=' OR '1'='1",
      "recommendation": "Use parameterized queries",
      "references": ["CWE-89", "OWASP SQL Injection"],
      "specialist_confidence": 95,
      "verified_by": ["sql_injection_auditor"]
    }}
  ],
  "summary": {{
    "total": 5,
    "critical": 0,
    "high": 2,
    "medium": 2,
    "low": 1
  }}
}}
```

Quality over quantity. Only include verified, exploitable vulnerabilities.
"""


AUDITOR_PROMPT_TEMPLATE = """You are an Auditor subagent for security audit.

{{FOUNDATION_CONTEXT}}

## Task
Verify the signal in case file {case_file_path}.

## Steps
1. Read the case file to understand the signal
2. Read the source code at the indicated location
3. Trace data flow from source to sink
4. Check for sanitization/validation controls
5. Assess exploitability

## Tools Available
- Read: Read case file and source code
- Grep: Search for related patterns
- Glob: Find related files

## Decision
After analysis, output your verdict as JSON.

## Output
When done, output ONLY the following JSON (no other text):
```json
{{
  "signal_id": "{signal_id}",
  "verdict": "vulnerable|not_vulnerable|needs_more_investigation",
  "confidence": 90,
  "title": "SQL Injection in user search",
  "severity": "HIGH|MEDIUM|LOW|INFO",
  "description": "Detailed description",
  "proof_of_concept": "How to exploit (if vulnerable)",
  "recommendation": "How to fix",
  "reasoning": "Why you reached this verdict"
}}
```

ONLY mark as vulnerable if you are confident the vulnerability is real and exploitable.

Case file location: {case_file_path}
"""


# =============================================================================
# HELPER FUNCTIONS
# =============================================================================

def get_scope_mapper_prompt(scope_id: str = None, scope_path: str = None) -> str:
    """Get ScopeMapper prompt."""
    return SCOPE_MAPPER_PROMPT


def get_threat_modeler_prompt() -> str:
    """Get ThreatModeler prompt."""
    return THREAT_MODELER_PROMPT


def get_sink_hunter_prompt(scope_id: str = None, scope_path: str = None) -> str:
    """Get SinkHunter prompt."""
    return SINK_HUNTER_PROMPT


def get_entrypoint_hunter_prompt(scope_id: str = None, scope_path: str = None) -> str:
    """Get EntrypointHunter prompt."""
    return ENTRYPOINT_HUNTER_PROMPT


def get_decider_prompt() -> str:
    """Get Decider prompt."""
    return DECIDER_PROMPT


def get_family_coordinator_prompt(family_name: str, specialist_list: str) -> str:
    """Get FamilyCoordinator prompt for a specific family."""
    return FAMILY_COORDINATOR_PROMPT.format(
        family_name=family_name,
        specialist_list=specialist_list
    )


def get_specialist_prompt(
    specialist_name: str,
    specialist_id: str,
    proficiency: str,
    signal_id: str,
    signal_context: str,
) -> str:
    """Get Specialist prompt for a specific specialist and signal."""
    return SPECIALIST_PROMPT_TEMPLATE.format(
        specialist_name=specialist_name,
        specialist_id=specialist_id,
        proficiency=proficiency,
        signal_id=signal_id,
        signal_context=signal_context,
    )


def get_arbiter_prompt(
    signal_id: str,
    disagreement_context: str,
    specialist_verdicts: str,
) -> str:
    """Get Arbiter prompt for resolving disagreements."""
    return ARBITER_PROMPT.format(
        signal_id=signal_id,
        disagreement_context=disagreement_context,
        specialist_verdicts=specialist_verdicts,
    )


def get_devils_advocate_prompt(signal_context: str, dismissal_verdict: str) -> str:
    """Get Devil's Advocate prompt for challenging dismissals."""
    return DEVILS_ADVOCATE_PROMPT.format(
        signal_context=signal_context,
        dismissal_verdict=dismissal_verdict,
    )


def get_triager_prompt() -> str:
    """Get Triager prompt."""
    return TRIAGER_PROMPT


def get_auditor_prompt(case_file_path: str, signal: Dict[str, Any] = None) -> str:
    """Get Auditor prompt for a specific case file.

    Args:
        case_file_path: Path to the case file
        signal: Optional signal dictionary for category-specific validity checklist

    Returns:
        Assembled prompt with validity checklist if signal is provided
    """
    signal_id = signal.get("signal_id", "unknown") if signal else "unknown"

    if signal and assemble_auditor_prompt_for_signal:
        # Use PromptRouter integration for category-specific validity checklist
        return assemble_auditor_prompt_for_signal(signal, case_file_path)
    else:
        # Fallback to template
        return AUDITOR_PROMPT_TEMPLATE.format(
            case_file_path=case_file_path,
            signal_id=signal_id,
        )


# Map agent types to their prompts for dispatcher lookup
AGENT_PROMPTS = {
    "RepoProfiler": REPO_PROFILER_PROMPT,
    "ScopeMapper": SCOPE_MAPPER_PROMPT,
    "ThreatModeler": THREAT_MODELER_PROMPT,
    "SinkHunter": SINK_HUNTER_PROMPT,
    "EntrypointHunter": ENTRYPOINT_HUNTER_PROMPT,
    "Decider": DECIDER_PROMPT,
    "Triager": TRIAGER_PROMPT,
    # FamilyCoordinator, Specialist, Arbiter, DevilsAdvocate need dynamic context
}


def get_prompt_for_agent_type(agent_type: str) -> str:
    """Get the base prompt for an agent type.

    For agents that need dynamic context (Specialist, Arbiter, etc.),
    use the specific get_*_prompt() functions instead.
    """
    return AGENT_PROMPTS.get(agent_type, f"You are a {agent_type} agent. Complete the assigned task.")
