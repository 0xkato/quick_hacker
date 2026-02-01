# Validation Profile Design

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Create a flexible, project-level validation profile system that enforces strict evidence requirements, configurable attacker models, and optional verification tools (GDB) for security finding validation.

**Architecture:** Extend project model with `validation_profile` JSON field. Inject profile into LLM validator prompt. Add GDB as MCP tool. Apply exclusions at scan start.

**Tech Stack:** Python, Pydantic, SQLAlchemy, Anthropic API, GDB

---

## 1. Data Model

### ValidationProfile

```python
class ValidationProfile(BaseModel):
    """Project-level validation configuration."""

    # Pre-scan exclusions - paths to skip entirely
    excluded_paths: list[str] = []
    # e.g., ["tools/", "test/", "third_party/", "build/"]

    # Threat model definition
    attacker_roles: dict[str, AttackerRole] = {}
    trust_boundaries: dict[str, TrustBoundary] = {}

    # Evidence requirements per category
    evidence_gates: dict[str, CategoryEvidenceGate] = {}

    # Verification tools enabled
    enabled_verifiers: list[str] = []  # e.g., ["gdb"]

    # Validation behavior
    default_verdict: str = "not_actionable"  # Default to rejection
    require_shipped_reachability: bool = True  # Must prove code ships
```

### AttackerRole

```python
class AttackerRole(BaseModel):
    """Defines what an attacker type can and cannot control."""

    # Input channels this attacker controls
    can_control: list[str] = []
    # e.g., ["http_request_body", "url_params", "cookies", "ipc_messages"]

    # Input channels explicitly NOT attacker-controlled
    cannot_control: list[str] = []
    # e.g., ["cli_args", "env_vars", "local_files"]

    # Inherit capabilities from another role
    inherits: Optional[str] = None
    # e.g., "remote_web" - child role gets parent's capabilities

    # Trust boundary this attacker operates from
    trust_boundary: Optional[str] = None
    # e.g., "renderer_sandbox"

    # Exception conditions - when cannot_control items become controllable
    exceptions: dict[str, str] = {}
    # e.g., {"local_files": "prove remote attacker can write to path"}
```

### TrustBoundary

```python
class TrustBoundary(BaseModel):
    """Defines a security boundary where escalation matters."""

    # Components on the untrusted side
    untrusted_side: list[str] = []
    # e.g., ["renderer_process", "extension_process"]

    # Components on the trusted side
    trusted_side: list[str] = []
    # e.g., ["browser_process", "gpu_process", "network_service"]

    # Description of what crossing this boundary means
    description: Optional[str] = None
    # e.g., "Escaping renderer sandbox to browser process"
```

### CategoryEvidenceGate

```python
class CategoryEvidenceGate(BaseModel):
    """Evidence requirements for a vulnerability category."""

    # All of these must be present for finding to be actionable
    required: list[str] = [
        "source_identified",
        "sink_identified",
        "dataflow_chain",
        "shipped_reachability",
        "security_impact"
    ]

    # Auto-reject if any of these conditions are true
    reject_if: list[str] = []
    # e.g., ["tooling_only", "test_only", "build_only", "by_design"]

    # Verification tools that can be invoked for this category
    verifiers: list[str] = []
    # e.g., ["gdb"] for memory_corruption
```

---

## 2. Evidence Gate Defaults

### Default Gate (all categories)

```python
DEFAULT_EVIDENCE_GATE = CategoryEvidenceGate(
    required=[
        "source_identified",      # Where attacker input enters
        "sink_identified",        # Where dangerous operation occurs
        "dataflow_chain",         # How data flows source → sink
        "shipped_reachability",   # Proof code runs in shipped product
        "security_impact"         # What damage attacker can do
    ],
    reject_if=[
        "tooling_only",           # Developer tools, not shipped
        "test_only",              # Test code
        "build_only",             # Build scripts
        "by_design",              # Intentional behavior
        "user_intended_execution" # User explicitly runs command
    ]
)
```

### Memory Corruption Gate

```python
MEMORY_CORRUPTION_GATE = CategoryEvidenceGate(
    required=[
        "source_identified",
        "sink_identified",
        "dataflow_chain",
        "shipped_reachability",
        "security_impact",
        "crash_or_corruption_proven"  # Extra: must show memory impact
    ],
    reject_if=[
        "tooling_only",
        "test_only",
        "build_only",
        "by_design"
    ],
    verifiers=["gdb"]  # Can use GDB to verify
)
```

### Command Injection Gate

```python
COMMAND_INJECTION_GATE = CategoryEvidenceGate(
    required=[
        "source_identified",
        "sink_identified",
        "dataflow_chain",
        "shipped_reachability",
        "security_impact",
        "unsanitized_flow",   # No escaping between source and sink
        "shell_context"       # Prove it reaches shell execution
    ],
    reject_if=[
        "tooling_only",
        "test_only",
        "by_design",
        "user_intended_execution"  # e.g., "Run command" button
    ]
)
```

---

## 3. LLM Validator Prompt

The validation profile is injected into the LLM validator prompt:

```python
def _build_validation_prompt(
    self,
    finding: Finding,
    evidence: Evidence,
    validation_profile: ValidationProfile,
) -> str:
    # Build attacker model section
    attacker_section = self._format_attacker_roles(validation_profile.attacker_roles)
    boundary_section = self._format_trust_boundaries(validation_profile.trust_boundaries)

    # Get evidence gate for this category
    category = self._normalize_category(finding.vulnerability_type)
    gate = validation_profile.evidence_gates.get(category, DEFAULT_EVIDENCE_GATE)

    return f"""You are validating a potential security vulnerability.

## Attacker Model

### Attacker Roles
{attacker_section}

### Trust Boundaries
{boundary_section}

**CRITICAL RULES:**
- Only consider input channels listed in attacker roles as attacker-controlled
- Do NOT treat CLI args/env vars/local files as attacker-controlled unless:
  - You prove a remote attacker can influence them in the shipped threat model
  - An explicit exception condition is met
- Crossing a trust boundary from untrusted → trusted side indicates escalation

## Evidence Requirements

To output "Candidate vulnerability", you MUST provide ALL of:
{self._format_required_evidence(gate.required)}

If ANY required evidence is MISSING, output "Not actionable" with list of missing items.

## Auto-Reject Conditions

Immediately reject and output "Not actionable" if:
{self._format_reject_conditions(gate.reject_if)}
- File is in excluded paths: {validation_profile.excluded_paths}

## Finding Under Review

- Title: {finding.title}
- Type: {finding.vulnerability_type}
- File: {finding.file_path}:{finding.line_start}
- Code:
```
{finding.code_snippet}
```

## Available Tools

- read_file(file_path): Read source file contents
- grep_code(pattern, glob): Search codebase with regex
- glob_files(pattern): Find files by name pattern
{self._format_verifier_tools(gate.verifiers)}

## Response Format

```
VERDICT: CANDIDATE | NOT_ACTIONABLE

EVIDENCE:
  source: <identified source or MISSING>
  sink: <identified sink or MISSING>
  dataflow: <chain description or MISSING>
  reachability: <shipped proof or MISSING>
  impact: <security impact or MISSING>
  {self._format_extra_evidence_fields(gate.required)}

REJECT_REASON: <if NOT_ACTIONABLE, which condition triggered>

REASONING:
- [Investigation step 1]
- [Investigation step 2]
- [Final determination]
```

Be highly skeptical. Default to NOT_ACTIONABLE unless all evidence is proven.
"""
```

---

## 4. GDB MCP Tool

Add GDB as a tool available to the LLM validator:

```python
def _get_tool_definitions(self, enabled_verifiers: list[str]) -> list[dict]:
    """Get tool definitions including optional verifiers."""

    tools = [
        # Existing tools
        {"name": "read_file", ...},
        {"name": "grep_code", ...},
        {"name": "glob_files", ...},
    ]

    # Add GDB if enabled
    if "gdb" in enabled_verifiers:
        tools.append({
            "name": "gdb_debug",
            "description": "Run GDB to analyze crash or memory corruption. "
                          "Use to verify memory corruption findings.",
            "input_schema": {
                "type": "object",
                "properties": {
                    "binary_path": {
                        "type": "string",
                        "description": "Path to binary to debug (relative to repo)"
                    },
                    "input_file": {
                        "type": "string",
                        "description": "Optional path to crash input/PoC file"
                    },
                    "commands": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "GDB commands to execute in order. "
                                      "e.g., ['run', 'bt', 'info registers', 'x/20x $rsp']"
                    }
                },
                "required": ["binary_path", "commands"]
            }
        })

    return tools
```

### GDB Tool Implementation

```python
def _tool_gdb_debug(
    self,
    binary_path: str,
    commands: list[str],
    input_file: Optional[str] = None
) -> str:
    """Execute GDB commands on a binary."""

    # Security: validate paths are within repo
    full_binary = (self.repo_root / binary_path).resolve()
    if not self._is_within_repo(full_binary):
        return "Error: binary_path must be within repository"

    if not full_binary.exists():
        return f"Error: Binary not found: {binary_path}"

    # Build GDB command
    gdb_script = "\n".join(commands)

    try:
        cmd = ["gdb", "-batch", "-x", "-", str(full_binary)]

        if input_file:
            full_input = (self.repo_root / input_file).resolve()
            if not self._is_within_repo(full_input):
                return "Error: input_file must be within repository"
            # Pass input file via stdin redirection in GDB
            gdb_script = f"run < {full_input}\n" + gdb_script

        result = subprocess.run(
            cmd,
            input=gdb_script,
            capture_output=True,
            text=True,
            timeout=30,  # 30 second timeout
            cwd=str(self.repo_root)
        )

        output = result.stdout + result.stderr
        return output[:10000]  # Limit output size

    except subprocess.TimeoutExpired:
        return "Error: GDB execution timed out (30s limit)"
    except FileNotFoundError:
        return "Error: GDB not found - install GDB to use this tool"
    except Exception as e:
        return f"Error: GDB execution failed: {str(e)}"
```

---

## 5. Pre-Scan Exclusions

Apply exclusions before scanning begins:

```python
# In base_agent.py

def get_scannable_files(
    self,
    repo_root: Path,
    validation_profile: Optional[ValidationProfile] = None
) -> list[str]:
    """Discover files to scan, applying exclusions."""

    all_files = self._discover_all_files(repo_root)

    if not validation_profile or not validation_profile.excluded_paths:
        return all_files

    excluded = validation_profile.excluded_paths

    def is_excluded(file_path: str) -> bool:
        for pattern in excluded:
            # Normalize pattern
            pattern = pattern.rstrip("/")
            # Check if file is under excluded path
            if file_path.startswith(pattern + "/"):
                return True
            if f"/{pattern}/" in file_path:
                return True
        return False

    included = [f for f in all_files if not is_excluded(f)]

    logger.info(
        f"Pre-scan exclusion: {len(all_files)} files → {len(included)} files "
        f"({len(all_files) - len(included)} excluded)"
    )

    return included
```

---

## 6. Database Schema

Add validation_profile column to projects table:

```sql
-- Migration: add_validation_profile.sql

ALTER TABLE projects
ADD COLUMN validation_profile JSONB DEFAULT NULL;

-- Index for querying profiles
CREATE INDEX idx_projects_validation_profile
ON projects USING gin (validation_profile);

COMMENT ON COLUMN projects.validation_profile IS
'Project-level validation configuration including attacker model, evidence gates, and exclusions';
```

---

## 7. API Endpoints

```python
# In routers/projects.py

@router.get("/{project_id}/validation-profile")
async def get_validation_profile(project_id: str) -> ValidationProfile:
    """Get validation profile for project."""
    project = await get_project(project_id)
    if project.validation_profile:
        return ValidationProfile.model_validate(project.validation_profile)
    return ValidationProfile()  # Return default empty profile


@router.put("/{project_id}/validation-profile")
async def update_validation_profile(
    project_id: str,
    profile: ValidationProfile
) -> ValidationProfile:
    """Replace validation profile for project."""
    project = await get_project(project_id)
    project.validation_profile = profile.model_dump()
    await save_project(project)
    return profile


@router.patch("/{project_id}/validation-profile")
async def patch_validation_profile(
    project_id: str,
    updates: dict
) -> ValidationProfile:
    """Partially update validation profile."""
    project = await get_project(project_id)
    current = project.validation_profile or {}
    merged = {**current, **updates}
    project.validation_profile = merged
    await save_project(project)
    return ValidationProfile.model_validate(merged)


@router.post("/{project_id}/validation-profile/apply-preset")
async def apply_preset(
    project_id: str,
    request: ApplyPresetRequest
) -> ValidationProfile:
    """Apply a preset validation profile."""
    if request.preset not in VALIDATION_PRESETS:
        raise HTTPException(404, f"Unknown preset: {request.preset}")

    profile = VALIDATION_PRESETS[request.preset]
    project = await get_project(project_id)
    project.validation_profile = profile.model_dump()
    await save_project(project)
    return profile


@router.get("/validation-presets")
async def list_presets() -> dict[str, ValidationProfile]:
    """List available validation presets."""
    return VALIDATION_PRESETS
```

---

## 8. Presets

Generic presets based on codebase characteristics:

```python
VALIDATION_PRESETS = {
    "large_c_codebase": ValidationProfile(
        excluded_paths=[
            "tools/",
            "test/",
            "tests/",
            "testing/",
            "build/",
            "buildtools/",
            "third_party/",
            "infra/",
        ],
        attacker_roles={
            "remote_network": AttackerRole(
                can_control=["network_input", "http_request", "ipc_messages"],
                cannot_control=["cli_args", "env_vars", "local_files"],
                exceptions={
                    "local_files": "prove remote attacker can write to path"
                }
            ),
            "sandboxed_process": AttackerRole(
                inherits="remote_network",
                can_control=["shared_memory", "mojo_messages"],
                trust_boundary="process_sandbox"
            ),
        },
        trust_boundaries={
            "process_sandbox": TrustBoundary(
                untrusted_side=["renderer", "utility_process"],
                trusted_side=["browser_process", "gpu_process"],
                description="Sandbox escape from isolated process"
            ),
            "network_edge": TrustBoundary(
                untrusted_side=["internet", "remote_server"],
                trusted_side=["local_process"],
                description="Remote code execution from network"
            ),
        },
        evidence_gates={
            "memory_corruption": CategoryEvidenceGate(
                required=[
                    "source_identified",
                    "sink_identified",
                    "dataflow_chain",
                    "shipped_reachability",
                    "security_impact",
                    "crash_or_corruption_proven"
                ],
                reject_if=["tooling_only", "test_only", "by_design"],
                verifiers=["gdb"]
            ),
            "command_injection": CategoryEvidenceGate(
                required=[
                    "source_identified",
                    "sink_identified",
                    "dataflow_chain",
                    "shipped_reachability",
                    "security_impact",
                    "unsanitized_flow"
                ],
                reject_if=["tooling_only", "test_only", "by_design", "user_intended_execution"]
            ),
        },
        enabled_verifiers=["gdb"],
        default_verdict="not_actionable",
        require_shipped_reachability=True,
    ),

    "webapp": ValidationProfile(
        excluded_paths=[
            "test/",
            "tests/",
            "spec/",
            "fixtures/",
            "vendor/",
            "node_modules/",
        ],
        attacker_roles={
            "remote_web": AttackerRole(
                can_control=[
                    "http_request_body",
                    "url_params",
                    "cookies",
                    "http_headers",
                    "file_upload"
                ],
                cannot_control=["cli_args", "env_vars", "server_config"]
            ),
            "authenticated_user": AttackerRole(
                inherits="remote_web",
                can_control=["session_data", "user_input_fields"]
            ),
        },
        trust_boundaries={
            "auth_boundary": TrustBoundary(
                untrusted_side=["anonymous_user"],
                trusted_side=["authenticated_session"],
                description="Authentication bypass"
            ),
            "server_boundary": TrustBoundary(
                untrusted_side=["client_browser"],
                trusted_side=["server_process", "database"],
                description="Server-side code execution"
            ),
        },
        evidence_gates={
            "xss": CategoryEvidenceGate(
                required=[
                    "source_identified",
                    "sink_identified",
                    "dataflow_chain",
                    "security_impact"
                ],
                reject_if=["test_only", "csp_blocks_execution"]
            ),
            "sqli": CategoryEvidenceGate(
                required=[
                    "source_identified",
                    "sink_identified",
                    "dataflow_chain",
                    "security_impact",
                    "unsanitized_flow"
                ],
                reject_if=["test_only", "parameterized_query"]
            ),
        },
        default_verdict="not_actionable",
        require_shipped_reachability=False,  # Webapp = always shipped
    ),

    "strict": ValidationProfile(
        excluded_paths=[],
        attacker_roles={},  # User must define
        trust_boundaries={},  # User must define
        evidence_gates={},  # Uses defaults which are strict
        enabled_verifiers=[],
        default_verdict="not_actionable",
        require_shipped_reachability=True,
    ),

    "blank": ValidationProfile(
        # Empty starting point for full customization
    ),
}
```

---

## 9. Integration Flow

```
┌─────────────────────────────────────────────────────────────────┐
│                        Project Setup                             │
├─────────────────────────────────────────────────────────────────┤
│  1. Create project                                               │
│  2. Apply validation preset OR configure custom profile          │
│     PUT /api/projects/{id}/validation-profile                    │
└─────────────────────────────────────────────────────────────────┘
                                │
                                ▼
┌─────────────────────────────────────────────────────────────────┐
│                        Agent Scan                                │
├─────────────────────────────────────────────────────────────────┤
│  1. Load project.validation_profile                              │
│  2. Apply excluded_paths → filter file list before scan         │
│  3. Run agent analysis on remaining files                        │
│  4. Generate raw findings                                        │
└─────────────────────────────────────────────────────────────────┘
                                │
                                ▼
┌─────────────────────────────────────────────────────────────────┐
│                     LLM Validation                               │
├─────────────────────────────────────────────────────────────────┤
│  1. Build prompt with:                                           │
│     - Attacker roles + trust boundaries                         │
│     - Evidence gate for finding category                         │
│     - Available tools (+ gdb if enabled)                         │
│  2. LLM investigates using tools                                 │
│  3. LLM outputs CANDIDATE or NOT_ACTIONABLE                      │
│     - CANDIDATE: all required evidence present                   │
│     - NOT_ACTIONABLE: missing evidence listed                    │
└─────────────────────────────────────────────────────────────────┘
                                │
                                ▼
┌─────────────────────────────────────────────────────────────────┐
│                       Final Output                               │
├─────────────────────────────────────────────────────────────────┤
│  Only CANDIDATE findings progress to report                      │
│  NOT_ACTIONABLE findings stored with rejection reason            │
└─────────────────────────────────────────────────────────────────┘
```

---

## 10. Files to Modify/Create

| File | Action | Description |
|------|--------|-------------|
| `backend/models/schemas.py` | Modify | Add ValidationProfile, AttackerRole, TrustBoundary, CategoryEvidenceGate |
| `backend/services/validation/llm_validator.py` | Modify | Inject profile into prompt, add gdb_debug tool |
| `backend/services/validation/presets.py` | Create | VALIDATION_PRESETS dictionary |
| `backend/agents/base_agent.py` | Modify | Apply excluded_paths in file discovery |
| `backend/routers/projects.py` | Modify | Add validation-profile endpoints |
| `backend/database/migrations/add_validation_profile.sql` | Create | Add column to projects |
| `backend/tests/services/test_validation_profile.py` | Create | Unit tests |

---

## 11. Success Criteria

1. Projects can have a validation_profile configured via API
2. Presets can be applied with one API call
3. Excluded paths prevent files from entering scan pipeline
4. LLM validator prompt includes attacker model and evidence requirements
5. Findings without complete evidence chain are marked NOT_ACTIONABLE
6. GDB tool available for memory corruption verification when enabled
7. All configuration is generic - no hardcoded project names
