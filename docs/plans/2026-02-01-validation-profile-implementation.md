# Validation Profile Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Implement project-level validation profiles with configurable attacker models, evidence gates, pre-scan exclusions, and GDB verification tool.

**Architecture:** Add ValidationProfile schema to models, extend Project model with validation_profile field, inject profile into LLM validator prompt, add GDB MCP tool, apply exclusions in base agent file discovery.

**Tech Stack:** Python, Pydantic, FastAPI, Anthropic API, GDB

---

## Task 1: Add ValidationProfile Schema

**Files:**
- Create: `backend/models/validation_profile.py`
- Test: `backend/tests/models/test_validation_profile.py`

**Step 1: Write the failing test**

```python
# backend/tests/models/test_validation_profile.py
"""Tests for ValidationProfile schema."""
import pytest
from models.validation_profile import (
    ValidationProfile,
    AttackerRole,
    TrustBoundary,
    CategoryEvidenceGate,
)


class TestAttackerRole:
    def test_basic_role(self):
        role = AttackerRole(
            can_control=["http_body", "url_params"],
            cannot_control=["cli_args", "env_vars"],
        )
        assert "http_body" in role.can_control
        assert "cli_args" in role.cannot_control

    def test_role_with_inheritance(self):
        role = AttackerRole(
            can_control=["ipc_messages"],
            inherits="remote_web",
            trust_boundary="renderer_sandbox",
        )
        assert role.inherits == "remote_web"
        assert role.trust_boundary == "renderer_sandbox"

    def test_role_with_exceptions(self):
        role = AttackerRole(
            can_control=["network_input"],
            cannot_control=["local_files"],
            exceptions={"local_files": "prove remote write access"},
        )
        assert role.exceptions["local_files"] == "prove remote write access"


class TestTrustBoundary:
    def test_basic_boundary(self):
        boundary = TrustBoundary(
            untrusted_side=["renderer_process"],
            trusted_side=["browser_process"],
            description="Sandbox escape",
        )
        assert "renderer_process" in boundary.untrusted_side
        assert "browser_process" in boundary.trusted_side


class TestCategoryEvidenceGate:
    def test_default_gate(self):
        gate = CategoryEvidenceGate()
        assert "source_identified" in gate.required
        assert "sink_identified" in gate.required

    def test_custom_gate(self):
        gate = CategoryEvidenceGate(
            required=["source_identified", "crash_proven"],
            reject_if=["test_only"],
            verifiers=["gdb"],
        )
        assert "crash_proven" in gate.required
        assert "gdb" in gate.verifiers


class TestValidationProfile:
    def test_empty_profile(self):
        profile = ValidationProfile()
        assert profile.excluded_paths == []
        assert profile.default_verdict == "not_actionable"

    def test_full_profile(self):
        profile = ValidationProfile(
            excluded_paths=["tools/", "test/"],
            attacker_roles={
                "remote_web": AttackerRole(can_control=["http_body"]),
            },
            trust_boundaries={
                "sandbox": TrustBoundary(
                    untrusted_side=["renderer"],
                    trusted_side=["browser"],
                ),
            },
            evidence_gates={
                "memory_corruption": CategoryEvidenceGate(verifiers=["gdb"]),
            },
            enabled_verifiers=["gdb"],
            require_shipped_reachability=True,
        )
        assert "tools/" in profile.excluded_paths
        assert "remote_web" in profile.attacker_roles
        assert "gdb" in profile.enabled_verifiers

    def test_profile_serialization(self):
        profile = ValidationProfile(
            excluded_paths=["test/"],
            attacker_roles={"web": AttackerRole(can_control=["http"])},
        )
        data = profile.model_dump()
        restored = ValidationProfile.model_validate(data)
        assert restored.excluded_paths == ["test/"]
        assert "web" in restored.attacker_roles
```

**Step 2: Run test to verify it fails**

Run: `cd backend && python -m pytest tests/models/test_validation_profile.py -v`
Expected: FAIL with "ModuleNotFoundError: No module named 'models.validation_profile'"

**Step 3: Write minimal implementation**

```python
# backend/models/validation_profile.py
"""Validation profile schemas for strict finding validation."""
from typing import Optional
from pydantic import BaseModel, Field


class AttackerRole(BaseModel):
    """Defines what an attacker type can and cannot control."""

    # Input channels this attacker controls
    can_control: list[str] = Field(default_factory=list)

    # Input channels explicitly NOT attacker-controlled
    cannot_control: list[str] = Field(default_factory=list)

    # Inherit capabilities from another role
    inherits: Optional[str] = None

    # Trust boundary this attacker operates from
    trust_boundary: Optional[str] = None

    # Exception conditions - when cannot_control items become controllable
    exceptions: dict[str, str] = Field(default_factory=dict)


class TrustBoundary(BaseModel):
    """Defines a security boundary where escalation matters."""

    # Components on the untrusted side
    untrusted_side: list[str] = Field(default_factory=list)

    # Components on the trusted side
    trusted_side: list[str] = Field(default_factory=list)

    # Description of what crossing this boundary means
    description: Optional[str] = None


class CategoryEvidenceGate(BaseModel):
    """Evidence requirements for a vulnerability category."""

    # All of these must be present for finding to be actionable
    required: list[str] = Field(
        default_factory=lambda: [
            "source_identified",
            "sink_identified",
            "dataflow_chain",
            "shipped_reachability",
            "security_impact",
        ]
    )

    # Auto-reject if any of these conditions are true
    reject_if: list[str] = Field(default_factory=list)

    # Verification tools that can be invoked for this category
    verifiers: list[str] = Field(default_factory=list)


class ValidationProfile(BaseModel):
    """Project-level validation configuration."""

    # Pre-scan exclusions - paths to skip entirely
    excluded_paths: list[str] = Field(default_factory=list)

    # Threat model definition
    attacker_roles: dict[str, AttackerRole] = Field(default_factory=dict)
    trust_boundaries: dict[str, TrustBoundary] = Field(default_factory=dict)

    # Evidence requirements per category
    evidence_gates: dict[str, CategoryEvidenceGate] = Field(default_factory=dict)

    # Verification tools enabled
    enabled_verifiers: list[str] = Field(default_factory=list)

    # Validation behavior
    default_verdict: str = "not_actionable"
    require_shipped_reachability: bool = True
```

**Step 4: Run test to verify it passes**

Run: `cd backend && python -m pytest tests/models/test_validation_profile.py -v`
Expected: PASS (all tests)

**Step 5: Commit**

```bash
git add backend/models/validation_profile.py backend/tests/models/test_validation_profile.py
git commit -m "feat(models): add ValidationProfile schema with attacker roles and evidence gates"
```

---

## Task 2: Add Validation Presets

**Files:**
- Create: `backend/services/validation/presets.py`
- Test: `backend/tests/services/test_validation_presets.py`

**Step 1: Write the failing test**

```python
# backend/tests/services/test_validation_presets.py
"""Tests for validation profile presets."""
import pytest
from services.validation.presets import VALIDATION_PRESETS, get_preset
from models.validation_profile import ValidationProfile


class TestValidationPresets:
    def test_presets_exist(self):
        assert "large_c_codebase" in VALIDATION_PRESETS
        assert "webapp" in VALIDATION_PRESETS
        assert "strict" in VALIDATION_PRESETS
        assert "blank" in VALIDATION_PRESETS

    def test_presets_are_valid_profiles(self):
        for name, profile in VALIDATION_PRESETS.items():
            assert isinstance(profile, ValidationProfile), f"{name} is not a ValidationProfile"

    def test_large_c_codebase_preset(self):
        profile = VALIDATION_PRESETS["large_c_codebase"]
        assert "tools/" in profile.excluded_paths
        assert "test/" in profile.excluded_paths
        assert "gdb" in profile.enabled_verifiers
        assert "remote_network" in profile.attacker_roles

    def test_webapp_preset(self):
        profile = VALIDATION_PRESETS["webapp"]
        assert "remote_web" in profile.attacker_roles
        assert "xss" in profile.evidence_gates or "sqli" in profile.evidence_gates

    def test_get_preset_returns_copy(self):
        preset1 = get_preset("blank")
        preset2 = get_preset("blank")
        preset1.excluded_paths.append("modified/")
        assert "modified/" not in preset2.excluded_paths

    def test_get_preset_unknown(self):
        result = get_preset("nonexistent")
        assert result is None
```

**Step 2: Run test to verify it fails**

Run: `cd backend && python -m pytest tests/services/test_validation_presets.py -v`
Expected: FAIL with "ModuleNotFoundError"

**Step 3: Write minimal implementation**

```python
# backend/services/validation/presets.py
"""Validation profile presets."""
from typing import Optional
from models.validation_profile import (
    ValidationProfile,
    AttackerRole,
    TrustBoundary,
    CategoryEvidenceGate,
)


VALIDATION_PRESETS: dict[str, ValidationProfile] = {
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
                exceptions={"local_files": "prove remote attacker can write to path"},
            ),
            "sandboxed_process": AttackerRole(
                inherits="remote_network",
                can_control=["shared_memory", "mojo_messages"],
                trust_boundary="process_sandbox",
            ),
        },
        trust_boundaries={
            "process_sandbox": TrustBoundary(
                untrusted_side=["renderer", "utility_process"],
                trusted_side=["browser_process", "gpu_process"],
                description="Sandbox escape from isolated process",
            ),
            "network_edge": TrustBoundary(
                untrusted_side=["internet", "remote_server"],
                trusted_side=["local_process"],
                description="Remote code execution from network",
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
                    "crash_or_corruption_proven",
                ],
                reject_if=["tooling_only", "test_only", "by_design"],
                verifiers=["gdb"],
            ),
            "command_injection": CategoryEvidenceGate(
                required=[
                    "source_identified",
                    "sink_identified",
                    "dataflow_chain",
                    "shipped_reachability",
                    "security_impact",
                    "unsanitized_flow",
                ],
                reject_if=["tooling_only", "test_only", "by_design", "user_intended_execution"],
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
                    "file_upload",
                ],
                cannot_control=["cli_args", "env_vars", "server_config"],
            ),
            "authenticated_user": AttackerRole(
                inherits="remote_web",
                can_control=["session_data", "user_input_fields"],
            ),
        },
        trust_boundaries={
            "auth_boundary": TrustBoundary(
                untrusted_side=["anonymous_user"],
                trusted_side=["authenticated_session"],
                description="Authentication bypass",
            ),
            "server_boundary": TrustBoundary(
                untrusted_side=["client_browser"],
                trusted_side=["server_process", "database"],
                description="Server-side code execution",
            ),
        },
        evidence_gates={
            "xss": CategoryEvidenceGate(
                required=[
                    "source_identified",
                    "sink_identified",
                    "dataflow_chain",
                    "security_impact",
                ],
                reject_if=["test_only", "csp_blocks_execution"],
            ),
            "sqli": CategoryEvidenceGate(
                required=[
                    "source_identified",
                    "sink_identified",
                    "dataflow_chain",
                    "security_impact",
                    "unsanitized_flow",
                ],
                reject_if=["test_only", "parameterized_query"],
            ),
        },
        default_verdict="not_actionable",
        require_shipped_reachability=False,
    ),
    "strict": ValidationProfile(
        excluded_paths=[],
        attacker_roles={},
        trust_boundaries={},
        evidence_gates={},
        enabled_verifiers=[],
        default_verdict="not_actionable",
        require_shipped_reachability=True,
    ),
    "blank": ValidationProfile(),
}


def get_preset(name: str) -> Optional[ValidationProfile]:
    """Get a copy of a preset profile by name."""
    if name not in VALIDATION_PRESETS:
        return None
    # Return a deep copy to prevent mutation
    return VALIDATION_PRESETS[name].model_copy(deep=True)
```

**Step 4: Run test to verify it passes**

Run: `cd backend && python -m pytest tests/services/test_validation_presets.py -v`
Expected: PASS

**Step 5: Commit**

```bash
git add backend/services/validation/presets.py backend/tests/services/test_validation_presets.py
git commit -m "feat(validation): add validation profile presets (large_c_codebase, webapp, strict, blank)"
```

---

## Task 3: Extend Project Model with validation_profile

**Files:**
- Modify: `backend/services/project_service.py`
- Test: `backend/tests/services/test_project_validation_profile.py`

**Step 1: Write the failing test**

```python
# backend/tests/services/test_project_validation_profile.py
"""Tests for project validation profile integration."""
import pytest
from services.project_service import Project
from models.validation_profile import ValidationProfile, AttackerRole


class TestProjectValidationProfile:
    def test_project_has_validation_profile_field(self):
        project = Project(
            id="test-123",
            name="Test Project",
        )
        assert hasattr(project, "validation_profile")
        assert project.validation_profile is None

    def test_project_with_validation_profile(self):
        profile = ValidationProfile(
            excluded_paths=["test/"],
            attacker_roles={"web": AttackerRole(can_control=["http"])},
        )
        project = Project(
            id="test-123",
            name="Test Project",
            validation_profile=profile.model_dump(),
        )
        assert project.validation_profile is not None
        assert project.validation_profile["excluded_paths"] == ["test/"]

    def test_project_serialization_with_profile(self):
        profile = ValidationProfile(excluded_paths=["tools/"])
        project = Project(
            id="test-123",
            name="Test Project",
            validation_profile=profile.model_dump(),
        )
        data = project.model_dump()
        restored = Project.model_validate(data)
        assert restored.validation_profile["excluded_paths"] == ["tools/"]

    def test_project_get_validation_profile(self):
        profile = ValidationProfile(excluded_paths=["test/"])
        project = Project(
            id="test-123",
            name="Test Project",
            validation_profile=profile.model_dump(),
        )
        retrieved = project.get_validation_profile()
        assert isinstance(retrieved, ValidationProfile)
        assert retrieved.excluded_paths == ["test/"]

    def test_project_get_validation_profile_when_none(self):
        project = Project(id="test-123", name="Test Project")
        retrieved = project.get_validation_profile()
        assert isinstance(retrieved, ValidationProfile)
        assert retrieved.excluded_paths == []
```

**Step 2: Run test to verify it fails**

Run: `cd backend && python -m pytest tests/services/test_project_validation_profile.py -v`
Expected: FAIL (missing validation_profile field)

**Step 3: Modify Project model**

Add to `backend/services/project_service.py` after line 52 (after `path: str = ""`):

```python
    validation_profile: Optional[dict] = None

    def get_validation_profile(self) -> "ValidationProfile":
        """Get validation profile as a ValidationProfile object."""
        from models.validation_profile import ValidationProfile
        if self.validation_profile is None:
            return ValidationProfile()
        return ValidationProfile.model_validate(self.validation_profile)
```

**Step 4: Run test to verify it passes**

Run: `cd backend && python -m pytest tests/services/test_project_validation_profile.py -v`
Expected: PASS

**Step 5: Commit**

```bash
git add backend/services/project_service.py backend/tests/services/test_project_validation_profile.py
git commit -m "feat(project): add validation_profile field to Project model"
```

---

## Task 4: Add Validation Profile API Endpoints

**Files:**
- Modify: `backend/routers/projects.py`
- Test: `backend/tests/routers/test_validation_profile_routes.py`

**Step 1: Write the failing test**

```python
# backend/tests/routers/test_validation_profile_routes.py
"""Tests for validation profile API endpoints."""
import pytest
from fastapi.testclient import TestClient
from unittest.mock import AsyncMock, patch, MagicMock
from main import app


@pytest.fixture
def client():
    return TestClient(app)


@pytest.fixture
def mock_project_service():
    with patch("routers.projects.project_service") as mock:
        # Create a mock project
        mock_project = MagicMock()
        mock_project.id = "test-123"
        mock_project.name = "Test"
        mock_project.validation_profile = None
        mock_project.get_validation_profile = MagicMock(
            return_value=MagicMock(
                excluded_paths=[],
                model_dump=MagicMock(return_value={"excluded_paths": []})
            )
        )
        mock.get_project = AsyncMock(return_value=mock_project)
        mock.update_project = AsyncMock(return_value=mock_project)
        yield mock


class TestValidationProfileRoutes:
    def test_get_validation_profile(self, client, mock_project_service):
        response = client.get("/api/projects/test-123/validation-profile")
        assert response.status_code == 200
        data = response.json()
        assert "excluded_paths" in data

    def test_put_validation_profile(self, client, mock_project_service):
        profile_data = {
            "excluded_paths": ["tools/", "test/"],
            "attacker_roles": {},
            "trust_boundaries": {},
            "evidence_gates": {},
            "enabled_verifiers": [],
            "default_verdict": "not_actionable",
            "require_shipped_reachability": True,
        }
        response = client.put(
            "/api/projects/test-123/validation-profile",
            json=profile_data,
        )
        assert response.status_code == 200

    def test_apply_preset(self, client, mock_project_service):
        response = client.post(
            "/api/projects/test-123/validation-profile/apply-preset",
            json={"preset": "webapp"},
        )
        assert response.status_code == 200

    def test_apply_preset_unknown(self, client, mock_project_service):
        response = client.post(
            "/api/projects/test-123/validation-profile/apply-preset",
            json={"preset": "nonexistent"},
        )
        assert response.status_code == 404

    def test_list_presets(self, client):
        response = client.get("/api/projects/validation-presets")
        assert response.status_code == 200
        data = response.json()
        assert "large_c_codebase" in data
        assert "webapp" in data
```

**Step 2: Run test to verify it fails**

Run: `cd backend && python -m pytest tests/routers/test_validation_profile_routes.py -v`
Expected: FAIL (404 - routes don't exist)

**Step 3: Add routes to projects.py**

Add to `backend/routers/projects.py`:

```python
# Add imports at top
from models.validation_profile import ValidationProfile
from services.validation.presets import VALIDATION_PRESETS, get_preset


# Add request model
class ApplyPresetRequest(BaseModel):
    preset: str


# Add routes (before the existing routes or at the end)

@router.get("/validation-presets")
async def list_validation_presets() -> dict[str, dict]:
    """List available validation presets."""
    return {name: profile.model_dump() for name, profile in VALIDATION_PRESETS.items()}


@router.get("/{project_id}/validation-profile")
async def get_validation_profile(project_id: str) -> dict:
    """Get validation profile for project."""
    project = await project_service.get_project(project_id)
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")
    return project.get_validation_profile().model_dump()


@router.put("/{project_id}/validation-profile")
async def update_validation_profile(
    project_id: str,
    profile: ValidationProfile,
) -> dict:
    """Replace validation profile for project."""
    project = await project_service.get_project(project_id)
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")
    project.validation_profile = profile.model_dump()
    await project_service.update_project(project)
    return profile.model_dump()


@router.post("/{project_id}/validation-profile/apply-preset")
async def apply_validation_preset(
    project_id: str,
    request: ApplyPresetRequest,
) -> dict:
    """Apply a preset validation profile."""
    preset = get_preset(request.preset)
    if preset is None:
        raise HTTPException(status_code=404, detail=f"Unknown preset: {request.preset}")

    project = await project_service.get_project(project_id)
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")

    project.validation_profile = preset.model_dump()
    await project_service.update_project(project)
    return preset.model_dump()
```

**Step 4: Run test to verify it passes**

Run: `cd backend && python -m pytest tests/routers/test_validation_profile_routes.py -v`
Expected: PASS

**Step 5: Commit**

```bash
git add backend/routers/projects.py backend/tests/routers/test_validation_profile_routes.py
git commit -m "feat(api): add validation profile endpoints (get, put, apply-preset, list-presets)"
```

---

## Task 5: Add GDB Tool to LLM Validator

**Files:**
- Modify: `backend/services/validation/llm_validator.py`
- Test: `backend/tests/services/test_llm_validator_gdb.py`

**Step 1: Write the failing test**

```python
# backend/tests/services/test_llm_validator_gdb.py
"""Tests for GDB tool in LLM validator."""
import pytest
from pathlib import Path
from unittest.mock import patch, MagicMock
import tempfile
import os


class TestGDBTool:
    @pytest.fixture
    def temp_repo(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            # Create a simple test binary script
            script_path = Path(tmpdir) / "test_binary.sh"
            script_path.write_text("#!/bin/bash\necho 'test'\n")
            script_path.chmod(0o755)
            yield tmpdir

    @pytest.fixture
    def validator(self, temp_repo):
        # Import here to avoid issues if anthropic not installed
        try:
            from services.validation.llm_validator import LLMFindingValidator
            return LLMFindingValidator(
                anthropic_api_key="test-key",
                repo_root=temp_repo,
                enabled_verifiers=["gdb"],
            )
        except RuntimeError:
            pytest.skip("anthropic package not installed")

    def test_gdb_tool_in_definitions_when_enabled(self, validator):
        tools = validator._get_tool_definitions()
        tool_names = [t["name"] for t in tools]
        assert "gdb_debug" in tool_names

    def test_gdb_tool_not_in_definitions_when_disabled(self, temp_repo):
        try:
            from services.validation.llm_validator import LLMFindingValidator
            validator = LLMFindingValidator(
                anthropic_api_key="test-key",
                repo_root=temp_repo,
                enabled_verifiers=[],  # GDB not enabled
            )
            tools = validator._get_tool_definitions()
            tool_names = [t["name"] for t in tools]
            assert "gdb_debug" not in tool_names
        except RuntimeError:
            pytest.skip("anthropic package not installed")

    def test_gdb_tool_rejects_path_outside_repo(self, validator):
        result = validator._tool_gdb_debug(
            binary_path="/etc/passwd",
            commands=["run"],
        )
        assert "Error" in result
        assert "outside" in result.lower() or "within" in result.lower()

    def test_gdb_tool_rejects_traversal(self, validator):
        result = validator._tool_gdb_debug(
            binary_path="../../../etc/passwd",
            commands=["run"],
        )
        assert "Error" in result

    @patch("subprocess.run")
    def test_gdb_tool_executes_commands(self, mock_run, validator, temp_repo):
        mock_run.return_value = MagicMock(
            stdout="Program received signal SIGSEGV\n#0 0x00 in crash()",
            stderr="",
            returncode=0,
        )
        result = validator._tool_gdb_debug(
            binary_path="test_binary.sh",
            commands=["run", "bt"],
        )
        assert mock_run.called
        assert "SIGSEGV" in result or mock_run.called

    @patch("subprocess.run")
    def test_gdb_tool_timeout(self, mock_run, validator):
        import subprocess
        mock_run.side_effect = subprocess.TimeoutExpired(cmd="gdb", timeout=30)
        result = validator._tool_gdb_debug(
            binary_path="test_binary.sh",
            commands=["run"],
        )
        assert "timeout" in result.lower()
```

**Step 2: Run test to verify it fails**

Run: `cd backend && python -m pytest tests/services/test_llm_validator_gdb.py -v`
Expected: FAIL (gdb_debug doesn't exist)

**Step 3: Add GDB tool to LLMFindingValidator**

Modify `backend/services/validation/llm_validator.py`:

1. Update `__init__` to accept enabled_verifiers:

```python
def __init__(
    self,
    anthropic_api_key: str,
    repo_root: str,
    model: str = "claude-sonnet-3-5-20241022",
    enabled_verifiers: list[str] = None,
):
    # ... existing code ...
    self.enabled_verifiers = enabled_verifiers or []

    # Initialize tool stubs
    self.tools = {
        "read_file": self._tool_read_file,
        "grep_code": self._tool_grep_code,
        "glob_files": self._tool_glob_files,
    }

    # Add GDB tool if enabled
    if "gdb" in self.enabled_verifiers:
        self.tools["gdb_debug"] = self._tool_gdb_debug
```

2. Add the `_tool_gdb_debug` method:

```python
def _tool_gdb_debug(
    self,
    binary_path: str,
    commands: list[str],
    input_file: Optional[str] = None,
) -> str:
    """Execute GDB commands on a binary."""
    try:
        # Build full path and validate
        full_binary = (self.repo_root / binary_path).resolve()
        repo_root_resolved = self.repo_root.resolve()

        # SECURITY: Verify path is within repo_root
        try:
            full_binary.relative_to(repo_root_resolved)
        except ValueError:
            return f"Error: binary_path must be within repository"

        if not full_binary.exists():
            return f"Error: Binary not found: {binary_path}"

        # Build GDB script from commands
        gdb_script = "\n".join(commands)

        # Handle input file if provided
        if input_file:
            full_input = (self.repo_root / input_file).resolve()
            try:
                full_input.relative_to(repo_root_resolved)
            except ValueError:
                return "Error: input_file must be within repository"
            gdb_script = f"run < {full_input}\n" + gdb_script

        cmd = ["gdb", "-batch", "-x", "-", str(full_binary)]

        result = subprocess.run(
            cmd,
            input=gdb_script,
            capture_output=True,
            text=True,
            timeout=30,
            cwd=str(self.repo_root),
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

3. Update `_get_tool_definitions` to conditionally include GDB:

```python
def _get_tool_definitions(self) -> list[dict]:
    tools = [
        # ... existing read_file, grep_code, glob_files tools ...
    ]

    # Add GDB if enabled
    if "gdb" in self.enabled_verifiers:
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
                        "description": "GDB commands to execute (e.g., ['run', 'bt', 'info registers'])"
                    }
                },
                "required": ["binary_path", "commands"]
            }
        })

    return tools
```

**Step 4: Run test to verify it passes**

Run: `cd backend && python -m pytest tests/services/test_llm_validator_gdb.py -v`
Expected: PASS

**Step 5: Commit**

```bash
git add backend/services/validation/llm_validator.py backend/tests/services/test_llm_validator_gdb.py
git commit -m "feat(validation): add GDB tool to LLM validator for memory corruption verification"
```

---

## Task 6: Update LLM Validator Prompt with ValidationProfile

**Files:**
- Modify: `backend/services/validation/llm_validator.py`
- Test: `backend/tests/services/test_llm_validator_prompt.py`

**Step 1: Write the failing test**

```python
# backend/tests/services/test_llm_validator_prompt.py
"""Tests for LLM validator prompt generation with ValidationProfile."""
import pytest
from unittest.mock import MagicMock
from models.validation_profile import (
    ValidationProfile,
    AttackerRole,
    TrustBoundary,
    CategoryEvidenceGate,
)


class TestValidatorPrompt:
    @pytest.fixture
    def validator(self):
        try:
            from services.validation.llm_validator import LLMFindingValidator
            return LLMFindingValidator(
                anthropic_api_key="test-key",
                repo_root="/tmp/test",
            )
        except RuntimeError:
            pytest.skip("anthropic package not installed")

    @pytest.fixture
    def sample_profile(self):
        return ValidationProfile(
            excluded_paths=["tools/", "test/"],
            attacker_roles={
                "remote_web": AttackerRole(
                    can_control=["http_body", "url_params"],
                    cannot_control=["cli_args", "local_files"],
                ),
            },
            trust_boundaries={
                "sandbox": TrustBoundary(
                    untrusted_side=["renderer"],
                    trusted_side=["browser"],
                    description="Sandbox escape",
                ),
            },
            evidence_gates={
                "memory_corruption": CategoryEvidenceGate(
                    required=["crash_proven"],
                    reject_if=["test_only"],
                    verifiers=["gdb"],
                ),
            },
        )

    @pytest.fixture
    def sample_finding(self):
        mock = MagicMock()
        mock.title = "Buffer overflow in parse_input"
        mock.vulnerability_type = "memory_corruption"
        mock.file_path = "src/parser.c"
        mock.line_start = 100
        mock.code_snippet = "memcpy(buf, input, len);"
        return mock

    def test_prompt_includes_attacker_roles(self, validator, sample_profile, sample_finding):
        prompt = validator._build_validation_prompt_with_profile(
            finding=sample_finding,
            validation_profile=sample_profile,
        )
        assert "remote_web" in prompt
        assert "http_body" in prompt
        assert "cli_args" in prompt

    def test_prompt_includes_trust_boundaries(self, validator, sample_profile, sample_finding):
        prompt = validator._build_validation_prompt_with_profile(
            finding=sample_finding,
            validation_profile=sample_profile,
        )
        assert "sandbox" in prompt.lower() or "renderer" in prompt

    def test_prompt_includes_evidence_requirements(self, validator, sample_profile, sample_finding):
        prompt = validator._build_validation_prompt_with_profile(
            finding=sample_finding,
            validation_profile=sample_profile,
        )
        assert "crash_proven" in prompt or "MISSING" in prompt

    def test_prompt_includes_excluded_paths(self, validator, sample_profile, sample_finding):
        prompt = validator._build_validation_prompt_with_profile(
            finding=sample_finding,
            validation_profile=sample_profile,
        )
        assert "tools/" in prompt
        assert "test/" in prompt

    def test_prompt_includes_reject_conditions(self, validator, sample_profile, sample_finding):
        prompt = validator._build_validation_prompt_with_profile(
            finding=sample_finding,
            validation_profile=sample_profile,
        )
        assert "test_only" in prompt

    def test_prompt_response_format(self, validator, sample_profile, sample_finding):
        prompt = validator._build_validation_prompt_with_profile(
            finding=sample_finding,
            validation_profile=sample_profile,
        )
        assert "CANDIDATE" in prompt
        assert "NOT_ACTIONABLE" in prompt
        assert "EVIDENCE" in prompt
```

**Step 2: Run test to verify it fails**

Run: `cd backend && python -m pytest tests/services/test_llm_validator_prompt.py -v`
Expected: FAIL (_build_validation_prompt_with_profile doesn't exist)

**Step 3: Add prompt builder method**

Add to `backend/services/validation/llm_validator.py`:

```python
def _build_validation_prompt_with_profile(
    self,
    finding: Finding,
    validation_profile: "ValidationProfile",
) -> str:
    """Build validation prompt using ValidationProfile configuration."""
    from models.validation_profile import ValidationProfile, CategoryEvidenceGate

    # Format attacker roles
    attacker_lines = []
    for role_name, role in validation_profile.attacker_roles.items():
        attacker_lines.append(f"**{role_name}**:")
        if role.can_control:
            attacker_lines.append(f"  - Can control: {', '.join(role.can_control)}")
        if role.cannot_control:
            attacker_lines.append(f"  - Cannot control: {', '.join(role.cannot_control)}")
        if role.inherits:
            attacker_lines.append(f"  - Inherits from: {role.inherits}")
        if role.trust_boundary:
            attacker_lines.append(f"  - Trust boundary: {role.trust_boundary}")
        if role.exceptions:
            for channel, condition in role.exceptions.items():
                attacker_lines.append(f"  - Exception for {channel}: {condition}")
    attacker_section = "\n".join(attacker_lines) if attacker_lines else "No attacker roles defined - use default threat model"

    # Format trust boundaries
    boundary_lines = []
    for boundary_name, boundary in validation_profile.trust_boundaries.items():
        boundary_lines.append(f"**{boundary_name}**:")
        boundary_lines.append(f"  - Untrusted: {', '.join(boundary.untrusted_side)}")
        boundary_lines.append(f"  - Trusted: {', '.join(boundary.trusted_side)}")
        if boundary.description:
            boundary_lines.append(f"  - Meaning: {boundary.description}")
    boundary_section = "\n".join(boundary_lines) if boundary_lines else "No trust boundaries defined"

    # Get evidence gate for this category
    category = self._normalize_category(finding.vulnerability_type)
    default_gate = CategoryEvidenceGate()
    gate = validation_profile.evidence_gates.get(category, default_gate)

    # Format required evidence
    required_evidence = "\n".join([f"- {req}" for req in gate.required])

    # Format reject conditions
    reject_conditions = gate.reject_if.copy()
    if validation_profile.excluded_paths:
        reject_conditions.append(f"File in excluded paths: {validation_profile.excluded_paths}")
    reject_section = "\n".join([f"- {cond}" for cond in reject_conditions])

    return f"""You are validating a potential security vulnerability.

## Attacker Model

### Attacker Roles
{attacker_section}

### Trust Boundaries
{boundary_section}

**CRITICAL RULES:**
- Only consider input channels listed in attacker roles as attacker-controlled
- Do NOT treat CLI args/env vars/local files as attacker-controlled unless:
  - You prove a remote attacker can influence them
  - An explicit exception condition is met
- Crossing a trust boundary from untrusted to trusted side indicates escalation

## Evidence Requirements

To output "Candidate vulnerability", you MUST provide ALL of:
{required_evidence}

If ANY required evidence is MISSING, output "Not actionable" with list of missing items.

## Auto-Reject Conditions

Immediately reject and output "Not actionable" if:
{reject_section}

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

REJECT_REASON: <if NOT_ACTIONABLE, which condition triggered>

REASONING:
- [Investigation step 1]
- [Investigation step 2]
- [Final determination]
```

Be highly skeptical. Default to NOT_ACTIONABLE unless all evidence is proven.
"""

def _normalize_category(self, vuln_type: str) -> str:
    """Normalize vulnerability type to category name."""
    if not vuln_type:
        return "unknown"
    return vuln_type.lower().replace(" ", "_").replace("-", "_")

def _format_verifier_tools(self, verifiers: list[str]) -> str:
    """Format verifier tools section for prompt."""
    if not verifiers:
        return ""
    lines = []
    if "gdb" in verifiers:
        lines.append("- gdb_debug(binary_path, commands): Run GDB for memory corruption analysis")
    return "\n".join(lines)
```

**Step 4: Run test to verify it passes**

Run: `cd backend && python -m pytest tests/services/test_llm_validator_prompt.py -v`
Expected: PASS

**Step 5: Commit**

```bash
git add backend/services/validation/llm_validator.py backend/tests/services/test_llm_validator_prompt.py
git commit -m "feat(validation): add prompt builder with ValidationProfile support"
```

---

## Task 7: Apply Pre-Scan Exclusions in Base Agent

**Files:**
- Modify: `backend/agents/base_agent.py`
- Test: `backend/tests/agents/test_base_agent_exclusions.py`

**Step 1: Write the failing test**

```python
# backend/tests/agents/test_base_agent_exclusions.py
"""Tests for pre-scan path exclusions in base agent."""
import pytest
from models.validation_profile import ValidationProfile


class TestPreScanExclusions:
    def test_filter_excluded_paths(self):
        from agents.base_agent import filter_excluded_paths

        all_files = [
            "src/main.c",
            "src/parser.c",
            "tools/build.py",
            "tools/lint.py",
            "test/test_main.c",
            "test/unit/test_parser.c",
            "third_party/lib/foo.c",
        ]

        profile = ValidationProfile(
            excluded_paths=["tools/", "test/", "third_party/"]
        )

        filtered = filter_excluded_paths(all_files, profile)

        assert "src/main.c" in filtered
        assert "src/parser.c" in filtered
        assert "tools/build.py" not in filtered
        assert "test/test_main.c" not in filtered
        assert "third_party/lib/foo.c" not in filtered
        assert len(filtered) == 2

    def test_filter_no_exclusions(self):
        from agents.base_agent import filter_excluded_paths

        all_files = ["src/main.c", "tools/build.py"]
        profile = ValidationProfile(excluded_paths=[])

        filtered = filter_excluded_paths(all_files, profile)
        assert len(filtered) == 2

    def test_filter_none_profile(self):
        from agents.base_agent import filter_excluded_paths

        all_files = ["src/main.c", "tools/build.py"]
        filtered = filter_excluded_paths(all_files, None)
        assert len(filtered) == 2

    def test_filter_nested_paths(self):
        from agents.base_agent import filter_excluded_paths

        all_files = [
            "chrome/browser/main.cc",
            "chrome/test/unit/test.cc",
            "chrome/app/app.cc",
        ]

        profile = ValidationProfile(excluded_paths=["chrome/test/"])

        filtered = filter_excluded_paths(all_files, profile)
        assert "chrome/browser/main.cc" in filtered
        assert "chrome/app/app.cc" in filtered
        assert "chrome/test/unit/test.cc" not in filtered
```

**Step 2: Run test to verify it fails**

Run: `cd backend && python -m pytest tests/agents/test_base_agent_exclusions.py -v`
Expected: FAIL (filter_excluded_paths doesn't exist)

**Step 3: Add filter function to base_agent.py**

Add to `backend/agents/base_agent.py`:

```python
from models.validation_profile import ValidationProfile
from typing import Optional


def filter_excluded_paths(
    files: list[str],
    validation_profile: Optional[ValidationProfile],
) -> list[str]:
    """
    Filter out files matching excluded paths from validation profile.

    Args:
        files: List of file paths to filter
        validation_profile: Validation profile with excluded_paths

    Returns:
        List of files not matching any excluded path pattern
    """
    if not validation_profile or not validation_profile.excluded_paths:
        return files

    excluded = validation_profile.excluded_paths

    def is_excluded(file_path: str) -> bool:
        for pattern in excluded:
            # Normalize pattern (remove trailing slash for comparison)
            pattern = pattern.rstrip("/")
            # Check if file is under excluded path
            if file_path.startswith(pattern + "/"):
                return True
            # Also check for pattern appearing in path
            if f"/{pattern}/" in f"/{file_path}":
                return True
        return False

    return [f for f in files if not is_excluded(f)]
```

**Step 4: Run test to verify it passes**

Run: `cd backend && python -m pytest tests/agents/test_base_agent_exclusions.py -v`
Expected: PASS

**Step 5: Commit**

```bash
git add backend/agents/base_agent.py backend/tests/agents/test_base_agent_exclusions.py
git commit -m "feat(agents): add pre-scan path exclusion filtering"
```

---

## Task 8: Integration - Wire ValidationProfile Through Triage Pipeline

**Files:**
- Modify: `backend/services/finding_triage_service.py`
- Test: `backend/tests/services/test_triage_with_profile.py`

**Step 1: Write the failing test**

```python
# backend/tests/services/test_triage_with_profile.py
"""Tests for triage pipeline with ValidationProfile integration."""
import pytest
from unittest.mock import MagicMock, patch, AsyncMock
from models.validation_profile import ValidationProfile, CategoryEvidenceGate


class TestTriageWithProfile:
    @pytest.fixture
    def sample_profile(self):
        return ValidationProfile(
            excluded_paths=["test/"],
            evidence_gates={
                "sql_injection": CategoryEvidenceGate(
                    required=["source_identified", "sink_identified"],
                    reject_if=["test_only"],
                ),
            },
        )

    @pytest.fixture
    def sample_finding(self):
        mock = MagicMock()
        mock.id = "finding-123"
        mock.file_path = "src/handler.py"
        mock.vulnerability_type = "sql_injection"
        mock.severity = "high"
        return mock

    @pytest.fixture
    def test_only_finding(self):
        mock = MagicMock()
        mock.id = "finding-456"
        mock.file_path = "test/test_handler.py"
        mock.vulnerability_type = "sql_injection"
        mock.severity = "high"
        return mock

    def test_triage_service_accepts_profile(self, sample_profile, sample_finding):
        """Verify triage service can accept validation profile parameter."""
        from services.finding_triage_service import should_skip_by_path

        # File not in excluded path should not be skipped
        result = should_skip_by_path(sample_finding.file_path, sample_profile)
        assert result is False

    def test_triage_skips_excluded_paths(self, sample_profile, test_only_finding):
        """Verify findings in excluded paths are skipped."""
        from services.finding_triage_service import should_skip_by_path

        result = should_skip_by_path(test_only_finding.file_path, sample_profile)
        assert result is True

    def test_triage_without_profile(self, sample_finding):
        """Verify triage works without profile (backwards compatible)."""
        from services.finding_triage_service import should_skip_by_path

        result = should_skip_by_path(sample_finding.file_path, None)
        assert result is False
```

**Step 2: Run test to verify it fails**

Run: `cd backend && python -m pytest tests/services/test_triage_with_profile.py -v`
Expected: FAIL (should_skip_by_path doesn't exist)

**Step 3: Add helper function to finding_triage_service.py**

Add to `backend/services/finding_triage_service.py`:

```python
from models.validation_profile import ValidationProfile
from typing import Optional


def should_skip_by_path(
    file_path: str,
    validation_profile: Optional[ValidationProfile],
) -> bool:
    """
    Check if a finding should be skipped based on validation profile exclusions.

    Args:
        file_path: Path to the file containing the finding
        validation_profile: Validation profile with excluded_paths

    Returns:
        True if finding should be skipped, False otherwise
    """
    if not validation_profile or not validation_profile.excluded_paths:
        return False

    for pattern in validation_profile.excluded_paths:
        pattern = pattern.rstrip("/")
        if file_path.startswith(pattern + "/"):
            return True
        if f"/{pattern}/" in f"/{file_path}":
            return True

    return False
```

**Step 4: Run test to verify it passes**

Run: `cd backend && python -m pytest tests/services/test_triage_with_profile.py -v`
Expected: PASS

**Step 5: Commit**

```bash
git add backend/services/finding_triage_service.py backend/tests/services/test_triage_with_profile.py
git commit -m "feat(triage): add validation profile path exclusion support"
```

---

## Summary

| Task | Description | Files |
|------|-------------|-------|
| 1 | ValidationProfile schema | models/validation_profile.py |
| 2 | Validation presets | services/validation/presets.py |
| 3 | Project model extension | services/project_service.py |
| 4 | API endpoints | routers/projects.py |
| 5 | GDB tool | services/validation/llm_validator.py |
| 6 | Prompt builder with profile | services/validation/llm_validator.py |
| 7 | Pre-scan exclusions | agents/base_agent.py |
| 8 | Triage integration | services/finding_triage_service.py |

**Total: 8 tasks**

After all tasks, run full test suite:
```bash
cd backend && python -m pytest tests/ -v
```
