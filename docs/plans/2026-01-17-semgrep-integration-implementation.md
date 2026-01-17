# Semgrep Integration Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Integrate Semgrep as a dual-mode (pre-scan + on-demand) sink discovery tool with multi-language support, LLM-based filtering, and graceful degradation.

**Architecture:** SemgrepScanner class scans codebase with curated rules, stores raw results in database, LLM filters noise via MCP tools, validated findings enter triage pipeline.

**Tech Stack:** Python 3.12+, Semgrep CLI, SQLite, Pydantic, MCP Protocol, pytest

**Working Directory:** `/Users/0xkato/Desktop/Hobby/claude_apps/quick_hack/.worktrees/semgrep-integration/backend`

---

## Phase 1: Foundation & Scanner Core

### Task 1: Add SEMGREP to ScannerTool Enum

**Files:**
- Modify: `services/security_scanners/base.py:35-45`

**Step 1: Write the failing test**

Create: `tests/services/security_scanners/test_semgrep_scanner.py`

```python
"""Tests for Semgrep integration."""
import pytest
from services.security_scanners.base import ScannerTool


def test_semgrep_tool_enum_exists():
    """Verify SEMGREP exists in ScannerTool enum."""
    assert hasattr(ScannerTool, "SEMGREP")
    assert ScannerTool.SEMGREP == "semgrep"
    assert str(ScannerTool.SEMGREP) == "semgrep"
```

**Step 2: Run test to verify it fails**

```bash
pytest tests/services/security_scanners/test_semgrep_scanner.py::test_semgrep_tool_enum_exists -v
```

Expected output:
```
AttributeError: type object 'ScannerTool' has no attribute 'SEMGREP'
FAILED
```

**Step 3: Write minimal implementation**

Edit `services/security_scanners/base.py`:

```python
class ScannerTool(str, Enum):
    """Available scanner tools.

    Inherits from str to allow direct string comparison and serialization.
    """
    SECRETS = "secrets"
    DEPENDENCIES = "dependencies"
    GREP = "grep"
    SEMGREP = "semgrep"  # NEW

    def __str__(self) -> str:
        return self.value
```

**Step 4: Run test to verify it passes**

```bash
pytest tests/services/security_scanners/test_semgrep_scanner.py::test_semgrep_tool_enum_exists -v
```

Expected output:
```
test_semgrep_tool_enum_exists PASSED
```

**Step 5: Commit**

```bash
git add services/security_scanners/base.py tests/services/security_scanners/test_semgrep_scanner.py
git commit -m "feat(scanner): add SEMGREP to ScannerTool enum

- Add SEMGREP enum value to ScannerTool
- Create test file for semgrep scanner tests
- Test enum exists and converts to string correctly"
```

---

### Task 2: Create SemgrepScanner Skeleton

**Files:**
- Create: `services/security_scanners/semgrep.py`
- Modify: `tests/services/security_scanners/test_semgrep_scanner.py`

**Step 1: Write the failing test**

Append to `tests/services/security_scanners/test_semgrep_scanner.py`:

```python
from services.security_scanners.semgrep import SemgrepScanner
from services.security_scanners.base import WorkspacePolicy, ScanLimits
from pathlib import Path


def test_semgrep_scanner_initializes(tmp_path):
    """Verify SemgrepScanner can be initialized."""
    scanner = SemgrepScanner(workspace_root=str(tmp_path))
    assert scanner.workspace_root == tmp_path
    assert scanner.get_tool_name() == ScannerTool.SEMGREP
```

**Step 2: Run test to verify it fails**

```bash
pytest tests/services/security_scanners/test_semgrep_scanner.py::test_semgrep_scanner_initializes -v
```

Expected output:
```
ModuleNotFoundError: No module named 'services.security_scanners.semgrep'
FAILED
```

**Step 3: Write minimal implementation**

Create `services/security_scanners/semgrep.py`:

```python
"""Semgrep-based vulnerability pattern scanner."""
from __future__ import annotations

from pathlib import Path

from services.security_scanners.base import ScannerTool


class SemgrepScanner:
    """Semgrep-based vulnerability pattern scanner.

    Executes Semgrep with curated rule sets and returns structured findings
    with rich context for LLM analysis.
    """

    def __init__(self, workspace_root: str, rules_dir: str | None = None):
        """Initialize Semgrep scanner.

        Args:
            workspace_root: Root directory of the workspace to scan
            rules_dir: Optional custom rules directory (default: bundled rules)
        """
        self.workspace_root = Path(workspace_root).resolve()
        self.rules_dir = rules_dir

    def get_tool_name(self) -> ScannerTool:
        """Return the scanner tool identifier."""
        return ScannerTool.SEMGREP
```

**Step 4: Run test to verify it passes**

```bash
pytest tests/services/security_scanners/test_semgrep_scanner.py::test_semgrep_scanner_initializes -v
```

Expected output:
```
test_semgrep_scanner_initializes PASSED
```

**Step 5: Commit**

```bash
git add services/security_scanners/semgrep.py tests/services/security_scanners/test_semgrep_scanner.py
git commit -m "feat(scanner): create SemgrepScanner skeleton

- Add SemgrepScanner class with basic initialization
- Store workspace_root as resolved Path
- Implement get_tool_name() method
- Test scanner initialization and tool name"
```

---

### Task 3: Add Semgrep Availability Check

**Files:**
- Modify: `services/security_scanners/semgrep.py`
- Modify: `tests/services/security_scanners/test_semgrep_scanner.py`

**Step 1: Write the failing test**

Append to `tests/services/security_scanners/test_semgrep_scanner.py`:

```python
from unittest import mock
import subprocess


class SemgrepNotAvailableError(Exception):
    """Raised when Semgrep is not available."""
    pass


def test_semgrep_checks_availability_on_init(tmp_path):
    """Verify scanner checks if Semgrep is installed."""
    # Mock Semgrep available
    with mock.patch('subprocess.run') as mock_run:
        mock_run.return_value = mock.Mock(returncode=0)
        scanner = SemgrepScanner(workspace_root=str(tmp_path))
        mock_run.assert_called_once()
        assert "semgrep" in mock_run.call_args[0][0]
        assert "--version" in mock_run.call_args[0][0]


def test_semgrep_raises_when_not_found(tmp_path):
    """Verify error raised when Semgrep not installed."""
    with mock.patch('subprocess.run', side_effect=FileNotFoundError):
        with pytest.raises(SemgrepNotAvailableError, match="not found"):
            SemgrepScanner(workspace_root=str(tmp_path))


def test_semgrep_raises_when_fails(tmp_path):
    """Verify error raised when Semgrep fails to execute."""
    with mock.patch('subprocess.run') as mock_run:
        mock_run.return_value = mock.Mock(returncode=1)
        with pytest.raises(SemgrepNotAvailableError, match="failed"):
            SemgrepScanner(workspace_root=str(tmp_path))


def test_semgrep_raises_on_timeout(tmp_path):
    """Verify error raised when version check times out."""
    with mock.patch('subprocess.run', side_effect=subprocess.TimeoutExpired("semgrep", 5)):
        with pytest.raises(SemgrepNotAvailableError, match="timed out"):
            SemgrepScanner(workspace_root=str(tmp_path))
```

**Step 2: Run test to verify it fails**

```bash
pytest tests/services/security_scanners/test_semgrep_scanner.py::test_semgrep_checks_availability_on_init -v
```

Expected output:
```
AssertionError: Expected 'subprocess.run' to be called once
FAILED
```

**Step 3: Write minimal implementation**

Edit `services/security_scanners/semgrep.py`:

```python
"""Semgrep-based vulnerability pattern scanner."""
from __future__ import annotations

import subprocess
from pathlib import Path

from services.security_scanners.base import ScannerTool


class SemgrepNotAvailableError(Exception):
    """Raised when Semgrep is not available."""
    pass


class SemgrepScanner:
    """Semgrep-based vulnerability pattern scanner.

    Executes Semgrep with curated rule sets and returns structured findings
    with rich context for LLM analysis.
    """

    def __init__(self, workspace_root: str, rules_dir: str | None = None):
        """Initialize Semgrep scanner.

        Args:
            workspace_root: Root directory of the workspace to scan
            rules_dir: Optional custom rules directory (default: bundled rules)

        Raises:
            SemgrepNotAvailableError: If Semgrep is not installed or not working
        """
        self.workspace_root = Path(workspace_root).resolve()
        self.rules_dir = rules_dir
        self._check_semgrep_available()

    def _check_semgrep_available(self) -> None:
        """Verify Semgrep is installed and accessible.

        Raises:
            SemgrepNotAvailableError: If Semgrep is not available
        """
        try:
            result = subprocess.run(
                ["semgrep", "--version"],
                capture_output=True,
                timeout=5,
                check=False
            )
            if result.returncode != 0:
                raise SemgrepNotAvailableError("Semgrep failed to execute")
        except FileNotFoundError:
            raise SemgrepNotAvailableError("Semgrep not found in PATH")
        except subprocess.TimeoutExpired:
            raise SemgrepNotAvailableError("Semgrep version check timed out")

    def get_tool_name(self) -> ScannerTool:
        """Return the scanner tool identifier."""
        return ScannerTool.SEMGREP
```

**Step 4: Run tests to verify they pass**

```bash
pytest tests/services/security_scanners/test_semgrep_scanner.py -v -k "availability or not_found or fails or timeout"
```

Expected output:
```
test_semgrep_checks_availability_on_init PASSED
test_semgrep_raises_when_not_found PASSED
test_semgrep_raises_when_fails PASSED
test_semgrep_raises_on_timeout PASSED
4 passed
```

**Step 5: Commit**

```bash
git add services/security_scanners/semgrep.py tests/services/security_scanners/test_semgrep_scanner.py
git commit -m "feat(scanner): add Semgrep availability check

- Check Semgrep installed on scanner initialization
- Raise SemgrepNotAvailableError if not found/fails/times out
- Test all error conditions with mocked subprocess
- Graceful degradation foundation"
```

---

### Task 4: Implement Scan Method Signature

**Files:**
- Modify: `services/security_scanners/semgrep.py`
- Modify: `tests/services/security_scanners/test_semgrep_scanner.py`

**Step 1: Write the failing test**

Append to `tests/services/security_scanners/test_semgrep_scanner.py`:

```python
from services.security_scanners.base import ScanResult


def test_scan_method_exists(tmp_path):
    """Verify scan method signature."""
    with mock.patch('subprocess.run', return_value=mock.Mock(returncode=0)):
        scanner = SemgrepScanner(workspace_root=str(tmp_path))

        policy = WorkspacePolicy(
            workspace_root=str(tmp_path),
            max_file_size=10_000_000,
            excluded_dirs={"node_modules", ".git"}
        )
        limits = ScanLimits()

        # Should accept all parameters
        result = scanner.scan(
            workspace_policy=policy,
            limits=limits,
            language="python",
            severity=["high", "critical"],
            category="sql-injection",
            path="app/"
        )

        assert isinstance(result, ScanResult)
```

**Step 2: Run test to verify it fails**

```bash
pytest tests/services/security_scanners/test_semgrep_scanner.py::test_scan_method_exists -v
```

Expected output:
```
AttributeError: 'SemgrepScanner' object has no attribute 'scan'
FAILED
```

**Step 3: Write minimal implementation**

Edit `services/security_scanners/semgrep.py`:

```python
# Add to imports
from services.security_scanners.base import (
    ScannerTool,
    WorkspacePolicy,
    ScanLimits,
    ScanResult,
    ScanFinding,
    Severity,
)

# Add to SemgrepScanner class
    def scan(
        self,
        workspace_policy: WorkspacePolicy,
        limits: ScanLimits,
        language: str | None = None,
        severity: list[str] | None = None,
        category: str | None = None,
        path: str | None = None,
    ) -> ScanResult:
        """Run Semgrep scan with filters.

        Args:
            workspace_policy: Security boundaries (inherits excluded_dirs)
            limits: Timeout and cancellation support
            language: Filter by language (python, javascript, c, cpp, java)
            severity: Filter by severity (default: ["high", "critical"])
            category: Filter by category (sql-injection, command-injection, etc.)
            path: Specific file/directory to scan (relative to workspace_root)

        Returns:
            ScanResult with findings containing rich context
        """
        # Minimal stub - return empty successful result
        return ScanResult(
            success=True,
            findings=[],
            files_scanned=0,
            files_skipped=0,
            bytes_scanned=0,
            duration_ms=0,
        )
```

**Step 4: Run test to verify it passes**

```bash
pytest tests/services/security_scanners/test_semgrep_scanner.py::test_scan_method_exists -v
```

Expected output:
```
test_scan_method_exists PASSED
```

**Step 5: Commit**

```bash
git add services/security_scanners/semgrep.py tests/services/security_scanners/test_semgrep_scanner.py
git commit -m "feat(scanner): add scan method signature

- Add scan() method with full parameter set
- Accept workspace_policy, limits, language, severity, category, path
- Return ScanResult (stub implementation)
- Test method signature and return type"
```

---

### Task 5: Create Test Fixture for SQL Injection

**Files:**
- Create: `tests/fixtures/vulnerable_code/python/sql_injection.py`
- Modify: `tests/services/security_scanners/test_semgrep_scanner.py`

**Step 1: Create vulnerable code fixture**

Create `tests/fixtures/vulnerable_code/python/sql_injection.py`:

```python
"""SQL injection vulnerability for testing Semgrep detection."""
import sqlite3


def search_users(user_input):
    """Vulnerable function with SQL injection via f-string."""
    conn = sqlite3.connect('app.db')
    cursor = conn.cursor()
    # VULNERABLE: SQL injection via f-string
    query = f"SELECT * FROM users WHERE name = '{user_input}'"
    cursor.execute(query)
    return cursor.fetchall()


def search_users_format(user_input):
    """Vulnerable function with SQL injection via .format()."""
    conn = sqlite3.connect('app.db')
    cursor = conn.cursor()
    # VULNERABLE: SQL injection via .format()
    query = "SELECT * FROM users WHERE name = '{}'".format(user_input)
    cursor.execute(query)
    return cursor.fetchall()


def search_users_concat(user_input):
    """Vulnerable function with SQL injection via string concatenation."""
    conn = sqlite3.connect('app.db')
    cursor = conn.cursor()
    # VULNERABLE: SQL injection via concatenation
    query = "SELECT * FROM users WHERE name = '" + user_input + "'"
    cursor.execute(query)
    return cursor.fetchall()
```

**Step 2: Write the failing test**

Append to `tests/services/security_scanners/test_semgrep_scanner.py`:

```python
import shutil
from pathlib import Path


@pytest.mark.skipif(not shutil.which("semgrep"), reason="Semgrep not installed")
def test_semgrep_finds_sql_injection(tmp_path):
    """Verify Semgrep detects SQL injection patterns (REAL SCAN)."""
    # Copy fixture to tmp workspace
    fixture_src = Path("tests/fixtures/vulnerable_code/python/sql_injection.py")
    fixture_dst = tmp_path / "sql_injection.py"
    shutil.copy(fixture_src, fixture_dst)

    scanner = SemgrepScanner(workspace_root=str(tmp_path))

    policy = WorkspacePolicy(
        workspace_root=str(tmp_path),
        max_file_size=10_000_000,
        excluded_dirs=set()
    )
    limits = ScanLimits()

    result = scanner.scan(
        workspace_policy=policy,
        limits=limits,
        language="python",
        severity=["high", "critical"]
    )

    # Should find at least 3 SQL injection vulnerabilities
    assert result.success is True
    assert len(result.findings) >= 3

    # Check finding properties
    finding = result.findings[0]
    assert finding.tool == ScannerTool.SEMGREP
    assert finding.severity in [Severity.HIGH, Severity.CRITICAL]
    assert "sql" in finding.title.lower() or "injection" in finding.title.lower()
    assert finding.file_path == "sql_injection.py"
    assert finding.line_start > 0
    assert len(finding.snippet) > 0
```

**Step 3: Run test to verify it fails**

```bash
pytest tests/services/security_scanners/test_semgrep_scanner.py::test_semgrep_finds_sql_injection -v
```

Expected output:
```
AssertionError: assert 0 >= 3
 (scan returns empty findings)
FAILED
```

**Step 4: Commit fixture (implementation comes in next task)**

```bash
git add tests/fixtures/vulnerable_code/python/sql_injection.py tests/services/security_scanners/test_semgrep_scanner.py
git commit -m "test(scanner): add SQL injection test fixture

- Create SQL injection fixture with 3 vulnerable patterns
- Add test for Semgrep detection (currently failing)
- Use f-string, .format(), and concatenation patterns
- Skip test if Semgrep not installed"
```

---

### Task 6: Download and Install Semgrep Rules

**Files:**
- Create: `services/security_scanners/semgrep_rules/python/sql-injection.yaml`
- Create: `services/security_scanners/semgrep_rules/metadata.json`
- Create: `services/security_scanners/semgrep_rules/README.md`

**Step 1: Create rules directory structure**

```bash
mkdir -p services/security_scanners/semgrep_rules/python
mkdir -p services/security_scanners/semgrep_rules/c
mkdir -p services/security_scanners/semgrep_rules/javascript
mkdir -p services/security_scanners/semgrep_rules/java
```

**Step 2: Create initial Python SQL injection rule**

Create `services/security_scanners/semgrep_rules/python/sql-injection.yaml`:

```yaml
rules:
  - id: python-sql-injection-fstring
    pattern-either:
      - pattern: $CURSOR.execute(f"...{$VAR}...")
      - pattern: $CURSOR.execute(f'...{$VAR}...')
    message: |
      SQL query constructed using f-string with variable interpolation.
      This could lead to SQL injection if $VAR contains user input.
      Use parameterized queries instead: cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))
    languages:
      - python
    severity: WARNING
    metadata:
      cwe: "CWE-89"
      owasp: "A03:2021 - Injection"
      category: security
      subcategory: vuln
      confidence: HIGH
      likelihood: HIGH
      impact: HIGH

  - id: python-sql-injection-format
    pattern-either:
      - pattern: $CURSOR.execute("...".format(...))
      - pattern: $CURSOR.execute('...'.format(...))
      - pattern: $CURSOR.execute($STR.format(...))
    message: |
      SQL query constructed using .format() method.
      This could lead to SQL injection if format arguments contain user input.
      Use parameterized queries instead.
    languages:
      - python
    severity: WARNING
    metadata:
      cwe: "CWE-89"
      owasp: "A03:2021 - Injection"
      category: security
      subcategory: vuln
      confidence: HIGH
      likelihood: HIGH
      impact: HIGH

  - id: python-sql-injection-concat
    pattern-either:
      - pattern: $CURSOR.execute("..." + $VAR + "...")
      - pattern: $CURSOR.execute('...' + $VAR + '...')
    message: |
      SQL query constructed using string concatenation.
      This could lead to SQL injection if $VAR contains user input.
      Use parameterized queries instead.
    languages:
      - python
    severity: WARNING
    metadata:
      cwe: "CWE-89"
      owasp: "A03:2021 - Injection"
      category: security
      subcategory: vuln
      confidence: HIGH
      likelihood: HIGH
      impact: HIGH
```

**Step 3: Create metadata.json**

Create `services/security_scanners/semgrep_rules/metadata.json`:

```json
{
  "version": "1.0.0",
  "last_updated": "2026-01-17",
  "rules": {
    "python-sql-injection-fstring": {
      "severity": "high",
      "category": "sql-injection",
      "validity_checklist": "sql_injection",
      "sink_type": "sql_execution",
      "cwe": "CWE-89",
      "owasp": "A03:2021 - Injection",
      "source": "custom",
      "curated_date": "2026-01-17",
      "notes": "Detects f-string SQL queries"
    },
    "python-sql-injection-format": {
      "severity": "high",
      "category": "sql-injection",
      "validity_checklist": "sql_injection",
      "sink_type": "sql_execution",
      "cwe": "CWE-89",
      "owasp": "A03:2021 - Injection",
      "source": "custom",
      "curated_date": "2026-01-17",
      "notes": "Detects .format() SQL queries"
    },
    "python-sql-injection-concat": {
      "severity": "high",
      "category": "sql-injection",
      "validity_checklist": "sql_injection",
      "sink_type": "sql_execution",
      "cwe": "CWE-89",
      "owasp": "A03:2021 - Injection",
      "source": "custom",
      "curated_date": "2026-01-17",
      "notes": "Detects concatenated SQL queries"
    }
  },
  "categories": {
    "sql-injection": {
      "description": "SQL query construction with user input",
      "sink_types": ["sql_execution", "orm_raw_query"]
    }
  }
}
```

**Step 4: Create README**

Create `services/security_scanners/semgrep_rules/README.md`:

```markdown
# Semgrep Rules for QuickHack

Curated collection of high/critical severity security rules for multi-language vulnerability detection.

## Structure

```
semgrep_rules/
├── python/          # Python security rules
├── c/               # C/C++ security rules
├── javascript/      # JavaScript security rules
├── java/            # Java security rules
├── metadata.json    # Rule metadata and mappings
└── README.md        # This file
```

## Rule Curation Criteria

- **Severity:** High or Critical only
- **False Positives:** Low rate (< 20% based on testing)
- **Coverage:** Maps to OWASP Top 10 or CWE
- **Integration:** Aligns with QuickHack validity checklists
- **Maintenance:** Active (updated in last 12 months)

## Sources

- **C/C++:** [0xdea/semgrep-rules](https://github.com/0xdea/semgrep-rules)
- **Python/JS/Java:** Semgrep Registry + manual curation

## Usage

Rules are loaded automatically by SemgrepScanner. To run manually:

```bash
semgrep --config services/security_scanners/semgrep_rules/python app/
```

## Adding New Rules

1. Add YAML file to appropriate language directory
2. Update metadata.json with rule details
3. Create test fixture in tests/fixtures/vulnerable_code/
4. Run tests to verify detection

## Maintenance

Quarterly review process:
1. Check Semgrep Registry for new/updated rules
2. Review community feedback on false positives
3. Add rules meeting curation criteria
4. Update CHANGELOG
```

**Step 5: Test rule syntax**

```bash
# If Semgrep is installed, validate syntax
if command -v semgrep &> /dev/null; then
    semgrep --validate --config services/security_scanners/semgrep_rules/python/sql-injection.yaml
fi
```

Expected output:
```
✓ All rules are valid
```

**Step 6: Commit**

```bash
git add services/security_scanners/semgrep_rules/
git commit -m "feat(rules): add initial Semgrep rules for Python SQL injection

- Create rules directory structure for multi-language support
- Add 3 Python SQL injection detection rules (f-string, format, concat)
- Create metadata.json with rule mappings to CWE/OWASP
- Add README with curation criteria and usage instructions
- Initial rule set: 3 Python rules"
```

---

### Task 7: Implement Semgrep Command Building

**Files:**
- Modify: `services/security_scanners/semgrep.py`
- Modify: `tests/services/security_scanners/test_semgrep_scanner.py`

**Step 1: Write the failing test**

Append to `tests/services/security_scanners/test_semgrep_scanner.py`:

```python
def test_build_command_basic(tmp_path):
    """Verify basic Semgrep command structure."""
    with mock.patch('subprocess.run', return_value=mock.Mock(returncode=0)):
        scanner = SemgrepScanner(workspace_root=str(tmp_path))

        cmd = scanner._build_command(
            language=None,
            severity=["high", "critical"],
            category=None,
            scan_path=str(tmp_path)
        )

        assert cmd[0] == "semgrep"
        assert "--json" in cmd
        assert "--config" in cmd
        assert str(tmp_path) in cmd


def test_build_command_with_language_filter(tmp_path):
    """Verify language filtering in command."""
    with mock.patch('subprocess.run', return_value=mock.Mock(returncode=0)):
        scanner = SemgrepScanner(workspace_root=str(tmp_path))

        cmd = scanner._build_command(
            language="python",
            severity=["high"],
            category=None,
            scan_path=str(tmp_path)
        )

        # Should only scan Python rules
        assert "--config" in cmd
        config_idx = cmd.index("--config")
        config_path = cmd[config_idx + 1]
        assert "python" in config_path.lower()
```

**Step 2: Run test to verify it fails**

```bash
pytest tests/services/security_scanners/test_semgrep_scanner.py::test_build_command_basic -v
```

Expected output:
```
AttributeError: 'SemgrepScanner' object has no attribute '_build_command'
FAILED
```

**Step 3: Write minimal implementation**

Edit `services/security_scanners/semgrep.py`:

```python
# Add to imports at top
import os

# Add method to SemgrepScanner class
    def _default_rules_dir(self) -> str:
        """Get default rules directory path."""
        # Rules are bundled with the scanner
        scanner_dir = Path(__file__).parent
        rules_dir = scanner_dir / "semgrep_rules"
        return str(rules_dir)

    def _build_command(
        self,
        language: str | None,
        severity: list[str],
        category: str | None,
        scan_path: str,
    ) -> list[str]:
        """Build Semgrep command with filters.

        Args:
            language: Language filter (python, javascript, c, cpp, java)
            severity: Severity levels to include
            category: Vulnerability category filter
            scan_path: Path to scan

        Returns:
            List of command arguments
        """
        rules_dir = self.rules_dir or self._default_rules_dir()

        cmd = ["semgrep", "--json", "--quiet"]

        # Add config path
        if language:
            # Scan specific language rules
            config_path = Path(rules_dir) / language
            if config_path.exists():
                cmd.extend(["--config", str(config_path)])
            else:
                # Fallback to all rules if language dir doesn't exist
                cmd.extend(["--config", rules_dir])
        else:
            # Scan all rules
            cmd.extend(["--config", rules_dir])

        # Add target path
        cmd.append(scan_path)

        return cmd
```

**Step 4: Run tests to verify they pass**

```bash
pytest tests/services/security_scanners/test_semgrep_scanner.py -v -k "build_command"
```

Expected output:
```
test_build_command_basic PASSED
test_build_command_with_language_filter PASSED
```

**Step 5: Commit**

```bash
git add services/security_scanners/semgrep.py tests/services/security_scanners/test_semgrep_scanner.py
git commit -m "feat(scanner): implement Semgrep command building

- Add _build_command() to construct Semgrep CLI arguments
- Support language filtering (scan specific language dir)
- Use bundled rules directory by default
- Output JSON format for parsing
- Test command structure and language filtering"
```

---

### Task 8: Implement Semgrep Output Parsing

**Files:**
- Modify: `services/security_scanners/semgrep.py`
- Modify: `tests/services/security_scanners/test_semgrep_scanner.py`

**Step 1: Write the failing test**

Append to `tests/services/security_scanners/test_semgrep_scanner.py`:

```python
def test_parse_semgrep_output():
    """Verify Semgrep JSON output parsing."""
    # Sample Semgrep JSON output
    semgrep_json = """{
      "results": [
        {
          "check_id": "python-sql-injection-fstring",
          "path": "app/db.py",
          "start": {"line": 10, "col": 5},
          "end": {"line": 10, "col": 60},
          "extra": {
            "message": "SQL injection via f-string",
            "severity": "WARNING",
            "metadata": {
              "cwe": "CWE-89",
              "owasp": "A03:2021",
              "confidence": "HIGH"
            },
            "lines": "    cursor.execute(f\\"SELECT * FROM users WHERE id={user_id}\\")"
          }
        }
      ],
      "errors": []
    }"""

    with mock.patch('subprocess.run', return_value=mock.Mock(returncode=0)):
        scanner = SemgrepScanner(workspace_root="/tmp")
        findings = scanner._parse_semgrep_output(semgrep_json)

        assert len(findings) == 1
        finding = findings[0]

        assert finding.tool == ScannerTool.SEMGREP
        assert finding.file_path == "app/db.py"
        assert finding.line_start == 10
        assert finding.line_end == 10
        assert finding.severity == Severity.HIGH
        assert "sql" in finding.title.lower()
        assert "cwe" in finding.details
        assert finding.details["cwe"] == "CWE-89"
```

**Step 2: Run test to verify it fails**

```bash
pytest tests/services/security_scanners/test_semgrep_scanner.py::test_parse_semgrep_output -v
```

Expected output:
```
AttributeError: 'SemgrepScanner' object has no attribute '_parse_semgrep_output'
FAILED
```

**Step 3: Write minimal implementation**

Edit `services/security_scanners/semgrep.py`:

```python
# Add to imports
import json

# Add method to SemgrepScanner class
    def _map_severity(self, semgrep_severity: str) -> Severity:
        """Map Semgrep severity to scanner Severity enum.

        Args:
            semgrep_severity: Semgrep severity (INFO, WARNING, ERROR)

        Returns:
            Mapped Severity enum value
        """
        severity_map = {
            "ERROR": Severity.CRITICAL,
            "WARNING": Severity.HIGH,
            "INFO": Severity.MEDIUM,
        }
        return severity_map.get(semgrep_severity.upper(), Severity.MEDIUM)

    def _extract_category(self, rule_id: str) -> str:
        """Extract vulnerability category from rule ID.

        Args:
            rule_id: Semgrep rule identifier

        Returns:
            Category string (e.g., "sql-injection")
        """
        # Extract from rule ID pattern like "python-sql-injection-fstring"
        parts = rule_id.lower().split("-")

        # Common patterns
        if "sql" in parts:
            return "sql-injection"
        elif "command" in parts:
            return "command-injection"
        elif "xss" in parts:
            return "xss"
        elif "buffer" in parts:
            return "buffer-overflow"
        elif "deserial" in parts:
            return "deserialization"

        # Fallback: use rule ID as category
        return rule_id

    def _parse_semgrep_output(self, output: str) -> list[ScanFinding]:
        """Parse Semgrep JSON output into ScanFinding objects.

        Args:
            output: Semgrep JSON output string

        Returns:
            List of ScanFinding objects
        """
        try:
            data = json.loads(output)
        except json.JSONDecodeError:
            return []

        findings = []
        for result in data.get("results", []):
            # Extract rich context
            extra = result.get("extra", {})
            metadata = extra.get("metadata", {})

            finding = ScanFinding(
                tool=ScannerTool.SEMGREP,
                severity=self._map_severity(extra.get("severity", "WARNING")),
                title=result.get("check_id", "Unknown"),
                file_path=result.get("path", ""),
                line_start=result.get("start", {}).get("line", 0),
                line_end=result.get("end", {}).get("line", 0),
                snippet=extra.get("lines", ""),
                confidence=0.9,  # Semgrep rules are high confidence
                details={
                    "rule_id": result.get("check_id"),
                    "category": self._extract_category(result.get("check_id", "")),
                    "message": extra.get("message", ""),
                    "cwe": metadata.get("cwe"),
                    "owasp": metadata.get("owasp"),
                },
            )
            findings.append(finding)

        return findings
```

**Step 4: Run test to verify it passes**

```bash
pytest tests/services/security_scanners/test_semgrep_scanner.py::test_parse_semgrep_output -v
```

Expected output:
```
test_parse_semgrep_output PASSED
```

**Step 5: Commit**

```bash
git add services/security_scanners/semgrep.py tests/services/security_scanners/test_semgrep_scanner.py
git commit -m "feat(scanner): implement Semgrep output parsing

- Add _parse_semgrep_output() to convert JSON to ScanFinding objects
- Map Semgrep severity (ERROR/WARNING/INFO) to scanner Severity enum
- Extract vulnerability category from rule ID
- Include CWE, OWASP, and message in finding details
- Test JSON parsing with sample Semgrep output"
```

---

### Task 9: Implement Full Scan Execution

**Files:**
- Modify: `services/security_scanners/semgrep.py`
- Modify: `tests/services/security_scanners/test_semgrep_scanner.py`

**Step 1: Update the failing test from Task 5**

The test `test_semgrep_finds_sql_injection` should now work with full implementation.

**Step 2: Write additional tests for scan execution**

Append to `tests/services/security_scanners/test_semgrep_scanner.py`:

```python
def test_scan_execution_with_mock(tmp_path):
    """Verify scan executes Semgrep and parses results."""
    # Mock Semgrep execution
    mock_output = """{
      "results": [
        {
          "check_id": "test-rule",
          "path": "test.py",
          "start": {"line": 1, "col": 1},
          "end": {"line": 1, "col": 10},
          "extra": {
            "message": "Test finding",
            "severity": "WARNING",
            "metadata": {},
            "lines": "test code"
          }
        }
      ]
    }"""

    with mock.patch('subprocess.run', return_value=mock.Mock(returncode=0)):
        scanner = SemgrepScanner(workspace_root=str(tmp_path))

    with mock.patch('subprocess.Popen') as mock_popen:
        mock_process = mock.Mock()
        mock_process.poll.side_effect = [None, None, 0]  # Running, then done
        mock_process.communicate.return_value = (mock_output, "")
        mock_popen.return_value = mock_process

        policy = WorkspacePolicy(
            workspace_root=str(tmp_path),
            max_file_size=10_000_000,
            excluded_dirs=set()
        )
        limits = ScanLimits()

        result = scanner.scan(
            workspace_policy=policy,
            limits=limits,
        )

        assert result.success is True
        assert len(result.findings) == 1
        assert result.findings[0].file_path == "test.py"
```

**Step 3: Implement full scan method**

Edit `services/security_scanners/semgrep.py`:

```python
# Add to imports
import time

# Replace stub scan method with full implementation
    def scan(
        self,
        workspace_policy: WorkspacePolicy,
        limits: ScanLimits,
        language: str | None = None,
        severity: list[str] | None = None,
        category: str | None = None,
        path: str | None = None,
    ) -> ScanResult:
        """Run Semgrep scan with filters.

        Args:
            workspace_policy: Security boundaries (inherits excluded_dirs)
            limits: Timeout and cancellation support
            language: Filter by language (python, javascript, c, cpp, java)
            severity: Filter by severity (default: ["high", "critical"])
            category: Filter by category (sql-injection, command-injection, etc.)
            path: Specific file/directory to scan (relative to workspace_root)

        Returns:
            ScanResult with findings containing rich context
        """
        severity = severity or ["high", "critical"]
        scan_path = path or str(self.workspace_root)
        if not os.path.isabs(scan_path):
            scan_path = str(self.workspace_root / scan_path)

        start_time = time.time()

        # Build Semgrep command
        cmd = self._build_command(language, severity, category, scan_path)

        # Execute with timeout and cancellation support
        try:
            process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )

            findings = []
            while process.poll() is None:
                # Check cancellation
                if limits.is_cancelled():
                    process.terminate()
                    duration_ms = int((time.time() - start_time) * 1000)
                    return ScanResult(
                        success=False,
                        findings=findings,
                        files_scanned=0,
                        files_skipped=0,
                        bytes_scanned=0,
                        duration_ms=duration_ms,
                        cancelled=True,
                    )

                time.sleep(0.1)

            # Parse results
            stdout, stderr = process.communicate()
            findings = self._parse_semgrep_output(stdout)

            duration_ms = int((time.time() - start_time) * 1000)

            return ScanResult(
                success=True,
                findings=findings,
                files_scanned=len(findings),  # Approximate
                files_skipped=0,
                bytes_scanned=0,
                duration_ms=duration_ms,
            )

        except Exception as e:
            duration_ms = int((time.time() - start_time) * 1000)
            return ScanResult(
                success=False,
                findings=[],
                files_scanned=0,
                files_skipped=0,
                bytes_scanned=0,
                duration_ms=duration_ms,
                error=str(e),
            )
```

**Step 4: Run tests to verify they pass**

```bash
pytest tests/services/security_scanners/test_semgrep_scanner.py::test_scan_execution_with_mock -v
pytest tests/services/security_scanners/test_semgrep_scanner.py::test_semgrep_finds_sql_injection -v
```

Expected output:
```
test_scan_execution_with_mock PASSED
test_semgrep_finds_sql_injection PASSED  (or SKIPPED if Semgrep not installed)
```

**Step 5: Commit**

```bash
git add services/security_scanners/semgrep.py tests/services/security_scanners/test_semgrep_scanner.py
git commit -m "feat(scanner): implement full Semgrep scan execution

- Execute Semgrep subprocess with timeout and cancellation support
- Poll process and check limits.is_cancelled() during execution
- Parse JSON output and return ScanResult with findings
- Handle errors gracefully with error message in result
- Test with mocked Popen and real Semgrep (if installed)
- SQL injection fixture test now passes with real Semgrep"
```

---

## Summary of Phase 1

**Completed:**
- ✅ Added SEMGREP to ScannerTool enum
- ✅ Created SemgrepScanner class skeleton
- ✅ Implemented Semgrep availability check with graceful degradation
- ✅ Added scan method signature
- ✅ Created SQL injection test fixture
- ✅ Downloaded and configured initial Semgrep rules (3 Python SQL injection rules)
- ✅ Implemented command building with language filtering
- ✅ Implemented JSON output parsing
- ✅ Implemented full scan execution with timeout/cancellation

**Test Results:** 13+ tests passing (scan execution, parsing, command building, availability checks)

**Next Phase:** Phase 2 - MCP Tools (run_semgrep and filter_semgrep_results)

---

## Phase 2: MCP Tool Integration

### Task 10: Add Database Schema for Semgrep Results

**Files:**
- Modify: `models/database.py` (or schema initialization file)
- Create: `tests/models/test_semgrep_schema.py`

**Step 1: Write the failing test**

Create `tests/models/test_semgrep_schema.py`:

```python
"""Tests for Semgrep database schema."""
import pytest
import sqlite3
from pathlib import Path


def test_semgrep_raw_results_table_exists(tmp_path):
    """Verify semgrep_raw_results table schema."""
    db_path = tmp_path / "test.db"
    conn = sqlite3.connect(str(db_path))
    cursor = conn.cursor()

    # Import and run schema creation
    from models.database import create_tables
    create_tables(conn)

    # Verify table exists
    cursor.execute("""
        SELECT name FROM sqlite_master
        WHERE type='table' AND name='semgrep_raw_results'
    """)
    result = cursor.fetchone()
    assert result is not None

    # Verify columns
    cursor.execute("PRAGMA table_info(semgrep_raw_results)")
    columns = {row[1]: row[2] for row in cursor.fetchall()}

    assert "id" in columns
    assert "session_id" in columns
    assert "file_path" in columns
    assert "line_number" in columns
    assert "rule_id" in columns
    assert "severity" in columns
    assert "message" in columns
    assert "snippet" in columns
    assert "metadata" in columns  # JSON
    assert "filtered" in columns  # BOOLEAN
    assert "filter_reason" in columns

    conn.close()


def test_semgrep_indices_created(tmp_path):
    """Verify performance indices created."""
    db_path = tmp_path / "test.db"
    conn = sqlite3.connect(str(db_path))
    cursor = conn.cursor()

    from models.database import create_tables
    create_tables(conn)

    # Check indices
    cursor.execute("""
        SELECT name FROM sqlite_master
        WHERE type='index' AND tbl_name='semgrep_raw_results'
    """)
    indices = {row[0] for row in cursor.fetchall()}

    assert "idx_semgrep_session" in indices
    assert "idx_semgrep_filtered" in indices

    conn.close()
```

**Step 2: Run test to verify it fails**

```bash
pytest tests/models/test_semgrep_schema.py::test_semgrep_raw_results_table_exists -v
```

Expected output:
```
AttributeError: 'Connection' object has no attribute 'semgrep_raw_results'
 (or table not found error)
FAILED
```

**Step 3: Add schema definition**

Find the database schema file (likely `models/database.py` or similar) and add:

```python
# Add to schema creation function
def create_semgrep_tables(conn):
    """Create tables for Semgrep integration."""
    conn.execute("""
        CREATE TABLE IF NOT EXISTS semgrep_raw_results (
            id TEXT PRIMARY KEY,
            session_id TEXT NOT NULL,
            file_path TEXT NOT NULL,
            line_number INTEGER NOT NULL,
            end_line_number INTEGER,
            column_number INTEGER,
            rule_id TEXT NOT NULL,
            category TEXT NOT NULL,
            severity TEXT NOT NULL,
            message TEXT NOT NULL,
            snippet TEXT NOT NULL,
            metadata JSON,
            filtered BOOLEAN DEFAULT FALSE,
            filter_reason TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (session_id) REFERENCES sessions(id) ON DELETE CASCADE
        )
    """)

    # Create indices for performance
    conn.execute("""
        CREATE INDEX IF NOT EXISTS idx_semgrep_session
        ON semgrep_raw_results(session_id)
    """)

    conn.execute("""
        CREATE INDEX IF NOT EXISTS idx_semgrep_filtered
        ON semgrep_raw_results(session_id, filtered)
    """)

    conn.commit()

# Call this in create_tables() function
def create_tables(conn):
    # ... existing table creation ...
    create_semgrep_tables(conn)
```

**Step 4: Run tests to verify they pass**

```bash
pytest tests/models/test_semgrep_schema.py -v
```

Expected output:
```
test_semgrep_raw_results_table_exists PASSED
test_semgrep_indices_created PASSED
```

**Step 5: Commit**

```bash
git add models/database.py tests/models/test_semgrep_schema.py
git commit -m "feat(db): add semgrep_raw_results table schema

- Create semgrep_raw_results table for raw scan results
- Store finding details (file, line, rule, severity, message, snippet)
- Add filtered boolean and filter_reason for LLM filtering
- Create indices on session_id and (session_id, filtered)
- Cascade delete when session deleted
- Test table creation and indices"
```

---

**[Continue with Tasks 11-20 for MCP tools, Phase 3 for pre-scan integration, Phase 4 for multi-language rules, etc.]**

---

## Execution Notes

**Test Execution Pattern:**
```bash
# Run specific test
pytest path/to/test.py::test_name -v

# Run all tests in file
pytest path/to/test.py -v

# Run tests matching pattern
pytest -k "pattern" -v

# Run with coverage
pytest --cov=services --cov-report=term-missing
```

**Commit Message Format:**
```
<type>(<scope>): <subject>

<body>

<footer>
```

Types: feat, fix, test, refactor, docs, chore

**Development Flow:**
1. Write failing test
2. Run test - verify it fails with expected error
3. Write minimal code to pass test
4. Run test - verify it passes
5. Commit with descriptive message
6. Repeat

**DRY Principle:** Don't repeat logic. Extract to functions/methods.

**YAGNI Principle:** Implement only what's needed now. No speculative features.

**TDD Principle:** Test first, code second. Red → Green → Refactor.

---

## Estimated Timeline

**Phase 1:** 6-8 hours (9 tasks completed)
**Phase 2:** 8-10 hours (MCP tools + database integration)
**Phase 3:** 4-6 hours (Pre-scan orchestrator integration)
**Phase 4:** 10-12 hours (Multi-language rule curation)
**Phase 5:** 4-6 hours (Polish, documentation, error handling)
**Phase 6:** 8-10 hours (Production validation, performance tuning)

**Total:** 40-52 hours (~1-1.5 weeks of focused development)
