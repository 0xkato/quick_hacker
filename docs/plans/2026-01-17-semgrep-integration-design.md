# Semgrep Integration Design
**Date:** 2026-01-17
**Status:** Design Approved
**Author:** Claude Sonnet 4.5 with 0xkato

---

## Overview

Integrate Semgrep as a dual-mode sink discovery tool to help QuickHack find more vulnerabilities by identifying more potential sinks for LLM investigation. Semgrep operates as both a pre-scan phase and an on-demand LLM tool, with multi-language support from day one.

## Goals

1. **More Sinks → More Vulnerabilities:** Use Semgrep's battle-tested patterns to discover vulnerability sinks the LLM should investigate
2. **LLM-Driven Quality:** Semgrep identifies "where to look", LLM determines "is this exploitable"
3. **Multi-Language Coverage:** Support C/C++, Python, JavaScript, Java with curated high/critical rules
4. **Autonomous Usage:** Semgrep is just another tool in the LLM's toolbox, no special workflows
5. **Intelligent Filtering:** LLM-based filtering to avoid noise from third-party/test/config files

## Architecture

### High-Level Design

```
┌─────────────────────────────────────────────────────────────┐
│                    Session Start                            │
└──────────────────────┬──────────────────────────────────────┘
                       ↓
              ┌────────────────────┐
              │  Pre-Scan Phase    │
              │  (Semgrep runs on  │
              │   entire codebase) │
              └────────┬───────────┘
                       ↓
              ┌────────────────────┐
              │ LLM Filter Phase   │
              │ (Reviews results,  │
              │  discards noise)   │
              └────────┬───────────┘
                       ↓
              ┌────────────────────┐
              │ Candidate Sinks    │
              │ (Stored for LLM    │
              │  investigation)    │
              └────────┬───────────┘
                       ↓
       ┌───────────────┴───────────────┐
       ↓                               ↓
┌──────────────┐              ┌──────────────┐
│ LLM Analysis │              │ On-Demand    │
│ (Guided by   │◄─────────────┤ run_semgrep  │
│  pre-scan)   │              │ Tool Calls   │
└──────┬───────┘              └──────────────┘
       ↓
┌──────────────┐
│ LLM validates│
│ builds proof │
│ checklist    │
└──────┬───────┘
       ↓
┌──────────────┐
│ Finding →    │
│ Triage →     │
│ Storage      │
└──────────────┘
```

### Dual-Mode Operation

**Pre-Scan Mode (Session Start):**
- Semgrep runs automatically across codebase with high/critical severity filters
- Results stored as "candidate sinks" in temporary storage
- LLM receives summary: "Semgrep found 847 potential sinks across 234 files"
- LLM filters results using `filter_semgrep_results` tool to remove noise
- Filtered results guide LLM's investigation priorities

**On-Demand Mode (During Analysis):**
- LLM has access to `run_semgrep` tool anytime during investigation
- Can search for specific patterns: `run_semgrep(category="sql-injection", path="app/db/")`
- Validates suspicions: "Is this pattern a known vulnerability?"
- Discovers additional sinks: "Find all command execution points in this file"

**Key Principle:** Semgrep identifies candidate sinks, LLM validates exploitability. Only LLM-validated discoveries become Findings that enter the triage pipeline.

---

## Component Design

### 1. Security Scanner Implementation

**File:** `backend/services/security_scanners/semgrep.py`

```python
class SemgrepScanner(BaseSecurityScanner):
    """Semgrep-based vulnerability pattern scanner.

    Executes Semgrep with curated rule sets and returns structured findings
    with rich context for LLM analysis.
    """

    def __init__(self, workspace_root: str, rules_dir: str | None = None):
        self.workspace_root = Path(workspace_root)
        self.rules_dir = rules_dir or self._default_rules_dir()
        self._check_semgrep_available()

    def scan(
        self,
        workspace_policy: WorkspacePolicy,
        limits: ScanLimits,
        language: str | None = None,
        severity: list[str] | None = None,
        category: str | None = None,
        path: str | None = None
    ) -> ScanResult:
        """Run Semgrep scan with filters.

        Args:
            workspace_policy: Security boundaries (inherits excluded_dirs)
            limits: Timeout and cancellation support
            language: Filter by language (python, javascript, c, cpp, java)
            severity: Filter by severity (default: ["high", "critical"])
            category: Filter by category (sql-injection, command-injection, etc.)
            path: Specific file/directory to scan

        Returns:
            ScanResult with findings containing rich context
        """
        severity = severity or ["high", "critical"]
        scan_path = path or str(self.workspace_root)

        # Build Semgrep command
        cmd = self._build_command(language, severity, category, scan_path)

        # Execute with timeout and cancellation support
        start_time = time.time()
        process = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )

        findings = []
        try:
            while process.poll() is None:
                # Check cancellation
                if limits.cancel_path and Path(limits.cancel_path).exists():
                    process.terminate()
                    return ScanResult(cancelled=True, findings=findings)

                # Check timeout
                if time.time() - start_time > limits.max_runtime_s:
                    process.terminate()
                    return ScanResult(timeout=True, findings=findings)

                time.sleep(0.1)

            # Parse results
            stdout, stderr = process.communicate()
            findings = self._parse_semgrep_output(stdout)

        except Exception as e:
            logger.error(f"Semgrep scan failed: {e}")
            return ScanResult(error=str(e), findings=findings)

        return ScanResult(findings=findings)

    def _parse_semgrep_output(self, output: str) -> list[ScanFinding]:
        """Parse Semgrep JSON output into ScanFinding objects."""
        try:
            data = json.loads(output)
        except json.JSONDecodeError:
            return []

        findings = []
        for result in data.get("results", []):
            # Extract rich context
            finding = ScanFinding(
                tool=ScannerTool.SEMGREP,
                file=result["path"],
                line=result["start"]["line"],
                end_line=result["end"]["line"],
                column=result["start"]["col"],
                severity=self._map_severity(result["extra"]["severity"]),
                rule_id=result["check_id"],
                category=self._extract_category(result["check_id"]),
                message=result["extra"]["message"],
                snippet=result["extra"]["lines"],
                metadata={
                    "cwe": result["extra"].get("metadata", {}).get("cwe"),
                    "owasp": result["extra"].get("metadata", {}).get("owasp"),
                    "confidence": result["extra"].get("metadata", {}).get("confidence", "high")
                }
            )
            findings.append(finding)

        return findings

    def _check_semgrep_available(self) -> None:
        """Verify Semgrep is installed and accessible."""
        try:
            result = subprocess.run(
                ["semgrep", "--version"],
                capture_output=True,
                timeout=5
            )
            if result.returncode != 0:
                raise SemgrepNotAvailableError("Semgrep failed to execute")
        except FileNotFoundError:
            raise SemgrepNotAvailableError("Semgrep not found in PATH")
        except subprocess.TimeoutExpired:
            raise SemgrepNotAvailableError("Semgrep version check timed out")

    def get_tool_name(self) -> ScannerTool:
        return ScannerTool.SEMGREP
```

**Graceful Degradation:**
- If Semgrep unavailable, pre-scan skipped
- `run_semgrep` tool returns error but doesn't fail session
- LLM continues analysis without Semgrep (existing flow unaffected)

### 2. MCP Tool Interface

**File:** `backend/quickhack_mcp/quickhack_mcp_server.py`

**Tool 1: run_semgrep**
```python
{
  "name": "run_semgrep",
  "description": "Execute Semgrep to find vulnerability patterns. Returns detailed findings with code snippets, CWE mappings, and severity ratings. Use this to discover potential sinks for investigation.",
  "inputSchema": {
    "type": "object",
    "properties": {
      "language": {
        "type": "string",
        "enum": ["python", "javascript", "c", "cpp", "java"],
        "description": "Filter by programming language"
      },
      "severity": {
        "type": "array",
        "items": {"type": "string", "enum": ["critical", "high", "medium", "low"]},
        "default": ["high", "critical"],
        "description": "Filter by severity levels"
      },
      "category": {
        "type": "string",
        "enum": ["sql-injection", "command-injection", "xss", "path-traversal",
                 "buffer-overflow", "use-after-free", "deserialization", "code-injection"],
        "description": "Filter by vulnerability category"
      },
      "path": {
        "type": "string",
        "description": "Specific file or directory to scan (relative to repo root)"
      },
      "rule_ids": {
        "type": "array",
        "items": {"type": "string"},
        "description": "Specific Semgrep rule IDs to run"
      }
    }
  }
}
```

**Returns:**
```json
{
  "results": [
    {
      "file": "app/db.py",
      "line": 45,
      "end_line": 45,
      "column": 12,
      "severity": "high",
      "rule_id": "python.lang.security.audit.formatted-sql-query",
      "category": "sql-injection",
      "message": "Formatted SQL query detected. Use parameterized queries to prevent SQL injection.",
      "snippet": "cursor.execute(f'SELECT * FROM users WHERE id={user_id}')",
      "cwe": "CWE-89",
      "owasp": "A03:2021 - Injection",
      "confidence": "high",
      "validity_checklist": "sql_injection"
    }
  ],
  "total": 1,
  "scan_time_ms": 234
}
```

**Tool 2: filter_semgrep_results**
```python
{
  "name": "filter_semgrep_results",
  "description": "Review and filter Semgrep pre-scan results to remove noise from third-party libraries, test files, and generated code. Use this to focus on first-party application code.",
  "inputSchema": {
    "type": "object",
    "properties": {
      "action": {
        "type": "string",
        "enum": ["review", "apply_filter"],
        "description": "review: Get batch of results to classify. apply_filter: Submit filtering decisions"
      },
      "batch_size": {
        "type": "integer",
        "default": 50,
        "description": "Number of results to return per review batch"
      },
      "offset": {
        "type": "integer",
        "default": 0,
        "description": "Starting offset for pagination"
      },
      "decisions": {
        "type": "object",
        "description": "Map of finding_id to {keep: bool, reason: str}",
        "additionalProperties": {
          "type": "object",
          "properties": {
            "keep": {"type": "boolean"},
            "reason": {"type": "string"}
          },
          "required": ["keep", "reason"]
        }
      }
    },
    "required": ["action"]
  }
}
```

**Workflow Example:**
```python
# Step 1: LLM reviews first batch
filter_semgrep_results(action="review", batch_size=50, offset=0)
# Returns 50 results for classification

# Step 2: LLM provides decisions
filter_semgrep_results(
  action="apply_filter",
  decisions={
    "sem_001": {"keep": true, "reason": "first-party database code"},
    "sem_002": {"keep": false, "reason": "vendored third-party library"},
    "sem_003": {"keep": false, "reason": "test fixture"},
    # ... 47 more
  }
)

# Step 3: Review next batch
filter_semgrep_results(action="review", batch_size=50, offset=50)
# Continues until all results filtered
```

### 3. Integration with Agent Orchestrator

**File:** `backend/services/agent_orchestrator.py`

```python
class AgentOrchestrator:
    async def run_session(self, session_id: str):
        """Run analysis session with Semgrep pre-scan."""
        session = self.session_service.get(session_id)

        # Existing setup...
        base_prompt = self._build_system_prompt(session)

        # NEW: Pre-scan phase (if enabled)
        prescan_summary = ""
        if self.enable_semgrep_prescan:
            try:
                prescan_summary = await self._run_semgrep_prescan(session)
            except SemgrepNotAvailableError as e:
                logger.warning(f"Semgrep unavailable: {e}")
                # Continue without pre-scan

        # Inject pre-scan context into initial prompt
        if prescan_summary:
            initial_prompt = f"{base_prompt}\n\n{prescan_summary}"
        else:
            initial_prompt = base_prompt

        # Continue with existing agent loop...

    async def _run_semgrep_prescan(self, session: Session) -> str:
        """Run Semgrep pre-scan and return summary for LLM."""
        scanner = SemgrepScanner(
            workspace_root=self.repo_root,
            rules_dir=self.semgrep_rules_dir
        )

        # Run scan
        result = await asyncio.to_thread(
            scanner.scan,
            workspace_policy=self._get_workspace_policy(),
            limits=self._get_scan_limits()
        )

        # Store raw results
        await self._store_semgrep_results(session.id, result.findings)

        # Build summary for LLM
        summary = f"""
## Semgrep Pre-Scan Results

Semgrep discovered {len(result.findings)} potential vulnerability sinks:
- {self._count_by_severity(result.findings, "critical")} critical severity
- {self._count_by_severity(result.findings, "high")} high severity

Use the `filter_semgrep_results` tool to review and filter these results.
Focus on first-party application code and discard third-party libraries, tests, and generated code.

After filtering, investigate the remaining candidate sinks to determine if they are exploitable.
"""
        return summary

    async def _store_semgrep_results(
        self,
        session_id: str,
        findings: list[ScanFinding]
    ):
        """Store raw Semgrep results for filtering."""
        for finding in findings:
            await self.db.execute("""
                INSERT INTO semgrep_raw_results
                (id, session_id, file_path, line_number, rule_id,
                 severity, message, snippet, metadata)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                f"sem_{uuid.uuid4().hex[:8]}",
                session_id,
                finding.file,
                finding.line,
                finding.rule_id,
                finding.severity.value,
                finding.message,
                finding.snippet,
                json.dumps(finding.metadata)
            ))
```

### 4. Database Schema

**File:** `backend/models/schemas.py`

```sql
-- Temporary storage for raw Semgrep results (per-session)
CREATE TABLE semgrep_raw_results (
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
    metadata JSON,  -- CWE, OWASP, confidence, validity_checklist
    filtered BOOLEAN DEFAULT FALSE,
    filter_reason TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (session_id) REFERENCES sessions(id) ON DELETE CASCADE
);

CREATE INDEX idx_semgrep_session ON semgrep_raw_results(session_id);
CREATE INDEX idx_semgrep_filtered ON semgrep_raw_results(session_id, filtered);
```

**Enum Addition:**
```python
class ScannerTool(str, Enum):
    SECRETS = "secrets"
    DEPENDENCIES = "dependencies"
    GREP = "grep"
    SEMGREP = "semgrep"  # NEW
```

---

## Rule Management

### Directory Structure

```
backend/services/security_scanners/semgrep_rules/
├── c/                           # C/C++ rules (from 0xdea/semgrep-rules)
│   ├── buffer-overflow.yaml
│   ├── use-after-free.yaml
│   ├── double-free.yaml
│   ├── format-string.yaml
│   ├── integer-overflow.yaml
│   └── ... (40+ rules)
├── python/                      # Python rules (curated from Semgrep Registry)
│   ├── sql-injection.yaml
│   ├── command-injection.yaml
│   ├── code-injection.yaml
│   ├── deserialization.yaml
│   ├── path-traversal.yaml
│   └── ... (~15-20 rules)
├── javascript/                  # JavaScript rules
│   ├── xss.yaml
│   ├── prototype-pollution.yaml
│   ├── command-injection.yaml
│   ├── path-traversal.yaml
│   └── ... (~15-20 rules)
├── java/                        # Java rules
│   ├── sql-injection.yaml
│   ├── deserialization.yaml
│   ├── xxe.yaml
│   └── ... (~10-15 rules)
├── metadata.json                # Rule metadata and mappings
└── README.md                    # Curation criteria and sources
```

### metadata.json Structure

```json
{
  "rules": {
    "python.lang.security.audit.formatted-sql-query": {
      "severity": "high",
      "category": "sql-injection",
      "validity_checklist": "sql_injection",
      "sink_type": "sql_execution",
      "cwe": "CWE-89",
      "owasp": "A03:2021 - Injection",
      "source": "semgrep-registry",
      "curated_date": "2026-01-17",
      "notes": "Detects f-string and .format() SQL queries"
    },
    "c.lang.security.buffer-overflow-strcpy": {
      "severity": "critical",
      "category": "buffer-overflow",
      "validity_checklist": "memory_safety",
      "sink_type": "memory_write",
      "cwe": "CWE-120",
      "source": "0xdea/semgrep-rules",
      "curated_date": "2026-01-17",
      "notes": "Unbounded strcpy() usage"
    }
  },
  "categories": {
    "sql-injection": {
      "description": "SQL query construction with user input",
      "sink_types": ["sql_execution", "orm_raw_query"]
    },
    "command-injection": {
      "description": "OS command execution with user input",
      "sink_types": ["shell_execution", "subprocess_call"]
    },
    "buffer-overflow": {
      "description": "Unbounded memory operations",
      "sink_types": ["memory_write", "memory_copy"]
    }
  }
}
```

### Initial Rule Curation

**Sources:**
1. **C/C++:** All rules from [0xdea/semgrep-rules](https://github.com/0xdea/semgrep-rules) (40+ rules, memory safety focused)
2. **Python:** Semgrep Registry security rules filtered by "high"/"critical" + manual review
3. **JavaScript:** Semgrep Registry + OWASP top 10 coverage
4. **Java:** Semgrep Registry enterprise rules (deserialization, XXE, SQL injection)

**Curation Criteria:**
- High/critical severity only
- Low false positive rate (based on Semgrep Registry ratings)
- Maps to OWASP Top 10 or CWE
- Aligns with existing QuickHack validity checklists
- Active maintenance (rules updated in last 12 months)

**Target:** 80-100 curated rules across 4 languages for MVP

### Rule Update Strategy

**Quarterly Review Process:**
1. Check Semgrep Registry for new/updated security rules
2. Review community feedback on false positives
3. Add new rules that meet curation criteria
4. Update metadata.json with new mappings
5. Add test fixtures for new rules
6. Update CHANGELOG with rule additions

**Community Contributions:**
- Rules can be contributed via PR
- Must include: rule file, metadata entry, test fixture
- Reviewed for quality and false positive rate
- Maintainer approval required

---

## LLM-Based Result Filtering

### Problem

Semgrep scanning entire codebase returns 100s-1000s of results, many from:
- Third-party libraries (vendor/, node_modules/, site-packages/)
- Test files (*_test.py, *.test.js, /tests/)
- Generated code (migrations/, .proto files)
- Config files (webpack.config.js, setup.py)

Hardcoded exclusion lists are brittle and miss context.

### Solution: Scan-Then-Filter

**Workflow:**

1. **Full Scan:** Semgrep runs on entire codebase (respecting only basic WorkspacePolicy boundaries)
2. **Store Raw Results:** All findings stored in `semgrep_raw_results` table
3. **LLM Summary:** LLM receives: "Semgrep found 847 potential sinks across 234 files"
4. **Batch Review:** LLM calls `filter_semgrep_results(action="review")` to get batches of 50 results
5. **LLM Classification:** LLM reviews file paths, patterns, and decides keep/discard for each
6. **Apply Filter:** LLM calls `filter_semgrep_results(action="apply_filter", decisions={...})`
7. **Repeat:** Continue until all results filtered
8. **Candidate Sinks:** Kept results become candidate sinks for investigation

**LLM Filtering Heuristics:**

The LLM learns to identify low-value files based on:

**Path Patterns:**
- Third-party: `/vendor/`, `/node_modules/`, `/site-packages/`, imports from packages
- Tests: `/tests/`, `/spec/`, `_test.`, `.test.`, `test_`, `*_spec.`
- Generated: `// AUTO-GENERATED`, `DO NOT EDIT`, `.pb.`, `/migrations/`
- Config: `.config.`, `webpack.`, `rollup.`, `setup.py`

**Content Markers:**
- License headers indicating third-party code
- Comments like "vendored from", "copied from"
- Test framework imports (pytest, jest, junit)

**Contextual Understanding:**
- If finding is in dependency but application imports it → might be worth investigating
- If test file tests actual production code pattern → could indicate real vulnerability
- If generated file is from user input → still relevant

**Example LLM Decision Logic:**
```
Finding: sql-injection in vendor/sqlalchemy/engine/base.py
Decision: DISCARD - "Third-party library code, not application logic"

Finding: command-injection in tests/test_security.py
Decision: DISCARD - "Test fixture demonstrating vulnerability, not production code"

Finding: buffer-overflow in app/parser.c
Decision: KEEP - "First-party application code, high priority"

Finding: xss in node_modules/react-dom/cjs/react-dom.production.min.js
Decision: DISCARD - "Minified third-party library"
```

**Efficiency:**
- Typical 800 findings → ~200 kept after filtering
- ~16 LLM turns (50 results per batch)
- Takes ~2-3 minutes of LLM time
- Drastically improves signal-to-noise for investigation phase

---

## Integration with Validity Checklists

### Mapping Semgrep Rules to Checklists

Each Semgrep rule maps to a QuickHack validity checklist category. When the LLM investigates a Semgrep-discovered sink, it automatically loads the appropriate checklist.

**Example Flow:**

1. Semgrep finds: `python.lang.security.audit.formatted-sql-query` in `app/db.py:45`
2. Metadata maps rule to: `validity_checklist: "sql_injection"`
3. LLM investigates sink using `prompting/validity_checklists/sql_injection.md`
4. LLM follows checklist: verify sink, trace dataflow, check reachability, etc.
5. LLM builds proof checklist and creates Finding
6. Finding enters triage pipeline with full evidence

**Validity Checklist Coverage:**

| Semgrep Category | Validity Checklist | Languages |
|------------------|-------------------|-----------|
| sql-injection | sql_injection.md | Python, Java, JS |
| command-injection | command_injection.md | Python, JS, Java |
| buffer-overflow, use-after-free | memory_safety.md | C, C++, Rust |
| xss | xss.md | JS, Python (templates) |
| path-traversal | path_traversal.md | All |
| code-injection | code_injection.md | Python, JS, Ruby |
| deserialization | deserialization.md | Python, Java |
| ssrf | ssrf.md | Python, JS, Java |
| auth-bypass, idor | auth_idor.md | All |

**Benefit:** Semgrep provides structured starting points, validity checklists provide investigation methodology. Together they create comprehensive vulnerability validation.

---

## Error Handling & Edge Cases

### 1. Semgrep Installation

**Problem:** Semgrep not installed or not in PATH

**Detection:**
```python
def _check_semgrep_available(self):
    try:
        subprocess.run(["semgrep", "--version"],
                      capture_output=True, timeout=5)
    except FileNotFoundError:
        raise SemgrepNotAvailableError("Semgrep not in PATH")
```

**Handling:**
- Pre-scan: Skip silently, log warning, continue session
- On-demand tool call: Return error to LLM: `{"error": "semgrep_unavailable", "message": "Semgrep not installed. Install with: pip install semgrep"}`
- LLM adapts: Continues analysis without Semgrep (existing workflow unaffected)

**Installation Documentation:**
```bash
# Add to README.md
pip install semgrep
# or
brew install semgrep
```

### 2. Performance & Timeouts

**Problem:** Large codebases (10,000+ files) can take minutes to scan

**Solution - Timeout & Cancellation:**
```python
def scan(self, limits: ScanLimits):
    process = subprocess.Popen(["semgrep", ...])
    start = time.time()

    while process.poll() is None:
        # Check cancellation flag
        if Path(limits.cancel_path).exists():
            process.terminate()
            return ScanResult(cancelled=True)

        # Check timeout
        if time.time() - start > limits.max_runtime_s:
            process.terminate()
            return ScanResult(timeout=True, partial_results=[...])

        time.sleep(0.1)
```

**Partial Results:**
- Semgrep outputs results incrementally (JSON streaming)
- If timeout, return what was found so far
- LLM receives: `{"timeout": true, "results": [...], "note": "Scan timed out, partial results"}`

**Default Limits:**
- Pre-scan timeout: 60 seconds (configurable)
- On-demand timeout: 30 seconds
- Cancellation: Respects session-level cancel flag

### 3. Rule Parsing Errors

**Problem:** Malformed YAML in rule files

**Detection:**
```python
def load_rules(self) -> list[Path]:
    valid_rules = []
    for rule_file in self.rules_dir.glob("**/*.yaml"):
        try:
            with open(rule_file) as f:
                yaml.safe_load(f)
            valid_rules.append(rule_file)
        except yaml.YAMLError as e:
            logger.warning(f"Skipping invalid rule {rule_file}: {e}")
    return valid_rules
```

**Handling:**
- Skip invalid rules, continue with valid ones
- Log warnings for debugging
- Don't fail entire scan due to one bad rule

**Validation:**
- Pre-commit hook validates all rule files parse correctly
- CI test: `test_all_rules_are_valid_yaml()`

### 4. LLM Filter Tool Misuse

**Problem:** LLM provides malformed filter decisions

**Validation:**
```python
def apply_filter(self, decisions: dict):
    for finding_id, decision in decisions.items():
        # Validate finding_id exists
        if finding_id not in self.results:
            logger.warning(f"Unknown finding_id: {finding_id}")
            continue

        # Validate decision structure
        if not isinstance(decision, dict) or "keep" not in decision:
            logger.warning(f"Malformed decision for {finding_id}")
            continue

        # Apply valid decision
        self._apply_decision(finding_id, decision)
```

**Graceful Degradation:**
- Skip malformed decisions, don't fail entire batch
- Log warnings for debugging
- Continue with remaining valid decisions

### 5. Memory Constraints

**Problem:** 5000+ Semgrep results could exhaust memory

**Solution - Streaming & Pagination:**
```python
def store_results(self, session_id: str, findings: list[ScanFinding]):
    """Stream results to database incrementally."""
    batch_size = 100
    for i in range(0, len(findings), batch_size):
        batch = findings[i:i+batch_size]
        self.db.executemany("INSERT INTO semgrep_raw_results ...", batch)
        self.db.commit()

def get_results_batch(self, session_id: str, offset: int, limit: int):
    """Paginated retrieval for LLM filtering."""
    return self.db.execute("""
        SELECT * FROM semgrep_raw_results
        WHERE session_id = ? AND filtered = FALSE
        LIMIT ? OFFSET ?
    """, (session_id, limit, offset))
```

**Benefits:**
- Never load all results into memory at once
- LLM filter tool naturally paginates (batches of 50)
- Database handles large result sets efficiently

---

## Testing Strategy

### 1. Unit Tests

**File:** `backend/tests/services/test_semgrep_scanner.py`

```python
def test_semgrep_finds_known_sql_injection(tmp_path):
    """Verify Semgrep detects SQL injection pattern."""
    vuln_file = tmp_path / "vuln.py"
    vuln_file.write_text("""
        import sqlite3
        def search(user_input):
            cursor.execute(f"SELECT * FROM users WHERE name = '{user_input}'")
    """)

    scanner = SemgrepScanner(str(tmp_path))
    result = scanner.scan(...)

    assert len(result.findings) == 1
    assert "sql-injection" in result.findings[0].rule_id
    assert result.findings[0].file == "vuln.py"
    assert result.findings[0].severity == Severity.HIGH

def test_semgrep_finds_buffer_overflow(tmp_path):
    """Verify Semgrep detects buffer overflow in C."""
    vuln_file = tmp_path / "vuln.c"
    vuln_file.write_text("""
        #include <string.h>
        void copy(char *input) {
            char buffer[64];
            strcpy(buffer, input);  // Unbounded copy
        }
    """)

    scanner = SemgrepScanner(str(tmp_path))
    result = scanner.scan(language="c")

    assert len(result.findings) == 1
    assert "buffer-overflow" in result.findings[0].category

def test_semgrep_respects_workspace_policy():
    """Verify WorkspacePolicy boundaries enforced."""
    # Test that symlinks, oversized files rejected
    # Test that excluded_dirs honored

def test_semgrep_timeout_returns_partial_results():
    """Verify timeout handling with partial results."""
    limits = ScanLimits(max_runtime_s=1)  # Short timeout
    result = scanner.scan(limits=limits)

    assert result.timeout is True
    assert len(result.findings) > 0  # Partial results

def test_semgrep_graceful_degradation_when_unavailable():
    """Verify system continues when Semgrep not installed."""
    with mock.patch('subprocess.run', side_effect=FileNotFoundError):
        with pytest.raises(SemgrepNotAvailableError):
            scanner = SemgrepScanner("/path")
```

### 2. Integration Tests

**File:** `backend/tests/integration/test_semgrep_mcp_tools.py`

```python
@pytest.mark.asyncio
async def test_run_semgrep_tool_returns_rich_context():
    """Verify run_semgrep MCP tool returns expected format."""
    server = QuickHackMCPServer(tool_core)

    response = await server.handle_request({
        "method": "tools/call",
        "params": {
            "name": "run_semgrep",
            "arguments": {"language": "python", "severity": ["high"]}
        }
    })

    results = response["result"]["content"][0]["results"]
    assert len(results) > 0
    assert "file" in results[0]
    assert "snippet" in results[0]
    assert "cwe" in results[0]
    assert "validity_checklist" in results[0]

@pytest.mark.asyncio
async def test_filter_semgrep_results_workflow():
    """Test full LLM filtering workflow."""
    # Populate semgrep_raw_results
    session_id = "test_session"
    findings = [create_test_finding() for _ in range(100)]
    await store_semgrep_results(session_id, findings)

    # Step 1: Review batch
    response = await server.handle_request({
        "method": "tools/call",
        "params": {
            "name": "filter_semgrep_results",
            "arguments": {"action": "review", "batch_size": 50}
        }
    })
    assert len(response["result"]["content"]) == 50

    # Step 2: Apply filter
    decisions = {
        finding["id"]: {"keep": i < 25, "reason": "test"}
        for i, finding in enumerate(response["result"]["content"])
    }
    await server.handle_request({
        "method": "tools/call",
        "params": {
            "name": "filter_semgrep_results",
            "arguments": {"action": "apply_filter", "decisions": decisions}
        }
    })

    # Verify filtering applied
    filtered = await get_filtered_results(session_id)
    assert len(filtered) == 25
```

### 3. End-to-End Tests

**File:** `backend/tests/e2e/test_semgrep_integration.py`

```python
@pytest.mark.asyncio
async def test_full_session_with_semgrep_prescan():
    """Test complete session flow with Semgrep integration."""
    # Create project with vulnerable code
    project = await create_test_project_with_vulnerabilities()

    # Start session with Semgrep pre-scan enabled
    session = await orchestrator.create_session(
        project_id=project.id,
        enable_semgrep_prescan=True
    )

    # Verify pre-scan ran
    prescan_results = await get_semgrep_raw_results(session.id)
    assert len(prescan_results) > 0

    # Verify LLM received candidate sinks
    # (check initial prompt contains Semgrep summary)

    # Run session
    await orchestrator.run_session(session.id)

    # Verify LLM investigated sinks
    findings = await get_findings(session.id)
    assert len(findings) > 0

    # Verify findings have proof checklists
    for finding in findings:
        assert finding.proof_checklist is not None
        assert finding.disposition is not None
```

### 4. Rule Quality Tests

**File:** `backend/tests/services/test_semgrep_rules.py`

```python
def test_all_rules_are_valid_yaml():
    """Verify all rule files parse correctly."""
    rules_dir = Path("backend/services/security_scanners/semgrep_rules")

    for rule_file in rules_dir.glob("**/*.yaml"):
        with open(rule_file) as f:
            try:
                data = yaml.safe_load(f)
                assert "rules" in data, f"{rule_file} missing 'rules' key"
            except yaml.YAMLError as e:
                pytest.fail(f"Invalid YAML in {rule_file}: {e}")

def test_rules_have_required_metadata():
    """Verify metadata.json is complete."""
    metadata_path = Path("backend/services/security_scanners/semgrep_rules/metadata.json")
    with open(metadata_path) as f:
        metadata = json.load(f)

    rules = metadata["rules"]
    for rule_id, info in rules.items():
        assert "severity" in info, f"{rule_id} missing severity"
        assert "category" in info, f"{rule_id} missing category"
        assert "validity_checklist" in info, f"{rule_id} missing validity_checklist"
        assert info["severity"] in ["critical", "high"], f"{rule_id} not high/critical"

def test_all_rule_files_have_metadata_entries():
    """Verify metadata.json covers all rule files."""
    rules_dir = Path("backend/services/security_scanners/semgrep_rules")
    metadata_path = rules_dir / "metadata.json"

    with open(metadata_path) as f:
        metadata = json.load(f)

    # Extract rule IDs from files
    file_rule_ids = set()
    for rule_file in rules_dir.glob("**/*.yaml"):
        with open(rule_file) as f:
            data = yaml.safe_load(f)
            for rule in data.get("rules", []):
                file_rule_ids.add(rule["id"])

    # Verify all are in metadata
    metadata_rule_ids = set(metadata["rules"].keys())
    missing = file_rule_ids - metadata_rule_ids
    assert not missing, f"Rules missing from metadata.json: {missing}"
```

### 5. Fixture Repository

**Directory:** `backend/tests/fixtures/vulnerable_code/`

```
vulnerable_code/
├── python/
│   ├── sql_injection.py          # f-string SQL query
│   ├── command_injection.py      # os.system(user_input)
│   ├── code_injection.py         # eval(user_input)
│   ├── deserialization.py        # pickle.load(user_data)
│   └── path_traversal.py         # open(user_path)
├── c/
│   ├── buffer_overflow.c         # strcpy() unbounded
│   ├── use_after_free.c          # free() then dereference
│   ├── format_string.c           # printf(user_input)
│   └── integer_overflow.c        # unchecked arithmetic
├── javascript/
│   ├── xss.js                    # innerHTML = userInput
│   ├── prototype_pollution.js   # Object.assign vulnerability
│   ├── command_injection.js     # child_process.exec(userInput)
│   └── path_traversal.js        # fs.readFile(userPath)
└── java/
    ├── sql_injection.java        # String concatenation in SQL
    ├── deserialization.java      # ObjectInputStream
    └── xxe.java                  # XML External Entity
```

Each file contains a known vulnerability that Semgrep should detect. Tests verify:
1. Semgrep finds the vulnerability
2. Correct rule triggers
3. Severity and category correct
4. Metadata (CWE, OWASP) present

---

## Implementation Phases

### Phase 1: Core Scanner (Week 1)
- [ ] Implement `SemgrepScanner` class
- [ ] Add `ScannerTool.SEMGREP` enum
- [ ] Curate initial rule set (C/C++ from 0xdea)
- [ ] Create `metadata.json`
- [ ] Unit tests for scanner
- [ ] Graceful degradation for missing Semgrep

### Phase 2: MCP Tools (Week 1-2)
- [ ] Implement `run_semgrep` MCP tool
- [ ] Implement `filter_semgrep_results` MCP tool
- [ ] Database schema: `semgrep_raw_results` table
- [ ] Integration tests for MCP tools

### Phase 3: Pre-Scan Integration (Week 2)
- [ ] Add pre-scan to `AgentOrchestrator`
- [ ] Store raw results in database
- [ ] Build summary for LLM
- [ ] E2E test with pre-scan

### Phase 4: Multi-Language Rules (Week 2-3)
- [ ] Curate Python rules from Semgrep Registry
- [ ] Curate JavaScript rules
- [ ] Curate Java rules
- [ ] Update `metadata.json` with all mappings
- [ ] Create vulnerability fixtures for all languages

### Phase 5: Polish & Documentation (Week 3)
- [ ] Performance optimization (timeout, cancellation)
- [ ] Error handling edge cases
- [ ] Update SYSTEM-SPECIFICATION.md
- [ ] Installation documentation
- [ ] User guide for interpreting Semgrep results

### Phase 6: Production Validation (Week 4)
- [ ] Test on real-world codebases
- [ ] Validate false positive rate
- [ ] Tune filtering heuristics
- [ ] Benchmark performance (scan times, memory usage)
- [ ] Production deployment

---

## Success Metrics

**Effectiveness:**
- **More Sinks Discovered:** Semgrep finds 3-5x more candidate sinks than LLM alone
- **Higher Coverage:** Vulnerabilities in less-explored code paths discovered
- **False Positive Rate:** <20% after LLM filtering (compared to raw Semgrep ~40-60%)

**Performance:**
- **Pre-Scan Speed:** <60 seconds for typical project (1000 files)
- **Filtering Efficiency:** LLM filters 800 results in <3 minutes (16 turns)
- **Memory Usage:** <500MB for 5000+ result sets

**Quality:**
- **Proof Checklist Completion:** 90%+ of Semgrep-guided findings have complete checklists
- **Triage Success:** 80%+ pass through triage as VALID or HARDENING (vs SPECULATIVE)

**Usability:**
- **Graceful Degradation:** Sessions continue without Semgrep if unavailable
- **LLM Autonomy:** LLM uses `run_semgrep` effectively without explicit instructions
- **Rule Maintenance:** Quarterly rule updates with <1 hour manual curation

---

## Future Enhancements

**Phase 2 (Post-MVP):**
- **Custom Rules:** UI for users to add project-specific Semgrep rules
- **Rule Suggestions:** LLM suggests new rules based on patterns it discovers
- **Performance Optimization:** Incremental scanning (only changed files)
- **Integration with External Tools:** Import Semgrep SARIF from CI/CD

**Phase 3 (Advanced):**
- **Rule Learning:** Track which rules produce high-value findings, prioritize them
- **Context-Aware Filtering:** Use project metadata (package.json, requirements.txt) to improve filtering
- **Differential Scanning:** Compare results across git commits to find new vulnerabilities

---

## Alternatives Considered

### Alternative 1: Pre-scan Only (No On-Demand Tool)
- **Pro:** Simpler implementation, predictable performance
- **Con:** LLM can't dynamically request additional scans during investigation
- **Decision:** Rejected - on-demand capability is valuable for deep investigations

### Alternative 2: LLM Tool Only (No Pre-Scan)
- **Pro:** Maximum LLM autonomy, no workflow changes
- **Con:** LLM might under-utilize Semgrep, miss valuable sinks
- **Decision:** Rejected - pre-scan provides consistent baseline coverage

### Alternative 3: Hardcoded Exclusion Lists
- **Pro:** Fast, no LLM filtering overhead
- **Con:** Brittle, misses context, hard to maintain across diverse projects
- **Decision:** Rejected - LLM-based filtering is more robust and adaptable

### Alternative 4: Semgrep Findings as Direct Findings
- **Pro:** Fast path to results, no LLM validation needed
- **Con:** High false positive rate, lacks proof checklists, no exploit validation
- **Decision:** Rejected - maintains QuickHack's quality standards with LLM validation

---

## Conclusion

Integrating Semgrep as a dual-mode sink discovery tool significantly enhances QuickHack's ability to find vulnerabilities by:

1. **Discovering More Sinks:** Leverages battle-tested patterns from 0xdea and Semgrep Registry
2. **Maintaining Quality:** LLM validates exploitability and builds proof checklists
3. **Multi-Language Coverage:** C/C++, Python, JavaScript, Java from day one
4. **Intelligent Filtering:** LLM-based filtering removes noise without brittle exclusion lists
5. **Autonomous Usage:** Semgrep as just another tool in the LLM's toolbox

The hybrid approach (pre-scan + on-demand tool) provides both consistent baseline coverage and dynamic investigation capability. LLM-based result filtering adapts to diverse project structures while avoiding hardcoded assumptions.

**Next Steps:** Proceed to implementation using superpowers:writing-plans to create detailed step-by-step implementation plan.
