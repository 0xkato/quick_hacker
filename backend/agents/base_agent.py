"""Base agent class for security auditing."""

import asyncio
import json
import re
import uuid
from abc import ABC, abstractmethod
from datetime import datetime
from typing import Callable, Optional

from models.schemas import (
    Agent,
    AgentCreateRequest,
    AgentStatus,
    AgentType,
    Finding,
    FindingClassification,
    FindingCreate,
    Severity,
    WSMessage,
    WSMessageType,
)
from providers import BaseProvider, Message, get_provider
from services.attack_surface_service import attack_surface_service
from services.flow_service import flow_service
from services.project_service import project_service
from pipelines import (
    PromptPipeline,
    PipelineConfig,
    PipelineStage,
    StageResult,
)


class BaseAgent(ABC):
    """Abstract base class for security auditing agents."""

    agent_type: AgentType = AgentType.CUSTOM

    def __init__(
        self,
        request: AgentCreateRequest,
        repo_path: str,
        on_message: Optional[Callable[[WSMessage], None]] = None,
        use_pipeline: bool = False,
        pipeline_config: Optional[PipelineConfig] = None,
    ):
        self.id = str(uuid.uuid4())[:12]
        self.repo_id = request.repo_id
        self.repo_path = repo_path
        self.provider_config = request.provider_config
        self.custom_prompt = request.custom_prompt
        self.target_files = request.target_files
        self.focus_areas = request.focus_areas
        self.on_message = on_message

        # State
        self.status = AgentStatus.PENDING
        self.created_at = datetime.utcnow()
        self.started_at: Optional[datetime] = None
        self.completed_at: Optional[datetime] = None
        self.files_analyzed = 0
        self.findings: list[Finding] = []
        self.error_message: Optional[str] = None

        # Cancellation
        self._cancelled = False
        self._task: Optional[asyncio.Task] = None

        # Pause support
        self._pause_requested = False
        self.processed_files: list[str] = []
        self.pending_files: list[str] = []
        self.current_file: Optional[str] = None

        # Provider (lazy init)
        self._provider: Optional[BaseProvider] = None

        # Name
        self.name = request.name or f"{self.agent_type.value}_{self.id}"

        # Multi-stage pipeline (for optimized model usage)
        self.use_pipeline = use_pipeline
        self.pipeline_config = pipeline_config or PipelineConfig()
        self._pipeline: Optional[PromptPipeline] = None

    @property
    def provider(self) -> BaseProvider:
        """Lazy initialize provider."""
        if self._provider is None:
            self._provider = get_provider(self.provider_config)
        return self._provider

    @property
    def pipeline(self) -> PromptPipeline:
        """Lazy initialize the prompt pipeline."""
        if self._pipeline is None:
            self._pipeline = PromptPipeline(
                config=self.pipeline_config,
                on_stage_start=self._on_pipeline_stage_start,
                on_stage_complete=self._on_pipeline_stage_complete,
            )
        return self._pipeline

    def _on_pipeline_stage_start(self, stage: PipelineStage):
        """Callback when a pipeline stage starts."""
        asyncio.create_task(self.emit_pipeline_stage(stage.value, "started"))

    def _on_pipeline_stage_complete(self, result: StageResult):
        """Callback when a pipeline stage completes."""
        asyncio.create_task(self.emit_pipeline_stage(
            result.stage.value,
            "completed" if result.success else "failed",
            {
                "model": result.model_used,
                "tokens_in": result.tokens_in,
                "tokens_out": result.tokens_out,
                "duration_ms": result.duration_ms,
                "error": result.error,
            }
        ))

    async def emit_pipeline_stage(self, stage: str, status: str, details: Optional[dict] = None):
        """Emit a pipeline stage event."""
        await self.emit(
            WSMessageType.PIPELINE_STAGE,
            {
                "stage": stage,
                "status": status,
                "details": details or {},
            }
        )

    def to_schema(self) -> Agent:
        """Convert to Agent schema."""
        return Agent(
            id=self.id,
            repo_id=self.repo_id,
            name=self.name,
            agent_type=self.agent_type,
            status=self.status,
            provider_config=self.provider_config,
            custom_prompt=self.custom_prompt,
            target_files=self.target_files,
            focus_areas=self.focus_areas,
            created_at=self.created_at,
            started_at=self.started_at,
            completed_at=self.completed_at,
            files_analyzed=self.files_analyzed,
            findings_count=len(self.findings),
            error_message=self.error_message,
        )

    async def emit(self, msg_type: WSMessageType, data: dict):
        """Emit a WebSocket message."""
        if self.on_message:
            msg = WSMessage(
                type=msg_type,
                agent_id=self.id,
                data=data,
            )
            await asyncio.to_thread(self.on_message, msg)

    async def emit_log(self, message: str):
        """Emit a log message."""
        await self.emit(WSMessageType.LOG, {"message": message})

    async def emit_progress(self, current: int, total: int, file: str = ""):
        """Emit progress update."""
        await self.emit(
            WSMessageType.PROGRESS,
            {"current": current, "total": total, "file": file},
        )

    async def emit_flow_update(self) -> None:
        """Emit a flow update (if a flow exists) for the investigation diagram."""
        flow = flow_service.get_flow(self.id)
        if flow:
            await self.emit(WSMessageType.PROGRESS, {"type": "flow_update", "flow": flow.to_dict()})

    async def emit_finding(self, finding: Finding):
        """Emit a new finding."""
        await self.emit(WSMessageType.FINDING, finding.model_dump())

    async def emit_status(self, status: AgentStatus):
        """Emit status change."""
        self.status = status
        await self.emit(
            WSMessageType.AGENT_STATUS,
            {"status": status.value},
        )

    async def _build_attack_surface_tree(self) -> None:
        """Build an initial attack-surface tree (best-effort)."""
        threat_model = "AB"
        try:
            project = await project_service.get_project(self.repo_id)
            if project and getattr(project, "threat_model", None):
                threat_model = project.threat_model
        except Exception:
            threat_model = "AB"

        scan_node = flow_service.add_node(
            self.id,
            "scan",
            f"Attack Surface Scan ({threat_model})",
            {"threat_model": threat_model},
        )
        flow_service.update_node_status(self.id, scan_node.id, "running")
        await self.emit_flow_update()

        provider = None
        try:
            provider = self.provider
        except Exception:
            provider = None

        try:
            triaged = []
            if provider is None:
                flow_service.update_node_data(
                    self.id,
                    scan_node.id,
                    {"skipped": True, "reason": "no_provider_configured"},
                )
                flow_service.update_node_status(self.id, scan_node.id, "completed")
                await self.emit_flow_update()
                return

            candidates = attack_surface_service.scan_candidates(repo_path=self.repo_path)
            triaged = await attack_surface_service.triage(
                agent_id=self.id,
                repo_path=self.repo_path,
                threat_model=threat_model,  # type: ignore[arg-type]
                provider=provider,
                candidates=candidates,
            )

            flow_service.update_node_data(
                self.id,
                scan_node.id,
                {
                    "candidates_found": len(candidates),
                    "investigate_count": len(triaged),
                },
            )
            flow_service.update_node_status(self.id, scan_node.id, "completed")

            for item in triaged[:20]:
                c = item.candidate
                node_type = "entry_point" if c.kind == "entry_point" else "dangerous_sink"
                exposure = item.exposure if item.exposure != "unknown" else ""
                label = f"[{exposure}] {c.label}" if exposure else c.label

                flow_service.add_node(
                    self.id,
                    node_type,  # type: ignore[arg-type]
                    label,
                    data={
                        "attack_surface_candidate_id": c.id,
                        "kind": c.kind,
                        "file_path": c.file_path,
                        "line_number": c.line_number,
                        "metadata": c.metadata,
                        "threat_model": threat_model,
                        "exposure": item.exposure,
                    },
                    parent_id=scan_node.id,
                    edge_label="candidate",
                    llm_reasoning=item.reasoning,
                    code_context=c.code_context,
                    confidence_score=item.confidence_score,
                    set_current=False,
                )

            await self.emit_flow_update()
        except Exception as e:
            flow_service.update_node_data(self.id, scan_node.id, {"error": str(e)})
            flow_service.update_node_status(self.id, scan_node.id, "failed")
            await self.emit_flow_update()

    def add_finding(self, finding_create: FindingCreate) -> Finding:
        """Add a finding."""
        finding = Finding(
            id=str(uuid.uuid4())[:12],
            agent_id=self.id,
            repo_id=self.repo_id,
            created_at=datetime.utcnow(),
            **finding_create.model_dump(),
        )
        self.findings.append(finding)
        return finding

    async def run(self) -> list[Finding]:
        """Run the agent."""
        try:
            self.started_at = datetime.utcnow()
            await self.emit_status(AgentStatus.RUNNING)
            await self.emit_log(f"Starting {self.agent_type.value} agent...")

            # Initialize investigation flow (used by the Flow diagram UI)
            flow_service.initialize_flow(self.id)
            start_node = flow_service.add_node(
                self.id,
                "user_input",
                f"Start {self.agent_type.value}",
                {"agent_type": self.agent_type.value},
            )
            flow_service.update_node_status(self.id, start_node.id, "completed")
            await self.emit_flow_update()

            # Best-effort initial scan + triage (safe to no-op on failure).
            await self._build_attack_surface_tree()

            # Run the actual analysis
            await self.analyze()

            if self._cancelled:
                await self.emit_status(AgentStatus.CANCELLED)
                await self.emit_log("Agent cancelled")
            else:
                self.completed_at = datetime.utcnow()
                await self.emit_status(AgentStatus.COMPLETED)
                await self.emit_log(
                    f"Analysis complete. Found {len(self.findings)} potential issues."
                )
                flow_service.add_node(
                    self.id,
                    "analysis",
                    "Audit Complete",
                    {"findings_count": len(self.findings)},
                )
                await self.emit_flow_update()

        except Exception as e:
            self.error_message = str(e)
            await self.emit_status(AgentStatus.FAILED)
            await self.emit(WSMessageType.ERROR, {"error": str(e)})
            raise

        return self.findings

    def cancel(self):
        """Cancel the agent."""
        self._cancelled = True
        if self._task:
            self._task.cancel()

    def pause(self):
        """Pause the agent (sets flag, analysis must check)."""
        self.status = AgentStatus.PAUSED

    def resume(self):
        """Resume the agent."""
        if self.status == AgentStatus.PAUSED:
            self.status = AgentStatus.RUNNING

    def request_pause(self):
        """Request the agent to pause at the next safe point."""
        self._pause_requested = True

    def is_pausable(self) -> bool:
        """Check if agent can be paused."""
        return self.status == AgentStatus.RUNNING

    def get_pause_state(self) -> dict:
        """Get current state for snapshot."""
        return {
            "processed_files": getattr(self, "processed_files", []),
            "pending_files": getattr(self, "pending_files", []),
            "current_file": getattr(self, "current_file", None),
        }

    @abstractmethod
    async def analyze(self):
        """Perform the actual analysis. Must be implemented by subclasses."""
        pass

    def get_state_snapshot(self):
        """
        Create a state snapshot for persistence.
        Allows agents to be restored after restart.
        """
        from models.observability import AgentStateSnapshot

        return AgentStateSnapshot(
            id=str(uuid.uuid4())[:12],
            agent_id=self.id,
            repo_id=self.repo_id,
            repo_path=self.repo_path,
            agent_type=self.agent_type.value if hasattr(self.agent_type, 'value') else str(self.agent_type),
            provider_config={
                "provider": self.provider_config.provider if self.provider_config else "unknown",
                "model": self.provider_config.model if self.provider_config else "unknown",
            } if self.provider_config else {},
            custom_prompt=self.custom_prompt,
            status=self.status.value if hasattr(self.status, 'value') else str(self.status),
            files_analyzed=self.files_analyzed,
            total_files=0,
            current_file=None,
            findings=[f.model_dump(mode='json') for f in self.findings],
            conversation_history=[],  # BaseAgent doesn't track conversation
            flow_nodes=[],
            flow_edges=[],
            current_flow_node_id=None,
            investigation_context={
                "focus_areas": self.focus_areas,
                "target_files": self.target_files,
            },
            total_prompt_tokens=0,
            total_completion_tokens=0,
            total_api_calls=0,
            last_error=self.error_message,
        )

    async def analyze_file(self, file_path: str, content: str) -> list[Finding]:
        """Analyze a single file for vulnerabilities.

        Note: This method is deprecated. Use ReActSecurityAgent for file analysis.
        """
        raise NotImplementedError(
            "analyze_file is deprecated. Use ReActSecurityAgent for security analysis."
        )

    async def _analyze_file_with_pipeline(self, file_path: str, content: str) -> list[Finding]:
        """Analyze a file using the multi-stage prompt pipeline.

        Note: This method is deprecated. Use ReActSecurityAgent for file analysis.
        """
        raise NotImplementedError(
            "_analyze_file_with_pipeline is deprecated. Use ReActSecurityAgent for security analysis."
        )

    def _detect_language(self, file_path: str) -> str:
        """Detect language from file extension."""
        ext_map = {
            ".py": "python", ".js": "javascript", ".ts": "typescript",
            ".java": "java", ".go": "go", ".php": "php", ".rb": "ruby",
            ".rs": "rust", ".sol": "solidity", ".c": "c", ".cpp": "cpp",
        }
        for ext, lang in ext_map.items():
            if file_path.endswith(ext):
                return lang
        return "unknown"

    def _build_analysis_prompt(self, file_path: str, content: str, structured: bool = False) -> str:
        """Build the user prompt for file analysis."""
        # Truncate very long files
        max_lines = 2000
        lines = content.split("\n")
        if len(lines) > max_lines:
            content = "\n".join(lines[:max_lines])
            content += f"\n\n[... truncated {len(lines) - max_lines} more lines ...]"

        if structured:
            # Structured methodology prompt for strict modes
            prompt = f"""Perform source-to-sink security analysis on this file:

**File:** `{file_path}`
**Lines:** {len(lines)}

```
{content}
```

=== REQUIRED ANALYSIS ===

1. IDENTIFY SOURCES: Find all attacker-controlled inputs in this file
2. IDENTIFY SINKS: Find all dangerous operations (SQL, exec, file ops, etc.)
3. TRACE: For each source, trace if it reaches a sink without sanitization
4. VERIFY: Confirm attacker control and prove no defenses exist

=== OUTPUT FORMAT ===
Return ONLY valid JSON matching this structure:

```json
{{
  "findings": [
    {{
      "id": "F-001",
      "status": "confirmed",
      "title": "Brief vulnerability title",
      "severity": "critical|high|medium|low",
      "confidence": 0.95,
      "cwe": "CWE-XX",
      "source": {{
        "type": "http_param|body|header|file|etc",
        "location": "{file_path}:line_number",
        "variable": "variable_name",
        "attacker_control": "How attacker controls this input"
      }},
      "sink": {{
        "type": "sql|command|file|ssrf|etc",
        "location": "{file_path}:line_number",
        "vulnerable_code": "exact code snippet",
        "why_dangerous": "Why this is exploitable"
      }},
      "trace": [
        "Step 1: source receives input at line X",
        "Step 2: passed to function Y without validation",
        "Step 3: reaches sink at line Z"
      ],
      "poc": {{
        "payload": "malicious input value",
        "expected_result": "what happens"
      }},
      "remediation": "How to fix"
    }}
  ],
  "candidates": [
    {{
      "title": "Potential issue needing more investigation",
      "reason_not_confirmed": "What's missing to confirm",
      "location": "{file_path}:line"
    }}
  ]
}}
```

If no vulnerabilities found, return: {{"findings": [], "candidates": []}}

CRITICAL: Only include "confirmed" findings with complete source→sink traces.
"""
        else:
            # Standard prompt
            prompt = f"""Analyze this file for security vulnerabilities:

**File:** `{file_path}`

```
{content}
```

Find and report ALL security issues. For each vulnerability:
1. Identify the exact location (line numbers)
2. Explain the vulnerability type
3. Describe the attack scenario
4. Provide a severity rating
5. Suggest a fix

If no vulnerabilities are found, respond with: NO_VULNERABILITIES_FOUND

Format each finding as:
---FINDING---
SEVERITY: [CRITICAL|HIGH|MEDIUM|LOW|INFO]
TITLE: [Brief title]
TYPE: [Vulnerability type, e.g., SQL Injection, XSS, etc.]
LINES: [start_line]-[end_line]
DESCRIPTION: [Detailed description]
ATTACK: [Attack scenario]
FIX: [Recommended fix]
CONFIDENCE: [0.0-1.0]
---END---
"""
        return prompt

    def _parse_structured_findings(self, response: str, file_path: str) -> list[FindingCreate]:
        """Parse structured JSON findings from response."""
        findings = []

        # Extract JSON from response (handle markdown code blocks)
        json_match = re.search(r'```(?:json)?\s*([\s\S]*?)\s*```', response)
        if json_match:
            json_str = json_match.group(1)
        else:
            # Try to find raw JSON
            json_str = response.strip()

        try:
            data = json.loads(json_str)
        except json.JSONDecodeError:
            # Try to extract just the findings array
            findings_match = re.search(r'"findings"\s*:\s*\[([\s\S]*?)\]', response)
            if findings_match:
                try:
                    data = {"findings": json.loads("[" + findings_match.group(1) + "]")}
                except:
                    return self._parse_findings(response, file_path)  # Fallback
            else:
                return self._parse_findings(response, file_path)  # Fallback to legacy

        for f in data.get("findings", []):
            if f.get("status") != "confirmed":
                continue  # Skip unconfirmed

            try:
                # Parse severity
                sev_str = f.get("severity", "medium").lower()
                severity = Severity(sev_str if sev_str in ["critical", "high", "medium", "low", "info"] else "medium")

                # Parse line numbers from source/sink locations
                line_start, line_end = 1, 1
                source_loc = f.get("source", {}).get("location", "")
                sink_loc = f.get("sink", {}).get("location", "")

                for loc in [source_loc, sink_loc]:
                    if ":" in loc:
                        try:
                            line_num = int(loc.split(":")[-1])
                            if line_start == 1:
                                line_start = line_num
                            line_end = max(line_end, line_num)
                        except ValueError:
                            pass

                # Build description with trace
                trace = f.get("trace", [])
                trace_text = "\n".join(f"  {i+1}. {step}" for i, step in enumerate(trace))

                description = f"""{f.get('title', 'Unknown')}

**Source:** {f.get('source', {}).get('type', 'unknown')} at {source_loc}
- Variable: `{f.get('source', {}).get('variable', 'unknown')}`
- Attacker Control: {f.get('source', {}).get('attacker_control', 'unknown')}

**Sink:** {f.get('sink', {}).get('type', 'unknown')} at {sink_loc}
- Code: `{f.get('sink', {}).get('vulnerable_code', 'unknown')}`
- Why Dangerous: {f.get('sink', {}).get('why_dangerous', 'unknown')}

**Source-to-Sink Trace:**
{trace_text}
"""

                # Build attack scenario with PoC
                poc = f.get("poc", {})
                attack = f"""Payload: {poc.get('payload', 'N/A')}
Expected Result: {poc.get('expected_result', 'N/A')}"""

                # Extract classification fields from agent output
                classification_str = f.get("classification", "security_issue")
                try:
                    classification = FindingClassification(classification_str)
                except ValueError:
                    classification = FindingClassification.SECURITY_ISSUE

                config_dependent = f.get("config_dependent", False)
                config_flag = f.get("config_flag")
                default_secure = f.get("default_secure")
                contradiction_present = f.get("contradiction_present", False)
                fix_type = f.get("fix_type", "code")
                # Validate fix_type is one of the allowed values
                if fix_type not in ("code", "config", "docs", "warning"):
                    fix_type = "code"
                classification_reasoning = f.get("classification_reasoning", "")

                finding = FindingCreate(
                    severity=severity,
                    title=f.get("title", "Unknown Issue"),
                    description=description,
                    file_path=file_path,
                    line_start=line_start,
                    line_end=line_end,
                    vulnerability_type=f.get("cwe", f.get("sink", {}).get("type", "Unknown")),
                    attack_scenario=attack,
                    recommended_fix=f.get("remediation"),
                    confidence=min(max(f.get("confidence", 0.5), 0.0), 1.0),
                    vulnerable_code=f.get("sink", {}).get("vulnerable_code"),
                    cwe_id=f.get("cwe"),
                    # Classification gate fields
                    classification=classification,
                    config_dependent=config_dependent,
                    config_flag=config_flag,
                    default_secure=default_secure,
                    contradiction_present=contradiction_present,
                    fix_type=fix_type,
                    classification_reasoning=classification_reasoning,
                )
                findings.append(finding)

            except Exception as e:
                print(f"Failed to parse structured finding: {e}")
                continue

        return findings

    def _parse_findings(self, response: str, file_path: str) -> list[FindingCreate]:
        """Parse findings from model response (legacy format)."""
        if "NO_VULNERABILITIES_FOUND" in response:
            return []

        findings = []
        current_finding = {}

        for line in response.split("\n"):
            line = line.strip()

            if line == "---FINDING---":
                current_finding = {}
            elif line == "---END---" and current_finding:
                try:
                    # Parse line range
                    lines_str = current_finding.get("LINES", "1-1")
                    if "-" in lines_str:
                        start, end = lines_str.split("-")
                        line_start = int(start.strip())
                        line_end = int(end.strip())
                    else:
                        line_start = int(lines_str.strip())
                        line_end = line_start

                    # Parse severity
                    severity_str = current_finding.get("SEVERITY", "INFO").upper()
                    severity = Severity(severity_str.lower())

                    # Parse confidence
                    conf_str = current_finding.get("CONFIDENCE", "0.5")
                    try:
                        confidence = float(conf_str)
                    except ValueError:
                        confidence = 0.5

                    # Parse classification fields from legacy format
                    classification_str = current_finding.get("CLASSIFICATION", "security_issue").lower()
                    try:
                        classification = FindingClassification(classification_str)
                    except ValueError:
                        classification = FindingClassification.SECURITY_ISSUE

                    config_dependent_str = current_finding.get("CONFIG_DEPENDENT", "false").lower()
                    config_dependent = config_dependent_str in ("true", "yes", "1")

                    config_flag = current_finding.get("CONFIG_FLAG")
                    if config_flag == "":
                        config_flag = None

                    default_secure_str = current_finding.get("DEFAULT_SECURE", "")
                    if default_secure_str.lower() in ("true", "yes", "1"):
                        default_secure = True
                    elif default_secure_str.lower() in ("false", "no", "0"):
                        default_secure = False
                    else:
                        default_secure = None

                    contradiction_str = current_finding.get("CONTRADICTION_PRESENT", "false").lower()
                    contradiction_present = contradiction_str in ("true", "yes", "1")

                    fix_type = current_finding.get("FIX_TYPE", "code").lower()
                    if fix_type not in ("code", "config", "docs", "warning"):
                        fix_type = "code"

                    classification_reasoning = current_finding.get("CLASSIFICATION_REASONING", "")

                    finding = FindingCreate(
                        severity=severity,
                        title=current_finding.get("TITLE", "Unknown Issue"),
                        description=current_finding.get("DESCRIPTION", ""),
                        file_path=file_path,
                        line_start=line_start,
                        line_end=line_end,
                        vulnerability_type=current_finding.get("TYPE", "Unknown"),
                        attack_scenario=current_finding.get("ATTACK"),
                        recommended_fix=current_finding.get("FIX"),
                        confidence=min(max(confidence, 0.0), 1.0),
                        # Classification gate fields
                        classification=classification,
                        config_dependent=config_dependent,
                        config_flag=config_flag,
                        default_secure=default_secure,
                        contradiction_present=contradiction_present,
                        fix_type=fix_type,
                        classification_reasoning=classification_reasoning,
                    )
                    findings.append(finding)

                except Exception as e:
                    print(f"Failed to parse finding: {e}")

                current_finding = {}

            elif ":" in line and current_finding is not None:
                key, _, value = line.partition(":")
                key = key.strip().upper()
                value = value.strip()
                # Include classification gate fields in accepted keys
                accepted_keys = [
                    "SEVERITY", "TITLE", "TYPE", "LINES", "DESCRIPTION", "ATTACK", "FIX", "CONFIDENCE",
                    "CLASSIFICATION", "CONFIG_DEPENDENT", "CONFIG_FLAG", "DEFAULT_SECURE",
                    "CONTRADICTION_PRESENT", "FIX_TYPE", "CLASSIFICATION_REASONING",
                ]
                if key in accepted_keys:
                    current_finding[key] = value

        return findings
