"""Ultrathink Agent - Maximum cognitive depth security analysis.

This agent integrates the ultrathink cascade with the existing agent framework,
providing full reasoning transparency and hierarchical verification.
"""

import asyncio
import os
import re
import uuid
from datetime import datetime
from typing import Callable, Optional

from agents.base_agent import BaseAgent
from models.schemas import (
    AgentCreateRequest,
    AgentStatus,
    AgentType,
    Finding,
    Severity,
    WSMessage,
)
from providers import Message
from services import file_service
from ultrathink import UltrathinkConfig, UltrathinkCascade
from ultrathink.cascade import CascadeResult
from ultrathink.events import UltrathinkEventEmitter
from ultrathink.gates import GateResult
from prompts.strict_prompts import get_strict_system_prompt
from prompts.classification_gate import get_classification_gate_prompt
from services.project_service import project_service


class UltrathinkAgent(BaseAgent):
    """
    Agent that uses ultrathink cascade for maximum precision security analysis.

    This agent:
    1. Performs initial analysis to identify candidate findings
    2. Runs each candidate through the full ultrathink cascade
    3. Emits real-time progress via WebSocket
    4. Only reports findings that pass ALL verification gates

    Key Features:
    - Provider-agnostic extended thinking
    - Full reasoning trace visibility
    - Hierarchical verification cascade
    - Zero false positive tolerance
    """

    agent_type = AgentType.ULTRATHINK

    def __init__(
        self,
        request: AgentCreateRequest,
        repo_path: str,
        on_message: Optional[Callable[[WSMessage], None]] = None,
        ultrathink_config: Optional[UltrathinkConfig] = None,
    ):
        super().__init__(request, repo_path, on_message)

        self.ultrathink_config = ultrathink_config or UltrathinkConfig()
        self.event_emitter = UltrathinkEventEmitter(
            agent_id=self.id,
            on_message=on_message,
        )

        # Initialize cascade with event callbacks
        self.cascade = UltrathinkCascade(
            config=self.ultrathink_config,
            on_gate_start=self._on_gate_start,
            on_gate_complete=self._on_gate_complete,
        )

        # Tracking
        self.candidate_findings: list[Finding] = []
        self.verified_findings: list[Finding] = []
        self.cascade_results: list[CascadeResult] = []
        self.discarded_count = 0

        # Initialize tracking variable
        self._current_finding: Optional[Finding] = None

        # Threat model for classification gate
        self._threat_model: str = "AB"

    def _on_gate_start(self, gate):
        """Callback when a gate starts."""
        if self._current_finding:
            self.event_emitter.emit_gate_start(gate, self._current_finding.id)

    def _on_gate_complete(self, result: GateResult):
        """Callback when a gate completes."""
        if self._current_finding:
            self.event_emitter.emit_gate_complete(result, self._current_finding.id)

    async def analyze(self):
        """Perform ultrathink security analysis."""
        await self.emit_log("Starting ULTRATHINK analysis. Maximum cognitive depth mode.")
        await self.emit_log(f"Thinking mode: {self.ultrathink_config.thinking_mode.value}")
        await self.emit_log(f"Gates: {[g.name for g in self.ultrathink_config.gates]}")

        # Get threat model from project for classification gate
        try:
            project = await project_service.get_project(self.repo_id)
            if project and getattr(project, "threat_model", None):
                self._threat_model = project.threat_model
        except Exception:
            self._threat_model = "AB"

        # Get files to analyze
        file_tree = await file_service.get_file_tree(self.repo_path)
        all_files = self._get_analyzable_files(file_tree)

        if self.target_files:
            all_files = [f for f in all_files if any(
                t in f for t in self.target_files
            )]

        total_files = len(all_files)
        await self.emit_log(f"Found {total_files} files to analyze")

        # Phase 1: Initial analysis to find candidates
        await self.emit_log("=== PHASE 1: Initial Analysis (Finding Candidates) ===")

        for i, file_path in enumerate(all_files):
            if self._cancelled or self.status == AgentStatus.PAUSED:
                while self.status == AgentStatus.PAUSED:
                    await asyncio.sleep(0.5)
                if self._cancelled:
                    break

            await self.emit_progress(i + 1, total_files, file_path)
            self.files_analyzed += 1

            try:
                content = await file_service.read_file(
                    os.path.join(self.repo_path, file_path)
                )
                if not content.strip():
                    continue

                # Run initial analysis
                findings = await self._initial_analysis(file_path, content)

                for finding in findings:
                    # Check if severity triggers ultrathink
                    if self.cascade.should_ultrathink(finding):
                        self.candidate_findings.append(finding)
                        await self.emit_log(
                            f"Candidate: {finding.title} ({finding.file_path}:{finding.line_start}) "
                            f"- will verify via ultrathink"
                        )
                    else:
                        # Low severity - report directly without ultrathink
                        self.findings.append(finding)
                        await self.emit_finding(finding)

            except Exception as e:
                await self.emit_log(f"Error analyzing {file_path}: {e}")

        if not self.candidate_findings:
            await self.emit_log("No medium+ severity candidates found for ultrathink verification.")
            return

        # Phase 2: Ultrathink cascade verification
        await self.emit_log(
            f"=== PHASE 2: Ultrathink Cascade ({len(self.candidate_findings)} candidates) ==="
        )

        # Read all code contexts
        code_contexts = {}
        for finding in self.candidate_findings:
            try:
                code_contexts[finding.file_path] = await file_service.read_file(
                    os.path.join(self.repo_path, finding.file_path)
                )
            except Exception:
                code_contexts[finding.file_path] = ""

        # Run each candidate through cascade
        for i, finding in enumerate(self.candidate_findings):
            if self._cancelled:
                break

            await self.emit_log(
                f"Ultrathink {i+1}/{len(self.candidate_findings)}: {finding.title}"
            )

            # Store current finding for event callbacks
            self._current_finding = finding

            # Emit cascade start
            self.event_emitter.emit_cascade_start(
                finding.id, finding.title
            )

            # Run cascade
            result = await self.cascade.evaluate(
                finding=finding,
                code_context=code_contexts.get(finding.file_path, ""),
                provider=self.provider,
                model=self.provider_config.model,
            )

            self.cascade_results.append(result)

            # Emit cascade complete
            self.event_emitter.emit_cascade_complete(result)

            if result.final_verdict:
                # Update finding with cascade evidence
                finding.confidence = result.final_confidence
                finding.metadata["ultrathink"] = {
                    "gates_passed": len(result.gate_results),
                    "total_thinking_tokens": result.total_thinking_tokens,
                    "evidence": result.evidence,
                }

                self.verified_findings.append(finding)
                self.findings.append(finding)
                await self.emit_finding(finding)
                await self.emit_log(f"VERIFIED: {finding.title}")
            else:
                self.discarded_count += 1
                await self.emit_log(
                    f"DISCARDED: {finding.title} - "
                    f"rejected by {result.rejected_by.value}: {result.rejection_reason}"
                )

        # Summary
        await self._emit_summary()

    async def _initial_analysis(self, file_path: str, content: str) -> list[Finding]:
        """Perform initial analysis to identify candidate findings."""
        # Use strict analysis prompt for initial pass
        ext = os.path.splitext(file_path)[1].lower()
        lang_map = {
            ".py": "python", ".js": "javascript", ".ts": "typescript",
            ".java": "java", ".go": "go", ".rs": "rust",
        }
        language = lang_map.get(ext, "")

        system_prompt = get_strict_system_prompt(language)

        # Inject classification gate prompt
        classification_prompt = get_classification_gate_prompt(self._threat_model)
        system_prompt += "\n\n" + classification_prompt

        # Truncate large files
        max_lines = 1500
        lines = content.split("\n")
        if len(lines) > max_lines:
            content = "\n".join(lines[:max_lines])

        user_prompt = f"""Analyze this file for security vulnerabilities.

FILE: {file_path}
LANGUAGE: {language or 'auto-detect'}

CODE:
```
{content}
```

Identify ALL potential vulnerabilities. For each finding, assess:
- How confident you are (0.0-1.0)
- Whether it needs deeper investigation

Format each finding as:
===POTENTIAL VULNERABILITY===
SEVERITY: [CRITICAL|HIGH|MEDIUM|LOW]
TITLE: [Brief title]
FILE: {file_path}
LINE: [line number]
DESCRIPTION: [description]
CONFIDENCE: [0.0-1.0]
NEEDS_ULTRATHINK: [YES/NO]
===END===
"""

        messages = [Message(role="user", content=user_prompt)]

        full_response = ""
        async for chunk in self.provider.generate_stream(messages, system_prompt):
            full_response += chunk.content
            if chunk.is_complete:
                break

        return self._parse_initial_findings(full_response, file_path)

    def _parse_initial_findings(self, response: str, file_path: str) -> list[Finding]:
        """Parse initial analysis findings."""
        findings = []
        blocks = re.split(r'===POTENTIAL VULNERABILITY===', response)

        for block in blocks[1:]:
            try:
                severity_m = re.search(r'SEVERITY:\s*(CRITICAL|HIGH|MEDIUM|LOW)', block, re.I)
                title_m = re.search(r'TITLE:\s*(.+?)(?:\n|$)', block)
                line_m = re.search(r'LINE:\s*(\d+)', block)
                desc_m = re.search(r'DESCRIPTION:\s*(.+?)(?=\nCONFIDENCE|$)', block, re.S)
                conf_m = re.search(r'CONFIDENCE:\s*([\d.]+)', block)

                if not title_m or not severity_m:
                    continue

                finding = Finding(
                    id=str(uuid.uuid4())[:12],
                    agent_id=self.id,
                    repo_id=self.repo_id,
                    severity=Severity(severity_m.group(1).lower()),
                    title=title_m.group(1).strip(),
                    description=desc_m.group(1).strip() if desc_m else "",
                    file_path=file_path,
                    line_start=int(line_m.group(1)) if line_m else 1,
                    vulnerability_type="ultrathink_candidate",
                    confidence=float(conf_m.group(1)) if conf_m else 0.5,
                    created_at=datetime.utcnow(),
                    metadata={"stage": "initial"},
                )
                findings.append(finding)

            except Exception:
                continue

        return findings

    def _get_analyzable_files(self, tree: dict, prefix: str = "") -> list[str]:
        """Extract analyzable file paths from tree."""
        files = []
        analyzable_exts = {
            ".py", ".js", ".ts", ".jsx", ".tsx", ".java", ".go",
            ".rs", ".c", ".cpp", ".h", ".hpp", ".rb", ".php",
            ".cs", ".swift", ".kt", ".scala", ".sol",
        }
        skip_dirs = {"node_modules", ".git", "__pycache__", "vendor", "dist", "build"}

        name = tree.get("name", "")
        path = f"{prefix}/{name}" if prefix else name

        if tree.get("is_dir"):
            if name in skip_dirs:
                return files
            for child in tree.get("children", []):
                files.extend(self._get_analyzable_files(child, path))
        else:
            ext = os.path.splitext(name)[1].lower()
            if ext in analyzable_exts:
                files.append(path.lstrip("/"))

        return files

    async def _emit_summary(self):
        """Emit analysis summary."""
        summary = f"""
=== ULTRATHINK ANALYSIS SUMMARY ===
Files Analyzed: {self.files_analyzed}
Initial Candidates: {len(self.candidate_findings)}
Verified (REPORTED): {len(self.verified_findings)}
Discarded: {self.discarded_count}
Verification Rate: {(len(self.verified_findings) / len(self.candidate_findings) * 100) if self.candidate_findings else 0:.1f}%

Total Thinking Tokens: {sum(r.total_thinking_tokens for r in self.cascade_results):,}
"""

        if self.verified_findings:
            summary += "\nVERIFIED FINDINGS:\n"
            for f in self.verified_findings:
                summary += f"  [{f.severity.value.upper()}] {f.title} ({f.file_path}:{f.line_start})\n"
        else:
            summary += "\nNO VERIFIED FINDINGS - All candidates rejected by ultrathink cascade.\n"

        await self.emit_log(summary)
