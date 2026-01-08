"""
Strict Analysis Agent - Zero False Positive Tolerance.

This agent uses the premium model with multi-gate verification to ensure
only proven vulnerabilities are reported. It prioritizes precision over recall.

Philosophy:
- Better to miss 10 real vulnerabilities than report 1 false positive
- Every finding must pass 5 verification gates
- When in doubt, DON'T report
"""

import asyncio
import os
import re
import uuid
from datetime import datetime
from typing import Callable, Optional

from agents.base_agent import BaseAgent
from models.schemas import (
    Agent,
    AgentCreateRequest,
    AgentStatus,
    AgentType,
    Finding,
    FindingCreate,
    Severity,
    WSMessage,
    WSMessageType,
)
from providers import BaseProvider, get_provider
from prompts.strict_prompts import (
    get_strict_system_prompt,
    STRICT_ANALYSIS_PROMPT,
    EVIDENCE_VERIFICATION_PROMPT,
    DEVILS_ADVOCATE_PROMPT,
    PROOF_OF_EXPLOIT_PROMPT,
    FINAL_GATE_PROMPT,
    BATCH_TRIAGE_PROMPT,
    CONFIDENCE_THRESHOLDS,
)
from services import file_service


class StrictAnalysisAgent(BaseAgent):
    """
    Agent that performs strict security analysis with zero false positive tolerance.

    This is the "fine tool model" - it uses expensive models but ensures
    every finding is thoroughly verified before being reported.

    Key Features:
    1. Uses strict prompts that require proof for every finding
    2. Runs every potential finding through multiple verification gates
    3. Model argues against its own findings (Devil's Advocate)
    4. Requires concrete proof of exploit
    5. Final reputation-stake check

    Use this agent when accuracy is more important than coverage.
    """

    agent_type = AgentType.STRICT_ANALYSIS

    def __init__(
        self,
        request: AgentCreateRequest,
        repo_path: str,
        on_message: Optional[Callable[[WSMessage], None]] = None,
    ):
        super().__init__(request, repo_path, on_message)
        self.potential_findings: list[Finding] = []
        self.verified_findings: list[Finding] = []
        self.discarded_count = 0
        self.discard_reasons: dict[str, int] = {}

    async def analyze(self):
        """Perform strict security analysis with multi-gate verification."""
        await self.emit_log("Starting STRICT analysis. Zero false positive tolerance mode.")
        await self.emit_log(f"Confidence thresholds: {CONFIDENCE_THRESHOLDS}")

        # Get files to analyze
        file_tree = await file_service.get_file_tree(self.repo_path)
        all_files = self._get_analyzable_files(file_tree)

        # Apply target files filter if specified
        if self.target_files:
            all_files = [f for f in all_files if any(
                t in f for t in self.target_files
            )]

        total_files = len(all_files)
        await self.emit_log(f"Found {total_files} files to analyze")

        # Phase 1: Initial strict analysis
        await self.emit_log("=== PHASE 1: Initial Analysis with Strict Prompts ===")

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

                # Run strict analysis on file
                findings = await self._analyze_file_strict(file_path, content)

                for finding in findings:
                    self.potential_findings.append(finding)
                    await self.emit_log(f"Potential: {finding.title} ({finding.file_path}:{finding.line_start})")

            except Exception as e:
                await self.emit_log(f"Error analyzing {file_path}: {e}")

        if not self.potential_findings:
            await self.emit_log("No potential vulnerabilities found in initial analysis.")
            await self.emit_log("This is the ideal outcome for secure code.")
            return

        # Phase 2: Batch triage
        await self.emit_log(f"=== PHASE 2: Batch Triage ({len(self.potential_findings)} candidates) ===")
        triaged = await self._batch_triage(self.potential_findings)
        filtered = len(self.potential_findings) - len(triaged)
        await self.emit_log(f"After triage: {len(triaged)} to verify (filtered {filtered} obvious non-issues)")

        # Phase 3: Multi-gate verification
        await self.emit_log(f"=== PHASE 3: Multi-Gate Verification ===")

        for i, finding in enumerate(triaged):
            if self._cancelled:
                break

            await self.emit_log(f"Verifying {i+1}/{len(triaged)}: {finding.title}")

            # Get code context
            try:
                code = await file_service.read_file(
                    os.path.join(self.repo_path, finding.file_path)
                )
            except Exception:
                code = ""

            # Run through verification gates
            is_verified, reason = await self._verify_finding(finding, code)

            if is_verified:
                self.verified_findings.append(finding)
                self.findings.append(finding)
                await self.emit_finding(finding)
                await self.emit_log(f"VERIFIED: {finding.title}")
            else:
                self.discarded_count += 1
                gate = reason.split(":")[0] if ":" in reason else "Unknown"
                self.discard_reasons[gate] = self.discard_reasons.get(gate, 0) + 1
                await self.emit_log(f"DISCARDED: {finding.title} - {reason}")

        # Summary
        await self._emit_summary()

    async def _analyze_file_strict(self, file_path: str, content: str) -> list[Finding]:
        """Analyze a file using strict prompts that require proof."""
        # Get language from extension
        ext = os.path.splitext(file_path)[1].lower()
        lang_map = {
            ".py": "python", ".js": "javascript", ".ts": "typescript",
            ".java": "java", ".go": "go", ".rs": "rust", ".c": "c",
            ".cpp": "cpp", ".rb": "ruby", ".php": "php",
        }
        language = lang_map.get(ext, "")

        # Get strict system prompt with language-specific additions
        system_prompt = get_strict_system_prompt(language)

        # Build user prompt
        max_lines = 1500
        lines = content.split("\n")
        if len(lines) > max_lines:
            content = "\n".join(lines[:max_lines])
            content += f"\n\n[... truncated {len(lines) - max_lines} lines ...]"

        user_prompt = f"""Analyze this file for security vulnerabilities.

FILE: {file_path}
LANGUAGE: {language or 'auto-detect'}

CODE:
```
{content}
```

Remember: Only report what you can PROVE. When in doubt, don't report.
"""

        from providers import Message
        messages = [Message(role="user", content=user_prompt)]

        # Generate analysis
        full_response = ""
        async for chunk in self.provider.generate_stream(messages, system_prompt):
            full_response += chunk.content
            if chunk.is_complete:
                break

        # Parse findings
        return self._parse_strict_response(full_response, file_path)

    def _parse_strict_response(self, response: str, file_path: str) -> list[Finding]:
        """Parse strict analysis response."""
        findings = []

        if "NO PROVEN VULNERABILITIES FOUND" in response.upper():
            return findings

        # Parse ===PROVEN VULNERABILITY=== blocks
        blocks = re.split(r'===PROVEN VULNERABILITY===', response)

        for block in blocks[1:]:
            try:
                severity_m = re.search(r'SEVERITY:\s*(CRITICAL|HIGH|MEDIUM|LOW)', block, re.I)
                title_m = re.search(r'TITLE:\s*(.+?)(?:\n|$)', block)
                file_m = re.search(r'FILE:\s*(.+?)(?:\n|$)', block)
                line_m = re.search(r'LINE:\s*(\d+)', block)
                source_m = re.search(r'SOURCE:\s*(.+?)(?=\nSINK:|$)', block, re.S)
                sink_m = re.search(r'SINK:\s*(.+?)(?=\nPATH:|$)', block, re.S)
                path_m = re.search(r'PATH:\s*(.+?)(?=\nPROOF|$)', block, re.S)
                proof_m = re.search(r'PROOF OF EXPLOITABILITY:\s*(.+?)(?=\nWHY|$)', block, re.S)
                why_m = re.search(r'WHY PROTECTIONS FAIL:\s*(.+?)(?=\nCONFIDENCE|$)', block, re.S)
                conf_m = re.search(r'CONFIDENCE:\s*([\d.]+)', block)

                if not title_m or not severity_m:
                    continue

                confidence = float(conf_m.group(1)) if conf_m else 0.85
                if confidence < CONFIDENCE_THRESHOLDS["initial_analysis"]:
                    continue

                # Build description with evidence
                desc_parts = []
                if source_m:
                    desc_parts.append(f"SOURCE: {source_m.group(1).strip()}")
                if sink_m:
                    desc_parts.append(f"SINK: {sink_m.group(1).strip()}")
                if path_m:
                    desc_parts.append(f"PATH: {path_m.group(1).strip()}")

                finding = Finding(
                    id=str(uuid.uuid4())[:12],
                    agent_id=self.id,
                    repo_id=self.repo_id,
                    severity=Severity(severity_m.group(1).lower()),
                    title=title_m.group(1).strip(),
                    description="\n".join(desc_parts) if desc_parts else "See attack scenario",
                    file_path=file_m.group(1).strip() if file_m else file_path,
                    line_start=int(line_m.group(1)) if line_m else 1,
                    vulnerability_type="strict_analysis",
                    attack_scenario=proof_m.group(1).strip() if proof_m else None,
                    recommended_fix=why_m.group(1).strip() if why_m else None,
                    confidence=confidence,
                    created_at=datetime.utcnow(),
                    metadata={"stage": "initial", "verified": False},
                )
                findings.append(finding)

            except Exception:
                continue

        return findings

    async def _batch_triage(self, findings: list[Finding]) -> list[Finding]:
        """Quick triage to filter obvious false positives."""
        if len(findings) <= 2:
            return findings  # Not worth triaging small lists

        findings_list = "\n".join([
            f"[{i}] {f.severity.value}: {f.title} at {f.file_path}:{f.line_start}"
            for i, f in enumerate(findings)
        ])

        prompt = BATCH_TRIAGE_PROMPT.replace("{{findings_list}}", findings_list)

        from providers import Message
        messages = [Message(role="user", content=prompt)]

        try:
            full_response = ""
            async for chunk in self.provider.generate_stream(
                messages,
                "Be aggressive in filtering. Only pass findings with genuine potential."
            ):
                full_response += chunk.content
                if chunk.is_complete:
                    break

            # Parse which to keep
            keep = set()
            for line in full_response.split("\n"):
                if "INVESTIGATE" in line.upper():
                    m = re.search(r'\[?(\d+)\]?', line)
                    if m:
                        keep.add(int(m.group(1)))

            if not keep:
                return findings  # Conservative: keep all if parsing fails

            return [f for i, f in enumerate(findings) if i in keep]

        except Exception:
            return findings  # Conservative on error

    async def _verify_finding(self, finding: Finding, code: str) -> tuple[bool, str]:
        """Run finding through verification gates."""

        # Gate 1: Evidence Verification
        passed, reason = await self._gate_evidence_verification(finding, code)
        if not passed:
            return False, f"Evidence Verification: {reason}"

        # Gate 2: Devil's Advocate
        passed, reason = await self._gate_devils_advocate(finding, code)
        if not passed:
            return False, f"Devil's Advocate: {reason}"

        # Gate 3: Proof of Exploit
        passed, reason = await self._gate_proof_of_exploit(finding, code)
        if not passed:
            return False, f"Proof of Exploit: {reason}"

        # Gate 4: Final Gate
        passed, reason = await self._gate_final_decision(finding)
        if not passed:
            return False, f"Final Gate: {reason}"

        return True, "All gates passed"

    async def _gate_evidence_verification(self, finding: Finding, code: str) -> tuple[bool, str]:
        """Gate 1: Verify the evidence is solid."""
        prompt = EVIDENCE_VERIFICATION_PROMPT.replace(
            "{{finding}}", self._format_finding(finding)
        ).replace(
            "{{code}}", code[:3000]
        ).replace(
            "{{language}}", "auto-detect"
        )

        from providers import Message
        messages = [Message(role="user", content=prompt)]

        try:
            full_response = ""
            async for chunk in self.provider.generate_stream(
                messages,
                "You are a skeptical security reviewer. Your job is to DISPROVE findings."
            ):
                full_response += chunk.content
                if chunk.is_complete:
                    break

            # Parse verdict
            json_match = re.search(r'\{[\s\S]*\}', full_response)
            if json_match:
                import json
                data = json.loads(json_match.group())
                verdict = data.get("verdict", "").upper()
                confidence = float(data.get("confidence", 0))

                if verdict == "CONFIRMED" and confidence >= CONFIDENCE_THRESHOLDS["evidence_verification"]:
                    return True, "Evidence verified"
                else:
                    return False, data.get("counter_evidence", "Evidence not verified")

            return False, "Could not parse verification response"

        except Exception as e:
            return False, f"Verification error: {e}"

    async def _gate_devils_advocate(self, finding: Finding, code: str) -> tuple[bool, str]:
        """Gate 2: Model argues against its own finding."""
        prompt = DEVILS_ADVOCATE_PROMPT.replace(
            "{{findings}}", self._format_finding(finding)
        )
        prompt += f"\n\nCODE:\n```\n{code[:2000]}\n```"

        from providers import Message
        messages = [Message(role="user", content=prompt)]

        try:
            full_response = ""
            async for chunk in self.provider.generate_stream(
                messages,
                "Argue AGAINST this vulnerability being real. Find every reason it might be a false positive."
            ):
                full_response += chunk.content
                if chunk.is_complete:
                    break

            json_match = re.search(r'\{[\s\S]*\}', full_response)
            if json_match:
                import json
                data = json.loads(json_match.group())
                revised_conf = float(data.get("revised_confidence", 0))
                should_report = data.get("should_report", False)

                if should_report and revised_conf >= CONFIDENCE_THRESHOLDS["devils_advocate"]:
                    return True, "Survived counter-arguments"
                else:
                    return False, data.get("strongest_counter_argument", "Counter-arguments prevailed")

            return False, "Could not parse devil's advocate response"

        except Exception as e:
            return False, f"Devil's advocate error: {e}"

    async def _gate_proof_of_exploit(self, finding: Finding, code: str) -> tuple[bool, str]:
        """Gate 3: Generate concrete proof of exploit."""
        prompt = PROOF_OF_EXPLOIT_PROMPT.replace(
            "{{finding}}", self._format_finding(finding)
        ).replace(
            "{{code}}", code[:2000]
        ).replace(
            "{{language}}", "auto-detect"
        )

        from providers import Message
        messages = [Message(role="user", content=prompt)]

        try:
            full_response = ""
            async for chunk in self.provider.generate_stream(
                messages,
                "Generate a CONCRETE proof of exploit. If you cannot, recommend DO_NOT_REPORT."
            ):
                full_response += chunk.content
                if chunk.is_complete:
                    break

            json_match = re.search(r'\{[\s\S]*\}', full_response)
            if json_match:
                import json
                data = json.loads(json_match.group())
                can_prove = data.get("can_prove", False)
                recommendation = data.get("recommendation", "").upper()

                if can_prove and recommendation == "REPORT":
                    return True, f"Payload: {data.get('payload', 'N/A')}"
                else:
                    return False, data.get("reason", "Cannot prove exploitability")

            return False, "Could not parse proof of exploit response"

        except Exception as e:
            return False, f"Proof of exploit error: {e}"

    async def _gate_final_decision(self, finding: Finding) -> tuple[bool, str]:
        """Gate 4: Final reputation-stake decision."""
        prompt = FINAL_GATE_PROMPT.replace(
            "{{finding}}", self._format_finding(finding)
        )

        from providers import Message
        messages = [Message(role="user", content=prompt)]

        try:
            full_response = ""
            async for chunk in self.provider.generate_stream(
                messages,
                "This is your final chance to reject a questionable finding. Be conservative."
            ):
                full_response += chunk.content
                if chunk.is_complete:
                    break

            json_match = re.search(r'\{[\s\S]*\}', full_response)
            if json_match:
                import json
                data = json.loads(json_match.group())
                stake = data.get("stake_reputation", False)
                decision = data.get("final_decision", "").upper()
                conf = float(data.get("confidence_percentage", 0)) / 100

                if stake and decision == "REPORT" and conf >= CONFIDENCE_THRESHOLDS["final_gate"]:
                    return True, data.get("strongest_evidence", "Ready to report")
                else:
                    return False, data.get("biggest_doubt", "Not confident enough")

            return False, "Could not parse final gate response"

        except Exception as e:
            return False, f"Final gate error: {e}"

    def _format_finding(self, finding: Finding) -> str:
        """Format finding for prompts."""
        return f"""
TITLE: {finding.title}
SEVERITY: {finding.severity.value}
FILE: {finding.file_path}
LINE: {finding.line_start}
TYPE: {finding.vulnerability_type}
DESCRIPTION: {finding.description}
ATTACK SCENARIO: {finding.attack_scenario or 'Not provided'}
CONFIDENCE: {finding.confidence}
"""

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
        total_potential = len(self.potential_findings)
        total_verified = len(self.verified_findings)

        summary = f"""
=== STRICT ANALYSIS SUMMARY ===
Initial Candidates: {total_potential}
Verified (REPORTED): {total_verified}
Discarded: {self.discarded_count}
Verification Rate: {(total_verified / total_potential * 100) if total_potential else 0:.1f}%

DISCARD BREAKDOWN:
"""
        for gate, count in sorted(self.discard_reasons.items(), key=lambda x: -x[1]):
            summary += f"  - {gate}: {count}\n"

        if self.verified_findings:
            summary += "\nVERIFIED FINDINGS:\n"
            for f in self.verified_findings:
                summary += f"  [{f.severity.value.upper()}] {f.title} ({f.file_path}:{f.line_start})\n"
        else:
            summary += "\nNO VERIFIED FINDINGS - This is the ideal outcome for secure code.\n"

        await self.emit_log(summary)


class UltraStrictAgent(StrictAnalysisAgent):
    """
    Even stricter variant that requires double verification.

    This agent runs the verification pipeline TWICE and only reports
    findings that pass both times.
    """

    agent_type = AgentType.ULTRA_STRICT

    async def analyze(self):
        """Run ultra-strict analysis with double verification."""
        await self.emit_log("ULTRA-STRICT MODE: Double verification enabled")

        # First pass
        await super().analyze()

        if not self.verified_findings:
            return

        first_pass = self.verified_findings.copy()
        await self.emit_log(f"First pass: {len(first_pass)} findings. Running second verification...")

        # Clear for second pass
        self.verified_findings = []
        self.findings = []

        # Second pass on first-pass findings
        for finding in first_pass:
            try:
                code = await file_service.read_file(
                    os.path.join(self.repo_path, finding.file_path)
                )
            except Exception:
                code = ""

            passed, reason = await self._verify_finding(finding, code)

            if passed:
                self.verified_findings.append(finding)
                self.findings.append(finding)
                await self.emit_finding(finding)
                await self.emit_log(f"DOUBLE VERIFIED: {finding.title}")
            else:
                await self.emit_log(f"SECOND PASS REJECT: {finding.title} - {reason}")

        await self.emit_log(f"Ultra-strict complete: {len(self.verified_findings)} double-verified findings")
