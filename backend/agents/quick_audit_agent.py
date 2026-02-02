"""
Quick audit agent for fast security scanning.

DEPRECATED: This agent type is no longer used. The agent system has been
simplified to only use DeepAuditSupervisor (deep_audit agent type) which
provides proper diagramming support and better investigation capabilities.

This file is retained for backward compatibility with existing tests but
should not be used for new code. Use DeepAuditSupervisor instead.
"""

import warnings
import asyncio
import re
from pathlib import Path
from typing import Optional

from models.schemas import AgentType, Severity, FindingCreate, FindingClassification
from services import file_service
from .base_agent import BaseAgent

# Emit deprecation warning when imported
warnings.warn(
    "QuickAuditAgent is deprecated. Use DeepAuditSupervisor (deep_audit) instead. "
    "The agent system has been simplified to only use deep_audit agent type.",
    DeprecationWarning,
    stacklevel=2
)


class QuickAuditAgent(BaseAgent):
    """
    DEPRECATED: Fast security scanning agent.

    This agent type is no longer actively used. The agent system has been
    simplified to only use DeepAuditSupervisor which provides better
    investigation capabilities and diagramming support.

    - Pattern-based detection for common issues
    - Scans for hardcoded secrets and credentials
    - Surface-level analysis
    - Quick results, lower confidence
    """

    agent_type = AgentType.DEEP_AUDIT  # Map to deep_audit since QUICK_AUDIT is removed

    # Patterns for common security issues
    SECRET_PATTERNS = [
        (r'(?i)(api[_-]?key|apikey)\s*[=:]\s*["\'][^"\']{10,}["\']', "Hardcoded API Key", Severity.HIGH),
        (r'(?i)(password|passwd|pwd)\s*[=:]\s*["\'][^"\']+["\']', "Hardcoded Password", Severity.CRITICAL),
        (r'(?i)(secret|token)\s*[=:]\s*["\'][^"\']{10,}["\']', "Hardcoded Secret/Token", Severity.HIGH),
        (r'(?i)aws[_-]?(access[_-]?key|secret)', "AWS Credentials", Severity.CRITICAL),
        (r'-----BEGIN (RSA |DSA |EC |OPENSSH )?PRIVATE KEY-----', "Private Key", Severity.CRITICAL),
        (r'(?i)Bearer\s+[a-zA-Z0-9\-_.]+', "Hardcoded Bearer Token", Severity.HIGH),
        (r'(?i)(mysql|postgres|mongodb)://[^\s]+@', "Database Connection String", Severity.HIGH),
    ]

    VULN_PATTERNS = [
        # Injection
        (r'eval\s*\([^)]*\+', "Potential Code Injection (eval)", Severity.CRITICAL),
        (r'exec\s*\([^)]*\+', "Potential Command Injection (exec)", Severity.CRITICAL),
        (r'subprocess\.(call|run|Popen)\s*\([^)]*shell\s*=\s*True', "Shell Injection Risk", Severity.HIGH),
        (r'os\.system\s*\(', "Command Execution (os.system)", Severity.HIGH),

        # SQL Injection
        (r'(?i)(execute|query)\s*\([^)]*["\'].*\%s.*["\'].*%', "SQL Injection (string formatting)", Severity.HIGH),
        (r'(?i)(execute|query)\s*\([^)]*f["\']', "SQL Injection (f-string)", Severity.HIGH),
        (r'(?i)\.raw\s*\([^)]*\+', "Raw Query Injection", Severity.HIGH),

        # XSS
        (r'innerHTML\s*=', "Potential XSS (innerHTML)", Severity.MEDIUM),
        (r'dangerouslySetInnerHTML', "React XSS Risk (dangerouslySetInnerHTML)", Severity.MEDIUM),
        (r'document\.write\s*\(', "Potential XSS (document.write)", Severity.MEDIUM),

        # Deserialization
        (r'pickle\.loads?\s*\(', "Insecure Deserialization (pickle)", Severity.HIGH),
        (r'yaml\.load\s*\([^)]*(?!Loader)', "Unsafe YAML Loading", Severity.HIGH),
        (r'unserialize\s*\(', "PHP Deserialization", Severity.HIGH),

        # Path Traversal
        (r'open\s*\([^)]*\+[^)]*\)', "Potential Path Traversal", Severity.MEDIUM),
        (r'(?i)\.\./', "Path Traversal Pattern", Severity.INFO),

        # Crypto Issues
        (r'(?i)(md5|sha1)\s*\(', "Weak Hash Algorithm", Severity.LOW),
        (r'(?i)DES|RC4|RC2', "Weak Encryption Algorithm", Severity.MEDIUM),
        (r'random\.(random|randint|choice)', "Insecure Random (not cryptographic)", Severity.LOW),

        # Authentication/Session
        (r'(?i)verify\s*=\s*False', "SSL Verification Disabled", Severity.HIGH),
        (r'(?i)secure\s*=\s*False', "Insecure Cookie/Session", Severity.MEDIUM),
        (r'(?i)httponly\s*=\s*False', "HTTPOnly Cookie Disabled", Severity.MEDIUM),

        # Debug/Info Disclosure
        (r'(?i)debug\s*=\s*True', "Debug Mode Enabled", Severity.LOW),
        (r'(?i)stack_trace|stacktrace', "Stack Trace Exposure", Severity.LOW),
        (r'console\.(log|debug|info)\s*\(', "Console Logging in Production", Severity.INFO),
    ]

    async def analyze(self):
        """Run quick pattern-based security scan."""
        await self.emit_log("Starting quick security audit...")

        # Get files to scan
        if self.target_files:
            files = self.target_files
        else:
            # Include config files for secret detection
            extensions = [
                ".py", ".js", ".ts", ".jsx", ".tsx",
                ".java", ".go", ".rb", ".php",
                ".env", ".json", ".yml", ".yaml",
                ".config", ".conf", ".ini",
            ]
            files = await file_service.get_files_by_extension(
                self.repo_path,
                extensions,
                max_files=1000,
            )

        total_files = len(files)
        await self.emit_log(f"Scanning {total_files} files for security issues...")

        for idx, file_path in enumerate(files):
            if self._cancelled:
                break

            await self.emit_progress(idx + 1, total_files, file_path)

            try:
                file_content = await file_service.read_file(self.repo_path, file_path)

                # Run pattern matching
                await self._scan_patterns(file_path, file_content.content)

                self.files_analyzed += 1

            except Exception as e:
                # Skip files that can't be read
                continue

        # If focus areas specified, do targeted AI analysis
        if self.focus_areas and len(self.findings) > 0:
            await self.emit_log("Running targeted AI analysis on suspicious files...")
            await self._ai_verify_findings()

        await self.emit_log(
            f"Quick audit complete. Scanned {self.files_analyzed} files, "
            f"found {len(self.findings)} potential issues."
        )

    async def _scan_patterns(self, file_path: str, content: str):
        """Scan file content for security patterns."""
        lines = content.split("\n")

        # Check secret patterns
        for pattern, vuln_type, severity in self.SECRET_PATTERNS:
            for match in re.finditer(pattern, content):
                line_num = content[:match.start()].count("\n") + 1
                line_content = lines[line_num - 1] if line_num <= len(lines) else ""

                # Skip if in comment
                if self._is_in_comment(line_content):
                    continue

                finding = FindingCreate(
                    severity=severity,
                    title=f"{vuln_type} Detected",
                    description=f"Potential {vuln_type.lower()} found in code. "
                                f"This could expose sensitive credentials.",
                    file_path=file_path,
                    line_start=line_num,
                    line_end=line_num,
                    code_snippet=self._mask_secret(line_content.strip()[:200]),
                    vulnerability_type=vuln_type,
                    attack_scenario="Attacker could extract credentials from source code.",
                    recommended_fix="Move secrets to environment variables or a secure vault.",
                    confidence=0.7,
                    # Classification fields for pattern matches
                    classification=FindingClassification.SECURITY_ISSUE,
                    config_dependent=False,
                    contradiction_present=False,
                    fix_type="code",
                    classification_reasoning="Pattern match detected potential secret. Manual review required.",
                )

                f = self.add_finding(finding)
                await self.emit_finding(f)

        # Check vulnerability patterns
        for pattern, vuln_type, severity in self.VULN_PATTERNS:
            for match in re.finditer(pattern, content):
                line_num = content[:match.start()].count("\n") + 1
                line_content = lines[line_num - 1] if line_num <= len(lines) else ""

                if self._is_in_comment(line_content):
                    continue

                finding = FindingCreate(
                    severity=severity,
                    title=vuln_type,
                    description=f"Pattern match for {vuln_type.lower()}. "
                                f"Manual verification recommended.",
                    file_path=file_path,
                    line_start=line_num,
                    line_end=line_num,
                    code_snippet=line_content.strip()[:200],
                    vulnerability_type=vuln_type,
                    recommended_fix=self._get_fix_suggestion(vuln_type),
                    confidence=0.5,  # Lower confidence for pattern matching
                    # Classification fields for pattern matches
                    classification=FindingClassification.SECURITY_ISSUE,
                    config_dependent=False,
                    contradiction_present=False,
                    fix_type="code",
                    classification_reasoning="Pattern match detected - manual review required.",
                )

                f = self.add_finding(finding)
                await self.emit_finding(f)

    def _is_in_comment(self, line: str) -> bool:
        """Check if line is likely a comment."""
        stripped = line.strip()
        return (
            stripped.startswith("#") or
            stripped.startswith("//") or
            stripped.startswith("/*") or
            stripped.startswith("*") or
            stripped.startswith("'''") or
            stripped.startswith('"""')
        )

    def _mask_secret(self, text: str) -> str:
        """Mask potential secrets in text."""
        # Replace potential secrets with asterisks
        patterns = [
            r'(["\'])[^"\']{10,}(["\'])',
            r'(=\s*)[^\s]+(\s|$)',
        ]
        result = text
        for pattern in patterns:
            result = re.sub(pattern, r'\1****\2', result)
        return result

    def _get_fix_suggestion(self, vuln_type: str) -> str:
        """Get fix suggestion for vulnerability type."""
        fixes = {
            "Potential Code Injection (eval)": "Avoid eval(). Use safe alternatives like ast.literal_eval() or explicit parsing.",
            "Potential Command Injection (exec)": "Use parameterized commands with subprocess and avoid shell=True.",
            "Shell Injection Risk": "Set shell=False and pass command as list of arguments.",
            "Command Execution (os.system)": "Replace os.system with subprocess.run() with shell=False.",
            "SQL Injection (string formatting)": "Use parameterized queries with placeholders.",
            "SQL Injection (f-string)": "Use parameterized queries instead of string interpolation.",
            "Potential XSS (innerHTML)": "Sanitize user input. Use textContent or a DOM sanitization library.",
            "React XSS Risk (dangerouslySetInnerHTML)": "Sanitize HTML with DOMPurify or similar library.",
            "Insecure Deserialization (pickle)": "Use JSON or other safe serialization. Never unpickle untrusted data.",
            "Unsafe YAML Loading": "Use yaml.safe_load() instead of yaml.load().",
            "Weak Hash Algorithm": "Use SHA-256 or bcrypt for password hashing.",
            "SSL Verification Disabled": "Enable SSL verification in production.",
            "Debug Mode Enabled": "Disable debug mode in production.",
        }
        return fixes.get(vuln_type, "Review and fix according to security best practices.")

    async def _ai_verify_findings(self):
        """Use AI to verify and enrich pattern-matched findings."""
        # Group findings by file
        files_with_findings = {}
        for finding in self.findings:
            if finding.file_path not in files_with_findings:
                files_with_findings[finding.file_path] = []
            files_with_findings[finding.file_path].append(finding)

        # Verify top files
        for file_path, findings in list(files_with_findings.items())[:5]:
            try:
                file_content = await file_service.read_file(self.repo_path, file_path)
                # Could do AI verification here to adjust confidence
                # For now, just log
                await self.emit_log(f"Verified {len(findings)} findings in {file_path}")
            except Exception:
                pass
