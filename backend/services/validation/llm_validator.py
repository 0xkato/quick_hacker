"""LLM-based finding validator using Anthropic API with tool use."""
import asyncio
import glob as glob_module
import logging
import re
import shlex
import subprocess
from datetime import UTC, datetime
from pathlib import Path
from typing import Optional, Any

from models.schemas import Finding, Evidence, ValidationResult
from services.classification.classifier import ClassificationResult

logger = logging.getLogger(__name__)


class LLMFindingValidator:
    """
    LLM-based validator that uses Anthropic API to deeply validate findings.

    Uses tool use (read_file, grep_code, glob_files) to investigate codebase
    and determine if findings are truly valid security issues.
    """

    def __init__(
        self,
        anthropic_api_key: str,
        repo_root: str,
        model: str = "claude-sonnet-3-5-20241022",
        enabled_verifiers: list[str] = None,
    ):
        """
        Initialize LLM validator.

        Args:
            anthropic_api_key: Anthropic API key
            repo_root: Path to repository root
            model: Model to use (default: claude-sonnet-3-5-20241022)

        Raises:
            RuntimeError: If anthropic package not installed
        """
        try:
            from anthropic import Anthropic
        except ModuleNotFoundError as exc:
            raise RuntimeError(
                "LLMFindingValidator requires the 'anthropic' dependency. "
                "Install it or disable LLM validation."
            ) from exc

        self.client = Anthropic(api_key=anthropic_api_key)
        self.repo_root = Path(repo_root)
        self.model = model
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

    def _tool_read_file(self, file_path: str) -> str:
        """Read file from repo."""
        try:
            # Build full path and resolve to absolute canonical path
            full_path = (self.repo_root / file_path).resolve()
            repo_root_resolved = self.repo_root.resolve()

            # SECURITY: Verify path is within repo_root
            try:
                # relative_to raises ValueError if path is not relative
                full_path.relative_to(repo_root_resolved)
            except ValueError:
                return f"Error: Access denied - path outside repository: {file_path}"

        except Exception as e:
            return f"Error: Invalid path: {str(e)}"

        # Now proceed with original logic
        if not full_path.exists():
            return f"Error: File not found: {file_path}"

        if not full_path.is_file():
            return f"Error: Not a file: {file_path}"

        try:
            with open(full_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read(100000)  # Limit to 100KB
            return content
        except Exception as e:
            return f"Error reading file: {str(e)}"

    def _tool_grep_code(self, pattern: str, glob: Optional[str] = None) -> str:
        """Search codebase using ripgrep."""
        try:
            cmd = ["rg", "--no-heading", "--line-number", pattern, str(self.repo_root)]

            if glob:
                cmd.extend(["--glob", glob])

            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=10,
            )

            # Return code 0 = found matches, 1 = no matches, 2+ = error
            if result.returncode == 0:
                output = result.stdout[:5000]  # Limit to 5000 chars
                return output
            elif result.returncode == 1:
                return f"No matches found for pattern: {pattern}"
            else:
                return f"Grep error: {result.stderr[:500]}"

        except FileNotFoundError:
            return "Error: ripgrep (rg) not found - install ripgrep"
        except subprocess.TimeoutExpired:
            return "Grep timeout - pattern may be too broad"
        except Exception as e:
            return f"Grep error: {str(e)}"

    def _tool_glob_files(self, pattern: str) -> str:
        """Find files by glob pattern."""
        try:
            # SECURITY: Reject patterns that obviously escape repo
            if pattern.startswith('/') or '..' in pattern:
                return f"Glob error: Pattern must be relative to repository root"

            # Build full pattern path
            full_pattern = str(self.repo_root / pattern)
            repo_root_resolved = self.repo_root.resolve()

            # Find matching files
            matches = glob_module.glob(full_pattern, recursive=True)
            original_count = len(matches)

            # Convert to relative paths and validate security
            relative_paths = []
            for match in matches:
                try:
                    match_resolved = Path(match).resolve()

                    # SECURITY: Only include files within repo_root
                    try:
                        match_resolved.relative_to(repo_root_resolved)
                    except ValueError:
                        continue  # Skip files outside repo

                    # Convert to relative path for display
                    rel_path = match_resolved.relative_to(repo_root_resolved)
                    relative_paths.append(str(rel_path))
                except (ValueError, OSError):
                    continue

            if not relative_paths:
                return f"No files found matching: {pattern}"

            # Limit to 100 files
            if len(relative_paths) > 100:
                limited_paths = relative_paths[:100]
                additional = len(relative_paths) - 100
                return "\n".join(limited_paths) + f"\n... ({additional} more files)"

            return "\n".join(relative_paths)

        except Exception as e:
            return f"Glob error: {str(e)}"

    def _tool_gdb_debug(
        self,
        binary_path: str,
        commands: list[str],
        input_file: Optional[str] = None,
    ) -> str:
        """Execute GDB commands on a binary for memory corruption analysis."""
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

            # Validate commands input
            if not commands:
                return "Error: No commands provided"
            if len(commands) > 100:
                return "Error: Too many commands (max 100)"
            total_cmd_size = sum(len(cmd) for cmd in commands)
            if total_cmd_size > 50000:
                return "Error: Commands too large (max 50KB)"

            # Build GDB script from commands
            gdb_script = "\n".join(commands)

            # Handle input file if provided
            if input_file:
                full_input = (self.repo_root / input_file).resolve()
                try:
                    full_input.relative_to(repo_root_resolved)
                except ValueError:
                    return "Error: input_file must be within repository"
                gdb_script = f"run < {shlex.quote(str(full_input))}\n" + gdb_script

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
            return "Error: GDB timeout - execution exceeded 30s limit"
        except FileNotFoundError:
            return "Error: GDB not found - install GDB to use this tool"
        except Exception as e:
            return f"Error: GDB execution failed: {str(e)}"

    def _get_tool_definitions(self) -> list[dict]:
        """
        Get tool definitions in Anthropic API format.

        Returns:
            List of tool definition dictionaries with name, description, and input_schema
        """
        tools = [
            {
                "name": "read_file",
                "description": "Read source file contents",
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "file_path": {
                            "type": "string",
                            "description": "Path to file relative to repo root"
                        }
                    },
                    "required": ["file_path"]
                }
            },
            {
                "name": "grep_code",
                "description": "Search codebase for patterns using regex",
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "pattern": {
                            "type": "string",
                            "description": "Regex pattern to search for"
                        },
                        "glob": {
                            "type": "string",
                            "description": "Optional glob pattern to filter files (e.g., '*.py')"
                        }
                    },
                    "required": ["pattern"]
                }
            },
            {
                "name": "glob_files",
                "description": "Find files by name pattern",
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "pattern": {
                            "type": "string",
                            "description": "Glob pattern (e.g., '**/*.py', 'src/**/*test*.py')"
                        }
                    },
                    "required": ["pattern"]
                }
            }
        ]

        # Add GDB tool definition if enabled
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

    def _build_validation_prompt(
        self,
        finding: Finding,
        evidence: Evidence,
        classification: ClassificationResult,
        threat_model_profile: Optional[dict],
        criticism_level: str,
    ) -> str:
        """
        Build the validation prompt for the Anthropic API.

        Args:
            finding: The finding to validate
            evidence: Evidence bundle for the finding
            classification: Classification result with proof checklist
            threat_model_profile: Threat model profile for context
            criticism_level: Level of criticism to apply (low, medium, high)

        Returns:
            Formatted prompt string
        """
        # Build checklist text
        checklist = classification.proof_checklist
        checklist_text = f"""- Source Controlled Input: {checklist.source_controlled_input.status.value} - {checklist.source_controlled_input.reason}
- Sink Present: {checklist.sink_present.status.value} - {checklist.sink_present.reason}
- Dataflow Evidenced: {checklist.dataflow_evidenced.status.value} - {checklist.dataflow_evidenced.reason}
- Reachable: {checklist.reachable.status.value} - {checklist.reachable.reason}
- Boundary Crossed: {checklist.boundary_crossed.status.value} - {checklist.boundary_crossed.reason}
- Not Only Misconfig: {checklist.not_only_misconfig.status.value} - {checklist.not_only_misconfig.reason}"""

        return f"""You are a security validation expert performing secondary triage on a potential vulnerability.

## Your Mission
Determine if this is a TRUE EXPLOITABLE SECURITY ISSUE or should be filtered out.

## Criticism Level: {criticism_level.upper()}
HIGH: Assume NOT exploitable unless you can prove both reachability AND attacker control
MEDIUM: Accept strong evidence for one dimension, require proof for the other
LOW: Trust the initial classification unless clearly wrong

## Finding Summary
- Title: {finding.title}
- Type: {finding.vulnerability_type}
- File: {finding.file_path}:{finding.line_start}
- Disposition: {classification.disposition.value}
- Classification Confidence: {classification.classification_confidence}%

## Initial Classification Checklist
{checklist_text}

## Your Investigation Tasks

**Task 1: Validate Attacker Control**
Question: Can an attacker ACTUALLY control the input to the dangerous sink?
- Use Grep to find all call sites of the vulnerable function
- Use Read to examine the data sources
- Trace back to untrusted boundaries (HTTP, file upload, repo checkout, etc.)
- HIGH CRITICISM: Reject if no clear path from untrusted source to sink

**Task 2: Validate Reachability**
Question: Is this code path ACTUALLY reachable in production?
- Use Grep to find route registrations, entry points, or invocations
- Use Read to check if code is conditionally disabled (feature flags, env checks)
- Verify the function is actually called, not just defined
- HIGH CRITICISM: Reject if no clear invocation path

**Task 3: Differentiate Security vs Bug vs Expected Behavior**
- Security issue: Exploitable by attacker with realistic capabilities
- Bug: Functional problem without security impact
- Hardening: Dangerous pattern but not proven exploitable
- By design: Intentional behavior (e.g., eval() in template engine)
- Expected behavior: Working as designed without risk

## Tools Available
- read_file(file_path): Read source files
- grep_code(pattern, glob): Search codebase for patterns
- glob_files(pattern): Find files by name pattern

## Response Format
Respond with exactly:
```
DECISION: VALID | INVALID
CATEGORY: security_issue | bug | hardening | by_design | expected_behavior
REASONING:
- [Bullet 1: key finding from investigation]
- [Bullet 2: evidence for/against exploitability]
- [Bullet 3: final determination]
```

Be highly skeptical. Default to INVALID unless you can prove it's exploitable."""

    async def validate(
        self,
        finding: Finding,
        evidence: Evidence,
        classification: ClassificationResult,
        threat_model_profile: Any,
        criticism_level: str,
        timeout_seconds: int = 120,
    ) -> ValidationResult:
        """
        Validate a finding using LLM with tool use.

        Args:
            finding: The finding to validate
            evidence: Evidence bundle for the finding
            classification: Classification result with proof checklist
            threat_model_profile: Threat model profile for context
            criticism_level: Level of criticism to apply (low, medium, high)
            timeout_seconds: Timeout in seconds (default: 120)

        Returns:
            ValidationResult with validation decision
        """
        try:
            # Wrap _run_validation in timeout
            result = await asyncio.wait_for(
                self._run_validation(
                    finding=finding,
                    evidence=evidence,
                    classification=classification,
                    threat_model_profile=threat_model_profile,
                    criticism_level=criticism_level,
                ),
                timeout=timeout_seconds,
            )
            return result
        except asyncio.TimeoutError:
            logger.warning(
                f"LLM validation timed out after {timeout_seconds}s for finding {finding.id}"
            )
            return ValidationResult(
                is_valid=False,
                reasoning=[
                    f"Validation timeout after {timeout_seconds}s",
                    "Insufficient time to prove exploitability - filtered conservatively",
                ],
                categories=["timeout"],
                confidence=0,
                timestamp=datetime.now(UTC),
            )
        except Exception as e:
            logger.error(f"Error during LLM validation for finding {finding.id}: {e}")
            return ValidationResult(
                is_valid=False,
                reasoning=[
                    f"Validation error: {str(e)[:200]}",
                    "Could not complete investigation - filtered conservatively",
                ],
                categories=["error"],
                confidence=0,
                timestamp=datetime.now(UTC),
            )

    async def _execute_tool_call(self, tool_use) -> dict:
        """
        Execute a single tool call and return result.

        Args:
            tool_use: Tool use object with name, input, and id attributes

        Returns:
            Tool result dict with type, tool_use_id, and content
        """
        tool_name = tool_use.name
        tool_input = tool_use.input
        tool_id = tool_use.id

        # Check if tool exists
        if tool_name not in self.tools:
            return {
                "type": "tool_result",
                "tool_use_id": tool_id,
                "content": f"Unknown tool: {tool_name}"
            }

        # Execute tool
        try:
            tool_fn = self.tools[tool_name]
            result = tool_fn(**tool_input)
            return {
                "type": "tool_result",
                "tool_use_id": tool_id,
                "content": result
            }
        except Exception as e:
            logger.error(f"Tool execution error for {tool_name}: {e}")
            return {
                "type": "tool_result",
                "tool_use_id": tool_id,
                "content": f"Tool error: {str(e)}"
            }

    def _parse_validation_response(self, response_text: str) -> ValidationResult:
        """
        Parse validation response from LLM.

        Extracts DECISION, CATEGORY, and REASONING from the LLM's response text.

        Args:
            response_text: Raw response text from LLM

        Returns:
            ValidationResult with parsed decision and reasoning
        """
        try:
            # Extract DECISION using regex
            decision_match = re.search(
                r"DECISION:\s*(VALID|INVALID)",
                response_text,
                re.IGNORECASE
            )
            if not decision_match:
                raise ValueError("DECISION not found in response")

            is_valid = decision_match.group(1).upper() == "VALID"

            # Extract CATEGORY using regex
            category_match = re.search(
                r"CATEGORY:\s*(\w+(?:_\w+)*)",
                response_text,
                re.IGNORECASE
            )
            category = category_match.group(1) if category_match else "unknown"

            # Extract REASONING bullets using regex
            reasoning_match = re.search(
                r"REASONING:\s*((?:^-.*$\n?)+)",
                response_text,
                re.MULTILINE | re.IGNORECASE
            )

            if reasoning_match:
                reasoning_text = reasoning_match.group(1)
                # Split by newlines and filter lines starting with "-"
                reasoning = []
                for line in reasoning_text.split("\n"):
                    line = line.strip()
                    if line.startswith("-"):
                        # Strip "- " prefix and whitespace
                        reasoning.append(line[1:].strip())
            else:
                reasoning = ["No reasoning provided"]

            return ValidationResult(
                is_valid=is_valid,
                reasoning=reasoning,
                categories=[category],
                confidence=95 if is_valid else 0,
                timestamp=datetime.now(UTC),
            )

        except Exception as e:
            logger.error(f"Failed to parse validation response: {e}")
            return ValidationResult(
                is_valid=False,
                reasoning=[
                    "Failed to parse validator response",
                    f"Parse error: {str(e)[:200]}"
                ],
                categories=["parse_error"],
                confidence=0,
                timestamp=datetime.now(UTC),
            )

    async def _run_validation(
        self,
        finding: Finding,
        evidence: Evidence,
        classification: ClassificationResult,
        threat_model_profile: Any,
        criticism_level: str,
    ) -> ValidationResult:
        """
        Run the actual validation logic with full agentic loop.

        Orchestrates multi-turn conversation with Anthropic API, allowing the LLM
        to use tools to investigate the codebase and reach a validation decision.

        Args:
            finding: The finding to validate
            evidence: Evidence bundle
            classification: Classification result
            threat_model_profile: Threat model profile
            criticism_level: Criticism level

        Returns:
            ValidationResult with validation decision
        """
        # Build system prompt and tool definitions
        system_prompt = self._build_validation_prompt(
            finding=finding,
            evidence=evidence,
            classification=classification,
            threat_model_profile=threat_model_profile,
            criticism_level=criticism_level,
        )
        tools = self._get_tool_definitions()

        # Initialize conversation
        messages = [{"role": "user", "content": "Begin investigation."}]
        max_turns = 10
        investigation_steps = []

        # Main agentic loop
        for turn in range(max_turns):
            try:
                # Call Anthropic API (synchronous call from async method)
                response = self.client.messages.create(
                    model=self.model,
                    max_tokens=4096,
                    system=system_prompt,
                    messages=messages,
                    tools=tools,
                )

                # Handle end_turn - LLM has finished investigation
                if response.stop_reason == "end_turn":
                    # Find text block in response
                    for block in response.content:
                        if hasattr(block, 'type') and block.type == "text":
                            return self._parse_validation_response(block.text)

                    # No text block found - error
                    logger.error("LLM ended turn without text response")
                    return ValidationResult(
                        is_valid=False,
                        reasoning=[
                            "LLM ended turn without providing decision",
                            "Missing expected response format"
                        ],
                        categories=["error"],
                        confidence=0,
                        timestamp=datetime.now(UTC),
                    )

                # Handle tool_use - LLM wants to use tools
                elif response.stop_reason == "tool_use":
                    tool_results = []

                    # Process each tool use in response
                    for block in response.content:
                        if hasattr(block, 'type') and block.type == "tool_use":
                            # Track investigation step
                            investigation_steps.append(f"{block.name}({block.input})")

                            # Execute tool
                            result = await self._execute_tool_call(block)
                            tool_results.append(result)

                    # Append assistant message with tool use
                    messages.append({"role": "assistant", "content": response.content})

                    # Append user message with tool results
                    messages.append({"role": "user", "content": tool_results})

                # Handle unexpected stop reason
                else:
                    logger.warning(f"Unexpected stop_reason: {response.stop_reason}")
                    return ValidationResult(
                        is_valid=False,
                        reasoning=[
                            f"Unexpected API stop_reason: {response.stop_reason}",
                            "Could not complete validation"
                        ],
                        categories=["error"],
                        confidence=0,
                        timestamp=datetime.now(UTC),
                    )

            except Exception as e:
                logger.error(f"Error in validation loop turn {turn}: {e}")
                raise  # Re-raise to be caught by validate()

        # Max turns exceeded - conservative filtering
        return ValidationResult(
            is_valid=False,
            reasoning=[
                f"Investigation exceeded maximum {max_turns} tool use rounds",
                "Could not reach conclusion - filtered conservatively"
            ],
            categories=["inconclusive"],
            investigation_steps=investigation_steps,
            confidence=0,
            timestamp=datetime.now(UTC),
        )
