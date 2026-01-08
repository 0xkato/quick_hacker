"""Custom agent for user-defined security analysis."""

import asyncio

from models.schemas import AgentType
from services import file_service
from .base_agent import BaseAgent


class CustomAgent(BaseAgent):
    """
    Custom security analysis agent.

    - User provides the prompt/instructions
    - User selects target files
    - Maximum flexibility for specific use cases
    """

    agent_type = AgentType.CUSTOM

    # Default extensions if no files specified
    DEFAULT_EXTENSIONS = [
        ".py", ".js", ".ts", ".jsx", ".tsx",
        ".java", ".go", ".rs", ".c", ".cpp",
        ".rb", ".php", ".cs", ".sol",
    ]

    async def analyze(self):
        """Run custom analysis with user-provided prompt."""
        if not self.custom_prompt:
            await self.emit_log("Warning: No custom prompt provided. Using default analysis.")

        await self.emit_log("Starting custom analysis...")
        await self.emit_log(f"Custom instructions: {self.custom_prompt or 'None'}...")

        # Get files to analyze
        if self.target_files:
            files = self.target_files
            await self.emit_log(f"Analyzing {len(files)} specified files")
        else:
            files = await file_service.get_files_by_extension(
                self.repo_path,
                self.DEFAULT_EXTENSIONS,
                max_files=200,
            )
            await self.emit_log(f"No files specified, analyzing {len(files)} source files")

        total_files = len(files)

        for idx, file_path in enumerate(files):
            if self._cancelled:
                break

            while self.status.value == "paused":
                await asyncio.sleep(1)
                if self._cancelled:
                    break

            await self.emit_progress(idx + 1, total_files, file_path)

            try:
                file_content = await file_service.read_file(self.repo_path, file_path)

                # Skip very small files
                if file_content.line_count < 3:
                    continue

                await self.emit_log(f"Analyzing: {file_path}")

                # Analyze with custom context
                await self.analyze_file(file_path, file_content.content)

                self.files_analyzed += 1

            except Exception as e:
                await self.emit_log(f"Error analyzing {file_path}: {e}")
                continue

            # Delay between files
            await asyncio.sleep(0.3)

        await self.emit_log(
            f"Custom analysis complete. Analyzed {self.files_analyzed} files, "
            f"found {len(self.findings)} potential issues."
        )


class FocusedAgent(CustomAgent):
    """
    Agent for focused analysis on specific vulnerability types.

    Use focus_areas to specify what to look for:
    - "injection": SQL, Command, Code injection
    - "xss": Cross-site scripting
    - "auth": Authentication/Authorization issues
    - "crypto": Cryptographic weaknesses
    - "secrets": Hardcoded secrets/credentials
    - "logic": Business logic vulnerabilities
    """

    FOCUS_PROMPTS = {
        "injection": """
Focus specifically on INJECTION vulnerabilities:
- SQL Injection (parameterized queries, ORM misuse, raw queries)
- Command Injection (shell commands, subprocess, exec)
- Code Injection (eval, dynamic code execution)
- LDAP Injection
- XML/XPath Injection

Look for:
1. User input flowing into queries/commands
2. String concatenation in queries
3. Unsafe deserialization
4. Dynamic code evaluation
""",
        "xss": """
Focus specifically on XSS (Cross-Site Scripting):
- Reflected XSS (input reflected in response)
- Stored XSS (persisted user input displayed)
- DOM-based XSS (client-side manipulation)

Look for:
1. User input rendered without encoding
2. innerHTML usage
3. document.write
4. dangerouslySetInnerHTML in React
5. Template injection
""",
        "auth": """
Focus specifically on AUTHENTICATION and AUTHORIZATION:
- Broken authentication
- Session management issues
- Insecure password storage
- Missing access controls
- IDOR (Insecure Direct Object Reference)
- Privilege escalation

Look for:
1. Hardcoded credentials
2. Weak password requirements
3. Missing authentication checks
4. Improper session handling
5. Authorization bypass opportunities
""",
        "crypto": """
Focus specifically on CRYPTOGRAPHIC issues:
- Weak algorithms (MD5, SHA1 for passwords, DES, RC4)
- Insecure random number generation
- Hardcoded encryption keys
- Missing encryption
- Improper key management

Look for:
1. Deprecated hash functions
2. Math.random() or random.random() for security
3. ECB mode usage
4. Missing salt in password hashing
5. Exposed cryptographic keys
""",
        "secrets": """
Focus specifically on SECRETS and CREDENTIALS:
- Hardcoded API keys
- Database passwords in code
- Private keys committed
- AWS/Cloud credentials
- OAuth tokens

Look for:
1. API keys in source code
2. Connection strings with passwords
3. Private keys or certificates
4. Environment variable defaults with real values
5. Configuration files with credentials
""",
        "logic": """
Focus specifically on BUSINESS LOGIC vulnerabilities:
- Race conditions
- Time-of-check to time-of-use (TOCTOU)
- Integer overflow/underflow
- Logic bypass
- State manipulation

Look for:
1. Non-atomic operations on shared resources
2. Missing validation on critical operations
3. Bypass conditions in business rules
4. Price/quantity manipulation
5. Workflow bypass opportunities
""",
    }

    async def analyze(self):
        """Run focused analysis based on focus_areas."""
        if not self.focus_areas:
            # Fall back to general custom analysis
            await super().analyze()
            return

        # Build enhanced prompt from focus areas
        enhanced_prompt = self.custom_prompt or ""
        enhanced_prompt += "\n\n=== FOCUS AREAS ===\n"

        for area in self.focus_areas:
            area_lower = area.lower()
            if area_lower in self.FOCUS_PROMPTS:
                enhanced_prompt += f"\n{self.FOCUS_PROMPTS[area_lower]}\n"

        self.custom_prompt = enhanced_prompt.strip()

        await self.emit_log(f"Focusing on: {', '.join(self.focus_areas)}")

        # Run analysis with enhanced prompt
        await super().analyze()
