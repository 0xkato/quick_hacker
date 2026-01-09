"""Path Traversal specialized analysis prompt.

Contains path traversal-specific:
- Sink patterns to look for
- Safe patterns that reject candidates
- Framework-specific considerations
- PoC patterns
"""

from typing import List, Dict, Any, Optional
from .base_analysis import BaseAnalysisPrompt


class PathTraversalAnalyzer:
    """Path traversal validation patterns."""

    dangerous_sinks = """
<path_traversal_dangerous_sinks>
DANGEROUS PATTERNS (flag these):

Python:
- open(user_input)
- open(os.path.join(base, user_input))
- read_file(user_input)
- send_file(user_input)
- send_from_directory(dir, user_input)
- flask.send_file(user_path)
- shutil.copy(user_input, dest) / shutil.move(user_input, dest)
- tarfile.extractall(user_path) / zipfile.extractall(user_path)
- os.path.join(base_dir, user_input) without validation

JavaScript/Node:
- fs.readFile(user_input)
- fs.readFileSync(user_input)
- res.sendFile(user_input)
- express.static(user_input)
- path.join(base, user_input) without validation
- require(user_input)

Java:
- new FileInputStream(user_input)
- new File(user_input)
- Files.readAllBytes(Paths.get(user_input))
- response.sendRedirect(user_input)
</path_traversal_dangerous_sinks>
"""

    safe_patterns = """
<path_traversal_safe_patterns>
SAFE PATTERNS (reject candidates using these):

Path normalization + validation:
- os.path.basename(user_input) - strips directory components
- werkzeug.secure_filename(user_input) - removes dangerous chars
- realpath + startswith check (chroot-style validation)
- os.path.normpath() + prefix validation

Allowlist validation:
- Checking filename against allowlist of permitted files
- Mapping user input to predefined paths (e.g., {"report": "/safe/report.pdf"})
- Validating file extension against allowlist

Chroot-style checks:
- resolved_path = os.path.realpath(os.path.join(base, user_input))
- if not resolved_path.startswith(base_dir): raise Error
- Using pathlib.Path.resolve() with parent check

Framework protections:
- Django MEDIA_ROOT with FileResponse (when properly configured)
- Express static middleware with proper root (when restricted)
</path_traversal_safe_patterns>
"""

    poc_patterns = """
<path_traversal_poc_patterns>
PROOF OF CONCEPT PATTERNS:

Basic traversal:
- ../../../etc/passwd
- ..\\..\\..\\windows\\win.ini
- ....//....//....//etc/passwd

URL-encoded:
- ..%2F..%2F..%2Fetc%2Fpasswd
- ..%252F..%252F..%252Fetc%252Fpasswd (double encoding)
- %2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd

Null byte injection (older systems):
- ../../../etc/passwd%00.jpg
- ../../../etc/passwd\x00.png

Path normalization bypasses:
- ..././..././..././etc/passwd
- ..;/..;/..;/etc/passwd
- ..\\..\\..\\/etc/passwd (mixed separators)

Absolute path injection:
- /etc/passwd
- file:///etc/passwd
- C:\\Windows\\win.ini

For PoC, use simplest payload that proves traversal.
Target /etc/passwd (Linux) or C:\\Windows\\win.ini (Windows).
</path_traversal_poc_patterns>
"""

    @classmethod
    def get_framework_guidance(cls, framework: Optional[str]) -> str:
        """Return framework-specific path traversal guidance."""
        if not framework:
            return ""

        guidance = {
            "flask": """
<flask_path_traversal_guidance>
Flask-specific:
- send_file(user_input) is DANGEROUS without validation
- send_from_directory() is safer but still needs filename validation
- Use werkzeug.utils.secure_filename() before file operations
- Check for os.path.join() in routes handling file downloads
- Verify static file serving doesn't expose sensitive paths
</flask_path_traversal_guidance>
""",
            "django": """
<django_path_traversal_guidance>
Django-specific:
- FileResponse(open(user_path)) is DANGEROUS
- HttpResponse with file content from user path is DANGEROUS
- MEDIA_ROOT/STATIC_ROOT should be properly configured
- Check for os.path.join() in views handling uploads/downloads
- Verify MEDIA_URL doesn't allow traversal
- Use Django's FileField/ImageField validators when possible
</django_path_traversal_guidance>
""",
            "express": """
<express_path_traversal_guidance>
Express/Node-specific:
- res.sendFile(user_input) is DANGEROUS without root option
- res.sendFile(path, {root: '/safe/dir'}) is safer
- express.static() should have restricted root
- path.join() with user input needs validation
- fs.readFile/readFileSync with user paths is DANGEROUS
- Use path.basename() to strip directory components
</express_path_traversal_guidance>
""",
        }
        return guidance.get(framework.lower(), "")

    @classmethod
    def get_full_prompt(cls, framework: Optional[str] = None) -> str:
        """Return full path traversal-specific prompt content."""
        parts = [
            cls.dangerous_sinks.strip(),
            cls.safe_patterns.strip(),
            cls.poc_patterns.strip(),
        ]

        fw_guidance = cls.get_framework_guidance(framework)
        if fw_guidance:
            parts.append(fw_guidance.strip())

        return "\n\n".join(parts)


def build_path_traversal_prompt(
    candidates: List[Dict[str, Any]],
    framework: Optional[str] = None,
    tech_stack: Optional[Dict[str, Any]] = None,
) -> str:
    """Build complete path traversal analysis prompt.

    Args:
        candidates: Path traversal candidates from triage phase
        framework: Detected framework (django, flask, express, etc.)
        tech_stack: Full tech stack context

    Returns:
        Complete path traversal analysis prompt
    """
    parts = [
        BaseAnalysisPrompt.get_analysis_mission("path_traversal"),
        BaseAnalysisPrompt.get_validation_requirements(),
        PathTraversalAnalyzer.get_full_prompt(framework),
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
