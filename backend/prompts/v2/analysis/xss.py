"""Cross-Site Scripting (XSS) specialized analysis prompt.

Contains XSS-specific:
- Sink patterns to look for
- Safe patterns that reject candidates
- Framework-specific considerations
- PoC patterns
"""

from typing import List, Dict, Any, Optional
from .base_analysis import BaseAnalysisPrompt


class XSSAnalyzer:
    """XSS validation patterns."""

    dangerous_sinks = """
<xss_dangerous_sinks>
DANGEROUS PATTERNS (flag these):

JavaScript DOM:
- element.innerHTML = userInput
- element.outerHTML = userInput
- document.write(userInput)
- document.writeln(userInput)
- document.body.innerHTML = userInput

React:
- dangerouslySetInnerHTML={{__html: userInput}}
- dangerouslySetInnerHTML with user-controlled content

Vue:
- v-html="userInput"
- v-html directive with user-controlled content

Angular:
- [innerHTML]="userInput" without sanitization
- bypassSecurityTrustHtml(userInput)
- bypassSecurityTrustScript(userInput)

jQuery:
- $(selector).html(userInput)
- $(selector).append(userInput)
- $(selector).prepend(userInput)
- $(userInput)  # Selector injection

Server-side templates (render without escape):
- {{ userInput | safe }}  # Django/Jinja2 safe filter
- {{! userInput }}  # Handlebars unescaped
- {{{ userInput }}}  # Mustache unescaped
- <%- userInput %>  # EJS unescaped
- !{userInput}  # Pug/Jade unescaped

Template literals in HTML context:
- `<div>${userInput}</div>`  # Template literal in HTML
- res.send(`<html>${userInput}</html>`)
</xss_dangerous_sinks>
"""

    safe_patterns = """
<xss_safe_patterns>
SAFE PATTERNS (reject candidates using these):

DOM text assignment:
- element.textContent = userInput  # SAFE - no HTML parsing
- element.innerText = userInput  # SAFE - no HTML parsing
- document.createTextNode(userInput)  # SAFE

Auto-escaping templates:
- Jinja2 with autoescaping enabled (default)
- React JSX expressions {userInput}  # SAFE - auto-escaped
- Angular interpolation {{userInput}}  # SAFE - auto-escaped
- Vue mustache syntax {{userInput}}  # SAFE - auto-escaped

Sanitization libraries:
- DOMPurify.sanitize(userInput)
- sanitize-html(userInput)
- xss(userInput)  # xss npm package
- bleach.clean(userInput)  # Python bleach

Content Security Policy:
- CSP headers preventing inline scripts
- CSP with strict nonce/hash requirements
- Content-Security-Policy: script-src 'strict-dynamic'

Framework sanitization:
- Angular DomSanitizer.sanitize()
- React dangerouslySetInnerHTML with sanitized input

Input validation:
- Strict allowlist validation before rendering
- HTML entity encoding before output
</xss_safe_patterns>
"""

    poc_patterns = """
<xss_poc_patterns>
PROOF OF CONCEPT PATTERNS:

Basic script injection:
- <script>alert(1)</script>
- <script>alert(document.domain)</script>
- <script>alert(document.cookie)</script>

Event handler injection:
- <img src=x onerror=alert(1)>
- <svg onload=alert(1)>
- <body onload=alert(1)>
- <input onfocus=alert(1) autofocus>
- <marquee onstart=alert(1)>
- <div onmouseover=alert(1)>test</div>

Protocol handlers:
- <a href="javascript:alert(1)">click</a>
- <iframe src="javascript:alert(1)">
- <form action="javascript:alert(1)">

HTML context escapes:
- "><script>alert(1)</script>
- '><script>alert(1)</script>
- </script><script>alert(1)</script>

Attribute injection:
- " onmouseover="alert(1)
- ' onfocus='alert(1)' autofocus='

Template literal injection:
- ${alert(1)}
- ${constructor.constructor('return this')()}

For PoC, use simplest payload that proves injection.
Prefer: <script>alert(1)</script> or <img src=x onerror=alert(1)>
</xss_poc_patterns>
"""

    @classmethod
    def get_framework_guidance(cls, framework: Optional[str]) -> str:
        """Return framework-specific XSS guidance."""
        if not framework:
            return ""

        guidance = {
            "react": """
<react_xss_guidance>
React-specific:
- JSX expressions {value} are SAFE - auto-escaped, reject these
- dangerouslySetInnerHTML is DANGEROUS - check if input is sanitized
- href="javascript:" is DANGEROUS in <a> tags
- Server-side rendering: check for unsanitized data in initial state
- Check for npm packages that bypass React's escaping
- URL parameters in href without validation can be dangerous
</react_xss_guidance>
""",
            "angular": """
<angular_xss_guidance>
Angular-specific:
- Interpolation {{value}} is SAFE - auto-escaped, reject these
- [innerHTML] without sanitization is DANGEROUS
- bypassSecurityTrust* methods are DANGEROUS - check input source
- DomSanitizer with sanitize() is SAFE - reject these
- Template injection in server-rendered Angular is DANGEROUS
- Check for user input in [src], [href] bindings
</angular_xss_guidance>
""",
            "vue": """
<vue_xss_guidance>
Vue-specific:
- Mustache syntax {{value}} is SAFE - auto-escaped, reject these
- v-html directive is DANGEROUS - check if input is sanitized
- v-bind:href with javascript: is DANGEROUS
- Server-side rendering: check for unsanitized data in initial state
- Vue templates compiled from user input are DANGEROUS
- Check for user input in v-bind:src, v-bind:href
</vue_xss_guidance>
""",
            "django": """
<django_xss_guidance>
Django-specific:
- Default template auto-escaping is SAFE - reject these
- {{ var | safe }} filter is DANGEROUS - bypasses escaping
- mark_safe() is DANGEROUS - check what's being marked safe
- {% autoescape off %} block is DANGEROUS
- format_html() with proper placeholders is SAFE
- Check for user input passed to safe filter
</django_xss_guidance>
""",
            "flask": """
<flask_xss_guidance>
Flask/Jinja2-specific:
- Jinja2 auto-escaping is SAFE when enabled - reject these
- {{ var | safe }} filter is DANGEROUS - bypasses escaping
- Markup() class marks content as safe - check source
- {% autoescape false %} is DANGEROUS
- render_template_string() with user input is DANGEROUS
- Check for user input in templates without escaping
</flask_xss_guidance>
""",
        }
        return guidance.get(framework.lower(), "")

    @classmethod
    def get_full_prompt(cls, framework: Optional[str] = None) -> str:
        """Return full XSS-specific prompt content."""
        parts = [
            cls.dangerous_sinks.strip(),
            cls.safe_patterns.strip(),
            cls.poc_patterns.strip(),
        ]

        fw_guidance = cls.get_framework_guidance(framework)
        if fw_guidance:
            parts.append(fw_guidance.strip())

        return "\n\n".join(parts)


def build_xss_prompt(
    candidates: List[Dict[str, Any]],
    framework: Optional[str] = None,
    tech_stack: Optional[Dict[str, Any]] = None,
) -> str:
    """Build complete XSS analysis prompt.

    Args:
        candidates: XSS candidates from triage phase
        framework: Detected framework (react, angular, vue, django, flask, etc.)
        tech_stack: Full tech stack context

    Returns:
        Complete XSS analysis prompt
    """
    parts = [
        BaseAnalysisPrompt.get_analysis_mission("xss"),
        BaseAnalysisPrompt.get_validation_requirements(),
        XSSAnalyzer.get_full_prompt(framework),
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
