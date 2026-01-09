"""SSRF (Server-Side Request Forgery) specialized analysis prompt.

Contains SSRF-specific:
- Sink patterns to look for
- Safe patterns that reject candidates
- Framework-specific considerations
- PoC patterns
"""

from typing import List, Dict, Any, Optional
from .base_analysis import BaseAnalysisPrompt


class SSRFAnalyzer:
    """SSRF validation patterns."""

    dangerous_sinks = """
<ssrf_dangerous_sinks>
DANGEROUS PATTERNS (flag these):

Python:
- requests.get(user_url)
- requests.post(user_url, ...)
- requests.request(method, user_url)
- urllib.request.urlopen(user_url)
- urllib.request.Request(user_url)
- http.client.HTTPConnection(user_host)
- http.client.HTTPSConnection(user_host)
- httpx.get(user_url)
- aiohttp.ClientSession().get(user_url)

JavaScript/Node:
- fetch(user_url)
- axios.get(user_url)
- axios.post(user_url, ...)
- axios(user_url)
- http.request(user_url)
- https.request(user_url)
- got(user_url)
- node-fetch(user_url)

Java:
- new URL(user_url).openConnection()
- HttpClient.newHttpClient().send(request_with_user_url)
- HttpURLConnection with user-controlled URL
- RestTemplate.getForObject(user_url, ...)
- WebClient.create(user_url)
</ssrf_dangerous_sinks>
"""

    safe_patterns = """
<ssrf_safe_patterns>
SAFE PATTERNS (reject candidates using these):

URL allowlist validation:
- Check URL against hardcoded list of allowed domains
- allowed_domains = ["api.example.com", "cdn.example.com"]
- if parsed_url.netloc not in allowed_domains: reject

Domain validation:
- Strict domain suffix check (not just substring)
- parsed = urlparse(url); if not parsed.netloc.endswith(".trusted.com"): reject

IP blocking (private ranges):
- Block 127.0.0.0/8 (localhost)
- Block 10.0.0.0/8 (private)
- Block 172.16.0.0/12 (private)
- Block 192.168.0.0/16 (private)
- Block 169.254.0.0/16 (link-local/metadata)
- Block 0.0.0.0/8 (invalid)

Protocol restriction:
- Only allow http:// and https://
- Block file://, gopher://, dict://, ftp://

Redirect controls:
- Disable redirects: requests.get(url, allow_redirects=False)
- Validate redirect targets before following
- Limit redirect count

DNS rebinding protection:
- Resolve hostname and validate IP before request
- Pin resolved IP for the request
</ssrf_safe_patterns>
"""

    poc_patterns = """
<ssrf_poc_patterns>
PROOF OF CONCEPT PATTERNS:

Cloud metadata endpoints:
- http://169.254.169.254/latest/meta-data/ (AWS)
- http://169.254.169.254/computeMetadata/v1/ (GCP)
- http://169.254.169.254/metadata/instance (Azure)
- http://100.100.100.200/latest/meta-data/ (Alibaba)

Internal service access:
- http://localhost:8080/admin
- http://127.0.0.1:6379/ (Redis)
- http://127.0.0.1:9200/ (Elasticsearch)
- http://[::1]/ (IPv6 localhost)

Protocol smuggling:
- file:///etc/passwd
- file:///c:/windows/win.ini
- gopher://127.0.0.1:6379/_*1%0d%0a$4%0d%0aINFO%0d%0a

Bypass techniques:
- http://0.0.0.0/ (may resolve to localhost)
- http://0/ (short for 0.0.0.0)
- http://[0:0:0:0:0:ffff:127.0.0.1]/ (IPv6 mapped)
- http://127.1/ (short localhost)
- http://localhost.attacker.com/ (DNS rebind)

For PoC, use cloud metadata endpoint (169.254.169.254) when possible.
</ssrf_poc_patterns>
"""

    @classmethod
    def get_framework_guidance(cls, framework: Optional[str]) -> str:
        """Return framework-specific SSRF guidance."""
        if not framework:
            return ""

        guidance = {
            "python-requests": """
<python_requests_ssrf_guidance>
Python requests-specific:
- requests.get(url, allow_redirects=False) disables redirects - SAFER
- Default allows redirects which can bypass domain checks
- Check for timeout parameter (missing timeout can hang)
- Session objects may have different redirect settings
- Verify URL is validated BEFORE passing to requests
</python_requests_ssrf_guidance>
""",
            "axios": """
<axios_ssrf_guidance>
Node axios-specific:
- axios follows redirects by default (maxRedirects: 5)
- Set maxRedirects: 0 to disable
- axios.create() may have base URL - check full URL construction
- Check validateStatus callback for error handling
- Interceptors may modify URLs - trace through interceptors
</axios_ssrf_guidance>
""",
            "java-httpclient": """
<java_httpclient_ssrf_guidance>
Java HttpClient-specific:
- HttpClient.followRedirects() controls redirect behavior
- NORMAL follows redirects (DANGEROUS)
- NEVER disables redirects (SAFER)
- Check HttpRequest.Builder URI source
- RestTemplate may have interceptors that modify URLs
- WebClient reactive client has same SSRF risks
</java_httpclient_ssrf_guidance>
""",
            "flask": """
<flask_ssrf_guidance>
Flask-specific:
- Check request.args, request.form for URL sources
- Blueprints may have URL parameters
- Check for URL fetch in background tasks/Celery
- Common pattern: image proxy, webhook handlers
</flask_ssrf_guidance>
""",
            "express": """
<express_ssrf_guidance>
Express/Node-specific:
- Check req.query, req.body, req.params for URL sources
- Common SSRF in: image proxy, link preview, webhook handlers
- Check npm packages: request, got, node-fetch, superagent
- Verify URL parsing before HTTP calls
</express_ssrf_guidance>
""",
        }
        return guidance.get(framework.lower(), "")

    @classmethod
    def get_full_prompt(cls, framework: Optional[str] = None) -> str:
        """Return full SSRF-specific prompt content."""
        parts = [
            cls.dangerous_sinks.strip(),
            cls.safe_patterns.strip(),
            cls.poc_patterns.strip(),
        ]

        fw_guidance = cls.get_framework_guidance(framework)
        if fw_guidance:
            parts.append(fw_guidance.strip())

        return "\n\n".join(parts)


def build_ssrf_prompt(
    candidates: List[Dict[str, Any]],
    framework: Optional[str] = None,
    tech_stack: Optional[Dict[str, Any]] = None,
) -> str:
    """Build complete SSRF analysis prompt.

    Args:
        candidates: SSRF candidates from triage phase
        framework: Detected framework (python-requests, axios, java-httpclient, etc.)
        tech_stack: Full tech stack context

    Returns:
        Complete SSRF analysis prompt
    """
    parts = [
        BaseAnalysisPrompt.get_analysis_mission("ssrf"),
        BaseAnalysisPrompt.get_validation_requirements(),
        SSRFAnalyzer.get_full_prompt(framework),
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
