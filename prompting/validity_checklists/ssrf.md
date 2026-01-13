# SSRF Proof Checklist

You are analyzing a potential Server-Side Request Forgery (SSRF) vulnerability. Follow this evidence-gathering plan:

## 1. Identify the Sink (sink_present)

**Goal:** Prove an outbound HTTP/network request is made by the server.

**Evidence Required:**
- Exact file path and line number of HTTP client call
- Function name: `requests.get()`, `requests.post()`, `urllib.request.urlopen()`, `httpx.get()`, `fetch()`, or similar

**Tool Call Example:**
```json
{
  "tool": "search_code",
  "arguments": {
    "pattern": "(requests\\.(get|post)|urllib\\.request|httpx\\.(get|post)|fetch)\\(",
    "file_pattern": "**/*.py",
    "max_results": 100
  }
}
```

**Checklist Update:**
- `sink_present = PROVEN_TRUE` if HTTP client call found
- `sink_present = PROVEN_FALSE` if no outbound requests in codebase
- `sink_present = UNKNOWN` if files are missing

## 2. Identify the Source (source_controlled_input)

**Goal:** Prove user/attacker controls the URL or URL component.

**Evidence Required:**
- URL comes from: request parameters, body, headers
- NOT from: hardcoded values, allowlist, config files

**Common Patterns:**
- Flask: `request.args.get('url')`, `request.json['callback_url']`
- Django: `request.GET['url']`, `request.POST['webhook']`
- FastAPI: `url: str = Query(...)`

**Checklist Update:**
- `source_controlled_input = PROVEN_TRUE` if URL is user-provided
- `source_controlled_input = PROVEN_FALSE` if URL is hardcoded or from allowlist
- `source_controlled_input = UNKNOWN` if URL origin is unclear

## 3. Trace Data Flow (dataflow_evidenced)

**Goal:** Prove user input flows to HTTP request URL without sufficient validation.

**Evidence Required:**
- Step-by-step path from source to sink
- Cite each intermediate variable/function
- Note any validation attempts (but prove they're insufficient)

**Safe Patterns:**
- Allowlist validation: `if url in ALLOWED_DOMAINS: requests.get(url)`
- URL parsing with validation: `if urlparse(url).netloc == 'trusted.com'`

**Unsafe Patterns:**
- Direct concatenation: `requests.get(user_url)`
- Weak validation: `if url.startswith('http://')` (bypassable)
- Blocklist: `if 'localhost' not in url` (incomplete)

**Tool Call Example:**
```json
{
  "tool": "read_file",
  "arguments": {
    "path": "app/webhook.py",
    "start_line": 30,
    "end_line": 60
  }
}
```

**Checklist Update:**
- `dataflow_evidenced = PROVEN_TRUE` if unvalidated flow exists
- `dataflow_evidenced = PROVEN_FALSE` if strict allowlist validation
- `dataflow_evidenced = UNKNOWN` if validation logic is unclear

## 4. Verify Reachability (reachable)

**Goal:** Prove the vulnerable code can actually execute.

**Evidence Required:**
- Function is called from an entrypoint
- Route is registered and accessible

**Tool Call Example:**
```json
{
  "tool": "find_usages",
  "arguments": {
    "name": "trigger_webhook",
    "max_results": 50
  }
}
```

**Checklist Update:**
- `reachable = PROVEN_TRUE` if called from registered route
- `reachable = PROVEN_FALSE` if dead code
- `reachable = UNKNOWN` if call graph is incomplete

## 5. Verify Boundary Crossing (boundary_crossed)

**Goal:** Prove external input reaches the HTTP client call.

**Evidence Required:**
- Input comes from external source (HTTP request, API)
- NOT an internal service or admin function

**Tool Call Example:**
```json
{
  "tool": "get_entry_points",
  "arguments": {
    "framework": "flask"
  }
}
```

**Checklist Update:**
- `boundary_crossed = PROVEN_TRUE` if externally accessible
- `boundary_crossed = PROVEN_FALSE` if internal-only
- `boundary_crossed = UNKNOWN` if access controls unclear

## 6. Rule Out Misconfiguration (not_only_misconfig)

**Goal:** Prove the vulnerability is in the code, not just a config issue.

**Checklist Update:**
- `not_only_misconfig = PROVEN_TRUE` if code is vulnerable by design
- `not_only_misconfig = PROVEN_FALSE` if only a config issue
- `not_only_misconfig = UNKNOWN` if unclear

## 7. StrictClassifier Alignment

**Expected Disposition:**
- If ALL 6 items are PROVEN_TRUE → `VALID_SECURITY_ISSUE`
- If dataflow_evidenced is PROVEN_FALSE (allowlist validated) → `BY_DESIGN`
- If not_only_misconfig is PROVEN_FALSE → `MISCONFIGURATION`
- If ANY is UNKNOWN → `SPECULATIVE`

## Common False Positives

**Trap 1: Requests to user-controlled paths on same domain**
```python
requests.get(f"https://api.example.com/{user_path}")  # Not SSRF if domain is fixed
```

**Trap 2: Allowlist validation present**
```python
if url in ALLOWED_WEBHOOKS:
    requests.get(url)  # dataflow_evidenced = PROVEN_FALSE
```

## Evidence Citation Format

Always cite evidence as:
- `file_path:line_start-line_end` for code snippets
- `artifact_id:finding_123` for previously collected evidence
