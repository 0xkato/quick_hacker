# LLM Validation Configuration Guide

## Overview

The LLM validation system autonomously investigates security findings to distinguish real vulnerabilities from false positives using Anthropic's Claude models.

## Architecture

```
Finding → Pre-Validation Gates → LLM Validator → Protocol Evaluator → Submission Decision
            ↓ (Fast Reject)         ↓ (INVALID)         ↓                 ↓ (SUBMIT/DONT_SUBMIT)
         30-50% filtered          Deep Investigation   Quality Check      Final Decision
```

## Pre-Validation Gates

Fast, rule-based checks that reject findings before expensive LLM calls:

### 1. Disposition Filter
Rejects findings with dispositions not eligible for submission:
- **Rejects**: HARDENING, BY_DESIGN (typically)
- **Allows**: VALID_SECURITY_ISSUE, BUG, SPECULATIVE

**Configuration:**
```python
protocol = ProtocolPolicy(
    min_disposition_to_submit=[Disposition.VALID_SECURITY_ISSUE, Disposition.BUG],
    # ... other settings
)
```

### 2. Checklist Quality Gate
Requires minimum number of PROVEN checklist items:

**Configuration:**
```python
protocol = ProtocolPolicy(
    min_checklist_proven_count=4,  # Require at least 4 PROVEN items
    allow_unknown_in_checklist=False,  # Reject findings with UNKNOWN items
    # ... other settings
)
```

**Checklist Items:**
- Source Controlled Input
- Sink Present
- Dataflow Evidenced
- Reachable
- Boundary Crossed
- Not Only Misconfig
- Security Control Bypassed (optional)

### 3. Social Engineering Filter
Detects and filters social-engineering-only findings:

**Indicators:**
- Keywords: "phishing", "social engineering", "user trick", "deceive user"
- No technical sink present (e.g., no code injection, no XSS)

**Configuration:**
```python
protocol = ProtocolPolicy(
    reject_social_engineering_only=True,
    # ... other settings
)
```

## LLM Validator

Agentic investigation using Anthropic's Claude models with tool use capabilities.

### Tools Available

The LLM validator has access to three tools for investigating the codebase:

#### 1. read_file(file_path)
Read source code files to examine vulnerable code.

**Limitations:**
- Max file size: 100KB
- Path must be relative to repository root
- Path traversal protection enforced

**Example usage:**
```python
# LLM calls:
read_file("src/api/routes.py")
```

#### 2. grep_code(pattern, glob=None)
Search codebase for code patterns using ripgrep.

**Limitations:**
- Max output: 5000 characters
- 10-second timeout
- Returns line numbers and file paths

**Example usage:**
```python
# Find all callers of vulnerable function:
grep_code("dangerous_exec\\(", glob="**/*.py")
```

#### 3. glob_files(pattern)
Find files by name pattern.

**Limitations:**
- Max results: 100 files
- Path traversal protection enforced
- Returns relative paths

**Example usage:**
```python
# Find all route definition files:
glob_files("**/routes/*.py")
```

### Validation Process

1. **LLM receives**:
   - Finding details (title, file, line, vulnerability type)
   - Proof checklist (6-7 items with PROVEN/UNKNOWN/DISPROVEN status)
   - Classification confidence score
   - Criticism level (high/medium/low)

2. **LLM autonomously investigates** using tools:
   - Read vulnerable code
   - Search for function callers
   - Trace dataflow from source to sink
   - Check reachability (route registrations, entry points)
   - Verify attacker control

3. **LLM makes decision**:
   - **VALID**: Exploitable security issue
   - **INVALID**: False positive, dead code, or not exploitable

4. **Resource limits**:
   - Max 10 tool use rounds
   - Timeout after configured duration (default: 120s)
   - Conservative filtering on timeout/error

### Response Format

The LLM returns a structured response:

```
DECISION: VALID | INVALID

CATEGORY: command_injection | unreachable_code | mitigated | by_design | etc.

REASONING:
- First reason (key finding from investigation)
- Second reason (evidence for/against exploitability)
- Third reason (final determination)
```

**Example VALID response:**
```
DECISION: VALID

CATEGORY: command_injection

REASONING:
- Found Flask route at line 45 calling vulnerable function with user input
- No input sanitization present in handler or vulnerable function
- shell=True enables arbitrary command execution
- Attacker can reach this via HTTP POST to /api/execute
```

**Example INVALID response:**
```
DECISION: INVALID

CATEGORY: unreachable_code

REASONING:
- Vulnerable function is never called in codebase (0 references found)
- No route registration or export declaration
- This is dead code that would never execute in production
- Not a real security issue
```

## Protocol Configuration

### Basic Configuration

Enable LLM validation in your protocol policy:

```python
from models.schemas import ProtocolPolicy, Disposition

policy = ProtocolPolicy(
    id="my-protocol",
    display_name="My Bug Bounty Program",

    # Enable LLM validation
    enable_llm_validation=True,

    # Validation settings
    validation_criticism_level="high",
    validation_model="claude-sonnet-4-20250514",
    validation_timeout_seconds=120,
    validation_fallback_on_error="invalid",  # invalid, valid, or skip

    # Pre-validation gates
    min_disposition_to_submit=[Disposition.VALID_SECURITY_ISSUE, Disposition.BUG],
    min_checklist_proven_count=4,
    allow_unknown_in_checklist=False,
    reject_social_engineering_only=True,

    # ... other protocol settings
)
```

### Criticism Levels

The `validation_criticism_level` controls how skeptical the LLM validator is:

#### High (Recommended for Paid Programs)
**Characteristics:**
- Strict validation
- Rejects findings with any uncertainty
- Requires proof of both reachability AND attacker control
- Low false positive rate, higher false negative rate

**Use for:**
- Paid bug bounty programs (HackerOne, Bugcrowd)
- Vendor VRPs (GitHub, Google)
- Programs with strict quality bars

**Prompt guidance:**
> "Assume NOT exploitable unless you can prove both reachability AND attacker control"

#### Medium (Balanced)
**Characteristics:**
- Moderate strictness
- Accepts strong evidence for one dimension, requires proof for the other
- Balanced false positive/negative rates

**Use for:**
- Internal security audits
- Research disclosure programs
- Programs accepting hardening recommendations

**Prompt guidance:**
> "Accept strong evidence for one dimension, require proof for the other"

#### Low (Permissive)
**Characteristics:**
- Permissive validation
- Accepts findings with minor gaps in evidence
- Higher false positive rate, lower false negative rate

**Use for:**
- Early development scanning
- Continuous security monitoring
- Educational/research purposes

**Prompt guidance:**
> "Trust the initial classification unless clearly wrong"

### Model Selection

#### claude-sonnet-4-20250514 (Recommended)
**Characteristics:**
- Fast, cost-effective
- Excellent reasoning capabilities
- Good for most validations
- ~$3 per million input tokens, ~$15 per million output tokens

**Use for:**
- Standard validation workflows
- High-volume scanning
- Cost-conscious operations

#### claude-opus-4-20250514 (Premium)
**Characteristics:**
- Maximum reasoning depth
- Best for complex validations
- Higher cost (~$15 per million input tokens, ~$75 per million output tokens)

**Use for:**
- High-value bug bounty programs
- Complex multi-step vulnerabilities
- Critical security audits

### Timeout Configuration

Configure per-finding timeout:

```python
protocol = ProtocolPolicy(
    validation_timeout_seconds=120,  # Default: 2 minutes
    # ... other settings
)
```

**Recommendations:**
- **Simple findings** (SQL injection, XSS): 60-120s
- **Complex findings** (SSRF chains, auth bypass): 180-300s
- **Multi-step attacks**: 300-600s (max)

### Error Handling

Configure fallback behavior when validation fails:

```python
protocol = ProtocolPolicy(
    validation_fallback_on_error="invalid",  # Options: invalid, valid, skip
    # ... other settings
)
```

**Options:**
- **invalid** (recommended): Conservative filtering, mark as INVALID
- **valid**: Optimistic, accept finding on error
- **skip**: Skip validation, pass to protocol evaluator

## Security

The validator enforces strict security controls to prevent abuse:

### 1. Path Traversal Protection
All file operations are sandboxed to `repo_root`:

```python
# Blocked attempts:
read_file("../../../etc/passwd")  # ❌ Path outside repository
read_file("/etc/passwd")          # ❌ Absolute path
glob_files("../**/*")              # ❌ Parent directory access

# Allowed:
read_file("src/api/routes.py")    # ✅ Relative path in repo
glob_files("**/*.py")              # ✅ Recursive search in repo
```

### 2. Resource Limits

**File reads:**
- Max file size: 100KB
- Larger files are truncated

**Grep output:**
- Max output: 5000 characters
- Prevents overwhelming LLM context

**Glob results:**
- Max files: 100
- Additional files indicated with "... (N more files)"

**Tool use rounds:**
- Max rounds: 10
- Prevents infinite loops

### 3. Timeout Protection

Validation times out after configured limit (default: 120s):
- Returns INVALID on timeout
- Logs timeout event
- Conservative filtering for safety

### 4. API Key Security

- API key stored in environment variable
- Never logged or exposed in responses
- Validated at startup

## Cost Management

### Estimated Costs

**Typical finding validation:**
- Pre-gates filter: ~40% of findings (FREE)
- LLM validation: ~60% of findings
- Average 2-3 tool use rounds per finding
- ~4000 tokens per validation

**Cost per finding:**
- **Sonnet**: ~$0.012 per finding
- **Opus**: ~$0.06 per finding

**For 100 findings:**
- Pre-gates filter: 40 findings (FREE)
- LLM validates: 60 findings
- **Sonnet**: ~$0.72 total
- **Opus**: ~$3.60 total

### Optimization Tips

1. **Use Pre-Gates Effectively**
   - Set appropriate `min_checklist_proven_count`
   - Enable `reject_social_engineering_only`
   - Configure disposition filters

2. **Choose Sonnet for Most Use Cases**
   - Use Opus only for critical programs
   - Sonnet provides 95%+ accuracy at 5x lower cost

3. **Set High Criticism Level**
   - Reduces tool use rounds
   - Filters more aggressively
   - Lower API usage

4. **Monitor Usage**
   - Check Anthropic console regularly
   - Set up billing alerts
   - Track cost per finding

5. **Batch Processing**
   - Process findings in batches
   - Leverage pre-gate filtering
   - Monitor API rate limits

## Troubleshooting

### Validation Always Returns INVALID

**Symptoms:**
- All findings marked as INVALID
- Reasoning mentions "insufficient evidence"

**Solutions:**
1. Check `ANTHROPIC_API_KEY` is set correctly:
   ```bash
   echo $ANTHROPIC_API_KEY
   ```

2. Verify repository path in validation config:
   ```python
   # Ensure repo_root points to actual repository
   validator = LLMFindingValidator(
       repo_root="/path/to/repository",  # Must be absolute path
       # ...
   )
   ```

3. Check file permissions:
   ```bash
   ls -la /path/to/repository
   # Ensure files are readable
   ```

4. Review LLM reasoning in UI:
   - Check validation reasoning bullets
   - Look for tool execution errors
   - Verify files are being read correctly

### Validation Times Out

**Symptoms:**
- Validation frequently hits timeout
- Reasoning mentions "timeout after Ns"

**Solutions:**
1. Increase timeout in protocol config:
   ```python
   protocol = ProtocolPolicy(
       validation_timeout_seconds=300,  # Increase to 5 minutes
       # ...
   )
   ```

2. Check repository size:
   - Large repos may require longer timeouts
   - Consider using more specific file patterns

3. Verify network connectivity:
   - Check firewall rules
   - Verify Anthropic API is reachable

4. Check Anthropic API status:
   - Visit https://status.anthropic.com
   - Look for service disruptions

### API Rate Limits

**Symptoms:**
- 429 errors in logs
- "Rate limit exceeded" messages

**Solutions:**
1. Add delays between validations:
   ```python
   # Implement rate limiting in triage pipeline
   await asyncio.sleep(1)  # 1 second delay
   ```

2. Use lower-tier model:
   - Switch from Opus to Sonnet
   - Lower rate limits for premium models

3. Contact Anthropic:
   - Request rate limit increase
   - Upgrade to higher tier

4. Batch process during off-peak hours:
   - Schedule large scans for night/weekend
   - Distribute load over time

### Tool Execution Errors

**Symptoms:**
- Reasoning mentions "Error reading file"
- "Grep error" or "Glob error" in reasoning

**Solutions:**
1. **File not found:**
   - Verify file exists in repository
   - Check file path is relative to repo root

2. **Access denied:**
   - Check file permissions
   - Verify path is within repository bounds

3. **Ripgrep not installed:**
   ```bash
   # Install ripgrep
   brew install ripgrep  # macOS
   apt-get install ripgrep  # Ubuntu
   ```

4. **Grep pattern errors:**
   - Verify regex pattern is valid
   - Escape special characters: `\(`, `\)`, `\*`

## Examples

### Example 1: Valid Command Injection

**Finding:**
```
Title: Command Injection in Execute API
File: api/execute.py:45
Type: COMMAND_INJECTION
```

**LLM Investigation:**
1. `read_file("api/execute.py")` → Sees `subprocess.call(user_input, shell=True)`
2. `grep_code("execute_command", glob="**/*.py")` → Finds Flask route calling function
3. `read_file("api/routes.py")` → Sees `@app.route('/api/execute', methods=['POST'])`
4. Traces dataflow: `request.json['command']` → `execute_command()` → `subprocess.call()`

**Decision:**
```
DECISION: VALID

CATEGORY: command_injection

REASONING:
- Flask route at api/routes.py:23 exposes this function via HTTP POST
- User-controlled input from request.json flows directly to subprocess.call
- shell=True enables arbitrary command execution with no sanitization
- Attacker can reach this via unauthenticated POST to /api/execute
```

### Example 2: Invalid (Dead Code)

**Finding:**
```
Title: Code Injection via exec()
File: utils/debug.py:78
Type: CODE_INJECTION
```

**LLM Investigation:**
1. `read_file("utils/debug.py")` → Sees `exec(user_input)` in function
2. `grep_code("debug_evaluate", glob="**/*.py")` → No references found (0 results)
3. `grep_code("from utils.debug import", glob="**/*.py")` → No imports found
4. `grep_code("class.*routes", glob="**/*.py")` → Checks main entry points, no calls

**Decision:**
```
DECISION: INVALID

CATEGORY: unreachable_code

REASONING:
- Function debug_evaluate is never called anywhere in codebase (0 references)
- No route registration, no imports, no invocations found
- This is dead code that would never execute in production
- Not a real security issue despite dangerous pattern
```

### Example 3: Invalid (Mitigated)

**Finding:**
```
Title: SQL Injection in User Query
File: database/queries.py:102
Type: SQL_INJECTION
```

**LLM Investigation:**
1. `read_file("database/queries.py")` → Sees string concatenation in SQL query
2. `grep_code("execute_user_query", glob="**/*.py")` → Finds caller in api/search.py
3. `read_file("api/search.py")` → Sees input sanitization with `bleach.clean()`
4. Sees parameterized query fallback and input validation

**Decision:**
```
DECISION: INVALID

CATEGORY: mitigated

REASONING:
- String concatenation is present but input is sanitized with bleach.clean() before query
- Caller in api/search.py validates input against whitelist of allowed characters
- Parameterized query fallback is used for complex queries
- Multiple layers of protection make this unexploitable
```

## Best Practices

### 1. Start with High Criticism
- Begin with `validation_criticism_level="high"`
- Lower to "medium" if too many false negatives
- Use "low" only for permissive scanning

### 2. Monitor False Positives
- Review rejected findings periodically
- Check validation reasoning for patterns
- Adjust criticism level if needed

### 3. Tune Per Protocol
- Different programs have different quality bars
- Paid bounties: high criticism
- Internal audits: medium criticism
- Research: low criticism

### 4. Use Validation Results for Transparency
- Display reasoning to users in UI
- Help users understand why findings were filtered
- Build trust in automated triage

### 5. Track Costs and Adjust
- Monitor API usage in Anthropic console
- Calculate cost per finding
- Adjust settings to balance cost/quality
- Use pre-gates to reduce LLM calls

### 6. Combine with Manual Review
- LLM validation reduces false positives, not eliminates
- Review high-value findings manually
- Use validation as first-pass filter

### 7. Iterate on Threat Models
- Update threat model profiles based on program scope
- Align with bug bounty program requirements
- Review and adjust regularly

## Integration with Threat Modeling

See [Threat Modeling Integration](threat-modeling.md) for details on threat model profiles.

## Related Documentation

- [Protocol Policies Guide](protocol-policies.md) - Protocol configuration
- [Manual Testing Checklist](manual-testing-checklist.md) - Testing procedures
- [System Specification](SYSTEM-SPECIFICATION.md) - Architecture details
