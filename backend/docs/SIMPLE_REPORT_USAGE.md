# Simple Report - All Findings in One Place

## Overview

A single endpoint that returns all findings for a project in one Markdown file. No options, no filters - just everything in one place.

## Endpoint

```
GET /api/agents/{agent_id}/report
```

**Parameters:**
- `agent_id` (path) - The project/agent ID

**Authentication:** Required (Bearer token)

**Returns:** Markdown file with all findings, sorted by severity

## Usage Examples

### Command Line (with auth token)

```bash
# Get report for a project
curl -H "Authorization: Bearer YOUR_TOKEN" \
  "http://localhost:8000/api/agents/my-project-id/report" \
  -o security-report.md
```

### JavaScript/TypeScript

```typescript
async function downloadReport(agentId: string) {
  const response = await fetch(`/api/agents/${agentId}/report`, {
    headers: {
      'Authorization': `Bearer ${localStorage.getItem('token')}`
    }
  });

  if (response.ok) {
    const blob = await response.blob();
    const url = window.URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `security-report-${agentId}.md`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    window.URL.revokeObjectURL(url);
  }
}
```

### Python

```python
import requests

def download_report(agent_id: str, token: str):
    url = f"http://localhost:8000/api/agents/{agent_id}/report"
    headers = {"Authorization": f"Bearer {token}"}

    response = requests.get(url, headers=headers)

    if response.ok:
        with open(f"security-report-{agent_id}.md", "wb") as f:
            f.write(response.content)
        print(f"Report saved to security-report-{agent_id}.md")
    else:
        print(f"Error: {response.text}")
```

## Report Format

The report includes:

1. **Header** - Project name, timestamp, total findings
2. **Summary** - Count by severity (critical, high, medium, low, info)
3. **All Findings** - Ordered by severity (critical first), then by date

For each finding:
- Title
- Severity badge, vulnerability type, CWE ID
- File location with line numbers
- Description
- Vulnerable code snippet
- Attack scenario (if available)
- Proof of concept (if available)
- Recommended fix (if available)

## Example Output

```markdown
# Security Findings Report

**Project:** my-project-id
**Generated:** 2026-01-17 22:30:00 UTC
**Total Findings:** 15

## Summary

- **CRITICAL**: 2
- **HIGH**: 5
- **MEDIUM**: 6
- **LOW**: 2

---

## Findings

### 1. SQL Injection in User Login

`CRITICAL` `sql_injection` `CWE-89`

**Location:** `src/auth/login.py:45-52`

**Description:**
User input is directly concatenated into SQL query without parameterization...

**Vulnerable Code:**
```
query = f"SELECT * FROM users WHERE username='{username}'"
```

**Attack Scenario:**
Attacker can bypass authentication by entering ' OR '1'='1 as username...

**Recommended Fix:**
Use parameterized queries instead of string concatenation...

---
```

## Error Responses

**404 Not Found**
```json
{"detail": "No findings found for this project"}
```

**401 Unauthorized**
```json
{"detail": "Not authenticated"}
```

## Notes

- Findings are always sorted by severity (critical → high → medium → low → info)
- Within same severity, sorted by creation date (newest first)
- Report is returned as `text/markdown` with `Content-Disposition: attachment` header
- No caching - always returns current state of findings
- Empty fields (no attack scenario, no PoC, etc.) are omitted from report
