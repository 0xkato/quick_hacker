# Report Generation Guide

## Overview

QuickHack now supports generating comprehensive security reports that consolidate all findings into a single document. This feature allows you to export findings in multiple formats (Markdown, HTML, JSON) with customizable options.

## Features

### Report Formats

1. **Markdown** (`.md`)
   - Human-readable, version-control friendly
   - Great for documentation and GitHub issues
   - Includes collapsible sections for metadata

2. **HTML** (`.html`)
   - Standalone web page with styling
   - Can be opened directly in browsers
   - Professional formatting for presentations

3. **JSON** (`.json`)
   - Machine-readable structured data
   - Ideal for automation and integration
   - Includes all finding fields and statistics

### Report Features

- **Executive Summary**: Statistics by severity, disposition, and submission decision
- **Grouped Findings**: Optional grouping by severity, disposition, category, or submission status
- **Detailed Information**: All finding details including:
  - Title, description, and location
  - Vulnerable code snippets
  - Attack scenarios and proof of concepts
  - Recommended fixes
  - Protocol evaluation results
  - Metadata (confidence scores, IDs, timestamps)

## API Endpoints

### 1. Export Full Report

```
GET /api/reports/findings/export
```

**Query Parameters:**
- `agent_id` (required): Project/agent ID
- `format`: Report format - `markdown`, `html`, or `json` (default: `markdown`)
- `title`: Custom report title
- `include_metadata`: Include detailed metadata (default: `true`)
- `group_by`: Group findings by - `severity`, `disposition`, `category`, or `submission`
- `min_severity`: Minimum severity to include - `critical`, `high`, `medium`, `low`, `info`
- `disposition_filter`: Filter by specific disposition
- `submission_decision`: Filter by submission decision - `submit`, `dont_submit`, `needs_more_info`

**Example:**
```bash
# Export Markdown report grouped by severity
curl -H "Authorization: Bearer $TOKEN" \
  "http://localhost:8000/api/reports/findings/export?agent_id=myproject&format=markdown&group_by=severity" \
  -o security-report.md

# Export HTML report of only submittable findings
curl -H "Authorization: Bearer $TOKEN" \
  "http://localhost:8000/api/reports/findings/export?agent_id=myproject&format=html&submission_decision=submit" \
  -o submittable-findings.html

# Export JSON with high and critical findings only
curl -H "Authorization: Bearer $TOKEN" \
  "http://localhost:8000/api/reports/findings/export?agent_id=myproject&format=json&min_severity=high" \
  -o critical-findings.json
```

### 2. Preview Report

```
GET /api/reports/findings/preview
```

Preview a report with limited findings (useful for testing).

**Query Parameters:**
- `agent_id` (required): Project/agent ID
- `format`: Report format (default: `markdown`)
- `limit`: Number of findings to preview (1-20, default: 5)

**Example:**
```bash
# Preview Markdown report in browser
curl -H "Authorization: Bearer $TOKEN" \
  "http://localhost:8000/api/reports/findings/preview?agent_id=myproject&format=html" \
  > preview.html && open preview.html
```

### 3. Get Statistics

```
GET /api/reports/findings/stats
```

Get summary statistics for findings.

**Query Parameters:**
- `agent_id` (required): Project/agent ID

**Response:**
```json
{
  "total": 42,
  "by_severity": {
    "critical": 3,
    "high": 8,
    "medium": 15,
    "low": 12,
    "info": 4
  },
  "by_disposition": {
    "valid_security_issue": 18,
    "bug": 12,
    "hardening": 8,
    "by_design": 4
  },
  "by_submission": {
    "submit": 15,
    "dont_submit": 20,
    "needs_more_info": 7
  }
}
```

## Frontend Integration

### Using the ExportReportButton Component

Add the export button to your findings panel:

```typescript
import { ExportReportButton } from '@/components/FindingsPanel/ExportReportButton';

// In your component
<ExportReportButton agentId={projectId} />
```

**Integration Example** (in `FindingsList.tsx`):

```typescript
// Add import at top
import { ExportReportButton } from './ExportReportButton';

// In the header section (around line 236), add:
<div className="flex items-center justify-between mb-2">
  <span className="text-vsc-xs text-vsc-text-muted">
    {filteredFindings.length} of {findings.length}
  </span>

  {/* Add export button */}
  <div className="flex items-center gap-2">
    <ExportReportButton agentId={agentId} />

    {/* Existing show filtered toggle */}
    {triageFilteredCount > 0 && (
      <button onClick={() => { /* ... */ }}>
        {/* ... */}
      </button>
    )}
  </div>
</div>
```

### Component Props

```typescript
interface ExportReportButtonProps {
  agentId: string;      // Required: Project/agent ID
  className?: string;   // Optional: Additional CSS classes
}
```

### Component Features

The ExportReportButton provides a dropdown menu with:

1. **Format Selection**:
   - Markdown (default)
   - HTML
   - JSON

2. **Advanced Options** (expandable):
   - **Group Findings**: No grouping, by severity, by disposition, by category, by submission
   - **Include Metadata**: Checkbox to include/exclude detailed metadata

3. **Actions**:
   - **Preview**: Opens report in new browser tab (limited to 5 findings)
   - **Export**: Downloads full report as file

## Report Formats

### Markdown Example

```markdown
# Security Findings Report

**Generated:** 2026-01-17 21:45:00 UTC
**Total Findings:** 42

## Executive Summary

### Findings by Severity
- **critical**: 3
- **high**: 8
- **medium**: 15

### Submission Decisions
- **submit**: 15
- **dont_submit**: 20
- **needs_more_info**: 7

---

## Detailed Findings

### Finding #1

#### SQL Injection in User Authentication

`critical` `valid_security_issue` `sql_injection` `CWE-89`

**Location:** `src/auth/login.py:45-52`

**Description:**
User-supplied input is directly concatenated into SQL query without sanitization...

**Vulnerable Code:**
```
query = f"SELECT * FROM users WHERE username='{username}' AND password='{password}'"
cursor.execute(query)
```

**Attack Scenario:**
An attacker can bypass authentication by entering ' OR '1'='1 as username...

**Recommended Fix:**
Use parameterized queries instead of string concatenation...

**Submission Evaluation:**
- **Decision:** submit
- **Protocol:** osvrp_strict
- **Reasoning:**
  - Meets minimum disposition requirement
  - Checklist quality gate passed (6/6 items proven)
  - Attacker model is realistic

<details>
<summary><b>Additional Metadata</b></summary>

- **Confidence:** 0.95
- **Classification Confidence:** 98/100
- **Finding ID:** `abc123def456`

</details>

---
```

### HTML Example

The HTML export generates a styled standalone web page with:
- Professional typography
- Syntax-highlighted code blocks
- Color-coded severity badges
- Collapsible metadata sections
- Print-friendly layout

### JSON Example

```json
{
  "generated_at": "2026-01-17 21:45:00 UTC",
  "total_findings": 42,
  "statistics": {
    "by_severity": {
      "critical": 3,
      "high": 8,
      "medium": 15
    },
    "by_disposition": {
      "valid_security_issue": 18,
      "bug": 12
    }
  },
  "findings": [
    {
      "id": "abc123def456",
      "title": "SQL Injection in User Authentication",
      "severity": "critical",
      "disposition": "valid_security_issue",
      "vulnerability_type": "sql_injection",
      "file_path": "src/auth/login.py",
      "line_start": 45,
      "line_end": 52,
      "description": "User-supplied input is directly concatenated...",
      "vulnerable_code": "query = f\"SELECT * FROM users...\"",
      "submission_result": {
        "protocol_id": "osvrp_strict",
        "decision": "submit",
        "reasons": ["Meets minimum disposition requirement"]
      }
    }
  ]
}
```

## Use Cases

### 1. Bug Bounty Submissions

Export findings with `submission_decision=submit` to get only submittable issues:

```bash
curl -H "Authorization: Bearer $TOKEN" \
  "http://localhost:8000/api/reports/findings/export?agent_id=myproject&format=markdown&submission_decision=submit&group_by=severity" \
  -o bug-bounty-report.md
```

### 2. Internal Security Reports

Export all findings grouped by severity for management review:

```bash
curl -H "Authorization: Bearer $TOKEN" \
  "http://localhost:8000/api/reports/findings/export?agent_id=myproject&format=html&group_by=severity" \
  -o internal-security-report.html
```

### 3. Remediation Tracking

Export findings by disposition to track fixing progress:

```bash
curl -H "Authorization: Bearer $TOKEN" \
  "http://localhost:8000/api/reports/findings/export?agent_id=myproject&format=json&disposition_filter=valid_security_issue" \
  -o findings-to-fix.json
```

### 4. Critical Issues Only

Export only critical and high severity findings:

```bash
curl -H "Authorization: Bearer $TOKEN" \
  "http://localhost:8000/api/reports/findings/export?agent_id=myproject&format=markdown&min_severity=high" \
  -o critical-issues.md
```

## Programmatic Usage

### Python Example

```python
import requests

def export_security_report(agent_id, api_token):
    """Export security findings report."""
    url = "http://localhost:8000/api/reports/findings/export"

    params = {
        "agent_id": agent_id,
        "format": "markdown",
        "group_by": "severity",
        "include_metadata": True
    }

    headers = {
        "Authorization": f"Bearer {api_token}"
    }

    response = requests.get(url, params=params, headers=headers)

    if response.ok:
        with open(f"report-{agent_id}.md", "wb") as f:
            f.write(response.content)
        print(f"Report exported successfully")
    else:
        print(f"Export failed: {response.text}")

# Usage
export_security_report("my-project", "your-token-here")
```

### JavaScript/TypeScript Example

```typescript
async function exportReport(agentId: string, format: 'markdown' | 'html' | 'json') {
  const params = new URLSearchParams({
    agent_id: agentId,
    format: format,
    group_by: 'severity'
  });

  const response = await fetch(`/api/reports/findings/export?${params}`, {
    headers: {
      'Authorization': `Bearer ${localStorage.getItem('token')}`
    }
  });

  if (response.ok) {
    const blob = await response.blob();
    const url = window.URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `report-${agentId}.${format === 'markdown' ? 'md' : format}`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    window.URL.revokeObjectURL(url);
  }
}
```

## Customization

### Custom Report Titles

```bash
curl -H "Authorization: Bearer $TOKEN" \
  "http://localhost:8000/api/reports/findings/export?agent_id=myproject&title=Q1+Security+Audit+Results" \
  -o q1-audit.md
```

### Filtering Combinations

Combine multiple filters for targeted reports:

```bash
# High+ severity findings that need more info
curl -H "Authorization: Bearer $TOKEN" \
  "http://localhost:8000/api/reports/findings/export?agent_id=myproject&min_severity=high&submission_decision=needs_more_info" \
  -o needs-investigation.md
```

## Troubleshooting

### No Findings Found

**Error:** `404 Not Found - No findings found matching criteria`

**Solutions:**
- Verify the `agent_id` is correct
- Check if findings exist for that project
- Remove filters to see if any findings match
- Use `/api/reports/findings/stats` to see what's available

### Empty Report

If the report downloads but is empty or has no findings:
- Check filter parameters (might be too restrictive)
- Verify findings have the fields you're filtering on
- Try exporting without filters first

### Format Issues

If the downloaded file doesn't render correctly:
- Markdown: Use a Markdown viewer or editor (VS Code, Typora, etc.)
- HTML: Open in a web browser
- JSON: Use a JSON formatter or viewer

## Best Practices

1. **Use Preview First**: Test format and options with preview endpoint before exporting large reports

2. **Group Strategically**:
   - Group by severity for management reports
   - Group by disposition for remediation tracking
   - Group by category for specialized team assignments

3. **Filter Wisely**:
   - Use `submission_decision=submit` for bug bounty reports
   - Use `min_severity=high` for critical issue tracking
   - Use `disposition_filter` for focused remediation

4. **Automate Reports**:
   - Schedule regular exports with cron/scripts
   - Integrate with CI/CD pipelines
   - Send reports to team communication channels

5. **Metadata Control**:
   - Include metadata for detailed analysis
   - Exclude metadata for executive summaries
   - JSON always includes all data regardless of setting

---

**Report Generation System is Ready!**

You can now export comprehensive security reports in multiple formats with full customization options.
