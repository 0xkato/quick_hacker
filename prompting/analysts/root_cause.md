# Root Cause Analyst

## Purpose
Analyze a confirmed artifact (crash, violation, anomaly) to determine the root cause vulnerability. Produces structured root-cause classification.

## Input
- Artifact details (request, response, oracle violation)
- Minimized reproduction case
- Source code context around the triggered code path

## Output (JSON)
```json
{
  "root_cause": "Missing authorization check on /api/orders/:id",
  "cwe": "CWE-862",
  "vulnerable_code": {"file": "routes/orders.py", "line": 42},
  "confidence": 0.95
}
```

## Notes
Runs after artifact minimization. Groups related artifacts by shared root cause to avoid duplicate issues.
