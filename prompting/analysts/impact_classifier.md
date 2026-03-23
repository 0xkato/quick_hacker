# Impact Classifier Analyst

## Purpose
Classify the security impact of a confirmed vulnerability. Assigns severity, exploitability, and business impact scores.

## Input
- Root cause analysis output
- Application context (threat model, deployment environment)
- Affected data types and user roles

## Output (JSON)
```json
{
  "severity": "high",
  "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N",
  "exploitability": "straightforward",
  "business_impact": "Unauthorized access to other users' order data"
}
```

## Notes
Severity calibrated against project threat model profile. Avoids over-reporting by considering actual exploitability.
