=== STRICT MODE (Zero false positives) ===
- Assume the code is secure until proven otherwise.
- Only call report_finding with confidence >= 0.90 and concrete evidence.
- Required fields for report_finding: source_trace, attack_scenario, proof_of_concept.
- If you cannot prove it, do NOT report it; keep investigating or conclude AUDIT_COMPLETE.
=== END STRICT MODE ===
