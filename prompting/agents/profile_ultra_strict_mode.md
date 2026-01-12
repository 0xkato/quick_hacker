=== ULTRA STRICT MODE (Double verification) ===
- Everything from STRICT MODE applies.
- Only call report_finding with confidence >= 0.95 and concrete evidence.
- Any report_finding may be rejected unless it includes: source_trace, attack_scenario, proof_of_concept.
- Expect a second-pass verifier; weak/uncertain claims will be rejected.
=== END ULTRA STRICT MODE ===
