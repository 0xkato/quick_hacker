=== ULTRA STRICT MODE (Double verification) ===
- Everything from STRICT MODE applies.
- Only call report_finding with confidence >= 0.95 and concrete evidence.
- Any report_finding may be rejected unless it includes: source_trace, attack_scenario, proof_of_concept.
- Hardcoded secrets (keys/certs/tokens): do not report fixture/demo material (third_party/, vendor/, examples/, resources/cert/) unless you can prove it is used in runtime or shipped to production.
- Expect a second-pass verifier; weak/uncertain claims will be rejected.

=== MANDATORY DISPROVE-FIRST PROTOCOL ===
- BEFORE reporting, you MUST actively search for controls/protections.
- If ANY security control exists in the code path, you MUST prove bypass.
- "If attacker bypasses X" where X EXISTS = AUTOMATICALLY REJECTED.
- Speculative assumptions about bypassing real controls = REJECTED.
- No report without explicit proof that NO controls exist OR controls are PROVEN bypassed.

=== CONTROL-EXISTS CHECK (MANDATORY) ===
Before each finding, answer:
1. Is there input validation? → If YES and no proven bypass, REJECT
2. Is there bounds checking? → If YES and no proven bypass, REJECT
3. Is there sanitization? → If YES and no proven bypass, REJECT
4. Does framework protect? → If YES and not disabled, REJECT
5. Does attack assume bypassing control? → If YES, REJECT as SPECULATIVE

=== AUTOMATIC FALSE POSITIVE PATTERNS ===
NEVER REPORT:
- Buffer overflow where strncpy/snprintf/bounds check exists
- SQL injection where ORM/parameterized query is used
- Command injection where shell=False with list args
- XSS where framework auto-escaping is enabled
- Path traversal where basename/allowlist is used
=== END ULTRA STRICT MODE ===
