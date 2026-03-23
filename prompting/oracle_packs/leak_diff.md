# Leak Diff Oracle

## Purpose
Detect sensitive data leakage by diffing responses for unexpected PII, credentials, internal IDs, or stack traces.

## Detection Logic
- Baseline: record normal response shape and field set
- Flag: response contains fields not present in schema (internal IDs, debug info)
- Flag: response contains patterns matching PII, API keys, or stack traces
- Flag: error responses leak more data than success responses

## Pairs With
- schema_property methodology (trigger error paths via invalid input)
- differential_actor methodology (compare data exposure across roles)

## Notes
Regex-based detection for common leak patterns (emails, JWTs, AWS keys). LM-assisted classification for ambiguous cases is v2.
