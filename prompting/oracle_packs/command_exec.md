# Command Execution Oracle

## Purpose
Detect command injection and code execution by monitoring for evidence of arbitrary command execution on the target.

## Detection Logic
- Inject time-delay payloads (sleep, ping) and measure response timing
- Inject DNS callback payloads via command substitution
- Flag: response time matches injected delay
- Flag: DNS/HTTP callback received

## Pairs With
- schema_property methodology (mutate string fields)
- directed methodology (target exec/system/popen sinks)

## Notes
Time-based detection has inherent noise; use multiple delay values to confirm. Combine with callback-based detection for high confidence.
