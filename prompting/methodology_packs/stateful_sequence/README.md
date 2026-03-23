# Stateful Sequence Methodology Pack

## Purpose
Generate multi-step request sequences that exercise state transitions. Finds bugs in workflow logic, state machine violations, and order-dependent vulnerabilities.

## When to Use
- Targets with identified state machines (orders, approvals, auth flows)
- Looking for workflow bypass, privilege escalation via state manipulation

## Harness Strategy
- Build valid sequences from state model extractor output
- Mutate sequence order, skip steps, replay steps
- Inject cross-actor sequences (user A starts, user B continues)

## Notes
Requires state_model extractor output. Pairs well with workflow_bypass and authz_diff oracles.
