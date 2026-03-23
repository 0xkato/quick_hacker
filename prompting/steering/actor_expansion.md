# Actor Expansion Steering

## Purpose
Dynamically add new actor identities when differential testing reveals interesting authorization boundaries worth deeper exploration.

## Trigger
- authz_diff oracle finds privilege boundary
- New role or permission level discovered in application
- Existing actors insufficient to test all authorization paths

## Actions
- Generate new actor credentials (e.g., role combinations not yet tested)
- Spawn differential_actor lanes with expanded actor set
- Focus on endpoints where authorization checks were detected

## Notes
Works with multi-tenant and RBAC applications. Requires credential provisioning support in harness.
