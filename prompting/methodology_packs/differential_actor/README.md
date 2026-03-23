# Differential Actor Methodology Pack

## Purpose
Send identical requests as different actors (roles, tenants, auth states) and diff the responses. Finds authorization and isolation bugs.

## When to Use
- Multi-role or multi-tenant applications
- Looking for IDOR, privilege escalation, tenant data leakage

## Harness Strategy
- Replay same request with different auth tokens (admin vs user vs anonymous)
- Compare response bodies, status codes, and headers
- Flag differences that indicate data leakage or access control failures

## Notes
Requires at least two actor credentials. Pairs with authz_diff oracle.
