# Authorization Bypass Validity Checklist

Use this checklist when evaluating a suspected authorization bypass vulnerability.
Validate only if ALL conditions are met.

## Required Conditions

### 1. Identify Intended Policy
- [ ] Clearly identify what authorization policy SHOULD be enforced
- [ ] Determine intended access restrictions (authentication, role-based, ownership, etc.)
- [ ] Understand what resources/actions should be protected
- [ ] Example: "Only user who owns resource X should access it" or "Only admin role should perform action Y"

### 2. Policy Not Enforced on Reachable Path
- [ ] Authorization check is missing on the code path OR check is present but flawed
- [ ] Sensitive action or data access occurs without required permission verification
- [ ] User can access resources/perform actions they shouldn't be authorized for
- [ ] Examples: Missing auth middleware, broken ownership checks, role verification bypassed

### 3. Middleware and Service Layer Analyzed
- [ ] Middleware/decorator/interceptor checks have been examined (not assumed absent)
- [ ] Framework-level authorization patterns investigated
- [ ] Service layer authorization verified (not just controller/route level)
- [ ] Confirmed the check is truly absent or bypassable, not just invisible at first glance

## Common False Positive Traps

DISPROVE the vulnerability if any of these apply:

- **Checks in Middleware/Service Layer**: Authorization enforced by middleware, decorators, or service layer not visible in route handler.
  - Example: Express middleware `ensureAuthenticated()`, Spring `@PreAuthorize`, Django `@login_required`

- **Routes Not Exposed/Disabled by Default**: Route appears unprotected but is disabled in production or never exposed.
  - Example: Debug routes only enabled in development, admin routes behind separate ingress/subdomain

- **Framework-Level Protection**: Framework automatically enforces policy through routing, annotations, or configuration.
  - Example: Rails routes scoped under `authenticate_user!`, API Gateway authorization rules

- **Partial Information Disclosure Only**: Missing auth on read-only endpoint that exposes non-sensitive or already-public data.
  - Example: Public blog post IDs accessible without auth where content is intended to be public anyway

## Evidence Requirements

To validate, you must show:
1. **Exact source**: Where request enters the application (file path + line number + code snippet)
2. **Exact sink**: Where sensitive action/data access occurs (file path + line number + code snippet)
3. **Dataflow trace**: How request reaches sensitive operation without authorization check
4. **Mitigation analysis**: Why middleware/framework-level checks don't apply or are bypassable
5. **Reachability**: Evidence the code path is reachable and exposed (routing/config/network analysis)

## Classification

- ✅ **VALIDATED_VULNERABILITY**: All conditions met, attacker can access protected resources or perform unauthorized actions
- ⚠️ **NEEDS_HUMAN_REVIEW**: Strong signal but uncertain about middleware behavior, framework magic, or network-level restrictions
- 🔧 **HARDENING_OPPORTUNITY**: Defense-in-depth opportunity but primary controls appear adequate
- ❌ **NOT_A_VULNERABILITY**: Authorization properly enforced through middleware, framework, or network controls
