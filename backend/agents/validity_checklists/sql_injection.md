# SQL Injection Validity Checklist

Use this checklist when evaluating a suspected SQL injection vulnerability.
Validate only if ALL conditions are met.

## Required Conditions

### 1. Attacker Data Reaches SQL Sink
- [ ] Attacker-controlled data flows into a SQL query construction point
- [ ] The data is interpreted as SQL syntax (not just data values)
- [ ] Examples: String concatenation, string interpolation, or dynamic query building

### 2. No Effective Parameterization
- [ ] Query is not using parameterized statements (prepared statements, query builders)
- [ ] OR parameterization is incomplete (e.g., table/column names are concatenated)
- [ ] Attacker can inject SQL syntax metacharacters (quotes, semicolons, comments, etc.)

### 3. Reachability
- [ ] Code path is reachable (routing/auth/config analysis confirms)
- [ ] Not dead code, disabled feature, or admin-only with strong auth

## Common False Positive Traps

DISPROVE the vulnerability if any of these apply:

- **Parameterized Queries**: Properly used prepared statements or parameterized queries prevent SQL injection.
  - Example: `cursor.execute("SELECT * FROM users WHERE id = ?", [user_id])` is safe

- **ORM with Safe Query Builders**: ORMs like Django ORM, SQLAlchemy, ActiveRecord properly parameterize when used correctly.
  - Example: `User.objects.filter(username=user_input)` is safe in Django

- **Allowlisted Input**: Strict allowlist validation where only predefined safe values are allowed.
  - Example: Sorting by column name where name is validated against `['id', 'name', 'created_at']`

- **Numeric Coercion**: User input is coerced to a number before query construction.
  - Example: `query = "SELECT * FROM users WHERE id = " + str(int(user_id))` (though poor practice, prevents SQL injection)

- **Read-Only Database User**: Database user has only SELECT privileges (reduces impact but doesn't eliminate vulnerability).

## Evidence Requirements

To validate, you must show:
1. **Exact source**: Where attacker data enters (file path + line number + code snippet)
2. **Exact sink**: Where SQL query is constructed/executed (file path + line number + code snippet)
3. **Dataflow trace**: How attacker data reaches the sink without being neutralized
4. **Mitigation analysis**: Why parameterization/escaping are absent, incomplete, or bypassable
5. **Reachability**: Evidence the code path is reachable (routing/auth/config)

## Classification

- ✅ **VALIDATED_VULNERABILITY**: All conditions met, no parameterization, attacker controls SQL syntax
- ⚠️ **NEEDS_HUMAN_REVIEW**: Strong signal but uncertain about ORM behavior or framework-level protections
- 🔧 **HARDENING_OPPORTUNITY**: Risky pattern but credible defenses (partial parameterization, allowlists) reduce exploitability
- ❌ **NOT_A_VULNERABILITY**: Effective mitigation confirmed (full parameterization, ORM safe query builders)
