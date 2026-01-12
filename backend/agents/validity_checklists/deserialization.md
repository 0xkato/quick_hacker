# Deserialization Validity Checklist

Use this checklist when evaluating a suspected insecure deserialization vulnerability.
Validate only if ALL conditions are met.

## Required Conditions

### 1. Untrusted Input Deserialized by Dangerous Mechanism
- [ ] Attacker-controlled data flows into deserialization function
- [ ] Mechanism can instantiate arbitrary classes or execute code during deserialization
- [ ] Examples: Python `pickle`, Java native serialization, PHP `unserialize()`, Ruby `Marshal.load()`, YAML with unsafe loading

### 2. No Signature, Allowlist, or Type Restriction
- [ ] No cryptographic signature verification prevents tampering OR signature is bypassable
- [ ] No class allowlist restricts deserializable types
- [ ] No type restrictions prevent attacker-controlled object graphs
- [ ] Attacker can craft malicious serialized objects with gadget chains

### 3. Path is Attacker-Reachable
- [ ] Code path is reachable from attacker-controlled entry point
- [ ] Not disabled/admin-only with strong auth
- [ ] Input vector confirmed (cookies, API parameters, file uploads, etc.)

## Common False Positive Traps

DISPROVE the vulnerability if any of these apply:

- **Safe Parsers Producing Primitives Only**: Deserialization limited to safe data formats producing only primitives.
  - Example: `JSON.parse()` in JavaScript (only produces primitives, arrays, objects—no code execution)

- **Signed/Verified Messages Correctly Enforced**: Cryptographic signatures prevent tampering and are properly verified before deserialization.
  - Example: Django sessions with `SECRET_KEY` HMAC verification, JWT with proper signature validation

- **Class Allowlists**: Deserialization restricted to specific safe classes that cannot be weaponized.
  - Example: Java with `ValidatingObjectInputStream` restricting classes, or custom deserializers with allowlists

- **Safe YAML Loading**: YAML loaded with safe loader that doesn't execute code.
  - Example: Python `yaml.safe_load()` instead of `yaml.load()`, Ruby `YAML.safe_load()` with allowed classes

## Evidence Requirements

To validate, you must show:
1. **Exact source**: Where attacker data enters (file path + line number + code snippet)
2. **Exact sink**: Where deserialization occurs (file path + line number + code snippet)
3. **Dataflow trace**: How attacker data reaches the sink without signature verification
4. **Mitigation analysis**: Why signatures/allowlists/type restrictions are absent or bypassable
5. **Reachability**: Evidence the code path is reachable (routing/auth/config)

## Classification

- ✅ **VALIDATED_VULNERABILITY**: All conditions met, attacker can deserialize malicious objects leading to code execution
- ⚠️ **NEEDS_HUMAN_REVIEW**: Strong signal but uncertain about signature verification, gadget chain availability, or class restrictions
- 🔧 **HARDENING_OPPORTUNITY**: Risky pattern but credible defenses (signatures, allowlists, safe parsers) reduce exploitability
- ❌ **NOT_A_VULNERABILITY**: Effective mitigation confirmed (safe parser, verified signatures, class allowlists)
