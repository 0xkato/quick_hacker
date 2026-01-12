# Sensitive Data Exposure Validity Checklist

Use this checklist when evaluating a suspected sensitive data exposure vulnerability.
Validate only if ALL conditions are met.

## Required Conditions

### 1. Sensitive Data Exposed Inappropriately
- [ ] Sensitive information is exposed to logs, API responses, error messages, or storage without proper controls
- [ ] Data qualifies as sensitive: credentials, tokens, PII, financial data, health records, cryptographic keys, etc.
- [ ] Exposure lacks appropriate access control, encryption, or redaction
- [ ] Examples: Passwords in logs, API keys in responses, SSNs in error messages, credit cards in unencrypted storage

### 2. Exposure Reachable Under Stated Attacker Model
- [ ] The exposure is accessible to attacker within the threat model
- [ ] Not limited to trusted administrators or secure internal systems only
- [ ] Examples: Public API endpoint, logs accessible to low-privilege users, client-side storage, unencrypted database
- [ ] Consider: Who can access logs? Who can trigger error messages? Who can read storage?

### 3. No Effective Redaction or Access Control
- [ ] No redaction/masking of sensitive data OR redaction is incomplete
- [ ] No access control restricts exposure to authorized parties only
- [ ] Sensitive data logged/stored/transmitted in plaintext or weakly protected form
- [ ] Examples: Full credit card numbers instead of last 4 digits, plaintext passwords, unredacted tokens

## Common False Positive Traps

DISPROVE the vulnerability if any of these apply:

- **Debug Logs Disabled by Default**: Verbose logging only enabled in development/debug mode, disabled in production.
  - Example: `if (process.env.NODE_ENV === 'development') { console.log(sensitiveData) }`

- **Redaction Utilities Applied Correctly**: Sensitive fields properly redacted/masked before logging or display.
  - Example: Logging `{ email: user.email, password: '[REDACTED]' }` or `creditCard: '****' + last4Digits`

- **Appropriate Access Controls**: Data exposure limited to authorized parties who legitimately need access.
  - Example: Admin-only logs, encrypted audit trails with proper key management, secure internal monitoring systems

- **Non-Sensitive Data Misidentified**: Data appears sensitive but is actually public, synthetic test data, or non-identifying.
  - Example: Public user profiles, demo/test credentials clearly marked, anonymized analytics data

## Evidence Requirements

To validate, you must show:
1. **Exact source**: Where sensitive data originates (file path + line number + code snippet)
2. **Exact sink**: Where exposure occurs (file path + line number + code snippet)
3. **Dataflow trace**: How sensitive data reaches the exposure point without redaction
4. **Mitigation analysis**: Why redaction/encryption/access controls are absent or ineffective
5. **Reachability**: Evidence the exposure is accessible under the attacker model (who can access logs/responses/storage)

## Classification

- ✅ **VALIDATED_VULNERABILITY**: All conditions met, sensitive data exposed to unauthorized parties
- ⚠️ **NEEDS_HUMAN_REVIEW**: Strong signal but uncertain about production configuration, access controls, or data sensitivity classification
- 🔧 **HARDENING_OPPORTUNITY**: Risky pattern but credible defenses (debug-only, redaction, access controls) reduce exposure
- ❌ **NOT_A_VULNERABILITY**: Effective mitigation confirmed (proper redaction, appropriate access controls, disabled in production)
