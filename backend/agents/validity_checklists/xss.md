# XSS / Template Injection Validity Checklist

Use this checklist when evaluating a suspected XSS or template injection vulnerability.
Validate only if ALL conditions are met.

## Required Conditions

### 1. Attacker Data Reaches Render Sink
- [ ] Attacker-controlled data flows into rendering context where interpreted as code/markup
- [ ] Examples: HTML response, JavaScript context, template engine, DOM manipulation
- [ ] Data is inserted into dangerous context (HTML tags, attributes, JavaScript, CSS, URL)

### 2. Autoescaping Absent or Bypassed
- [ ] No context-appropriate output encoding/escaping OR escaping is bypassable
- [ ] For HTML: no HTML entity encoding or use of dangerous sinks (`innerHTML`, `document.write`)
- [ ] For JavaScript: no JavaScript escaping or data in executable context
- [ ] For template injection: template syntax itself is user-controlled (not just variable values)

### 3. Template Injection: Attacker Controls Template Syntax
- [ ] For server-side template injection (SSTI): Attacker controls template content, not just variable values
- [ ] Attacker can inject template directives/expressions that execute code
- [ ] Example: `template.render(userInput)` where userInput contains `{{7*7}}` or `<%= system('ls') %>`
- [ ] Note: Regular XSS (client-side) doesn't require this; variable injection in templates is fine if autoescaped

## Common False Positive Traps

DISPROVE the vulnerability if any of these apply:

- **Context-Correct Autoescaping**: Framework automatically escapes output for the specific context.
  - Example: React/Vue automatically escape JSX variables, Jinja2 with autoescaping enabled, Rails `<%= h(...) %>`

- **Data as Text in Safe Contexts**: Data inserted into context that doesn't interpret code.
  - Example: JSON API response where attacker data is in string values, not keys or executable contexts

- **Strict Content Security Policy**: CSP prevents inline scripts and restricts sources effectively.
  - Example: `Content-Security-Policy: default-src 'self'; script-src 'self'` with no 'unsafe-inline' or 'unsafe-eval'

- **Variables Only in Templates**: Template uses user data only as variable values with autoescaping, not template syntax.
  - Example: `<h1>{{ userName }}</h1>` in Jinja2 with autoescaping (safe) vs `{% raw %}{{ userName }}{% endraw %}` or rendering `userName` as template

## Evidence Requirements

To validate, you must show:
1. **Exact source**: Where attacker data enters (file path + line number + code snippet)
2. **Exact sink**: Where rendering occurs (file path + line number + code snippet with context)
3. **Dataflow trace**: How attacker data reaches the sink without neutralization
4. **Mitigation analysis**: Why autoescaping/CSP are absent, disabled, or bypassable in this context
5. **Reachability**: Evidence the code path is reachable (routing/auth/config)

## Classification

- ✅ **VALIDATED_VULNERABILITY**: All conditions met, attacker can inject executable code/markup
- ⚠️ **NEEDS_HUMAN_REVIEW**: Strong signal but uncertain about framework autoescaping behavior or CSP effectiveness
- 🔧 **HARDENING_OPPORTUNITY**: Risky pattern but credible defenses (autoescaping, CSP, safe contexts) reduce exploitability
- ❌ **NOT_A_VULNERABILITY**: Effective mitigation confirmed (context-correct autoescaping, safe context, strong CSP)
