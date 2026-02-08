# Server-Side Template Injection (SSTI) Detection

## Methodology

### Step 1: Identify Template Engines and Rendering Calls

Map every location where a template engine renders content. The critical distinction is file-based vs. string-based (inline) rendering -- string-based is the primary injection surface.

**Python (Jinja2 / Mako):**
```python
Template(user_string).render()             # DANGEROUS: string-based
env.from_string(user_string).render()      # DANGEROUS: string-based
render_template("page.html", name=name)    # Usually safe: file-based
Template(filename="page.html").render()    # Usually safe (Mako)
```

**Java (Freemarker / Pebble / Velocity):**
```java
new Template("name", new StringReader(userInput), cfg);   // DANGEROUS
Velocity.evaluate(context, writer, "tag", userInput);     // DANGEROUS
engine.getLiteralTemplate(userInput);                      // DANGEROUS
cfg.getTemplate("page.ftl");                              // Usually safe
```

**PHP (Twig) / Ruby (ERB) / Node.js (Nunjucks, EJS, Handlebars):**
```php
$twig->createTemplate($userInput)->render();              // DANGEROUS
```
```ruby
ERB.new(user_input).result(binding)                       // DANGEROUS
```
```javascript
nunjucks.renderString(userInput, data);                   // DANGEROUS
ejs.render(userInput, data);                              // DANGEROUS
Handlebars.compile(userInput)(data);                      // DANGEROUS
res.render('page', { name: name });                       // Usually safe
```

### Step 2: Trace User Input to Template Source

Injection occurs only when user input is part of the template itself, not when it is passed as data.

```python
# VULNERABLE: user input IS the template
template = Template(f"Hello {request.args['greeting']}")
# SAFE: user input is passed as DATA
template = Template("Hello {{ name }}")
output = template.render(name=request.args['name'])
# SUBTLE: concatenation before rendering
Template(header + user_content + footer).render()
```

### Step 3: Detect Sandbox Escape Chains

Auto-escaping prevents XSS but does NOT prevent SSTI. Key introspection chains:

**Jinja2:** `{{ ''.__class__.__mro__[1].__subclasses__() }}`, `{{ config.__class__.__init__.__globals__['os'].popen('id').read() }}`
**Freemarker:** `${"freemarker.template.utility.Execute"?new()("id")}`
**Twig:** `{{['id']|filter('system')}}`
**Mako:** `<% import os; os.popen("id").read() %>`
**Nunjucks:** `{{ range.constructor("return global.process.mainModule.require('child_process').execSync('id')")() }}`

### Step 4: Evaluate Sandboxing and Restrictions

```python
# Jinja2 SandboxedEnvironment — restricts attribute access but has known bypasses
from jinja2.sandbox import SandboxedEnvironment
env = SandboxedEnvironment()
```
```php
// Twig sandbox — policy must whitelist allowed tags, filters, methods
$sandbox = new \Twig\Extension\SandboxExtension($policy);
```
```java
// Freemarker — restrict class resolution
cfg.setNewBuiltinClassResolver(TemplateClassResolver.ALLOWS_NOTHING_RESOLVER);
```

### Step 5: Check for Indirect SSTI via Stored Templates

Templates loaded from database or user-configurable storage (CMS themes, email templates, report builders) are high-risk even if not directly from HTTP input.

```python
template_source = db.query("SELECT body FROM email_templates WHERE id = ?", tpl_id)
Template(template_source).render(user=user)  # SSTI if any user can edit templates
```

## Decision Tree

```
User input reaches template SOURCE (not just data)?
|
+-- NO --> SAFE
|
+-- YES
    |
    Template engine sandbox enabled and correctly configured?
    |
    +-- YES --> HARDENED (Medium) — sandboxes have known bypasses
    +-- NO
        |
        Input is full template source or partial interpolation?
        |
        +-- Full source --> VULNERABLE (Critical) — full RCE
        +-- Partial, engine allows expression eval?
            +-- YES --> VULNERABLE (Critical)
            +-- NO  --> HARDENED (Medium)
```

## Real-World Examples

### Example 1: Jinja2 SSTI in Flask User Profile

```python
@app.route('/profile/<username>')
def profile(username):
    user = get_user(username)
    bio_html = Template(user.bio).render()
    return render_template('profile.html', bio=bio_html)
```

**Why vulnerable:** The user's bio field is used as Jinja2 template source. A user sets their bio to `{{ config.SECRET_KEY }}` or a MRO chain for RCE.

**Impact:** Remote code execution. Exposure of secret keys, database credentials, full server compromise.

**Fix:**
```python
@app.route('/profile/<username>')
def profile(username):
    user = get_user(username)
    return render_template('profile.html', bio=user.bio)  # Pass as DATA
```

### Example 2: Freemarker SSTI in Java Report Generator

```java
@PostMapping("/report/preview")
public String previewReport(@RequestParam String template, Model model) {
    Template tpl = new Template("preview", new StringReader(template), cfg);
    StringWriter out = new StringWriter();
    tpl.process(model.asMap(), out);
    return out.toString();
}
```

**Why vulnerable:** The `template` parameter is compiled as Freemarker source. Attacker injects `${"freemarker.template.utility.Execute"?new()("cat /etc/passwd")}`.

**Impact:** Full RCE on the Java application server.

**Fix:**
```java
@PostMapping("/report/preview")
public String previewReport(@RequestParam String reportId, Model model) {
    cfg.setNewBuiltinClassResolver(TemplateClassResolver.ALLOWS_NOTHING_RESOLVER);
    Template tpl = cfg.getTemplate("reports/" + sanitizeId(reportId) + ".ftl");
    StringWriter out = new StringWriter();
    tpl.process(model.asMap(), out);
    return out.toString();
}
```

### Example 3: Nunjucks SSTI in Node.js Email Personalization

```javascript
app.post('/api/send-email', async (req, res) => {
  const { recipientEmail, bodyTemplate } = req.body;
  const user = await User.findOne({ email: recipientEmail });
  const renderedBody = nunjucks.renderString(bodyTemplate, { name: user.name });
  await sendEmail(recipientEmail, "Welcome", renderedBody);
  res.json({ success: true });
});
```

**Why vulnerable:** `bodyTemplate` is user-controlled and passed to `nunjucks.renderString()`. Nunjucks supports constructor access for RCE.

**Impact:** Server-side RCE. Full server compromise.

**Fix:**
```javascript
app.post('/api/send-email', async (req, res) => {
  const { recipientEmail, templateId } = req.body;
  const templateFile = await EmailTemplate.findById(templateId);
  if (!templateFile) return res.status(404).json({ error: 'Template not found' });
  const renderedBody = nunjucks.render(templateFile.path, { name: user.name });
  await sendEmail(recipientEmail, templateFile.subject, renderedBody);
});
```

## Common False Positive Patterns

1. **File-based template rendering with user data** -- `render_template("page.html", name=user_input)` passes user input as context data, not template source.

2. **Auto-escaping in output context** -- `{{ name|e }}` is XSS defense, not SSTI. If `name` comes from context data, no SSTI exists.

3. **String formatting resembling template syntax** -- Python f-strings, `str.format()`, or JS template literals are language-level operations, not template engine rendering.

4. **Static templates with whitelisted dynamic includes** -- `{% include page_name %}` where `page_name` maps to predefined template files is typically safe.

5. **Client-side template rendering** -- Handlebars/Mustache/Vue rendered in the browser are client-side XSS concerns, not SSTI.

6. **Template compilation at build time** -- Precompiled templates (Handlebars.precompile) have no runtime injection surface.

7. **Admin-only template editors** -- CMS platforms intentionally allowing admin template editing. Flag as BY_DESIGN but note the trust boundary.
