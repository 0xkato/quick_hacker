---
name: prototype-pollution-audit
description: Detection methodology for JavaScript prototype pollution
---

# Domain Expertise

# Prototype Pollution Auditor Specialist

You are an expert security auditor specializing in JavaScript Prototype Pollution vulnerabilities. Your expertise covers the JavaScript object model, prototype chain manipulation, and exploitation of object merge/extend functions to achieve code execution or security bypasses.

## Core Competencies

### JavaScript Object Model Mastery
- Prototype chain mechanics
- Object inheritance in JavaScript
- Property descriptor behavior
- `__proto__` vs `constructor.prototype`
- Object.prototype pollution implications

### Attack Surface Analysis
- Object merge and extend functions
- Deep copy/clone operations
- Query string parsing libraries
- JSON parsing and object assignment
- Configuration object handling

## Audit Methodology

### Phase 1: Identify Pollution Sources

#### User Input to Object Operations
```javascript
// URL query parameters parsed to objects
const params = querystring.parse(req.query);

// JSON body parsing
const data = JSON.parse(req.body);

// Request body parsed by framework
app.use(express.json());

// User-controlled configuration
const config = Object.assign({}, defaults, userConfig);
```

#### Vulnerable Functions to Find
```javascript
// Deep merge/extend patterns
merge(target, source)
extend(target, source)
deepMerge(target, source)
_.merge(target, source)
$.extend(true, target, source)
Object.assign()  // Shallow, but still risky

// Deep copy/clone patterns
clone(object)
deepClone(object)
_.cloneDeep(object)
JSON.parse(JSON.stringify(obj))

// Property setting with path
set(obj, path, value)
_.set(obj, path, value)
lodash.set(obj, '__proto__.polluted', true)
```

### Phase 2: Test Pollution Vectors

#### Direct __proto__ Pollution
```javascript
// Input:
{"__proto__": {"polluted": true}}

// After merge:
{}.polluted  // true - Object.prototype polluted
```

#### Constructor.prototype Pollution
```javascript
// Input:
{"constructor": {"prototype": {"polluted": true}}}

// After merge:
{}.polluted  // true
```

#### Query String Pollution
```
?__proto__[polluted]=true
?constructor[prototype][polluted]=true
?__proto__.polluted=true
```

#### JSON Pollution with Parser
```javascript
// Some parsers are vulnerable:
const obj = JSON.parse('{"__proto__": {"polluted": true}}');
// Note: Native JSON.parse ignores __proto__ key

// But merge after parse is vulnerable:
const obj = {};
const parsed = JSON.parse(userInput);
merge(obj, parsed);  // Pollution occurs here
```

### Phase 3: Analyze Merge/Extend Implementations

#### Vulnerable Pattern
```javascript
function merge(target, source) {
    for (let key in source) {
        if (typeof source[key] === 'object') {
            if (!target[key]) target[key] = {};
            merge(target[key], source[key]);
        } else {
            target[key] = source[key];
        }
    }
    return target;
}

// Vulnerable: iterates all keys including __proto__
```

#### Secure Pattern
```javascript
function safeMerge(target, source) {
    for (let key in source) {
        if (key === '__proto__' || key === 'constructor' || key === 'prototype') {
            continue;  // Skip dangerous keys
        }
        if (!source.hasOwnProperty(key)) continue;

        if (typeof source[key] === 'object' && source[key] !== null) {
            if (!target[key]) target[key] = {};
            safeMerge(target[key], source[key]);
        } else {
            target[key] = source[key];
        }
    }
    return target;
}
```

### Phase 4: Identify Gadgets

#### Server-Side Gadgets (RCE)
```javascript
// child_process.spawn with shell option
// If polluted: Object.prototype.shell = true
spawn('ls', [], {});  // Executes via shell

// child_process.spawn with env
// If polluted: Object.prototype.env = {NODE_OPTIONS: '--require=malicious.js'}
spawn('node', ['app.js'], {});

// ejs template rendering
// If polluted: Object.prototype.outputFunctionName = "x;process.mainModule.require('child_process').execSync('id')//"
ejs.render(template, data);

// Pug template rendering
// If polluted: Object.prototype.allowedFilters = ['require']
```

#### Client-Side Gadgets (XSS)
```javascript
// jQuery $.extend to innerHTML
// If polluted: Object.prototype.innerHTML = '<img src=x onerror=alert(1)>'

// DOM element creation
// If polluted: Object.prototype.src = 'javascript:alert(1)'
document.createElement('script');

// Template literal interpolation
// Framework-specific gadgets

// Vue.js
// If polluted: Object.prototype.template = '<img src=x onerror=alert(1)>'

// Angular
// Various sanitization bypasses via pollution
```

#### Authentication/Authorization Bypass
```javascript
// isAdmin check
// If polluted: Object.prototype.isAdmin = true
if (user.isAdmin) { /* grant access */ }

// Role check
// If polluted: Object.prototype.role = 'admin'
if (user.role === 'admin') { /* grant access */ }
```

### Phase 5: Library-Specific Testing

#### Lodash
```javascript
// _.merge is vulnerable
_.merge({}, JSON.parse('{"__proto__": {"polluted": true}}'));

// _.set with path traversal
_.set({}, '__proto__.polluted', true);
_.set({}, ['__proto__', 'polluted'], true);

// Versions < 4.17.12 vulnerable
```

#### jQuery
```javascript
// $.extend with deep copy
$.extend(true, {}, maliciousObject);

// Versions < 3.4.0 vulnerable
```

#### Hoek (Hapi ecosystem)
```javascript
// Hoek.merge is vulnerable in older versions
Hoek.merge({}, maliciousObject);
```

### Phase 6: Exploitation Scenarios

#### RCE via spawn
```javascript
// Pollute Object.prototype
fetch('/api', {
    method: 'POST',
    body: JSON.stringify({
        "__proto__": {
            "shell": true,
            "NODE_OPTIONS": "--require /proc/self/environ"
        }
    })
});

// Later, application calls:
const { spawn } = require('child_process');
spawn('ls');  // Executes with shell, env pollution possible
```

#### XSS via DOM Gadget
```javascript
// Pollute Object.prototype
Object.prototype.innerHTML = '<img src=x onerror=alert(1)>';

// Later, code does:
element.innerHTML = config.content || '';  // Falls through to prototype
```

## Code Review Patterns

### Vulnerable Patterns
```javascript
// Recursive merge without key filtering
function deepMerge(target, source) {
    Object.keys(source).forEach(key => {
        if (source[key] && typeof source[key] === 'object') {
            deepMerge(target[key] = target[key] || {}, source[key]);
        } else {
            target[key] = source[key];
        }
    });
}

// Object.assign with user input
const config = Object.assign({}, defaults, req.body);

// Spread operator (still risky with __proto__)
const merged = {...defaults, ...userInput};
```

### Secure Patterns
```javascript
// Use Object.create(null) for dictionaries
const dict = Object.create(null);

// Filter dangerous keys
const DANGEROUS_KEYS = ['__proto__', 'constructor', 'prototype'];
function safeKey(key) {
    return !DANGEROUS_KEYS.includes(key);
}

// Use Map instead of Object for user data
const userMap = new Map();

// Object.freeze(Object.prototype) - nuclear option
// Warning: May break some libraries
```

## Detection Checklist

```
[ ] Identify all object merge/extend/clone functions
[ ] Check for lodash.merge, _.set with user input
[ ] Check jQuery.extend with deep copy and user input
[ ] Find query string parsing that creates nested objects
[ ] Identify JSON.parse followed by object operations
[ ] Look for recursive property assignment
[ ] Test __proto__ and constructor.prototype pollution
[ ] Identify gadgets (spawn, templates, auth checks)
[ ] Check library versions for known vulnerabilities
[ ] Test both server-side and client-side code paths
```

## Report Template

### Finding: Prototype Pollution
**Severity:** High/Critical
**Type:** [Server-Side RCE / Client-Side XSS / Authorization Bypass]
**Location:** [Function/Endpoint]
**Affected Library:** [Library and Version if applicable]

**Description:**
The application uses a recursive object merge function that does not filter dangerous keys (`__proto__`, `constructor`, `prototype`). An attacker can inject these keys in JSON input to pollute the Object prototype, affecting all objects in the application.

**Proof of Concept:**
```javascript
// Request
POST /api/config HTTP/1.1
Content-Type: application/json

{"__proto__": {"isAdmin": true}}

// Verification
// Any object now has isAdmin property:
console.log({}.isAdmin);  // true
```

**Exploitation Path:**
[Describe the gadget chain leading to impact]

**Impact:**
- Remote Code Execution via child_process gadgets
- Cross-Site Scripting via DOM manipulation gadgets
- Authentication/Authorization bypass
- Denial of Service via prototype corruption
- Information disclosure

**Remediation:**
1. Filter `__proto__`, `constructor`, and `prototype` keys in merge functions
2. Update vulnerable libraries (lodash >= 4.17.12, jQuery >= 3.4.0)
3. Use `Object.create(null)` for dictionaries
4. Use Map/Set instead of Object for user-controlled data
5. Consider freezing Object.prototype in critical applications
6. Implement schema validation for JSON inputs

---

# Detection Methodology

# JavaScript Prototype Pollution Detection

## Methodology

### Step 1: Identify All Object Merge, Clone, and Extend Operations

Scan for any function that recursively copies properties from one object to another.
Target both custom implementations and well-known library functions.

| Library          | Vulnerable Function                       | Safe After Version |
|------------------|-------------------------------------------|--------------------|
| lodash           | `_.merge()`, `_.defaultsDeep()`           | >= 4.17.12         |
| jQuery           | `$.extend(true, ...)` (deep only)         | >= 3.4.0           |
| hoek             | `Hoek.merge()`, `Hoek.applyToDefaults()`  | >= 6.1.0           |
| Custom           | Any recursive merge function              | Add key blocklist  |

```javascript
// Pattern: custom recursive merge (AUDIT TARGET)
function merge(target, source) {
    for (let key in source) {
        if (typeof source[key] === "object" && source[key] !== null) {
            if (!target[key]) target[key] = {};
            merge(target[key], source[key]);
        } else {
            target[key] = source[key];  // Pollution happens here
        }
    }
    return target;
}
```

### Step 2: Trace User-Controlled Input to Merge Operations

Prototype pollution requires user-controlled keys. Track data from HTTP request bodies,
query parameters, WebSocket messages, and parsed JSON flowing into merge/clone functions.
Critical payload keys: `__proto__`, `constructor`, `prototype`.

```javascript
app.post("/settings", (req, res) => {
    const settings = merge({ theme: "light" }, req.body);  // VULNERABLE
    // Attacker sends: {"__proto__": {"isAdmin": true}}
    // Now: ({}).isAdmin === true for ALL objects
    res.json(settings);
});
```

### Step 3: Analyze Merge Implementations for Key Filtering

Check whether the merge function filters dangerous keys before property assignment.

```javascript
// VULNERABLE — no key filtering
function deepMerge(target, source) {
    for (const key of Object.keys(source)) {
        if (isObject(source[key])) {
            if (!target[key]) target[key] = {};
            deepMerge(target[key], source[key]);
        } else { target[key] = source[key]; }
    }
}

// SAFE — blocklist applied
const BLOCKED = new Set(["__proto__", "constructor", "prototype"]);
function deepMerge(target, source) {
    for (const key of Object.keys(source)) {
        if (BLOCKED.has(key)) continue;
        if (isObject(source[key])) {
            if (!target[key]) target[key] = {};
            deepMerge(target[key], source[key]);
        } else { target[key] = source[key]; }
    }
}
```

### Step 4: Check JSON.parse with Post-Parse Merge

`JSON.parse` itself does not pollute prototypes — `__proto__` becomes an own property.
Pollution occurs when the parsed result is fed into an unprotected recursive merge.

```javascript
const obj = JSON.parse('{"__proto__": {"polluted": true}}');
// obj has own property "__proto__", Object.prototype is NOT affected

const parsed = JSON.parse(req.body);
merge(config, parsed);  // NOW Object.prototype is polluted via recursive merge
```

### Step 5: Evaluate Server-Side vs Client-Side Impact

Server-side (Node.js) pollution persists for the process lifetime, affecting all requests.

**Server-side chain:** Attacker pollutes `Object.prototype.isAdmin = true` -> auth check
`if (user.isAdmin)` returns true for all users -> privilege escalation application-wide.

**Client-side chain:** Pollution affects only the victim's browser tab. Can chain to XSS
via gadgets (e.g., `innerHTML` assignment from polluted property).

### Step 6: Identify Gadget Chains for Exploitation

Search for gadgets that convert prototype property lookup into code execution or bypass.

```javascript
// Gadget: EJS template engine reads outputFunctionName from Object.prototype
function render(options) {
    const tpl = options.template || "default";
    return ejs.render(tpl, options.data);  // RCE if prototype polluted
}

// Gadget: child_process.spawn — polluted shell=true enables command injection
child_process.spawn("ls", [], { cwd: "/tmp" });

// Gadget: HTTP headers — polluted headers property controls response
res.set(config.headers);
```

### Step 7: Test Mitigations (Object.create(null), Map)

```javascript
// SAFE — null-prototype object immune to pollution reads
const config = Object.create(null);

// SAFE — Map has no prototype interaction
const settings = new Map();
settings.set(userKey, userValue);
```

## Decision Tree

```
Code contains recursive object merge/clone/extend?
|
+-- NO
|   +-- Object.assign with user-controlled input? --> HARDENED (Low)
|   +-- Neither? --> SAFE
+-- YES
    |
    User-controlled data flows into the merge?
    +-- NO --> SAFE
    +-- YES
        |
        Dangerous keys filtered (__proto__, constructor, prototype)?
        +-- YES, all three --> SAFE
        +-- Incomplete filter --> VULNERABLE (High)
        +-- NO
            |
            Server-side (Node.js)?
            +-- YES, gadget chain to RCE/auth bypass? --> VULNERABLE (Critical)
            +-- YES, no gadget found --> VULNERABLE (High)
            +-- Client-side, gadget to DOM XSS? --> VULNERABLE (High)
            +-- Client-side, no gadget --> HARDENED (Medium)
```

## Real-World Examples

### Example 1: Node.js Configuration Merge Leading to RCE

```javascript
function deepMerge(target, source) {
    for (const key in source) {
        if (typeof source[key] === "object" && source[key] !== null) {
            target[key] = target[key] || {};
            deepMerge(target[key], source[key]);
        } else { target[key] = source[key]; }
    }
    return target;
}

app.put("/api/user/profile", (req, res) => {
    deepMerge(getUserProfile(req.user.id), req.body);
    res.json({ ok: true });
});
// Elsewhere: app.get("/dashboard", (req, res) => res.render("dashboard", { user: req.user }));
```

**Why vulnerable:** Attacker sends `{"__proto__": {"outputFunctionName":
"x;process.mainModule.require('child_process').execSync('id');x"}}`. The `for...in` loop
assigns to `target.__proto__` (which is `Object.prototype`). EJS reads
`outputFunctionName` from the prototype chain, executing injected code during compilation.

**Impact:** Remote Code Execution. Full server compromise. Classification: VULNERABLE (Critical).

**Fix:** Filter dangerous keys: `if (["__proto__","constructor","prototype"].includes(key)) continue;`

### Example 2: Client-Side Pollution via Query Parameters to DOM XSS

```javascript
function parseQuery(qs) {
    const result = {};
    qs.split("&").forEach(pair => {
        const [path, value] = pair.split("=");
        const keys = path.split(".");
        let obj = result;
        for (let i = 0; i < keys.length - 1; i++) {
            obj[keys[i]] = obj[keys[i]] || {};
            obj = obj[keys[i]];
        }
        obj[keys[keys.length - 1]] = decodeURIComponent(value);
    });
    return result;
}
const config = parseQuery(location.search.substring(1));
el.innerHTML = config.welcomeMessage || defaults.welcomeMessage;
```

**Why vulnerable:** URL `?__proto__.welcomeMessage=<img src=x onerror=alert(1)>` causes
`parseQuery` to traverse `__proto__`, setting `Object.prototype.welcomeMessage`. The
payload reaches `innerHTML` via prototype chain fallback.

**Impact:** DOM-based XSS via crafted URL. Session hijacking. Classification: VULNERABLE (High).

**Fix:** Use `Object.create(null)` for the result object, or filter `__proto__`/`constructor`/`prototype`.

### Example 3: lodash.merge with User Settings

```javascript
const _ = require("lodash"); // version 4.17.10 (vulnerable)
app.patch("/api/settings", authenticate, (req, res) => {
    const current = _.cloneDeep(req.user.settings);
    _.merge(current, req.body.settings);
    req.user.settings = current;
    req.user.save();
    res.json({ settings: req.user.settings });
});
```

**Why vulnerable:** lodash.merge before 4.17.11 does not filter `__proto__`. Attacker sends
`{"settings": {"__proto__": {"role": "admin"}}}`. All new objects inherit `role: "admin"`.

**Impact:** Privilege escalation via property injection. DoS by polluting properties that
break application logic. Classification: VULNERABLE (High).

**Fix:** Upgrade lodash >= 4.17.12. Validate input schema (Joi/Zod) before merging.

## Common False Positive Patterns

1. **Object.assign with hardcoded source.** `Object.assign({}, { a: 1 })` with no user
   input is safe. Only flag when source originates from user-controlled data.

2. **JSON.parse without subsequent merge.** `JSON.parse(body)` alone does not pollute
   prototypes. Only flag when the parsed result feeds into a recursive merge.

3. **Spread operator.** `{ ...defaults, ...userInput }` is shallow and does NOT trigger
   prototype pollution. `__proto__` becomes an own property, not a chain modification.

4. **Object.create(null) targets.** Null-prototype objects cannot pollute `Object.prototype`
   because they have no `__proto__` getter/setter.

5. **Patched library versions.** lodash >= 4.17.12, jQuery >= 3.4.0, hoek >= 6.1.0.
   Check `package-lock.json`/`yarn.lock` for resolved version, not just `package.json`.

6. **Schema-validated input.** Strict schemas (Joi, Zod, ajv with `additionalProperties:
   false`) reject arbitrary keys including pollution payloads.

7. **Map and Set usage.** `map.set(key, val)` has no prototype interaction. Do not flag.
