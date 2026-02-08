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
