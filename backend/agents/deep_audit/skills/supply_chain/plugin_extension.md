# Plugin and Extension Security

Systematic methodology for detecting insecure plugin loading, missing sandboxing,
excessive API privileges, unsigned plugins, insecure update mechanisms, and
deserialization in plugin communication. Covers Python, Node.js, Java, and CMS
plugin ecosystems.

## Methodology

### Step 1: Identify Plugin Loading Mechanisms

Locate all code paths that dynamically load external code.

```python
# Python patterns to search for
importlib.import_module(user_input)       # DANGEROUS
exec(open(plugin_path).read())            # CRITICAL
eval(plugin_code)                         # CRITICAL
# stevedore with user-controlled name
driver.DriverManager(namespace='x', name=user_config['driver'])  # RISK
# pkg_resources entry points
for ep in pkg_resources.iter_entry_points('myapp.plugins'): ep.load()
```

```javascript
// Node.js patterns
const plugin = require(userProvidedPath);          // DANGEROUS
const mod = await import(userProvidedPath);         // DANGEROUS
const p = require(`myapp-plugin-${userName}`);      // MODERATE
```

```java
// Java patterns
URLClassLoader cl = new URLClassLoader(new URL[]{userUrl});  // DANGEROUS
cl.loadClass(className);
bundleContext.installBundle(userProvidedLocation);             // DANGEROUS
ServiceLoader.load(PluginInterface.class);                    // MODERATE
```

Map every loading path. Note whether the plugin source is controlled by user
input, configuration file, or hardcoded.

### Step 2: Assess Path Traversal and Arbitrary Load Risks

```python
# VULNERABLE: user controls plugin directory
plugin_dir = config.get("plugin_dir", "/opt/app/plugins")
for f in os.listdir(plugin_dir):
    if f.endswith(".py"):
        spec = importlib.util.spec_from_file_location(f[:-3], os.path.join(plugin_dir, f))
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)  # Loads ANY .py from user-controlled dir
```

```javascript
// VULNERABLE: path traversal via plugin name
app.get('/load-plugin/:name', (req, res) => {
    const plugin = require(`./plugins/${req.params.name}`);
    // ../../etc/passwd or ../../malicious/module can be loaded
});
```

Check for: user-controlled paths without validation, unsanitized name
concatenation, symlink following, zip-slip in archive extraction.

### Step 3: Evaluate Plugin Sandboxing and Capability Restriction

```python
# NO SANDBOXING: plugin has full process access
class PluginManager:
    def load_plugin(self, path):
        spec = importlib.util.spec_from_file_location("plugin", path)
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)  # Can import os, open sockets, read env
        return mod
```

True sandboxing requires process isolation (subprocess, container), WASM, or
language-level sandbox (Deno permissions). In Python and Node.js, in-process
plugins can always escape soft API restrictions by importing system modules.

Check for: process isolation, filesystem restrictions (chroot, namespaces),
network restrictions (seccomp, firewall), memory/CPU limits, capability-based
permission models.

### Step 4: Check Plugin Signature and Integrity Verification

```python
# VULNERABLE: no verification on download
def install_plugin(url):
    resp = requests.get(url)
    open(f"/plugins/{name}.py", "wb").write(resp.content)  # Zero verification
```

```java
// SAFER: JAR signature verification
JarFile jar = new JarFile(pluginPath, true);  // verify=true
for (JarEntry entry : Collections.list(jar.entries())) {
    jar.getInputStream(entry).readAllBytes();  // Triggers verification
    if (entry.getCodeSigners() == null)
        throw new SecurityException("Unsigned: " + entry.getName());
}
```

Check for: cryptographic signatures, certificate chain validation (not just
self-signed), hash verification against trusted manifest, verification BEFORE
extraction (not after).

### Step 5: Analyze Plugin Update Mechanisms

```python
# VULNERABLE: HTTP + no integrity check
def update_plugin(name):
    r = requests.get(f"http://plugins.example.com/{name}/latest.zip")  # HTTP!
    zipfile.ZipFile(io.BytesIO(r.content)).extractall(f"/plugins/{name}/")
```

```javascript
// VULNERABLE: HTTPS but no signature verification
async function updatePlugin(name) {
    const code = await (await fetch(`https://plugins.example.com/${name}/latest.js`)).text();
    fs.writeFileSync(`./plugins/${name}.js`, code);  // Compromised server = compromised plugin
}
```

Secure update requires: HTTPS + certificate pinning, signed packages verified
before extraction, rollback protection, integrity hashes in signed manifests.

### Step 6: Inspect Plugin Communication for Deserialization

```python
# VULNERABLE: pickle deserialization from plugin IPC
message = pickle.loads(sock.recv(4096))  # Arbitrary code execution
```

```java
// VULNERABLE: Java ObjectInputStream
PluginMessage msg = (PluginMessage) new ObjectInputStream(in).readObject();
// Gadget chain exploitation possible
```

```javascript
// VULNERABLE: eval-based parsing
return eval('(' + pluginData + ')');  // Code injection
```

Safe alternatives: JSON, Protocol Buffers, MessagePack with strict typing. If
serialization required, use type allowlists.

### Step 7: Review CMS Plugin Patterns

```php
// WordPress VULNERABLE: unauth upload + include
add_action('wp_ajax_nopriv_import', 'handle_import');  // No auth required
function handle_import() {
    // Missing: check_ajax_referer(), current_user_can()
    move_uploaded_file($_FILES['f']['tmp_name'], WP_PLUGIN_DIR.'/'.$_FILES['f']['name']);
    include(WP_PLUGIN_DIR.'/'.$_FILES['f']['name']);  // RCE via uploaded PHP
}
```

Check for: file upload to plugin dirs, `eval()`/`assert()` on user data, missing
nonce verification, missing capability checks, unsanitized DB queries.

## Decision Tree

```
START: Plugin/extension system identified
  |
  +--[Source path]-- User-controlled path/name?
  |   | YES -> Path validated/allowlisted?
  |   |          | NO  -> VULNERABLE Critical
  |   |          | YES -> Continue
  |   | NO (hardcoded) -> Continue
  |
  +--[Sandboxing]-- Process-isolated / WASM?
  |   | YES -> SAFE (verify config)
  |   | NO  -> Plugin API restricts capabilities?
  |              | NO  -> VULNERABLE High
  |              | YES -> HARDENED Medium (soft sandbox, bypassable)
  |
  +--[Signatures]-- Plugins cryptographically signed?
  |   | NO  -> VULNERABLE High
  |   | YES -> Cert chain validated?
  |              | NO  -> HARDENED Medium
  |              | YES -> SAFE
  |
  +--[Updates]-- Over HTTPS + signed?
  |   | NO  -> VULNERABLE High
  |   | YES -> SAFE
  |
  +--[IPC]-- Uses pickle / Java deser / eval?
  |   | YES -> VULNERABLE Critical
  |   | NO (JSON/protobuf) -> SAFE
  END
```

## Real-World Examples

### Example 1: Python importlib with User-Controlled Path

```python
@app.post("/enable-plugin")
def enable_plugin(request):
    name = request.json["plugin"]  # User input: "../../tmp/evil"
    path = os.path.join("/opt/app/plugins", f"{name}.py")
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)  # Loads /tmp/evil.py
```

**Why vulnerable:** `os.path.join` does not prevent `..` traversal. Attacker
supplies `../../tmp/evil`, loading and executing `/tmp/evil.py`. On shared
systems `/tmp/` is world-writable.

**Impact:** RCE with application privileges -- access to DB connections, env
secrets, ability to pivot to other services.

**Fix:** Use an allowlist: `if name not in ALLOWED_PLUGINS: raise ValueError`.
Validate resolved path: `os.path.realpath(path).startswith(plugin_dir)`. Load
plugins at startup only, not from runtime user requests.

### Example 2: Node.js require() with URL Parameter

```javascript
app.get('/api/transform/:format', (req, res) => {
    const transformer = require(`./transformers/${req.params.format}`);
    transformer.transform(req.body);
});
```

**Why vulnerable:** `req.params.format` is interpolated into `require()`.
Attacker requests `/api/transform/../../config/database` to load internal
config modules (info disclosure) or a planted `.js` file (RCE).

**Impact:** Information disclosure of internal modules or RCE if attacker can
write a `.js` file anywhere on the filesystem via upload or log injection.

**Fix:** Pre-load plugins into a static map at startup:
```javascript
const TRANSFORMERS = { json: require('./transformers/json'), csv: require('./transformers/csv') };
const t = TRANSFORMERS[req.params.format];
if (!t) return res.status(400).json({ error: 'Unknown format' });
```

### Example 3: WordPress Plugin with Unauth Upload to RCE

```php
add_action('wp_ajax_nopriv_custom_import', 'handle_import');
function handle_import() {
    $target = wp_upload_dir()['basedir'] . '/imports/' . $_FILES['f']['name'];
    move_uploaded_file($_FILES['f']['tmp_name'], $target);
    include($target);  // Uploaded PHP webshell executes immediately
}
```

**Why vulnerable:** `wp_ajax_nopriv_` allows unauthenticated access. No nonce,
no capability check. Uploaded file is `include()`-ed as PHP. Attacker uploads
a webshell and gets immediate execution.

**Impact:** Unauthenticated RCE as the web server user (`www-data`). Full
database access, filesystem traversal, lateral movement, server takeover.

**Fix:** Remove `nopriv` hook. Add `check_ajax_referer()` and
`current_user_can('manage_options')`. Validate MIME type. Never `include()`
uploaded files -- parse data with `json_decode()` or CSV parser.

## Common False Positive Patterns

1. **Hardcoded plugin lists.** Static source-code-defined lists with no user
   input path. Verify the list is compile-time or deploy-time only.

2. **setuptools entry points.** `iter_entry_points()` loads pip-installed
   plugins. Attack surface is installation, not the loading call itself.

3. **Validated dynamic require().** If input is checked against a strict
   allowlist before `require()`, the dynamic call is safe. Verify no regex
   bypass or prototype pollution of the allowlist.

4. **Java SecurityManager.** Deprecated since Java 17, removed in 24, but
   effective on supported versions with correct policy configuration.

5. **JSON over Unix sockets.** `JSON.parse()` and `json.loads()` do not
   execute code. Only flag if custom deserialization or eval-based parsing.

6. **Container-isolated plugins.** Plugins in separate containers with no
   privileged mode, host mounts, or host network. Verify runtime config.

7. **Official marketplace plugins.** WordPress.org plugins undergo review.
   Lower risk than side-loaded ZIPs but not immune. Distinguish reviewed
   vs. unreviewed third-party installations.
