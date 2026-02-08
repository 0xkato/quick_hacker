# Dependency Vulnerability and Risk Detection

Systematic methodology for identifying vulnerable, unmaintained, malicious, and
misconfigured dependencies across package ecosystems. Covers known CVEs, abandoned
packages, typosquatting, excessive dependency trees, version pinning, and lockfile integrity.

## Methodology

### Step 1: Inventory All Dependency Manifests and Lockfiles

Locate every manifest and lockfile. A project may use multiple ecosystems simultaneously.

```bash
# Manifests
find . -name "package.json" -o -name "requirements*.txt" -o -name "Pipfile" \
       -o -name "Cargo.toml" -o -name "go.mod" -o -name "pom.xml" \
       -o -name "build.gradle*" -o -name "pyproject.toml"
# Lockfiles
find . -name "package-lock.json" -o -name "yarn.lock" -o -name "Pipfile.lock" \
       -o -name "poetry.lock" -o -name "Cargo.lock" -o -name "go.sum"
```

A missing lockfile means builds are non-reproducible and open to supply-chain hijack.

### Step 2: Run Ecosystem-Specific Audit Tools

```bash
npm audit --json > npm_audit.json          # npm
pip-audit -r requirements.txt -f json      # pip
cargo audit --json > cargo_audit.json      # Cargo
govulncheck ./...                          # Go
mvn org.owasp:dependency-check-maven:check # Maven
```

Any Critical/High CVE in a direct dependency is an immediate finding. Transitive
CVEs are findings when no override or patch path exists.

### Step 3: Detect Unmaintained and Abandoned Packages

Flag if: last publish > 2 years, repo archived, no commits in 18+ months, or
maintainer account inactive.

```python
import requests, datetime
def check_npm_staleness(pkg):
    data = requests.get(f"https://registry.npmjs.org/{pkg}").json()
    modified = datetime.datetime.fromisoformat(data["time"]["modified"].rstrip("Z"))
    age = (datetime.datetime.utcnow() - modified).days
    if age > 730: return "ABANDONED", age
    if age > 365: return "STALE", age
    return "ACTIVE", age
```

Query crates.io for Rust, `pypi.org/pypi/{name}/json` for Python.

### Step 4: Identify Typosquatting and Known Malicious Packages

Compare dependency names against known-malicious lists and Levenshtein-distance
matches to popular packages.

```python
def levenshtein_check(pkg_name, popular_packages, threshold=2):
    for popular in popular_packages:
        dist = levenshtein(pkg_name, popular)
        if 0 < dist <= threshold:
            return True, popular
    return False, None
```

Also check for: identical names across registries, very recent packages with
high version numbers, GitHub repo URL mismatching the published tarball.

### Step 5: Evaluate Dependency Tree Depth and Breadth

```bash
npm ls --all --json | jq '[.. | .version? // empty] | length'  # npm
cargo tree | wc -l                                               # Cargo
pipdeptree --warn silence | grep -c "^\S"                        # pip
go mod graph | wc -l                                             # Go
```

Thresholds: >500 transitive in npm = HIGH surface, >200 in Cargo = MEDIUM,
any single dep pulling >50 transitive = flag for review.

### Step 6: Audit Version Pinning and Range Specifiers

Unpinned versions create a hijack window where a compromised package auto-installs.

```json
// VULNERABLE: loose ranges in package.json
{ "dependencies": { "lodash": "^4.0.0", "express": "*" } }
```
```
# VULNERABLE: unpinned requirements.txt
flask
requests>=2.0
```

For applications, exact pinning is the standard. Lockfiles should always be
committed. Libraries may use ranges but must commit lockfiles for CI.

### Step 7: Verify Lockfile Integrity

A tampered lockfile can redirect installs. Verify lockfile is committed, integrity
hashes are present, and `resolved` URLs point to expected registries.

```bash
# Check for missing integrity hashes in npm
cat package-lock.json | jq -r \
  '.. | select(.resolved? and (.integrity == null)) | .resolved'
# Check for unexpected registry URLs
cat package-lock.json | jq -r '.. | .resolved? // empty' \
  | grep -v "https://registry.npmjs.org"
```

For Cargo.lock verify `checksum` fields. For go.sum verify against `sum.golang.org`.

## Decision Tree

```
START: Dependency manifest found
  |
  +--[Audit tool]--> CVEs found?
  |   | YES                      | NO
  |   v                          v
  |  Critical/High in           Continue
  |  direct dep?
  |   | YES -> VULN Crit
  |   | NO  -> VULN High (transitive, no patch)
  |
  +--[Staleness]--> Abandoned (>2yr)? -> VULN High
  |                 Stale (>1yr)?     -> HARDENED Med
  |                 Active?           -> Continue
  |
  +--[Typosquat]--> Match found?  -> VULN Critical
  |                 No match?     -> Continue
  |
  +--[Tree depth]--> >500 transitive? -> HARDENED Med
  |                  Otherwise?       -> Continue
  |
  +--[Pinning]--> Unpinned + no lockfile? -> VULN High
  |               Lockfile, no hashes?    -> HARDENED Med
  |               Lockfile + hashes?      -> SAFE
  END
```

## Real-World Examples

### Example 1: event-stream Compromise (npm)

```json
{ "dependencies": { "event-stream": "^3.3.4" } }
```

**Why vulnerable:** The package was transferred to a new maintainer who added the
malicious `flatmap-stream` transitive dependency in v3.3.6. The loose `^3.3.4`
range auto-installed the compromised version.

**Impact:** Cryptocurrency theft from Copay Bitcoin wallet users. A single
compromised transitive dependency affected millions of installs.

**Fix:** Pin to `"event-stream": "3.3.4"`. Commit `package-lock.json`. Use
`npm ci` in production builds. Enable `npm audit` in CI.

### Example 2: ua-parser-js Hijack (npm)

```json
{ "dependencies": { "ua-parser-js": ">=0.7.0" } }
```

**Why vulnerable:** Maintainer account compromised. Malicious versions 0.7.29,
0.8.0, 1.0.0 published with cryptominer and credential-stealing trojan. The
unbounded range `>=0.7.0` pulled in the malicious release.

**Impact:** Cryptomining and credential theft across 8M+ weekly downloads. CI
servers and developer machines compromised.

**Fix:** Pin to `"ua-parser-js": "0.7.28"`. Use lockfiles. Run `npm audit` as
CI gate. Enable npm 2FA on publish.

### Example 3: Unmaintained Rust Crate with RUSTSEC Advisory

```toml
[dependencies]
chrono = "0.4.19"
```

**Why vulnerable:** chrono 0.4.19 has RUSTSEC-2020-0159 (segfault in
`localtime_r`). Slow maintainer response left users exposed for months.

**Impact:** Denial of service via segfault, especially on musl-based Linux.

**Fix:** Upgrade to `chrono = "0.4.31"`. Run `cargo audit` in CI. Consider the
`time` crate if maintainer responsiveness is a concern.

## Common False Positive Patterns

1. **Platform-specific advisory.** A Linux-only CVE in a macOS/Windows-only
   deployment. Verify the advisory's affected-platform field.

2. **Unreachable transitive dependency.** The vulnerable function is never called.
   `govulncheck` handles this for Go; other ecosystems need manual analysis.

3. **Configuration-dependent vulnerability.** CVE triggers only with specific
   options (e.g., XML parsing in a JSON library). Check if the feature is used.

4. **"Complete" stale packages.** Packages like `inherits`, `ms`, `isarray` are
   intentionally minimal and finished. No commits does not mean abandoned.

5. **Lockfile reformatting diffs.** Different npm/yarn versions reformat lockfiles.
   Check for semantic changes vs. whitespace/ordering differences.

6. **Internal fork of a public package.** An org fork in a private registry looks
   like a typosquat. Verify the private registry is correctly scoped.

7. **CVE mitigated at application layer.** The app wraps calls with input
   validation preventing exploitation. Confirm mitigation is robust before
   downgrading severity.
