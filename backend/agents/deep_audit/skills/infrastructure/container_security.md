# Container Security Detection

## Methodology

### Step 1: Identify Container Configuration Files

Locate all container-related configuration in the repository:

**Dockerfiles:**
- `Dockerfile`, `Dockerfile.*`, `*.Dockerfile`
- Multi-stage builds: look for multiple `FROM` directives
- `.dockerignore` — check what is (and is not) excluded

**Docker Compose:**
- `docker-compose.yml`, `docker-compose.*.yml`, `compose.yml`, `compose.*.yml`
- Override files: `docker-compose.override.yml`

**Container Runtime Configs:**
- Podman: `Containerfile`, `containers.conf`
- Kubernetes pod specs (overlaps with Kubernetes skill, but check inline container definitions)
- CI/CD container definitions (GitHub Actions `container:`, GitLab CI `image:`)

**Scan for runtime invocations:**
- Shell scripts calling `docker run` with flags like `--privileged`, `--cap-add`, `--network host`
- Deployment scripts that pass security-relevant options

### Step 2: Check User and Privilege Configuration

Containers running as root have the same UID as the host root user. If a container escape occurs, the attacker is root on the host.

```dockerfile
# VULNERABLE — no USER directive, defaults to root
FROM python:3.12
COPY . /app
CMD ["python", "/app/main.py"]

# SAFE — explicit non-root user
FROM python:3.12
RUN groupadd -r appuser && useradd -r -g appuser appuser
COPY --chown=appuser:appuser . /app
USER appuser
CMD ["python", "/app/main.py"]
```

**Check for privilege escalation paths:**
```yaml
# docker-compose.yml — VULNERABLE configurations
services:
  app:
    privileged: true                    # VULNERABLE — full host access
    cap_add:
      - SYS_ADMIN                       # VULNERABLE — near-root capabilities
      - NET_RAW                         # RISKY — allows packet sniffing/spoofing
      - SYS_PTRACE                      # RISKY — allows process debugging
    security_opt:
      - seccomp:unconfined              # VULNERABLE — disables seccomp filtering
      - apparmor:unconfined             # VULNERABLE — disables AppArmor
      - no-new-privileges:false         # VULNERABLE — allows privilege escalation
```

**Also check:**
- `docker run --privileged` in shell scripts or CI pipelines
- `--pid=host`, `--ipc=host` — breaks process namespace isolation
- `--userns=host` — disables user namespace remapping
- `cap_drop: ALL` followed by selective `cap_add` is the correct pattern

### Step 3: Check Volume Mounts and Sensitive Paths

Mounting host paths into containers can expose sensitive host resources:

```yaml
# docker-compose.yml
services:
  app:
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock  # CRITICAL — container escape via Docker API
      - /etc:/host-etc                              # CRITICAL — host config access
      - /:/host-root                                # CRITICAL — full host filesystem
      - /proc:/host-proc                            # HIGH — host process information
      - /sys:/host-sys                              # HIGH — kernel parameters
      - /root:/root                                 # HIGH — root home directory
      - ~/.ssh:/root/.ssh                           # HIGH — SSH keys
      - ~/.aws:/root/.aws                           # HIGH — cloud credentials
```

**Docker socket mount is the most critical finding.** It allows the container to create new containers on the host, mount the host filesystem, and achieve full host compromise:

```bash
# Inside a container with Docker socket access:
docker run -v /:/host --privileged -it alpine chroot /host
# Now you have a root shell on the host
```

**Check for writable root filesystem:**
```yaml
# VULNERABLE — container can write to its own filesystem (default)
services:
  app:
    image: myapp:latest

# SAFE — read-only root filesystem with explicit writable tmpfs
services:
  app:
    image: myapp:latest
    read_only: true
    tmpfs:
      - /tmp
      - /var/run
```

### Step 4: Check for Secrets in Dockerfiles

Secrets baked into images persist in image layers and can be extracted even if deleted in later layers:

```dockerfile
# VULNERABLE — secret in build argument (visible in image history)
ARG DATABASE_PASSWORD=supersecret
ENV DB_PASS=$DATABASE_PASSWORD

# VULNERABLE — secret in ENV directive
ENV API_KEY=sk-live-abc123def456
ENV AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY

# VULNERABLE — copying secrets files into image
COPY .env /app/.env
COPY credentials.json /app/credentials.json
COPY id_rsa /root/.ssh/id_rsa

# VULNERABLE — secret in RUN command (persists in layer)
RUN echo "machine github.com login token password ghp_xxxx" > ~/.netrc
RUN git clone https://user:token@github.com/private/repo.git

# SAFE — use Docker BuildKit secrets (not persisted in image layers)
RUN --mount=type=secret,id=db_password \
    cat /run/secrets/db_password | setup_db
```

**Also check:**
- `docker-compose.yml` with `environment:` containing literal secrets instead of `${VAR}` references
- `.env` files not listed in `.dockerignore`
- SSH agent forwarding via `--ssh` flag (generally safe if used correctly)
- Multi-stage builds where secrets are used in a discarded builder stage (safe if done correctly)

### Step 5: Check Base Image Security

```dockerfile
# VULNERABLE — latest tag is mutable, unpinnable, and unreproducible
FROM python:latest
FROM node:latest
FROM ubuntu:latest

# VULNERABLE — using a very old or unmaintained base image
FROM python:3.6-slim        # Python 3.6 is EOL
FROM node:14                # Node 14 is EOL
FROM ubuntu:18.04           # Ubuntu 18.04 is EOL (past standard support)

# RISKY — full OS image includes unnecessary attack surface
FROM python:3.12            # Includes full Debian with gcc, make, etc.
FROM ubuntu:24.04           # Full OS — likely has unnecessary packages

# SAFE — minimal base images with pinned digests
FROM python:3.12-slim@sha256:abc123...
FROM gcr.io/distroless/python3-debian12
FROM alpine:3.20@sha256:def456...
```

**Check for:**
- Unpinned tags (`:latest`, `:stable`, `:lts`) — supply chain risk
- Missing digest pinning (`@sha256:...`) — tag can be overwritten
- EOL base images — known unpatched vulnerabilities
- Full OS images when slim/distroless/alpine would suffice
- `apt-get install` or `apk add` without version pinning

### Step 6: Check Network Configuration

```yaml
# docker-compose.yml
services:
  app:
    network_mode: host              # VULNERABLE — no network namespace isolation
    ports:
      - "0.0.0.0:8080:8080"        # RISKY — binds to all interfaces
      - "3306:3306"                 # VULNERABLE — database exposed to host network
      - "6379:6379"                 # VULNERABLE — Redis exposed without auth
      - "127.0.0.1:5432:5432"      # SAFE — bound to localhost only
```

**Host network mode** gives the container direct access to the host's network stack. It can bind to any port, see all host traffic, and access services listening on localhost.

### Step 7: Classify

- **VULNERABLE (Critical)**: Docker socket mounted, OR `privileged: true`, OR secrets hardcoded in Dockerfile ENV/ARG, OR host root filesystem mounted
- **VULNERABLE (High)**: Running as root with `SYS_ADMIN` capability, OR host network mode with sensitive services, OR secrets copied into image layers, OR seccomp/AppArmor disabled
- **HARDENED (Medium)**: Running as root but no extra capabilities, OR unpinned base image tags, OR writable root filesystem, OR database ports exposed on all interfaces
- **HARDENED (Low)**: Using full OS base image instead of slim/distroless, OR missing `no-new-privileges`, OR EOL base image in non-production environment
- **SAFE**: Non-root user, minimal capabilities, read-only root filesystem, no sensitive mounts, pinned base images, secrets via BuildKit or runtime injection
- **BY_DESIGN**: Privileged mode for system-level containers (e.g., log collectors, network plugins) that inherently require host access

## Decision Tree

```
Is a Dockerfile or container config present?
├── No → SAFE (not applicable)
└── Yes → Does the container run as root (no USER directive)?
    ├── Yes → Is the container privileged or have SYS_ADMIN?
    │   ├── Yes → VULNERABLE (Critical)
    │   └── No → Are sensitive host paths mounted?
    │       ├── Docker socket or /etc or / → VULNERABLE (Critical)
    │       ├── /proc, /sys, or home dirs → VULNERABLE (High)
    │       └── No sensitive mounts → HARDENED (Medium — root without escalation path)
    └── No (non-root USER set) → Are secrets baked into the image?
        ├── ENV/ARG with secrets → VULNERABLE (Critical)
        ├── COPY of .env or credential files → VULNERABLE (High)
        └── No secrets in image → Is the base image secure?
            ├── Unpinned :latest tag → HARDENED (Medium)
            ├── EOL base image → HARDENED (Medium)
            ├── Full OS image → HARDENED (Low)
            └── Pinned, minimal base → Check network and runtime
                ├── host network mode → VULNERABLE (High)
                ├── seccomp/AppArmor disabled → VULNERABLE (High)
                ├── Writable root filesystem → HARDENED (Low)
                └── All hardened → SAFE
```

## Real-World Examples

### Example 1: Docker Socket Mount with Root User

**Vulnerable configuration:**
```dockerfile
# Dockerfile
FROM python:3.12
COPY . /app
WORKDIR /app
RUN pip install -r requirements.txt
CMD ["python", "monitor.py"]
```

```yaml
# docker-compose.yml
services:
  monitor:
    build: .
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock
    environment:
      - DOCKER_HOST=unix:///var/run/docker.sock
```

**Why vulnerable:** The container runs as root (no `USER` directive) and has the Docker socket mounted. Any code running inside this container — including exploited dependencies — can use the Docker API to create a new container with the host's root filesystem mounted, effectively escaping the container. This is the most common container escape vector. The `monitor.py` script likely uses the Docker SDK to watch containers, but any vulnerability in the application (SSRF, command injection, dependency compromise) gives the attacker full host access.

**Impact:** Full host compromise. Attacker escapes the container, gains root access to the host, and can access all other containers, host filesystems, and potentially pivot to other hosts.

**Fix:**
```dockerfile
FROM python:3.12-slim
RUN groupadd -r monitor && useradd -r -g monitor monitor
COPY --chown=monitor:monitor . /app
WORKDIR /app
RUN pip install --no-cache-dir -r requirements.txt
USER monitor
CMD ["python", "monitor.py"]
```

```yaml
services:
  monitor:
    build: .
    read_only: true
    tmpfs:
      - /tmp
    # Use Docker API over TCP with TLS client certs instead of socket mount
    # Or use a read-only Docker socket proxy like tecnativa/docker-socket-proxy
    environment:
      - DOCKER_HOST=tcp://docker-proxy:2375
    depends_on:
      - docker-proxy

  docker-proxy:
    image: tecnativa/docker-socket-proxy
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock:ro
    environment:
      - CONTAINERS=1    # Only allow container listing
      - POST=0          # Deny all POST requests (no creating containers)
```

### Example 2: Secrets Baked into Dockerfile Layers

**Vulnerable configuration:**
```dockerfile
FROM node:20

WORKDIR /app

# Secret in build argument — visible in docker history
ARG NPM_TOKEN
RUN echo "//registry.npmjs.org/:_authToken=${NPM_TOKEN}" > .npmrc

COPY package*.json ./
RUN npm ci

# Attempt to "delete" the secret — but it persists in the previous layer
RUN rm .npmrc

COPY . .

# Secret in ENV — visible in image inspect and to all processes
ENV DATABASE_URL=postgres://admin:Pr0d_P@ssw0rd!@db.internal:5432/app
ENV STRIPE_SECRET_KEY=sk_live_4eC39HqLyjWDarjtT1zdp7dc

CMD ["node", "server.js"]
```

**Why vulnerable:** Docker images are composed of layers. Each `RUN`, `COPY`, or `ADD` instruction creates a new layer. Even though `.npmrc` is deleted in a subsequent `RUN` instruction, it still exists in the earlier layer. Anyone who pulls the image can run `docker history` or extract the layer to retrieve the NPM token. The `ENV` directives for `DATABASE_URL` and `STRIPE_SECRET_KEY` are visible via `docker inspect` and are available as environment variables to any process in the container, including malicious dependencies. The `ARG NPM_TOKEN` value can be recovered from image metadata if Docker BuildKit is not used.

**Impact:** Credential exposure. Anyone with access to the image (registry, CI artifacts, host) can extract production database credentials, payment API keys, and package registry tokens.

**Fix:**
```dockerfile
FROM node:20-slim AS builder

WORKDIR /app
COPY package*.json ./

# Use BuildKit secret mount — never persisted in image layers
RUN --mount=type=secret,id=npm_token \
    NPM_TOKEN=$(cat /run/secrets/npm_token) \
    echo "//registry.npmjs.org/:_authToken=${NPM_TOKEN}" > .npmrc && \
    npm ci && \
    rm .npmrc

COPY . .
RUN npm run build

# Clean production image — no build secrets, no build tools
FROM node:20-slim
RUN groupadd -r app && useradd -r -g app app
WORKDIR /app
COPY --from=builder --chown=app:app /app/dist ./dist
COPY --from=builder --chown=app:app /app/node_modules ./node_modules
USER app

# Secrets injected at runtime via orchestrator (Kubernetes Secrets, Docker secrets, Vault)
CMD ["node", "dist/server.js"]
```

### Example 3: Privileged Container with Host Network

**Vulnerable configuration:**
```yaml
# docker-compose.yml
services:
  debug-tools:
    image: nicolaka/netshoot:latest
    privileged: true
    network_mode: host
    pid: host
    cap_add:
      - SYS_ADMIN
      - SYS_PTRACE
      - NET_RAW
    security_opt:
      - seccomp:unconfined
      - apparmor:unconfined
    volumes:
      - /:/host
      - /var/run/docker.sock:/var/run/docker.sock
```

**Why vulnerable:** This container has every isolation mechanism disabled. `privileged: true` grants all Linux capabilities and device access. `network_mode: host` exposes the full host network stack. `pid: host` exposes all host processes. `seccomp:unconfined` and `apparmor:unconfined` remove kernel-level syscall filtering. The host root filesystem is mounted at `/host`. This configuration provides zero isolation — the container has strictly more access than a root shell on the host, since it also has the Docker socket. Even if intended as a temporary debug tool, leaving this configuration in a repository means it can be accidentally deployed or used as a template.

**Impact:** Equivalent to unauthenticated root access. Attacker (or any process in this container) can read/write any file on the host, access any process, sniff network traffic, pivot to other hosts, and control all other containers.

**Fix:**
```yaml
# Remove this service entirely from production configs.
# If debug tooling is needed, use ephemeral containers:
#   kubectl debug -it <pod> --image=nicolaka/netshoot -- /bin/bash
# Or a locked-down version:
services:
  debug-tools:
    image: nicolaka/netshoot:v0.13@sha256:abc123...
    read_only: true
    cap_drop:
      - ALL
    cap_add:
      - NET_RAW    # Only if packet capture is truly needed
    security_opt:
      - no-new-privileges:true
    profiles:
      - debug      # Only started with --profile debug
```

## Common False Positive Patterns

1. **Multi-stage build with secrets only in discarded builder stage**: A Dockerfile that `COPY`s credentials in a `FROM ... AS builder` stage but the final `FROM` stage only copies the compiled binary. The builder stage layers are not included in the final image. Verify the final stage does not `COPY --from=builder` the secret files.

2. **Privileged containers for infrastructure components that require it**: DaemonSet containers like `kube-proxy`, `calico-node`, `fluentd` log collectors, or CSI drivers legitimately need host access, `NET_ADMIN`, or privileged mode to function. Check if the container's purpose inherently requires the elevated privileges.

3. **Docker socket mount in CI/CD build containers**: A CI runner that needs to build Docker images mounts the Docker socket. This is a known trade-off in CI environments where the runner itself is ephemeral and isolated. Flag it but note the CI context and suggest alternatives (Docker-in-Docker with TLS, Kaniko, Buildah).

4. **Root user in distroless or scratch-based images**: Some minimal base images (`gcr.io/distroless/static`, `FROM scratch`) run as root but contain no shell, no package manager, and no writable paths. The attack surface is minimal despite the root user. Still recommend setting `USER` but classify lower.

5. **Development-only docker-compose overrides**: A `docker-compose.override.yml` or `docker-compose.dev.yml` that mounts source code, enables debug ports, or uses privileged mode, clearly marked as development-only and not referenced in production deployment scripts.

6. **Port exposure on 0.0.0.0 in containers behind a reverse proxy**: Containers expose ports on all interfaces within the Docker network, but the Docker network is internal and only the reverse proxy container exposes ports to the host. The `0.0.0.0` binding is within the container's network namespace, not the host.

7. **Unpinned tags in example or template files**: Documentation, README examples, or template Dockerfiles using `FROM python:latest` as a simplified example. Check if the actual production Dockerfiles use pinned versions.
