# Kubernetes Security Detection

## Methodology

### Step 1: Identify Kubernetes Configuration Files

Locate all Kubernetes manifests, Helm charts, and cluster configuration:

**Manifest files:**
- `*.yaml`, `*.yml` in `k8s/`, `kubernetes/`, `deploy/`, `manifests/`, `charts/`
- Files containing `apiVersion:` and `kind:` fields
- Common kinds: `Deployment`, `Pod`, `StatefulSet`, `DaemonSet`, `Job`, `CronJob`
- RBAC: `Role`, `ClusterRole`, `RoleBinding`, `ClusterRoleBinding`
- Network: `NetworkPolicy`, `Ingress`, `Service`
- Config: `ConfigMap`, `Secret`, `ServiceAccount`

**Helm charts:**
- `Chart.yaml`, `values.yaml`, `values.*.yaml`
- Templates in `templates/` directory
- Check both default `values.yaml` and environment-specific overrides

**Other configuration:**
- `kustomization.yaml` — Kustomize overlays
- `skaffold.yaml` — development deployment config
- `kubectl` commands in scripts or CI pipelines
- Terraform HCL defining Kubernetes resources (`kubernetes_deployment`, `kubernetes_pod`)

### Step 2: Check RBAC Configuration

RBAC misconfigurations are the most impactful Kubernetes security issues because they grant excessive permissions across the cluster.

**Wildcard permissions:**
```yaml
# VULNERABLE — grants all permissions on all resources
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: app-role
rules:
  - apiGroups: ["*"]
    resources: ["*"]
    verbs: ["*"]
```

**Dangerous verb combinations:**
```yaml
rules:
  # VULNERABLE — can create pods (container escape path)
  - apiGroups: [""]
    resources: ["pods"]
    verbs: ["create", "get", "list"]

  # VULNERABLE — can exec into any pod (direct shell access)
  - apiGroups: [""]
    resources: ["pods/exec"]
    verbs: ["create"]

  # VULNERABLE — can read all secrets in the cluster
  - apiGroups: [""]
    resources: ["secrets"]
    verbs: ["get", "list", "watch"]

  # VULNERABLE — can escalate privileges by modifying roles
  - apiGroups: ["rbac.authorization.k8s.io"]
    resources: ["clusterroles", "clusterrolebindings"]
    verbs: ["create", "update", "patch"]

  # VULNERABLE — can impersonate other users/service accounts
  - apiGroups: [""]
    resources: ["users", "groups", "serviceaccounts"]
    verbs: ["impersonate"]
```

**Binding cluster-admin to default service accounts:**
```yaml
# VULNERABLE — every pod in the namespace gets cluster-admin
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: default-admin
subjects:
  - kind: ServiceAccount
    name: default
    namespace: production
roleRef:
  kind: ClusterRole
  name: cluster-admin
  apiGroup: rbac.authorization.k8s.io
```

**Check for:**
- `ClusterRole` vs `Role` — prefer namespace-scoped `Role` unless cluster-wide access is needed
- Bindings to `default` service account (every pod uses this unless overridden)
- `system:masters` group bindings (bypasses all RBAC, cannot be restricted by admission controllers)
- Wildcard (`*`) in `apiGroups`, `resources`, or `verbs`

### Step 3: Check Pod Security Configuration

```yaml
# VULNERABLE — multiple security violations in one pod spec
apiVersion: v1
kind: Pod
metadata:
  name: insecure-pod
spec:
  hostNetwork: true                    # VULNERABLE — access host network stack
  hostPID: true                        # VULNERABLE — see all host processes
  hostIPC: true                        # VULNERABLE — shared memory with host
  containers:
    - name: app
      image: myapp:latest
      securityContext:
        privileged: true               # VULNERABLE — full host access
        runAsUser: 0                   # VULNERABLE — root user
        allowPrivilegeEscalation: true # VULNERABLE — can gain capabilities
        readOnlyRootFilesystem: false  # RISKY — writable filesystem
        capabilities:
          add:
            - SYS_ADMIN               # VULNERABLE — near-root
            - NET_RAW                  # RISKY — packet manipulation
      volumeMounts:
        - name: host-root
          mountPath: /host
  volumes:
    - name: host-root
      hostPath:
        path: /                        # VULNERABLE — entire host filesystem
```

**Secure pod spec:**
```yaml
spec:
  securityContext:
    runAsNonRoot: true
    runAsUser: 65534
    fsGroup: 65534
    seccompProfile:
      type: RuntimeDefault
  automountServiceAccountToken: false   # Disable unless needed
  containers:
    - name: app
      image: myapp:1.2.3@sha256:abc123...
      securityContext:
        allowPrivilegeEscalation: false
        readOnlyRootFilesystem: true
        capabilities:
          drop:
            - ALL
      resources:
        limits:
          cpu: "500m"
          memory: "256Mi"
```

### Step 4: Check Secrets Management

Kubernetes Secrets are base64-encoded, not encrypted, by default:

```yaml
# VULNERABLE — secret in plaintext manifest (base64 is NOT encryption)
apiVersion: v1
kind: Secret
metadata:
  name: db-credentials
type: Opaque
data:
  username: YWRtaW4=              # base64("admin")
  password: UHIwZF9QQHNzdzByZCE=  # base64("Pr0d_P@ssw0rd!")
```

```yaml
# VULNERABLE — secret in ConfigMap (not even base64)
apiVersion: v1
kind: ConfigMap
metadata:
  name: app-config
data:
  DATABASE_URL: "postgres://admin:Pr0d_P@ssw0rd!@db:5432/app"
  API_KEY: "sk_live_4eC39HqLyjWDarjtT1zdp7dc"
```

**Check for:**
- Secret values committed to version control (even base64-encoded)
- Secrets stored in ConfigMaps instead of Secret objects
- Missing encryption at rest (`EncryptionConfiguration` for etcd)
- Secrets mounted as environment variables (visible in `/proc/*/environ`) vs files
- Missing external secrets operators (Vault, AWS Secrets Manager, Sealed Secrets)

### Step 5: Check Network Policies and Service Exposure

```yaml
# Default Kubernetes behavior — ALL pods can talk to ALL pods (VULNERABLE)
# No NetworkPolicy objects = fully open network

# VULNERABLE — explicit allow-all policy
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: allow-all
spec:
  podSelector: {}
  ingress:
    - {}
  egress:
    - {}
  policyTypes:
    - Ingress
    - Egress
```

**Exposed dashboards and APIs:**
```yaml
# VULNERABLE — Kubernetes Dashboard exposed without authentication
apiVersion: v1
kind: Service
metadata:
  name: kubernetes-dashboard
spec:
  type: NodePort                    # VULNERABLE — accessible on node IP
  ports:
    - port: 443
      nodePort: 30443
```

```yaml
# VULNERABLE — Service of type LoadBalancer for internal services
apiVersion: v1
kind: Service
metadata:
  name: internal-api
spec:
  type: LoadBalancer                # Creates public IP for internal service
  ports:
    - port: 8080
```

**Check for:**
- Absence of `NetworkPolicy` objects (default-open cluster networking)
- `NodePort` or `LoadBalancer` service types for admin interfaces
- Dashboard, Prometheus, Grafana, Jaeger exposed without auth
- Missing egress policies (pods can reach the internet and cloud metadata)

### Step 6: Check Service Account Token Auto-Mounting

```yaml
# VULNERABLE — default: service account token auto-mounted in every pod
apiVersion: v1
kind: Pod
metadata:
  name: app
spec:
  containers:
    - name: app
      image: myapp:latest
  # automountServiceAccountToken defaults to true
  # Token at /var/run/secrets/kubernetes.io/serviceaccount/token
  # Allows API server access with the service account's RBAC permissions
```

If the pod does not need to call the Kubernetes API, the token should not be mounted:
```yaml
spec:
  automountServiceAccountToken: false
```

Or at the ServiceAccount level:
```yaml
apiVersion: v1
kind: ServiceAccount
metadata:
  name: app-sa
automountServiceAccountToken: false
```

### Step 7: Classify

- **VULNERABLE (Critical)**: `cluster-admin` bound to default SA, OR wildcard RBAC verbs/resources on ClusterRole, OR privileged pods with hostPath `/`, OR plaintext secrets in manifests committed to VCS
- **VULNERABLE (High)**: `hostNetwork`/`hostPID` enabled, OR pods can exec/create other pods, OR Dashboard exposed without auth, OR secrets in ConfigMaps, OR no NetworkPolicies in production
- **HARDENED (Medium)**: Service account tokens auto-mounted unnecessarily, OR broad but not wildcard RBAC, OR missing seccomp profile, OR LoadBalancer on internal services
- **HARDENED (Low)**: Missing `readOnlyRootFilesystem`, OR `allowPrivilegeEscalation` not explicitly false, OR missing resource limits
- **SAFE**: Least-privilege RBAC, pod security standards enforced, network policies in place, external secrets management, service account tokens disabled where unused
- **BY_DESIGN**: DaemonSets for CNI plugins or log collectors that require `hostNetwork` or privileged access

## Decision Tree

```
Are Kubernetes manifests present?
├── No → SAFE (not applicable)
└── Yes → Check RBAC first:
    ├── Wildcard verbs/resources on ClusterRole? → VULNERABLE (Critical)
    ├── cluster-admin bound to default SA? → VULNERABLE (Critical)
    ├── Can create pods or exec into pods? → VULNERABLE (High)
    └── RBAC is scoped → Check pod security:
        ├── privileged: true? → VULNERABLE (Critical)
        ├── hostNetwork/hostPID/hostIPC? → VULNERABLE (High)
        ├── hostPath to sensitive dirs? → VULNERABLE (High)
        ├── Running as root without need? → HARDENED (Medium)
        └── Pod is locked down → Check secrets:
            ├── Plaintext secrets in committed manifests? → VULNERABLE (Critical)
            ├── Secrets in ConfigMaps? → VULNERABLE (High)
            ├── No external secrets management? → HARDENED (Medium)
            └── Secrets managed externally → Check network:
                ├── No NetworkPolicies at all? → VULNERABLE (High)
                ├── Allow-all policies? → VULNERABLE (High)
                ├── Dashboard/admin exposed without auth? → VULNERABLE (High)
                ├── Missing egress policies? → HARDENED (Medium)
                └── Network locked down → Check remaining:
                    ├── SA token auto-mounted unnecessarily? → HARDENED (Medium)
                    ├── Missing seccomp/readOnlyRootFS? → HARDENED (Low)
                    └── All hardened → SAFE
```

## Real-World Examples

### Example 1: Wildcard ClusterRole Bound to Default Service Account

**Vulnerable configuration:**
```yaml
# clusterrole.yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: app-manager
rules:
  - apiGroups: [""]
    resources: ["*"]
    verbs: ["*"]
  - apiGroups: ["apps", "extensions"]
    resources: ["*"]
    verbs: ["*"]
---
# clusterrolebinding.yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: app-manager-binding
subjects:
  - kind: ServiceAccount
    name: default
    namespace: default
roleRef:
  kind: ClusterRole
  name: app-manager
  apiGroup: rbac.authorization.k8s.io
```

**Why vulnerable:** This grants every pod in the `default` namespace full control over all core and apps API resources across the entire cluster. Since the `default` service account is automatically used by any pod that does not specify a different one, and service account tokens are auto-mounted by default, any compromised pod — even from a minor vulnerability like SSRF — can use the mounted token to: read all Secrets in every namespace (extracting database passwords, API keys, TLS certificates), create privileged pods on any node (achieving container escape and host compromise), delete deployments (causing cluster-wide outage), or modify RBAC to create backdoor access.

**Impact:** Full cluster compromise from any single pod compromise. Lateral movement to all namespaces and hosts.

**Fix:**
```yaml
# Use namespace-scoped Role with minimal permissions
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: app-role
  namespace: production
rules:
  - apiGroups: [""]
    resources: ["configmaps"]
    verbs: ["get", "list"]
    resourceNames: ["app-config"]  # Restrict to specific resources
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: app-role-binding
  namespace: production
subjects:
  - kind: ServiceAccount
    name: app-sa              # Dedicated SA, not default
    namespace: production
roleRef:
  kind: Role
  name: app-role
  apiGroup: rbac.authorization.k8s.io
---
# Disable token for pods that don't need API access
apiVersion: v1
kind: ServiceAccount
metadata:
  name: app-sa
  namespace: production
automountServiceAccountToken: false
```

### Example 2: Kubernetes Dashboard Exposed Without Authentication

**Vulnerable configuration:**
```yaml
# dashboard-deployment.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: kubernetes-dashboard
  namespace: kubernetes-dashboard
spec:
  template:
    spec:
      containers:
        - name: dashboard
          image: kubernetesui/dashboard:v2.7.0
          args:
            - --enable-skip-login           # VULNERABLE — allows unauthenticated access
            - --disable-settings-authorizer # VULNERABLE — disables auth checks
            - --enable-insecure-login       # VULNERABLE — allows HTTP login
          ports:
            - containerPort: 9090
              protocol: TCP
---
apiVersion: v1
kind: Service
metadata:
  name: kubernetes-dashboard
  namespace: kubernetes-dashboard
spec:
  type: NodePort                            # VULNERABLE — exposed on node IP
  ports:
    - port: 9090
      targetPort: 9090
      nodePort: 30090                       # Accessible at <node-ip>:30090
---
# Dashboard bound to cluster-admin
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: dashboard-admin
subjects:
  - kind: ServiceAccount
    name: kubernetes-dashboard
    namespace: kubernetes-dashboard
roleRef:
  kind: ClusterRole
  name: cluster-admin
  apiGroup: rbac.authorization.k8s.io
```

**Why vulnerable:** The `--enable-skip-login` flag allows anyone to access the dashboard without authentication by clicking a "Skip" button. The dashboard's service account is bound to `cluster-admin`, so the unauthenticated user gets full cluster admin capabilities through the dashboard UI. The `NodePort` service type makes it accessible on every cluster node's IP at port 30090. An attacker who can reach any node IP can open the dashboard, skip login, and use the UI to read secrets, exec into pods, create deployments, and fully compromise the cluster.

**Impact:** Unauthenticated full cluster admin access. This exact misconfiguration was responsible for Tesla's Kubernetes cluster being compromised for cryptomining in 2018.

**Fix:**
```yaml
# Remove --enable-skip-login and --disable-settings-authorizer
# Use ClusterIP service (not NodePort) and access via kubectl proxy
apiVersion: v1
kind: Service
metadata:
  name: kubernetes-dashboard
  namespace: kubernetes-dashboard
spec:
  type: ClusterIP
  ports:
    - port: 443
      targetPort: 8443
---
# Minimal RBAC — read-only access to specific namespace
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: dashboard-viewer
  namespace: production
rules:
  - apiGroups: [""]
    resources: ["pods", "services", "configmaps"]
    verbs: ["get", "list", "watch"]
  - apiGroups: ["apps"]
    resources: ["deployments", "replicasets"]
    verbs: ["get", "list", "watch"]
```

### Example 3: Secrets in Manifests Committed to Git

**Vulnerable configuration:**
```yaml
# k8s/secrets.yaml (committed to repository)
apiVersion: v1
kind: Secret
metadata:
  name: production-secrets
  namespace: production
type: Opaque
data:
  db-password: c3VwM3JfczNjcjN0X3Bhc3N3MHJk    # base64("sup3r_s3cr3t_passw0rd")
  jwt-signing-key: bXktand0LXNlY3JldC1rZXktMjAyNA==  # base64("my-jwt-secret-key-2024")
  stripe-key: c2tfbGl2ZV80ZUMzOUhxTHlqV0RhcmpUMXpkcDdkYw==
stringData:
  aws-access-key-id: AKIAIOSFODNN7EXAMPLE
  aws-secret-access-key: wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
```

**Why vulnerable:** Base64 is an encoding, not encryption. Anyone with repository access (developers, CI systems, compromised SCM accounts) can decode these values instantly: `echo "c3VwM3JfczNjcjN0X3Bhc3N3MHJk" | base64 -d`. The `stringData` field does not even base64-encode the values. Once committed, secrets persist in git history even if the file is later deleted. Additionally, without encryption at rest configured for etcd, these secrets are stored in plaintext in the cluster's backing datastore.

**Impact:** Credential exposure to anyone with repository access. Leaked AWS keys enable full cloud account compromise. Leaked JWT signing keys enable token forgery for any user.

**Fix:**
```yaml
# Option 1: Use Sealed Secrets (encrypted in git, decrypted in cluster)
apiVersion: bitnami.com/v1alpha1
kind: SealedSecret
metadata:
  name: production-secrets
  namespace: production
spec:
  encryptedData:
    db-password: AgBY8...encrypted...blob==
    jwt-signing-key: AgCF7...encrypted...blob==

# Option 2: Use External Secrets Operator (fetches from Vault/AWS/GCP)
apiVersion: external-secrets.io/v1beta1
kind: ExternalSecret
metadata:
  name: production-secrets
  namespace: production
spec:
  refreshInterval: 1h
  secretStoreRef:
    name: vault-backend
    kind: ClusterSecretStore
  target:
    name: production-secrets
  data:
    - secretKey: db-password
      remoteRef:
        key: production/database
        property: password

# Also enable encryption at rest for etcd:
# apiVersion: apiserver.config.k8s.io/v1
# kind: EncryptionConfiguration
# resources:
#   - resources: ["secrets"]
#     providers:
#       - aescbc:
#           keys:
#             - name: key1
#               secret: <base64-encoded-encryption-key>
```

## Common False Positive Patterns

1. **Privileged DaemonSets for CNI plugins and node agents**: Components like `calico-node`, `cilium-agent`, `aws-vpc-cni`, `kube-proxy`, and `fluentd` legitimately require `hostNetwork`, `privileged`, or specific capabilities to manage node networking, iptables rules, or log collection. Verify the container is an official infrastructure component, not an application workload.

2. **cluster-admin for cluster operators and CI/CD controllers**: Tools like ArgoCD, Flux, Crossplane, or Terraform controllers need broad permissions to manage cluster resources. The key check is whether the binding is to a dedicated service account used only by the operator, not to `default` or application service accounts.

3. **Base64-encoded secrets in example or template files**: Documentation, README examples, or Helm chart templates using placeholder values like `{{ .Values.dbPassword | b64enc }}`. These are templates, not actual secrets. Check that `values.yaml` does not contain real credentials.

4. **NodePort services in development or testing clusters**: `NodePort` is acceptable in local development clusters (minikube, kind, k3d) where there is no external network exposure. Check the context — is this a production manifest or a local development overlay?

5. **Auto-mounted service account tokens for pods that use the Kubernetes API**: Pods running controllers, operators, or sidecar proxies (Istio envoy, Vault agent) that legitimately call the Kubernetes API need the mounted token. The finding is only valid when the pod does not need API access.

6. **NetworkPolicy absence in clusters using service mesh for mTLS**: Clusters running Istio, Linkerd, or Consul Connect with strict mTLS may rely on the service mesh for pod-to-pod authentication instead of NetworkPolicies. While defense in depth recommends both, the mesh provides equivalent access control at L7. Note the mesh presence in the finding.

7. **Secrets in Helm values files that are generated and never committed**: Helm `values.yaml` files that reference `${VARIABLE}` placeholders expanded at deploy time by CI/CD, where the actual values come from a secrets manager. Check git history to confirm the file has never contained real secrets.
