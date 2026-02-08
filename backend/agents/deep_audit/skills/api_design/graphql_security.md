# GraphQL-Specific Security Issues

GraphQL shifts attack surface from endpoint enumeration to query manipulation. The
client controls query structure, depth, and breadth, enabling DoS, data exfiltration,
and authorization bypass through crafted queries.

## Methodology

### Step 1: Check Introspection Exposure in Production

Introspection reveals the entire schema to any client. In production, this hands
attackers a complete API blueprint.

```javascript
// Apollo — VULNERABLE: default enabled (v3)
new ApolloServer({ typeDefs, resolvers });
// SAFE: new ApolloServer({ typeDefs, resolvers, introspection: false });
```

```python
# Graphene — VULNERABLE: graphiql=True implies introspection
# Ariadne — SAFE: GraphQL(schema, introspection=False)
# Strawberry — requires custom middleware to block __schema queries
```

```java
// graphql-java — SAFE: NoIntrospectionGraphqlInstrumentation
// VULNERABLE: GraphQL.newGraphQL(schema).build() with no filtering
```

### Step 2: Analyze Query Depth and Complexity Limits

Circular type relationships without depth limits allow exponential query expansion.

```graphql
# Depth bomb: each level multiplies DB queries exponentially
query { user(id:1) { friends { friends { friends { friends { name } } } } } }
```

```javascript
// Apollo — SAFE: depth + complexity limits
import depthLimit from "graphql-depth-limit";
import { createComplexityLimitRule } from "graphql-validation-complexity";
new ApolloServer({
  typeDefs, resolvers,
  validationRules: [depthLimit(5), createComplexityLimitRule(1000)],
});
// Graphene: validate(schema, doc, [DepthLimitValidator(max_depth=5)])
// graphql-java: MaxQueryDepthInstrumentation(10), MaxQueryComplexityInstrumentation(200)
```

### Step 3: Detect Batched Query Abuse

Batch-enabled servers allow thousands of operations in one HTTP request, bypassing
per-request rate limiting entirely.

```javascript
// Attack: [{ "query": "mutation { login(...) }" }, ...9999 more] in one HTTP request
// Apollo v4 — SAFE: allowBatchedHttpRequests: false
// Custom: reject Array.isArray(req.body) && req.body.length > N
```

### Step 4: Audit Field-Level Authorization in Resolvers

Resolvers must check permissions per field, not just per query. A user accessing
`user { name }` should not automatically access `user { ssn }`.

```javascript
// VULNERABLE: returns SSN to anyone
User: { ssn: (parent) => parent.ssn }

// SAFE: field-level auth
User: { ssn: (parent, args, ctx) => {
  if (ctx.user?.role !== "admin") throw new ForbiddenError("Forbidden");
  return parent.ssn;
}}
```

```python
# Graphene — SAFE: resolver checks permission
class UserType(graphene.ObjectType):
    ssn = graphene.String()
    def resolve_ssn(self, info):
        if not info.context.user.is_staff:
            return None
        return self.ssn
```

```java
// graphql-java — SAFE: auth in DataFetcher
.dataFetcher("salary", env -> {
    if (!env.getGraphQlContext().get("user").hasRole("FINANCE"))
        throw new AccessDeniedException("Forbidden");
    return env.<User>getSource().getSalary();
})
```

### Step 5: Check for Alias and Fragment Abuse

Aliases duplicate field execution; fragments amplify response size. Both bypass
complexity calculators that only count unique field names.

```graphql
# Alias abuse: 1000 resolver invocations in one query
query {
  a1: expensiveQuery(id: 1) { data }
  a2: expensiveQuery(id: 2) { data }
  # ... 998 more
}

# Fragment amplification
query { user(id:1) { ...F1 ...F2 ...F3 } }
fragment F1 on User { friends { posts { comments { text } } } }
fragment F2 on User { friends { posts { comments { text } } } }
fragment F3 on User { friends { posts { comments { text } } } }
```

Detection: verify complexity scoring accounts for aliases, not just unique fields.

### Step 6: Evaluate Mutation Rate Limiting

Write mutations without rate limits enable mass account creation, brute force login,
and email bombing attacks.

```javascript
// VULNERABLE: no rate limit
Mutation: {
  resetPassword: async (_, { email }) => sendResetEmail(email),
}
// SAFE: directive-based rate limiting
const { createRateLimitDirective } = require("graphql-rate-limit-directive");
```

### Step 7: Inspect Subscription and WebSocket Security

Subscriptions over WebSocket exhaust resources without connection limits and auth.

```javascript
// VULNERABLE: no auth on WebSocket
subscriptions: { onConnect: () => true }

// SAFE: token verification + connection limits
subscriptions: {
  onConnect: async (params) => {
    const user = await verifyToken(params.authToken);
    if (!user) throw new Error("Invalid token");
    return { user };
  },
}
```

### Step 8: Detect N+1 Timing Attacks

N+1 resolver patterns create predictable timing proportional to data cardinality.
Attackers infer record counts by measuring response latency.

```javascript
// VULNERABLE: one query per item — timing leaks count
friends: async (parent) => {
  return Promise.all(parent.friendIds.map(id => User.findById(id)));
}
// SAFE: DataLoader — constant time
friends: (parent, args, { loaders }) => loaders.user.loadMany(parent.friendIds)
```

## Decision Tree

```
GRAPHQL ENDPOINT DETECTED?
|
+--NO--> SAFE
|
+--YES
   |
   INTROSPECTION ENABLED IN PRODUCTION?
   +--YES--> VULNERABLE (High) — full schema exposure
   +--NO
      |
      QUERY DEPTH/COMPLEXITY LIMITS?
      +--NO--> VULNERABLE (High) — DoS via nesting
      +--YES
         |
         FIELD-LEVEL AUTH IN RESOLVERS?
         +--NO--> VULNERABLE (Critical) — unauthorized data access
         +--YES
            |
            BATCH LIMITS ENFORCED?
            +--NO--> VULNERABLE (High) — brute force via batching
            +--YES
               |
               ALIAS/FRAGMENT AMPLIFICATION BOUNDED?
               +--NO--> HARDENED (Medium)
               +--YES
                  |
                  MUTATION RATE LIMITING + SUBSCRIPTION AUTH?
                  +--NO--> HARDENED (Medium)
                  +--YES--> SAFE
```

## Real-World Examples

### Example 1: Introspection Exposes Internal Schema

```javascript
const server = new ApolloServer({
  typeDefs: gql`
    type Query { publicUser(id: ID!): PublicUser }
    type PublicUser { name: String }
    type InternalUser { ssn: String, salary: Float }
    type Mutation { _dangerousAdminReset(confirm: Boolean!): Boolean }
  `,
  resolvers, // introspection defaults to enabled
});
// Attacker: { __schema { types { name fields { name } } } }
// Discovers InternalUser.ssn and _dangerousAdminReset
```

**Why vulnerable:** Introspection reveals all types, including those not reachable
from the public query root. Attacker discovers hidden admin mutations and PII fields.

**Impact:** Complete API surface discovery enabling targeted exploitation.

**Fix:** `introspection: process.env.NODE_ENV !== "production"`

### Example 2: Nested Query Denial of Service

```python
class UserType(DjangoObjectType):
    class Meta:
        model = User
    friends = graphene.List(lambda: UserType)
    def resolve_friends(self, info):
        return self.friends.all()

schema = graphene.Schema(query=Query)  # no depth limit
# Attack: { users { friends { friends { ... 10 levels ... } } } }
# 100 users * 100 friends^10 = 10^20 records
```

**Why vulnerable:** Circular `User -> friends -> User` with no depth limit. Each level
multiplies queries exponentially. One request can generate billions of DB operations.

**Impact:** Complete denial of service from a single HTTP request.

**Fix:** Add `DepthLimitValidator(max_depth=5)` to query validation pipeline.

### Example 3: Batched Mutation Brute Force

```javascript
const resolvers = {
  Mutation: {
    login: async (_, { username, password }) => {
      const user = await User.findOne({ username });
      if (user && await bcrypt.compare(password, user.hash))
        return { token: generateJWT(user) };
      return { error: "Invalid credentials" };
    },
  },
};
app.use("/graphql", rateLimit({ windowMs: 60000, max: 100 }));
// ATTACK: 10,000 login mutations in one batched request
// Rate limiter sees 1 HTTP request — all 10,000 attempts execute
```

**Why vulnerable:** Rate limiter counts HTTP requests, not GraphQL operations. A
batched request multiplexes thousands of login attempts in a single request.

**Impact:** Account compromise via brute force bypassing rate limiting entirely.

**Fix:** `allowBatchedHttpRequests: false` or custom per-operation rate limiting.

## Common False Positive Patterns

1. **Introspection gated by environment.** `NODE_ENV !== "production"` check is safe
   if the environment variable cannot be spoofed externally.

2. **Internal-only GraphQL endpoints.** Introspection enabled behind verified network
   segmentation (not just authentication) is intentional for tooling.

3. **Persisted queries (static allowlist).** Servers accepting only pre-registered
   query hashes mitigate depth bombs, aliases, and batching by design.

4. **Gateway-enforced complexity limits.** An API gateway may enforce limits before
   requests reach the GraphQL server. Check the full request path.

5. **DataLoader batching.** N+1 timing attacks are mitigated when all records load
   in a single batched query with constant timing characteristics.

6. **Federation gateway introspection.** Apollo Federation gateways may expose
   introspection for schema composition. Only flag if exposed to external clients.

7. **Authenticated WebSockets with connection pools.** Subscriptions behind token
   verification with per-user connection limits are properly constrained.
