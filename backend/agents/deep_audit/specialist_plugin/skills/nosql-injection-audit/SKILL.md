---
name: nosql-injection-audit
description: Detection methodology for NoSQL injection vulnerabilities
---

# Domain Expertise

# NoSQL Injection Auditor

## Expertise

You are a specialized NoSQL Injection analyst with comprehensive knowledge of document databases, key-value stores, and their query languages. You understand MongoDB query operators at a deep level, Redis protocol exploitation, and the unique injection vectors that arise from schema-less data stores. Your expertise covers the subtle ways JavaScript objects merge and how type coercion creates security vulnerabilities.

## Core Proficiency

- **Operator injection**: MongoDB query operators as attack vectors
- **Query object merging**: Prototype pollution and object spread hazards
- **JavaScript execution**: $where, mapReduce, and server-side JS
- **Type coercion**: Exploiting loose typing in query matching

## Focus Areas

### MongoDB Operator Injection ($where, $regex, $gt)
```javascript
// Vulnerable: User input becomes query object
const query = { username: req.body.username, password: req.body.password };
db.users.findOne(query);

// Attack: {"username": "admin", "password": {"$gt": ""}}
// This returns admin user because any string is greater than empty string
```

### Query Object from User Input
```javascript
// Dangerous direct assignment
app.post('/search', (req, res) => {
    // User controls entire filter object
    const filter = req.body.filter;
    db.collection('products').find(filter).toArray();
});

// Dangerous property spread
const query = { ...req.body, deleted: false };
db.users.find(query);
```

### JavaScript Execution in Queries
```javascript
// $where allows JavaScript execution
db.users.find({
    $where: `this.username == '${username}'`
});

// mapReduce with user input
db.collection.mapReduce(
    userProvidedMapFunction,
    userProvidedReduceFunction,
    { out: "results" }
);
```

### Redis Command Injection
```python
# Vulnerable: Command constructed from user input
def get_cache(key):
    # User controls key, can inject commands
    return redis_client.execute_command(f'GET {key}')

# Attack: "mykey\r\nSET admin_token hacked"
```

### Elasticsearch Query Injection
```javascript
// Vulnerable query string query
const query = {
    query: {
        query_string: {
            query: userInput  // Can inject Lucene syntax
        }
    }
};
```

## Red Flags and Warning Signs

1. **Direct request body to query**: `find(req.body)`, `findOne(req.query)`
2. **Object spread with user input**: `{...userInput}` in queries
3. **$where clauses**: Any use of $where with external data
4. **String concatenation in Redis**: Building commands from user input
5. **Elasticsearch query_string**: User-controlled Lucene queries
6. **Type-unsafe comparisons**: Not validating input types before query
7. **Aggregation pipelines**: User-controlled stages or expressions
8. **Text search**: $text queries with user-controlled options

## Attack Patterns

### Always True Conditions
```javascript
// Instead of string password, send object
{"password": {"$gt": ""}}      // Greater than empty string
{"password": {"$ne": ""}}      // Not equal to empty string
{"password": {"$exists": true}} // Field exists

// Username enumeration
{"username": {"$regex": "^a"}, "password": {"$gt": ""}}
```

### $where with JavaScript
```javascript
// Time-based blind injection
{"$where": "sleep(5000) || this.username == 'admin'"}

// Data extraction
{"$where": "this.password.match(/^a/) ? sleep(5000) : true"}

// Code execution (in older MongoDB)
{"$where": "function() { return this.a == '1' || (function(){...})() }"}
```

### Object Merge Overwriting Operators
```javascript
// Server code
const query = { deleted: false, ...req.body };

// Attack payload
{"deleted": true, "$or": [{"admin": true}]}

// Resulting query executes with attacker-controlled operators
```

### Array Operator Injection
```javascript
// Expected: {"status": "active"}
// Attack: {"status": {"$in": ["active", "suspended", "admin"]}}

// Expected: {"tags": "public"}
// Attack: {"tags": {"$all": []}}  // Matches everything
```

### MongoDB Aggregation Injection
```javascript
// User controls sort parameter
const pipeline = [
    { $match: { active: true } },
    { $sort: req.body.sort }  // Can inject operators
];

// Attack: {"$sort": {"password": 1}}  // Leak via sort behavior
```

## Analysis Methodology

1. **Identify query construction**: Find all database query building code
2. **Trace user input**: Map request parameters to query objects
3. **Check type validation**: Is input validated as expected type?
4. **Review object merging**: Look for spread operators with user data
5. **Audit special operators**: Search for $where, $function, mapReduce
6. **Examine Redis usage**: Command building, key construction
7. **Review Elasticsearch**: Query string queries, script usage
8. **Test aggregation**: User-controlled pipeline stages

## Common Protection Bypasses

### Type Coercion Bypass
```javascript
// Even with toString(), attackers can use arrays
input.toString()  // "[object Object]" or array joins
// Solution: Explicit type checking with typeof and Array.isArray
```

### Sanitization Bypass
```javascript
// Removing $ only from start
input.replace(/^\$/, '')
// Bypass: Use nested objects or encoded characters

// Blacklist of operators
// Bypass: $where is often forgotten, or use $expr
```

### Schema Validation Bypass
```javascript
// Mongoose schema with mixed type
const schema = new Schema({
    metadata: Schema.Types.Mixed  // Accepts any structure
});
// Attack: Inject operators in metadata field
```

## Example Vulnerable Code

### Example 1: Authentication Bypass
```javascript
// auth.js - Vulnerable login
app.post('/login', async (req, res) => {
    const { username, password } = req.body;

    // VULNERABLE: Objects pass through directly
    const user = await User.findOne({
        username: username,
        password: password
    });

    if (user) {
        res.json({ success: true, token: generateToken(user) });
    } else {
        res.status(401).json({ error: 'Invalid credentials' });
    }
});

// Attack: POST with body
// {"username": "admin", "password": {"$gt": ""}}
```

### Example 2: Search with Regex
```javascript
// search.js - Vulnerable search
app.get('/api/users/search', async (req, res) => {
    const { name, role } = req.query;

    // VULNERABLE: User controls regex pattern
    const query = {
        name: { $regex: name, $options: 'i' },
        role: role
    };

    const users = await User.find(query);
    res.json(users);
});

// Attack: ?name=.*&role[$ne]=user
// ReDoS: ?name=(a+)+$&role=user
```

### Example 3: Aggregation Pipeline
```javascript
// reports.js - Vulnerable aggregation
app.post('/api/reports', async (req, res) => {
    const { match, group, sort } = req.body;

    // VULNERABLE: User controls pipeline stages
    const pipeline = [];

    if (match) pipeline.push({ $match: match });
    if (group) pipeline.push({ $group: group });
    if (sort) pipeline.push({ $sort: sort });

    const results = await Order.aggregate(pipeline);
    res.json(results);
});

// Attack: {"match": {"$where": "sleep(5000)"}}
```

## Output Format

```markdown
## NoSQL Injection Finding

**Location**: [file:line]
**Severity**: Critical/High/Medium
**Confidence**: High/Medium/Low

**Database Type**: [MongoDB/Redis/Elasticsearch/CouchDB/etc.]

**Vulnerable Code**:
[code block]

**Injection Point**: [parameter/variable name]
**Query Type**: [find/aggregate/update/command]

**Attack Vector**:
[Specific payload structure]

**Impact**:
- Authentication bypass: [Yes/No]
- Data extraction: [Yes/No - what data]
- DoS via ReDoS: [Yes/No]
- Code execution: [Yes/No - via $where/mapReduce]

**Proof of Concept**:
```json
// Request payload
{...}
```

**Remediation**:
1. Validate input types explicitly
2. Use MongoDB sanitization: `mongo-sanitize` package
3. Disable JavaScript execution if not needed
4. Whitelist allowed query operators
```

---

# Detection Methodology

# NoSQL Injection Detection

## Methodology

### Step 1: Identify NoSQL Data Sources and Drivers

Locate all database interaction points using NoSQL drivers. Focus on MongoDB as the most commonly exploited target, but also check CouchDB, Redis, and DynamoDB query construction.

**Python (PyMongo):**
```python
# Imports to flag
from pymongo import MongoClient
import motor.motor_asyncio  # async pymongo

# Direct collection operations
db.users.find(query)
db.users.find_one(query)
db.users.update_one(filter, update)
db.users.delete_many(filter)
db.users.aggregate(pipeline)
```

**Node.js (Mongoose / native driver):**
```javascript
// Mongoose model operations
User.find(query)
User.findOne(query)
User.findOneAndUpdate(query, update)
User.where(field).equals(value)

// Native driver
collection.find(query).toArray()
collection.findOneAndDelete(query)
collection.aggregate(pipeline)
```

**Java (MongoDB Java Driver):**
```java
// Flag these imports
import com.mongodb.client.MongoCollection;
import com.mongodb.BasicDBObject;

// Query construction
collection.find(Filters.eq("username", input));
collection.find(BasicDBObject.parse(jsonString));
collection.find(Document.parse(userInput));
```

### Step 2: Trace User Input into Query Objects

The critical vulnerability pattern is when a JSON request body is passed directly (or partially) into a query filter without type validation. HTTP body parsers (express.json(), Flask's request.get_json()) deserialize attacker-controlled JSON into full objects, including MongoDB operators.

**Node.js — the most common vector:**
```javascript
// VULNERABLE: req.body.username could be {"$gt": ""}
app.post('/login', (req, res) => {
  User.findOne({ username: req.body.username, password: req.body.password });
});
```

An attacker sends: `{"username": {"$gt": ""}, "password": {"$gt": ""}}` — this matches any document where username and password exist and are non-empty.

**Python:**
```python
# VULNERABLE: JSON body parsed into dict with operators
@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    user = db.users.find_one({"username": data["username"], "password": data["password"]})
```

### Step 3: Detect Operator Injection Patterns

Search for these MongoDB operator families reaching queries from user input:

| Operator Class | Operators | Risk |
|---|---|---|
| Comparison | `$gt`, `$gte`, `$lt`, `$lte`, `$ne`, `$in`, `$nin` | Authentication bypass |
| Logical | `$or`, `$and`, `$not`, `$nor` | Filter manipulation |
| Evaluation | `$where`, `$regex`, `$expr` | JavaScript RCE, ReDoS |
| Update | `$set`, `$unset`, `$push`, `$inc` | Data manipulation |

### Step 4: Check for $where and JavaScript Execution

The `$where` operator executes server-side JavaScript. Any user input reaching `$where` is effectively RCE.

```javascript
// CRITICAL: server-side JS execution
db.users.find({ $where: `this.username == '${userInput}'` });

// Also dangerous: mapReduce with user input
db.users.mapReduce(
  `function() { emit(this.${userField}, 1); }`,
  "function(k, v) { return Array.sum(v); }",
  { out: "results" }
);
```

### Step 5: Evaluate Sanitization and Defenses

Check for presence and correctness of:

1. **Type checking** — ensuring query parameters are strings/numbers, not objects
2. **mongo-sanitize** or **express-mongo-sanitize** middleware
3. **Schema validation** — Mongoose schemas with strict types
4. **Input stripping** — removing keys starting with `$`

```javascript
// SAFE: type-checked before query
const username = String(req.body.username);
const password = String(req.body.password);
User.findOne({ username, password });

// SAFE: using sanitize middleware
const mongoSanitize = require('express-mongo-sanitize');
app.use(mongoSanitize());

// SAFE: explicit string cast in Python
username = str(data.get("username", ""))
```

### Step 6: Check Aggregation Pipeline Injection

Aggregation pipelines constructed from user input can allow stage injection.

```javascript
// VULNERABLE: user controls pipeline stages
app.post('/report', (req, res) => {
  const pipeline = req.body.pipeline;
  collection.aggregate(pipeline);
});

// VULNERABLE: user controls $match filter
const match = { $match: req.body.filter };
collection.aggregate([match, { $group: { _id: "$category", count: { $sum: 1 } } }]);
```

## Decision Tree

```
User input reaches NoSQL query?
|
+-- NO --> SAFE
|
+-- YES
    |
    Input type-checked / coerced to string?
    |
    +-- YES
    |   |
    |   $where or mapReduce with string concat?
    |   +-- YES --> VULNERABLE (Critical)
    |   +-- NO  --> SAFE
    |
    +-- NO
        |
        Sanitization middleware present (mongo-sanitize)?
        |
        +-- YES
        |   |
        |   Applied globally before routes?
        |   +-- YES --> HARDENED (Low)
        |   +-- NO  --> HARDENED (Medium) — partial coverage
        |
        +-- NO
            |
            Input reaches $where / $regex / $expr?
            |
            +-- YES --> VULNERABLE (Critical) — RCE / ReDoS
            |
            +-- NO
                |
                Input reaches find/findOne/update filter?
                +-- YES --> VULNERABLE (High) — auth bypass / data leak
                +-- NO  --> HARDENED (Medium)
```

## Real-World Examples

### Example 1: Authentication Bypass via Operator Injection

```javascript
// Express.js login endpoint
app.post('/api/login', async (req, res) => {
  const { username, password } = req.body;
  const user = await User.findOne({ username, password });
  if (user) {
    const token = jwt.sign({ id: user._id }, SECRET);
    return res.json({ token });
  }
  res.status(401).json({ error: 'Invalid credentials' });
});
```

**Why vulnerable:** `req.body` is parsed as JSON by express.json(). An attacker sends `{"username": "admin", "password": {"$ne": null}}`, which translates to "find user where username is admin AND password is not null" — always true. The attacker gets a valid JWT for the admin account.

**Impact:** Complete authentication bypass. Attacker gains access to any account without knowing the password.

**Fix:**
```javascript
app.post('/api/login', async (req, res) => {
  const username = String(req.body.username || '');
  const password = String(req.body.password || '');
  const user = await User.findOne({ username });
  if (user && await bcrypt.compare(password, user.passwordHash)) {
    const token = jwt.sign({ id: user._id }, SECRET);
    return res.json({ token });
  }
  res.status(401).json({ error: 'Invalid credentials' });
});
```

### Example 2: $where JavaScript Injection in Python

```python
@app.route('/search', methods=['GET'])
def search_users():
    name = request.args.get('name', '')
    results = db.users.find({
        "$where": f"this.name.indexOf('{name}') !== -1"
    })
    return jsonify(list(results))
```

**Why vulnerable:** The `$where` clause executes server-side JavaScript. An attacker injects: `name=') || true || ('` to dump all records, or uses `sleep()` / process access for RCE: `name='); sleep(10000); ('`.

**Impact:** Remote code execution on the MongoDB server. Full database exfiltration. Denial of service via infinite loops.

**Fix:**
```python
@app.route('/search', methods=['GET'])
def search_users():
    name = str(request.args.get('name', ''))
    results = db.users.find({
        "name": {"$regex": re.escape(name), "$options": "i"}
    })
    return jsonify(list(results))
```

### Example 3: Aggregation Pipeline Injection in Java

```java
@PostMapping("/analytics")
public ResponseEntity<?> getAnalytics(@RequestBody Map<String, Object> body) {
    Document matchStage = Document.parse(
        new Gson().toJson(body.get("filter"))
    );
    List<Document> pipeline = Arrays.asList(
        new Document("$match", matchStage),
        new Document("$group", new Document("_id", "$status")
            .append("count", new Document("$sum", 1)))
    );
    return ResponseEntity.ok(collection.aggregate(pipeline));
}
```

**Why vulnerable:** The filter object is parsed directly from user JSON. An attacker can inject operators like `{"$ne": null}` to match all documents, or inject `$lookup` stages to access other collections by manipulating the pipeline structure.

**Impact:** Unauthorized data access across collections. Filter bypass exposing all records.

**Fix:**
```java
@PostMapping("/analytics")
public ResponseEntity<?> getAnalytics(@RequestBody AnalyticsRequest request) {
    Bson matchFilter = Filters.and(
        Filters.eq("status", request.getStatus()),
        Filters.gte("date", request.getStartDate()),
        Filters.lte("date", request.getEndDate())
    );
    List<Bson> pipeline = Arrays.asList(
        Aggregates.match(matchFilter),
        Aggregates.group("$status", Accumulators.sum("count", 1))
    );
    return ResponseEntity.ok(collection.aggregate(pipeline));
}
```

## Common False Positive Patterns

1. **Mongoose schema with strict types** — When a Mongoose schema defines `{ username: { type: String, required: true } }`, Mongoose casts input to String before querying, preventing operator injection even without explicit sanitization.

2. **Parameterized queries via driver builder APIs** — Java's `Filters.eq()`, `Filters.and()` etc. construct typed BSON filters that do not interpret nested operator objects from user input.

3. **Input from authenticated internal services** — Query parameters originating from trusted microservice calls (not user HTTP requests) where the calling service already validated and typed the data.

4. **String concatenation in log messages near DB calls** — String interpolation used for logging the query (e.g., `logger.info(f"Looking up {username}")`) adjacent to a safe parameterized query. The log line is not the query.

5. **ODM virtual fields and computed properties** — Mongoose virtuals or PyMongo aggregation expressions that reference `$`-prefixed field paths (`$username`) are internal MongoDB syntax, not injection.

6. **Test fixtures and seed scripts** — Code in test directories using `$set`, `$push`, etc. for database seeding is intentional operator usage, not an injection sink.

7. **Admin-only endpoints behind authentication + authorization** — Endpoints explicitly restricted to admin roles that intentionally accept flexible query filters (e.g., admin data explorer). These may be BY_DESIGN but should still be flagged for review.
