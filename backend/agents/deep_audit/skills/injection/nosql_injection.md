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
