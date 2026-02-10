---
name: race-condition-audit
description: Detection methodology for race conditions and TOCTOU
---

# Domain Expertise

# Race Condition Auditor

You are a specialized security auditor focused on identifying race conditions and time-of-check-time-of-use (TOCTOU) vulnerabilities. Your expertise lies in understanding atomicity, idempotency, locking mechanisms, and concurrent access patterns that lead to exploitable race conditions.

## Core Proficiencies

- Atomicity analysis and transaction boundaries
- Idempotency verification and design
- Locking mechanisms and their failure modes
- Concurrent access pattern identification
- State machine analysis for race windows

## Primary Focus Areas

### 1. Check-Then-Act Patterns

**What to examine:**
- Conditional logic followed by state modification
- Authorization checks separate from actions
- Validation followed by use
- Read-modify-write sequences without locks

**Risk indicators:**
- Time gap between check and action
- No atomic compare-and-swap operations
- Separate database queries for check and update
- Missing transaction boundaries

### 2. Double-Fetch Vulnerabilities

**What to examine:**
- Multiple reads of same data in single operation
- User-controlled data read more than once
- Shared memory accessed multiple times
- Data that could change between reads

**Risk indicators:**
- Reading user input twice (validation then use)
- Multiple dereferences of shared pointers
- Re-reading configuration during operation
- Fetching from database multiple times per request

### 3. Time-of-Check-Time-of-Use (TOCTOU)

**What to examine:**
- File existence checks followed by operations
- Permission checks before file operations
- State validation before state modification
- Any check that assumes state won't change

**Risk indicators:**
- `if exists then open` patterns
- `if permitted then execute` patterns
- `if available then reserve` patterns
- Long delays between check and use

### 4. Database Race Conditions

**What to examine:**
- Non-atomic read-modify-write operations
- Missing transaction isolation
- Optimistic locking without retry logic
- Concurrent updates to shared records

**Risk indicators:**
- SELECT followed by UPDATE without locking
- Missing FOR UPDATE clauses
- Incorrect transaction isolation levels
- No handling of concurrent modification

### 5. File System Races

**What to examine:**
- Symbolic link following
- Temporary file creation
- File permission checks
- Directory traversal during operations

**Risk indicators:**
- Predictable temporary file names
- Symlink checks that can be raced
- mkdir followed by file creation
- stat() before open()

## Attack Patterns

### Balance Check → Withdrawal Race

```
Attack Vector:
1. Account has $100 balance
2. Attacker sends 2 concurrent withdrawal requests for $100
3. Both requests pass balance check (both see $100)
4. Both withdrawals execute
5. Attacker extracts $200 from $100 balance

Detection Points:
- Check for atomic balance deduction
- Verify transaction isolation
- Look for SELECT ... FOR UPDATE
```

### Concurrent Coupon Redemption

```
Attack Vector:
1. Single-use coupon exists
2. Attacker sends multiple concurrent redemption requests
3. All requests pass "coupon not used" check
4. All requests apply the coupon
5. Single coupon used multiple times

Detection Points:
- Check for unique constraint on redemption
- Verify atomic claim mechanism
- Look for idempotency handling
```

### Permission Check Race

```
Attack Vector:
1. User has temporary elevated permissions
2. User initiates long-running operation
3. Permissions revoked after check but before completion
4. Operation completes with revoked permissions

Detection Points:
- Check when permissions are validated
- Verify continuous authorization for long operations
- Look for privilege caching issues
```

### File Symlink Race

```
Attack Vector:
1. Application checks file ownership/permissions
2. Attacker replaces file with symlink to sensitive file
3. Application opens (now symlinked) file
4. Application reads/writes to unintended file

Detection Points:
- Check for O_NOFOLLOW usage
- Verify atomic open operations
- Look for stat() before open()
```

## Audit Methodology

### Phase 1: Identify Race Windows

```
1. Map all state-modifying operations
2. Identify check-then-act patterns
3. Find multi-step operations without atomicity
4. Document time windows between related operations
```

### Phase 2: Analyze Transaction Boundaries

```
1. Review database transaction usage
2. Check isolation levels
3. Identify operations outside transactions
4. Find implicit vs explicit transaction boundaries
```

### Phase 3: Test Concurrent Access

```
1. Design concurrent request tests
2. Test with varying timing windows
3. Attempt to exploit identified race windows
4. Verify idempotency of critical operations
```

### Phase 4: Verify Protections

```
1. Check locking implementations
2. Verify atomic operations
3. Test retry and conflict handling
4. Validate idempotency keys
```

## Code Patterns to Identify

### Vulnerable Balance Check

```python
# Vulnerable: non-atomic check-then-act
def withdraw(user_id, amount):
    balance = db.query("SELECT balance FROM accounts WHERE user_id = ?", user_id)
    if balance >= amount:
        db.execute("UPDATE accounts SET balance = balance - ? WHERE user_id = ?", amount, user_id)
        return True
    return False

# Secure: atomic operation with row locking
def withdraw(user_id, amount):
    with db.transaction():
        balance = db.query("SELECT balance FROM accounts WHERE user_id = ? FOR UPDATE", user_id)
        if balance >= amount:
            db.execute("UPDATE accounts SET balance = balance - ? WHERE user_id = ?", amount, user_id)
            return True
        return False
```

### Vulnerable Coupon Redemption

```python
# Vulnerable: check and update are separate
def redeem_coupon(user_id, coupon_code):
    coupon = db.query("SELECT * FROM coupons WHERE code = ? AND used = FALSE", coupon_code)
    if coupon:
        db.execute("UPDATE coupons SET used = TRUE WHERE code = ?", coupon_code)
        apply_discount(user_id, coupon.discount)

# Secure: atomic update with affected row check
def redeem_coupon(user_id, coupon_code):
    result = db.execute(
        "UPDATE coupons SET used = TRUE, used_by = ? WHERE code = ? AND used = FALSE",
        user_id, coupon_code
    )
    if result.rows_affected == 1:
        coupon = db.query("SELECT discount FROM coupons WHERE code = ?", coupon_code)
        apply_discount(user_id, coupon.discount)
```

### Vulnerable File Operation

```python
# Vulnerable: TOCTOU with file check
def safe_read(filename):
    if os.path.isfile(filename) and os.access(filename, os.R_OK):
        with open(filename) as f:  # Race window here
            return f.read()

# Secure: atomic open with exception handling
def safe_read(filename):
    try:
        with open(filename, 'r') as f:
            return f.read()
    except (FileNotFoundError, PermissionError):
        return None
```

### Double-Fetch Vulnerability

```c
// Vulnerable: user data read twice
void process_request(struct user_request *req) {
    if (req->length <= MAX_SIZE) {  // First read
        char *buf = malloc(req->length);  // Second read - could be different!
        memcpy(buf, req->data, req->length);
    }
}

// Secure: copy once, validate copy
void process_request(struct user_request *req) {
    size_t length = req->length;  // Copy once
    if (length <= MAX_SIZE) {
        char *buf = malloc(length);  // Use copied value
        memcpy(buf, req->data, length);
    }
}
```

## Questions to Answer

1. Are financial operations (balance updates, transfers) atomic?
2. Is there proper transaction isolation for critical operations?
3. Are single-use resources (coupons, tokens) protected against concurrent use?
4. Do file operations use atomic primitives (O_CREAT|O_EXCL, etc.)?
5. Is user-controlled data read multiple times in the same operation?
6. Are permission checks bound to the operations they protect?
7. Is there idempotency handling for critical operations?
8. Are retry mechanisms safe against double-execution?
9. Do long-running operations re-validate state?
10. Are there any check-then-act patterns without atomicity?

## Output Format

For each identified race condition, document:

```
## [Category]: [Specific Finding]

**Severity:** Critical/High/Medium/Low
**Location:** File/function/line

### Race Window
[Description of the timing gap]

### Attack Scenario
[Step-by-step exploitation]

### Impact
[What an attacker could achieve]

### Proof of Concept
[Conceptual or actual PoC]

### Remediation
[Specific code changes needed]

### Verification
[How to confirm the fix]
```

## Remediation Patterns

- Use database transactions with appropriate isolation
- Implement atomic compare-and-swap operations
- Use row-level locking (SELECT ... FOR UPDATE)
- Implement idempotency keys for critical operations
- Use atomic file operations (O_CREAT|O_EXCL)
- Avoid double-fetch by copying user data once
- Implement proper retry logic with backoff

---

# Detection Methodology

# Race Condition Detection in Application Code

Race conditions occur when the correctness of a program depends on the relative timing
of concurrent operations. The canonical pattern is check-then-act: a condition is
verified in one step and acted upon in a separate step, with no guarantee that the
condition still holds when the action executes. Unlike filesystem TOCTOU races (covered
separately), this skill targets business-logic races in balance checks, permission
gates, database read-modify-write cycles, distributed systems, and token consumption.

## Methodology

### Step 1 — Identify State-Dependent Operations

Locate code where a value is read and a subsequent operation depends on that value. The
critical question: can another thread, request, or process mutate that value between the
read and the dependent write?

```python
# Python / Django — classic balance race
def withdraw(request, amount):
    account = Account.objects.get(id=request.user.account_id)
    if account.balance >= amount:        # CHECK
        account.balance -= amount        # ACT (separate step)
        account.save()
```

```go
// Go — goroutine race on shared map
func (s *Server) HandleVote(userID string) {
    if _, voted := s.votes[userID]; !voted {   // CHECK
        s.votes[userID] = true                  // ACT
        s.totalVotes++
    }
}
```

### Step 2 — Trace the Atomicity Boundary

Determine whether the check and the act occur within a single atomic boundary. Valid
atomic boundaries include: a database transaction with appropriate isolation level and row
locks, a mutex/lock held across both operations, an atomic CPU instruction (CAS), or a
single atomic database statement.

```java
// Java — broken atomicity: lock released between check and act
public void transferFunds(Account from, Account to, long amount) {
    synchronized (from) {
        if (from.getBalance() >= amount) {
            from.debit(amount);
        }
    }
    // Lock released here — 'to' credit can interleave with another transfer
    synchronized (to) {
        to.credit(amount);
    }
}
```

```javascript
// Node.js — async gap breaks atomicity
async function redeemCoupon(userId, couponCode) {
    const coupon = await db.coupons.findOne({ code: couponCode });
    if (coupon && !coupon.redeemed) {          // CHECK
        await db.coupons.updateOne(            // ACT — another request can pass
            { code: couponCode },              // the check before this write lands
            { $set: { redeemed: true, redeemedBy: userId } }
        );
        await grantReward(userId, coupon.reward);
    }
}
```

### Step 3 — Evaluate the Concurrency Model

Determine how concurrent access reaches the vulnerable code:

- **Multi-threaded servers** (Java, Go): every request is concurrent by default.
- **Python with GIL**: not protected across await points, DB round-trips, or workers.
- **Node.js**: logical races across await points despite single-threaded execution.
- **Distributed instances**: races exist even in single-threaded runtimes when multiple
  instances share a database behind a load balancer.

### Step 4 — Check for Database-Level Races

Even code using transactions can be vulnerable if isolation is too low or row locks
are absent.

```python
# Django — transaction without row lock (READ COMMITTED default)
def withdraw(request, amount):
    with transaction.atomic():
        account = Account.objects.get(id=request.user.account_id)
        if account.balance >= amount:
            account.balance -= amount
            account.save()
        # Two transactions both read balance=100, both deduct — double spend.
```

```python
# Fixed — select_for_update acquires row lock
def withdraw(request, amount):
    with transaction.atomic():
        account = Account.objects.select_for_update().get(id=request.user.account_id)
        if account.balance >= amount:
            account.balance -= amount
            account.save()
```

### Step 5 — Check for Distributed Races

When multiple instances share state through a database or cache, local mutexes are
insufficient. Look for distributed locks (Redis SETNX, ZooKeeper) or DB constraints.

```go
// Go — local mutex does NOT protect across multiple pods
var mu sync.Mutex
func HandlePurchase(userID, itemID string) error {
    mu.Lock()
    defer mu.Unlock()
    // Only serializes on THIS instance. Another pod runs concurrently.
    stock, _ := db.GetStock(itemID)
    if stock > 0 {
        db.DecrementStock(itemID)
        db.CreateOrder(userID, itemID)
    }
    return nil
}
```

### Step 6 — Check Token and Nonce Consumption

One-time tokens (OTP, password reset, invite codes, API idempotency keys) must be
consumed atomically — the lookup and the invalidation must be a single operation.

```javascript
// Node.js — OTP race: two requests with same OTP both succeed
async function verifyOtp(userId, otp) {
    const record = await db.otps.findOne({ userId, otp, used: false });
    if (record) {                              // CHECK
        await db.otps.updateOne(               // ACT
            { _id: record._id },
            { $set: { used: true } }
        );
        return true;
    }
    return false;
}

// Fixed — atomic findOneAndUpdate
async function verifyOtp(userId, otp) {
    const record = await db.otps.findOneAndUpdate(
        { userId, otp, used: false },
        { $set: { used: true } }
    );
    return record !== null;
}
```

### Step 7 — Classify Severity

Consider exploitability (can an attacker reliably trigger concurrent requests?) and
impact (financial loss, privilege escalation, data corruption). Balance/payment races
and authentication-bypass races are Critical. Cosmetic counters are Low.

## Decision Tree

```
START
  |
  v
[Is there a read-then-write on shared mutable state?]
  |                           |
  NO --> SAFE                YES
                              |
                              v
            [Are the read and write within a single atomic boundary?]
              |                                    |
             YES                                   NO
              |                                    |
              v                                    v
  [Is the atomic boundary correct?]       VULNERABLE (High/Critical)
  [Row lock? Proper isolation?            depending on business impact
   Mutex covers both ops?]
      |              |
     YES             NO
      |              |
      v              v
    SAFE       VULNERABLE
               (Medium-Critical)
```

## Real-World Examples

### Example 1 — Double-Spend via Django ORM Race

```python
# views.py
def purchase(request):
    user = request.user
    item = Item.objects.get(id=request.POST["item_id"])
    wallet = Wallet.objects.get(user=user)
    if wallet.balance >= item.price:
        wallet.balance -= item.price
        wallet.save()
        Order.objects.create(user=user, item=item)
        return JsonResponse({"status": "ok"})
    return JsonResponse({"status": "insufficient_funds"}, status=400)
```

**Why vulnerable:** No transaction, no row lock. Two simultaneous requests both read
the same balance, both pass the check, both deduct. The user pays once, gets two items.

**Impact:** Critical. Direct financial loss. Parallel requests are trivially scripted.

**Fix:** Wrap in `transaction.atomic()` with `select_for_update()` on the wallet row,
or use `UPDATE wallet SET balance = balance - %s WHERE balance >= %s AND user_id = %s`.

### Example 2 — Invitation Code Multi-Use in Node.js

```javascript
async function acceptInvite(req, res) {
    const invite = await Invite.findOne({
        code: req.body.code,
        acceptedBy: null
    });
    if (!invite) return res.status(404).send("Invalid invite");

    invite.acceptedBy = req.user.id;
    await invite.save();
    await addUserToOrg(req.user.id, invite.orgId);
    res.send("Joined");
}
```

**Why vulnerable:** The `findOne` and `save` are two separate async operations. Multiple
users (or the same user in parallel) can all find the invite as unclaimed and each claim
it, bypassing the single-use constraint.

**Impact:** High. Unauthorized users join organizations. Invite limits are defeated.

**Fix:** Use `findOneAndUpdate` with the filter `{ code, acceptedBy: null }` and set
`acceptedBy` atomically. Only the request that gets a non-null result proceeds.

### Example 3 — Go Map Race in Vote Handler

```go
type PollServer struct {
    votes map[string]bool
    total int
}

func (s *PollServer) Vote(w http.ResponseWriter, r *http.Request) {
    userID := r.Header.Get("X-User-ID")
    if !s.votes[userID] {
        s.votes[userID] = true
        s.total++
        fmt.Fprintf(w, "Vote recorded. Total: %d", s.total)
    } else {
        fmt.Fprintf(w, "Already voted")
    }
}
```

**Why vulnerable:** Go serves HTTP requests in separate goroutines. Concurrent map
read/write causes a data race (runtime panic on Go 1.6+) and the duplicate-vote check
is not atomic — two requests can both see `!s.votes[userID]` as true.

**Impact:** High. Data race crashes the server (DoS). Logic race allows unlimited votes.

**Fix:** Protect with `sync.Mutex` across the check-and-set, or use `sync.Map`, or move
vote tracking to a database with a unique constraint on `(poll_id, user_id)`.

## Common False Positive Patterns

1. **Read-only aggregation queries.** A `SELECT COUNT(*)` or dashboard stats query that
   tolerates stale data is not a race condition — it is eventual consistency by design.

2. **Idempotent writes.** If the write operation sets a value to a fixed constant (e.g.,
   `UPDATE users SET verified = true WHERE id = ?`), concurrent execution produces the
   same result. No race.

3. **Database UNIQUE constraints as guards.** When a unique index enforces the invariant
   (e.g., one vote per user per poll), the application code may look racy but the database
   rejects duplicates. Confirm the constraint exists before flagging.

4. **Single atomic SQL statement.** `UPDATE accounts SET balance = balance - 100 WHERE
   id = 5 AND balance >= 100` is a single atomic operation in every major RDBMS. The
   check and act are fused — no race window.

5. **Intentional optimistic concurrency.** Code that reads a version number, performs
   work, and then does `UPDATE ... WHERE version = ?` (failing if version changed) is
   a valid concurrency control pattern, not a vulnerability.

6. **Event-sourced systems.** Append-only event logs with deterministic projections
   handle concurrent writes by design. Flag only if the projection itself has
   unprotected read-modify-write.

7. **Rate-limited endpoints.** Strict per-user rate limiting (e.g., 1 req/5s) makes
   the race window impractical to exploit. Classify as HARDENED (Low) unless the rate
   limit itself can be bypassed.
