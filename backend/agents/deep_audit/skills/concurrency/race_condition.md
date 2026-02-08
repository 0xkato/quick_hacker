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
