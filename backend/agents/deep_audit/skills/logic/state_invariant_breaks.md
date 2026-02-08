# State Invariant Break Detection

## Methodology

This skill targets vulnerabilities where a system's state invariants — properties that must always hold true for correctness — can be violated through specific sequences of operations, concurrency, partial failures, or edge cases. These are logic bugs that live in the gaps between operations. Traditional scanners cannot find them because there is no single vulnerable line; the vulnerability is a *sequence* that produces an impossible state.

### Step 1: Identify State Invariants from the Security Map

The Security Map's `invariants.json` lists system invariants. For each invariant, understand:

1. **What state does it govern?** (balance, order status, session count, resource ownership)
2. **What is the exact predicate?** Express it formally if possible.
   - `balance >= 0` for all users at all times
   - `order.status ∈ {PENDING, CONFIRMED, SHIPPED, DELIVERED, CANCELLED}` with defined transitions
   - `count(active_sessions(user)) <= 1`
   - `∀ resource: resource.deleted == true → no endpoint returns resource`
3. **What is the consequence of violation?** (financial loss, auth bypass, data corruption, audit gap)
4. **Where is the invariant enforced?** (application code, database constraint, both, neither)

Prioritize invariants that govern:
- Financial state (balances, credits, transactions)
- Authentication/authorization state (sessions, roles, permissions)
- Resource lifecycle state (creation, modification, deletion, archival)
- Audit completeness (every action logged, no gaps)

### Step 2: For Each Invariant, Find All State Mutation Points

Map every function, endpoint, background job, migration, and admin tool that can modify the state governed by the invariant.

**Exhaustive enumeration matters.** The vulnerability is almost always in the mutation point the developer forgot about.

```python
# Invariant: "User balance can never go negative"
# Obvious mutation points:
#   - POST /api/payments          (purchase — decreases balance)
#   - POST /api/withdrawals       (withdrawal — decreases balance)
#   - POST /api/deposits          (deposit — increases balance)
#
# Non-obvious mutation points the developer may have missed:
#   - POST /api/refunds           (refund reversal — can it go negative if original refund was wrong?)
#   - Celery task: expire_credits  (scheduled job that removes expired credits)
#   - Admin panel: adjust_balance  (manual adjustment — any validation?)
#   - Database migration #47       (one-time script that recalculates balances)
#   - POST /api/subscriptions     (recurring charge — checked at creation but not at renewal?)
```

For each mutation point, answer:
- Does it check the invariant BEFORE mutating state?
- Does it check the invariant AFTER mutating state?
- Does it use a transaction that prevents partial updates?
- Can it be called concurrently with other mutation points?

### Step 3: Test Invariant Under Concurrent Operations

Race conditions are the most common way to break state invariants. The pattern is always **check-then-act without atomicity**.

**Pattern: Check-Then-Decrement Race**
```python
# VULNERABLE: Two concurrent requests can both pass the balance check
@app.post("/api/purchase")
def purchase(item_id: int, current_user: User):
    user = db.query(User).filter(User.id == current_user.id).first()
    item = db.query(Item).filter(Item.id == item_id).first()

    if user.balance >= item.price:        # Thread A: balance=100, price=80 → passes
                                           # Thread B: balance=100, price=80 → passes (stale read)
        user.balance -= item.price         # Thread A: balance = 20
                                           # Thread B: balance = 20 (reads stale 100, subtracts 80)
        db.commit()                        # Thread A commits: balance = 20
                                           # Thread B commits: balance = 20 (should be -60!)
    # Actually worse: with ORM session caching, Thread B may write balance = 20
    # when the real balance after Thread A is already 20, so final = 20 - 80 = -60
```

Questions to ask for each mutation point:
- Is the check-and-mutate atomic? (single UPDATE with WHERE clause, or SELECT FOR UPDATE)
- What isolation level does the database use? (READ COMMITTED allows phantom reads)
- Does the ORM cache stale values within a session?
- Is there a distributed lock if the invariant spans multiple services?

**Safe atomic alternative:**
```sql
-- Atomic: check and decrement in a single statement
UPDATE users SET balance = balance - :price
WHERE id = :user_id AND balance >= :price;
-- If 0 rows affected, the invariant would have been violated → reject
```

### Step 4: Test Invariant Under Error and Rollback Conditions

Multi-step operations are invariant-violation factories when they fail partway through.

**Pattern: Partial Completion Without Rollback**
```python
# Invariant: "Sum of all user balances equals sum of all deposits minus sum of all withdrawals"
# (conservation of money in the system)

@app.post("/api/transfer")
def transfer(from_id: int, to_id: int, amount: int):
    sender = db.query(User).filter(User.id == from_id).first()
    receiver = db.query(User).filter(User.id == to_id).first()

    sender.balance -= amount       # Step 1: debit sender
    db.flush()                     # Writes to DB but does not commit

    # External API call to log the transfer for compliance
    compliance_api.log_transfer(from_id, to_id, amount)  # Step 2: external call

    receiver.balance += amount     # Step 3: credit receiver
    db.commit()

    # BUG: If compliance_api.log_transfer() raises an exception:
    # - db.flush() already wrote the debit to the transaction
    # - The exception triggers a rollback of the DB transaction → debit is reversed ✓
    # BUT: What if the framework catches the exception and commits anyway?
    # What if there's a bare except that swallows the error?
    # What if compliance_api succeeds but receiver.balance += amount fails (e.g., integrity error)?
```

Check for:
- **Missing transaction boundaries**: Are multi-step operations wrapped in explicit transactions?
- **Exception handling that breaks rollback**: `except Exception: pass` or `except: log_and_continue()`
- **External side effects inside transactions**: API calls, email sends, file writes that cannot be rolled back
- **Savepoint misuse**: Nested transactions that commit when the outer should roll back
- **Finally blocks**: Do cleanup operations assume the happy path?

### Step 5: Test Invariant Under Edge Cases

**State Machine Invariants — Invalid Transitions**

```python
# Invariant: Order state machine has defined transitions
# PENDING → CONFIRMED → SHIPPED → DELIVERED
# PENDING → CANCELLED
# CONFIRMED → CANCELLED

class OrderService:
    def update_status(self, order_id: int, new_status: str):
        order = db.query(Order).filter(Order.id == order_id).first()
        order.status = new_status    # BUG: No transition validation!
        db.commit()

    # An attacker can: CANCELLED → SHIPPED, DELIVERED → PENDING, etc.
    # Impact: cancelled order gets shipped, delivered order gets re-processed
```

Always check:
- Is there a whitelist of valid transitions, or does the code just set the new state?
- Can an admin endpoint bypass transition validation?
- Can a race condition between two status updates produce an invalid state? (PENDING→CONFIRMED and PENDING→CANCELLED arrive simultaneously)

**Numeric Edge Cases**

```python
# Invariant: "Balance can never go negative"
# Edge: What about integer overflow?

# If balance is stored as a signed 32-bit integer:
# User has balance = 2,147,483,600
# User deposits 100 → balance = 2,147,483,700 → OVERFLOW → balance = -2,147,483,596
# Invariant broken via overflow, not via a deduction

# If balance is stored as unsigned and the check is:
if user.balance - price >= 0:    # unsigned subtraction wraps: 10 - 80 = 18446744073709551546 (u64)
    proceed()                     # Always passes for unsigned types!
```

**Soft-Delete Inconsistencies**

```python
# Invariant: "Deleted resources are not accessible via any endpoint"

class UserService:
    def delete_user(self, user_id: int):
        user = db.query(User).filter(User.id == user_id).first()
        user.is_deleted = True     # Soft delete
        db.commit()

    def get_user(self, user_id: int):
        # BUG: Forgot to filter deleted users
        return db.query(User).filter(User.id == user_id).first()

    def list_users(self):
        # Correct: filters deleted users
        return db.query(User).filter(User.is_deleted == False).all()

    # Partial enforcement: list_users is safe, get_user is not
```

**Cache-Database Inconsistency**

```python
# Invariant: "A user can only have one active session"

def login(user_id: int):
    # Invalidate existing sessions in DB
    db.query(Session).filter(Session.user_id == user_id, Session.active == True).update(
        {"active": False}
    )
    # Create new session
    new_session = Session(user_id=user_id, active=True, token=generate_token())
    db.add(new_session)
    db.commit()

    # Cache the session for fast auth checks
    redis.set(f"session:{new_session.token}", user_id, ex=3600)

    # BUG: Old session tokens are still in Redis cache!
    # DB says old sessions are inactive, but cache still validates them
    # The invariant holds in the DB but not in the system as a whole
```

### Step 6: Classify

- **VULNERABLE (Critical)**: Financial or auth invariant breakable via normal API calls without concurrency tricks (missing validation, no state machine enforcement)
- **VULNERABLE (High)**: Invariant breakable via race condition with practical timing window (check-then-act on balance, concurrent status updates)
- **VULNERABLE (High)**: State machine allows invalid transitions leading to auth bypass or data corruption (CANCELLED to SHIPPED, LOCKED to ACTIVE without re-authentication)
- **HARDENED (Medium)**: Invariant enforced in application code but not in database constraints — single point of failure if any code path skips the check
- **HARDENED (Medium)**: Cache and database can disagree on invariant state (stale session in cache, stale permission in cache)
- **HARDENED (Low)**: Invariant breakable only under extreme edge cases (integer overflow at u64 max, clock skew beyond NTP tolerance)
- **SAFE**: Invariant enforced at both application and database level with proper transactions, atomic operations, and cache invalidation

## Decision Tree

```
For each invariant in the Security Map:
│
├── Are ALL mutation points identified?
│   ├── No → Find missing mutation points (admin tools, cron jobs, migrations, other services)
│   │        Any unvalidated mutation point → VULNERABLE
│   └── Yes ↓
│
├── Does each mutation point validate the invariant before mutating?
│   ├── No → Is the unvalidated path reachable by users?
│   │   ├── Yes → VULNERABLE (Critical — invariant not enforced)
│   │   └── No (admin-only, dead code) → HARDENED (Medium — document risk)
│   └── Yes ↓
│
├── Is the check-and-mutate atomic?
│   ├── No → Is there a practical race window?
│   │   ├── Yes (network request between check and mutate) → VULNERABLE (High)
│   │   ├── Maybe (in-process but no lock) → HARDENED (Medium — needs load testing)
│   │   └── No (single-threaded, event loop) → HARDENED (Low)
│   └── Yes ↓
│
├── Can partial failure violate the invariant?
│   ├── Yes (multi-step without transaction) → VULNERABLE (High)
│   ├── Maybe (transaction exists but exception handling is suspect) → HARDENED (Medium)
│   └── No (single atomic operation or proper transaction) ↓
│
├── Is the invariant enforced at the database level?
│   ├── No → HARDENED (Medium — app-only enforcement is fragile)
│   └── Yes (CHECK constraint, UNIQUE, FK, trigger) ↓
│
├── Can cache/replica disagree with the source of truth?
│   ├── Yes → HARDENED (Medium — eventual consistency risk)
│   └── No ↓
│
└── SAFE
```

## Real-World Examples

### Example 1: Double-Spend via Race Condition on Balance Check

**Vulnerable pattern:**
```python
from flask import Flask, request, jsonify
from sqlalchemy.orm import Session

@app.post("/api/purchase")
def purchase():
    user_id = get_current_user_id()
    item_id = request.json["item_id"]

    with db.session() as session:
        user = session.query(User).filter(User.id == user_id).first()
        item = session.query(Item).filter(Item.id == item_id).first()

        # Check invariant: balance >= 0 after purchase
        if user.balance < item.price:
            return jsonify({"error": "Insufficient balance"}), 400

        # Time passes between check and mutation...
        # Another request can read the same stale balance here

        user.balance -= item.price
        order = Order(user_id=user_id, item_id=item_id, amount=item.price)
        session.add(order)
        session.commit()

    return jsonify({"status": "purchased"})
```

**Why vulnerable:** With `READ COMMITTED` isolation (the default in PostgreSQL), two simultaneous requests both read `balance = 100`. Both pass the `balance >= price` check. Both subtract 80. Both commit. Final balance: 20 (should be -60, which the invariant forbids). The user spent 160 while only having 100. This is a classic double-spend.

**Impact:** Direct financial loss. Users can drain their account below zero by sending concurrent purchase requests.

**Fix:**
```python
@app.post("/api/purchase")
def purchase():
    user_id = get_current_user_id()
    item_id = request.json["item_id"]

    with db.session() as session:
        item = session.query(Item).filter(Item.id == item_id).first()

        # Atomic check-and-decrement: invariant enforced in a single statement
        rows = session.execute(
            text("""
                UPDATE users SET balance = balance - :price
                WHERE id = :user_id AND balance >= :price
            """),
            {"price": item.price, "user_id": user_id}
        )

        if rows.rowcount == 0:
            return jsonify({"error": "Insufficient balance"}), 400

        order = Order(user_id=user_id, item_id=item_id, amount=item.price)
        session.add(order)
        session.commit()

    return jsonify({"status": "purchased"})
```

Also add a database constraint as defense in depth:
```sql
ALTER TABLE users ADD CONSTRAINT balance_non_negative CHECK (balance >= 0);
```

### Example 2: State Machine Bypass — Order CANCELLED to SHIPPED

**Vulnerable pattern:**
```python
# Order model with status field but no transition validation
class OrderStatus(str, Enum):
    PENDING = "PENDING"
    CONFIRMED = "CONFIRMED"
    SHIPPED = "SHIPPED"
    DELIVERED = "DELIVERED"
    CANCELLED = "CANCELLED"

@app.put("/api/orders/{order_id}/status")
@require_role("warehouse_staff")
def update_order_status(order_id: int, new_status: OrderStatus):
    order = db.query(Order).filter(Order.id == order_id).first()
    if not order:
        raise HTTPException(404)

    # BUG: No transition validation — any status can move to any other status
    order.status = new_status
    db.commit()

    if new_status == OrderStatus.SHIPPED:
        shipping_service.create_shipment(order)    # Ships the order
        billing_service.finalize_charge(order)      # Charges the credit card

    return {"status": order.status}

# Attack: Customer cancels order (PENDING → CANCELLED)
# Warehouse staff (or attacker with warehouse creds) sets CANCELLED → SHIPPED
# System ships a cancelled order and charges the card again
```

**Why vulnerable:** The status field is a free-form enum assignment with no transition guard. The state machine is implicit (in the developer's head) rather than explicit (in code). Any authenticated warehouse staff member can set any order to any status. A cancelled order can be shipped, a delivered order can be set back to pending for re-processing.

**Impact:** Financial fraud (re-shipping cancelled orders), inventory corruption, billing inconsistencies.

**Fix:**
```python
VALID_TRANSITIONS = {
    OrderStatus.PENDING:   {OrderStatus.CONFIRMED, OrderStatus.CANCELLED},
    OrderStatus.CONFIRMED: {OrderStatus.SHIPPED, OrderStatus.CANCELLED},
    OrderStatus.SHIPPED:   {OrderStatus.DELIVERED},
    OrderStatus.DELIVERED: set(),   # Terminal state
    OrderStatus.CANCELLED: set(),   # Terminal state
}

@app.put("/api/orders/{order_id}/status")
@require_role("warehouse_staff")
def update_order_status(order_id: int, new_status: OrderStatus):
    order = db.query(Order).filter(Order.id == order_id).with_for_update().first()
    if not order:
        raise HTTPException(404)

    if new_status not in VALID_TRANSITIONS.get(order.status, set()):
        raise HTTPException(
            400,
            detail=f"Invalid transition: {order.status} → {new_status}"
        )

    order.status = new_status
    db.commit()

    if new_status == OrderStatus.SHIPPED:
        shipping_service.create_shipment(order)
        billing_service.finalize_charge(order)

    return {"status": order.status}
```

### Example 3: False Positive — Invariant Enforced by Database Constraint

```python
@app.post("/api/accounts/{account_id}/withdraw")
def withdraw(account_id: int, amount: int):
    account = db.query(Account).filter(Account.id == account_id).first()

    # Application-level check
    if account.balance < amount:
        return {"error": "Insufficient funds"}, 400

    account.balance -= amount
    db.commit()

    return {"new_balance": account.balance}
```

**Initial assessment:** This looks like the classic check-then-decrement race from Example 1. Two concurrent withdrawals could both pass the check.

**Why actually safe (in this specific codebase):**
```sql
-- Database schema includes:
ALTER TABLE accounts ADD CONSTRAINT balance_non_negative CHECK (balance >= 0);
```

With this constraint, even if two concurrent requests both pass the application check and try to commit a negative balance, the database will reject the second commit with an `IntegrityError`. The application catches this:

```python
# In the exception handler middleware:
@app.exception_handler(IntegrityError)
def handle_integrity_error(request, exc):
    db.rollback()
    if "balance_non_negative" in str(exc):
        return JSONResponse({"error": "Insufficient funds"}, status_code=409)
    raise
```

**Classification: SAFE.** The invariant is enforced at the database level. The application-level check is an optimization (avoid the DB round-trip for the common case), not the sole enforcement point. The race condition exists but cannot violate the invariant because the database is the final arbiter. Verify that:
1. The CHECK constraint exists and is not deferred
2. The IntegrityError is caught and does not crash the application
3. The rollback actually executes (no swallowed exceptions above it)

## Common False Positive Patterns

### 1. Database Constraints as Backstop
The application code has a check-then-act pattern, but the database has a CHECK, UNIQUE, or FOREIGN KEY constraint that prevents the invariant from actually being violated. The race condition exists at the application level but is harmless because the database rejects the invalid state. **Verify:** the constraint exists, is not deferrable, and the application handles the resulting error gracefully.

### 2. Single-Writer Architecture
The code appears to have no locking around state mutations, but the system uses a single-writer pattern (one process, event loop, single-threaded worker, actor model). If only one thread or process can ever mutate the state, check-then-act is safe. **Verify:** the single-writer assumption holds in production (not just in dev). Check for horizontal scaling configs, multiple Celery workers, or Kubernetes replica counts > 1.

### 3. Idempotent Operations
An operation appears to allow double-execution (no deduplication), but the operation is idempotent — running it twice produces the same result as running it once. `SET balance = 500` is idempotent; `SET balance = balance - 100` is not. **Verify:** the operation is truly idempotent and not just "usually" idempotent (e.g., idempotent unless another operation interleaves).

### 4. Eventual Consistency by Design
The system appears to allow temporary invariant violations (cache says user has permissions, DB says they were revoked 2 seconds ago). But the system is explicitly designed for eventual consistency with bounded staleness, and the consequences of the temporary violation are acceptable (stale read of non-sensitive data, not stale auth token granting admin access). **Verify:** the bounded staleness is actually bounded (TTL on cache, not infinite), and the invariant is not security-critical.

### 5. Compensating Transactions
A multi-step operation can fail partway through, but the system has explicit compensating transactions (saga pattern) that detect and repair invariant violations asynchronously. **Verify:** the compensation logic actually runs (dead-letter queue is monitored, retry policy is configured), runs in bounded time, and handles its own failures (what if the compensation fails?).

### 6. Test/Staging vs Production Paths
An admin or debug endpoint allows arbitrary state mutation (bypassing invariant checks), but it is only accessible in test/staging environments via feature flag, environment variable, or network restriction. **Verify:** the restriction is enforced in production — check deployment configs, not just code comments. `if DEBUG:` is only safe if `DEBUG` is provably `False` in production.

### 7. Invariant Scoped to a Subset
The invariant appears to be violated, but it only applies to a specific subset of records. For example, "balance >= 0" applies to customer accounts but not to system accounts (which can go negative for settlement purposes). Or "single active session" applies to regular users but not to service accounts. **Verify:** the code distinguishes between the subsets correctly and the violation you found is genuinely out of scope for the invariant.
