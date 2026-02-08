# Business Logic Workflow Bypass Detection

Workflow bypass vulnerabilities occur when an attacker skips, reorders, or manipulates
steps in a multi-stage business process. The server trusts that the client followed the
prescribed flow, but each API endpoint can be called independently. If step N does not
verify that steps 1 through N-1 completed, the workflow is bypassable. These exploit
business logic, not authentication or authorization.

## Methodology

### Step 1: Map All Multi-Step Workflows

Identify every process spanning multiple requests or states: checkout flows, approval
chains, onboarding wizards, document lifecycle management.

```python
# Look for state/status fields in models
class Order(db.Model):
    status = db.Column(db.Enum(
        "cart", "checkout", "payment_pending", "payment_confirmed",
        "processing", "shipped", "delivered", "cancelled"
    ))
```

```javascript
// State machine definitions (good sign if they exist)
const orderStates = {
    initial: 'cart',
    states: {
        cart: { on: { CHECKOUT: 'checkout' } },
        checkout: { on: { PAY: 'payment_pending' } },
        payment_pending: { on: { CONFIRM: 'processing' } },
    }
};
```

Document every valid state transition as a directed graph.

### Step 2: Test Direct Endpoint Access Out of Order

Call later-stage endpoints directly without completing prior steps.

```python
# VULNERABLE: no prior-step verification
@app.route("/api/orders/<int:oid>/confirm", methods=["POST"])
def confirm_order(oid):
    order = Order.query.get(oid)
    order.status = "confirmed"           # skips payment entirely
    trigger_fulfillment(order)

# SAFE: validates previous step
def confirm_order(oid):
    order = Order.query.get(oid)
    if order.status != "payment_confirmed":
        abort(400, "Payment must be confirmed first")
    order.status = "confirmed"
```

```javascript
// VULNERABLE: skipping review stage
app.post("/api/documents/:id/publish", auth, async (req, res) => {
    const doc = await Document.findById(req.params.id);
    doc.status = "published";            // jumped from "draft" directly
    await doc.save();
});
```

### Step 3: Check Server-Side Price/Quantity Validation

Verify financial values are computed server-side, not accepted from client.

```python
# VULNERABLE: price from client
item = CartItem(product_id=data["product_id"], price=data["price"])  # 0.01

# SAFE: price from server catalog
product = Product.query.get_or_404(data["product_id"])
item = CartItem(product_id=product.id, price=product.current_price)
```

```javascript
// VULNERABLE: total from client
const { items, total } = req.body;
await chargePayment(req.user, total);   // whatever client says

// SAFE: recomputed
const total = await computeTotal(items);
await chargePayment(req.user, total);
```

### Step 4: Audit Discount and Coupon Logic

Look for unlimited stacking, negative prices, and percentage manipulation.

```python
# VULNERABLE: unlimited coupon stacking
cart.coupons.append(coupon)              # 10% + 10% + 10%... = free

# SAFE: enforce stacking rules
if len(cart.coupons) >= MAX_COUPONS: abort(400, "Limit reached")
if coupon.exclusive and cart.coupons: abort(400, "Cannot combine")
if cart.total_after_discounts() - coupon.amount < MIN_ORDER: abort(400)
```

### Step 5: Verify State Transition Integrity

Check for proper state machine enforcement vs arbitrary status updates.

```python
# VULNERABLE: arbitrary status
order.status = request.json["status"]    # "delivered" without shipping

# SAFE: transition table
VALID_TRANSITIONS = {
    "cart": ["checkout"], "checkout": ["payment_pending", "cart"],
    "payment_pending": ["payment_confirmed", "cart"],
    "processing": ["shipped"], "shipped": ["delivered"],
}
new = request.json["status"]
if new not in VALID_TRANSITIONS.get(order.status, []): abort(400)
```

### Step 6: Check Payment Verification Callbacks

Verify payment is confirmed server-to-server, not via client redirect.

```python
# VULNERABLE: trusts client redirect
@app.route("/payment/success")
def payment_success():
    order = Order.query.get(request.args["order_id"])
    order.status = "paid"                # no provider verification

# SAFE: webhook from payment provider
@app.route("/webhooks/stripe", methods=["POST"])
def stripe_webhook():
    event = stripe.Webhook.construct_event(
        request.data, request.headers["Stripe-Signature"], WEBHOOK_SECRET
    )
    if event["type"] == "checkout.session.completed":
        order = Order.query.get(event["data"]["object"]["metadata"]["order_id"])
        order.status = "paid"
```

### Step 7: Inspect Parameter Boundaries

Check for missing validation on quantities and numeric parameters.

```python
# VULNERABLE: no bounds
quantity = request.json["quantity"]       # could be -5, 0, or 999999
item.quantity = quantity

# SAFE: validated
if not isinstance(quantity, int) or quantity < 1 or quantity > MAX_QTY:
    abort(400)
```

### Step 8: Review TOCTOU Race Conditions

Check whether validation and action are atomic.

```python
# VULNERABLE: race window between check and deduction
if user.points >= 1000:
    user.points -= 1000                  # concurrent request double-spends

# SAFE: atomic database operation
db.session.execute(text(
    "UPDATE users SET points = points - 1000 WHERE id = :uid AND points >= 1000"
), {"uid": current_user.id})
if result.rowcount == 0: abort(400, "Insufficient points")
```

## Decision Tree

```
[Multi-step workflow or state machine identified?]
    +--NO--> SAFE (single-action, not applicable)
    +--YES
        [Each step validates prior steps completed?]
            +--NO--> VULNERABLE (Critical) "Steps can be skipped"
            +--YES
                [Financial values computed server-side?]
                    +--NO--> VULNERABLE (Critical) "Price from client"
                    +--YES
                        [State transitions restricted to valid paths?]
                            +--NO--> VULNERABLE (High) "Arbitrary status jumps"
                            +--YES
                                [Payment verified via server callback?]
                                    +--NO--> VULNERABLE (Critical)
                                    +--YES
                                        [TOCTOU prevented?]
                                            +--NO--> HARDENED (Medium)
                                            +--YES--> SAFE
```

## Real-World Examples

### Example 1: E-Commerce Checkout Skips Payment

```python
@app.route("/api/checkout/step3-confirm", methods=["POST"])
@login_required
def confirm_checkout():
    cart = Cart.query.filter_by(user_id=current_user.id, active=True).first()
    order = Order.create_from_cart(cart)
    order.status = "confirmed"; order.save()
    send_confirmation_email(order)
```

**Why vulnerable:** Step 3 (confirm) does not verify step 2 (payment) completed.
Attacker calls step1-address then jumps to step3-confirm, skipping payment.

**Impact:** Free goods. Fulfillment begins without payment. Direct financial loss.

**Fix:**
```python
payment = Payment.query.filter_by(cart_id=cart.id, status="completed").first()
if not payment: abort(400, "Payment must be completed before confirmation")
```

### Example 2: Document Published Without Approval

```javascript
router.put("/api/documents/:id", auth, async (req, res) => {
    const doc = await Document.findById(req.params.id);
    if (req.body.status) doc.status = req.body.status;  // any value accepted
    await doc.save();
});
```

**Why vulnerable:** Generic update endpoint allows setting status to "published",
bypassing review and approval. Same endpoint for title edits handles state transitions.

**Impact:** Unapproved content goes live. Compliance violations in regulated industries.

**Fix:** Separate status-change endpoints with state machine checks, remove `status`
from the generic update handler.

### Example 3: Negative Quantity Refund Exploit

```python
@app.route("/api/orders/<int:oid>/return", methods=["POST"])
def return_item(oid):
    quantity = request.json["quantity"]
    item = OrderItem.query.get(request.json["item_id"])
    refund_amount = item.unit_price * quantity      # no bounds check
    order.user.wallet_balance += refund_amount
```

**Why vulnerable:** No validation that quantity is positive or within purchased amount.
`quantity: -10` causes negative refund (wallet drain) or `quantity: 9999` generates
excess credit beyond what was purchased.

**Impact:** Financial manipulation. Unlimited wallet balance generation.

**Fix:**
```python
if quantity < 1 or quantity > (item.quantity - item.already_returned):
    abort(400, "Invalid return quantity")
```

## Common False Positive Patterns

1. **Idempotent step re-submission** (re-entering shipping address). Not a bypass if
   the step is genuinely repeated and subsequent steps still require completion.

2. **Admin override of workflow** where administrators manually advance status.
   Intentional if restricted to admin roles with audit logging.

3. **Draft auto-save** updating content without changing status. Not a state transition.

4. **Webhook retry logic** re-processing payment events. Idempotent handlers checking
   "already processed" before acting are expected behavior.

5. **Rollback/cancellation flows** moving state backward (shipped to processing for
   recall). Valid reverse transitions if properly authorized.

6. **Partial operations** (partial shipments, partial refunds) creating sub-states.
   Legitimate if parent workflow integrity is maintained.

7. **Feature-flagged fast paths** skipping steps for beta users. Verify the flag is
   server-controlled and not client-manipulable.
