# Stripe Webhook Smoke Test Checklist

## Pre-flight
1. `node --check server.js` passes
2. Server starts without errors: `npm start` (or `node server.js`)
3. MongoDB connection established

## Webhook Event Handling

### checkout.session.completed
- [x] Finds booking by `client_reference_id` or `metadata.bookingId`
- [x] Updates booking with Stripe session data (PI ID, amount, currency)
- [x] Marks event as `processedAt` + `status: "success"` after save
- [x] Sends invoice receipt email (gated by comms flag)

### payment_intent.succeeded
- [x] Finds booking by `stripePaymentIntentId`
- [x] **Terminal state guard**: Skips if booking is `cancelled/canceled/refunded/expired`
  - Logs `stripe_webhook_skip_terminal_state`
  - Updates event with `status: "skipped_terminal_state"`
- [x] **Idempotent guard**: Skips if already `confirmed` + `paid`
  - Logs `stripe_webhook_already_confirmed`
  - Updates event with `status: "success_idempotent"`
- [x] Updates booking: `status=confirmed`, `paymentStatus=paid`, `confirmedAt=now`
- [x] Marks event as `processedAt` + `status: "success"` after save
- [x] Sends booking confirmed email (gated by comms flag)

### checkout.session.async_payment_failed / checkout.session.expired
- [x] Finds booking by `client_reference_id` or `metadata.bookingId`
- [x] Updates `paymentStatus` based on outcome
- [x] Marks event as `processedAt` + `status: "success"` after save
- [x] Sends payment failed email (gated by comms flag)

## Event Ledger States
| Status | Meaning |
|--------|---------|
| `success` | Event fully processed, booking updated |
| `success_idempotent` | Booking was already in final state |
| `skipped_terminal_state` | Booking is cancelled/refunded/expired |
| `ignored_not_found` | Booking not found (PI or session ID mismatch) |
| `error` | Processing failed with error message |

## Manual Test Flow (Stripe CLI)
```bash
# 1. Start server locally
npm start

# 2. Forward webhooks (requires Stripe CLI)
stripe listen --forward-to localhost:4000/api/stripe/webhook

# 3. Trigger test events
stripe trigger payment_intent.succeeded
stripe trigger checkout.session.completed
stripe trigger checkout.session.expired

# 4. Verify in logs:
#    - "stripe_webhook_skip_terminal_state" for cancelled bookings
#    - "stripe_webhook_already_confirmed" for replay of same event
#    - Event ledger shows correct processedAt and status
```

## Expected Behavior Summary
| Scenario | Result |
|----------|--------|
| New payment success | Booking → confirmed, paid |
| Replay same event | Idempotent exit, no change |
| Cancelled booking + payment event | Skipped, stays cancelled |
| Missing booking | 200 OK, event logged as ignored |

## Verification Commands
```bash
# Syntax check
node --check server.js

# No Booking.findOneAndUpdate in webhook
grep -n "Booking\.findOneAndUpdate" server.js | wc -l  # should be 0

# BookingModel used consistently
grep -n "BookingModel" server.js | head -20
```
