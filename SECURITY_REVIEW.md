# Security Review — Campus Bite (customerview)

**Date:** 2026-09-14
**Scope:** Flutter client (`lib/`), Firebase Cloud Functions (`functions/index.js`), Firestore
Security Rules (`firestore.rules`), Cloudflare Worker (`cloudflare-worker/`), Firebase/web/Android/CI configuration.
**Method:** Manual code review against the `security-and-hardening` skill (threat-model-first,
STRIDE per trust boundary), focused on the CWE classes named in the brief: CWE-693, CWE-799,
CWE-284, CWE-307, CWE-200, CWE-209, CWE-204, CWE-20, CWE-327, CWE-319.
**Nature:** Read-only. No files were modified, no builds or deploys were run.

---

## 1. Executive summary

The security **architecture** of this codebase is well above average: App Check is enforced on
every authenticated callable, admin paths are deny-by-default, order creation is server-only,
`role` is immutable by every client path, the logging layer redacts exceptions, the app-update
flow verifies SHA-256 and fails closed, and there is no cleartext traffic or weak cryptography.

The weaknesses that remain fit the brief's central thesis precisely — **controls that exist in
principle but break down in practice, or are applied inconsistently across components**. Three
patterns dominate:

1. **Fields that are documented as "server-authoritative" are actually derived from client input.**
   `cafes` (the key that decides *which admin may act on an order*) is derived from the client's
   `items[].selectedCafe`; `foodIds` (the proof of purchase that authorises a review) is accepted
   from the client; `cafeName` (the admin's tenant scope) is self-editable by any account owner.
2. **Enforcement is present on one path and absent on its twin.** The scheduled no-show path
   re-verifies the deadline and grace period; the *manual* admin no-show path does not. Order
   pricing is recomputed by an async trigger but not at the authoritative write. `accountStatus`
   is checked with a denylist in `placeOrder` and an allowlist everywhere else. `pickupGracePeriodNotExpired()`
   fails **open** while its own comment promises it fails closed.
3. **No interaction-frequency control anywhere.** There is not a single rate limit, cooldown, or
   quota in the backend; the active-order ceiling is `null` for most users, so it does not fire
   either. App Check raises the bar against naive bots but does not bound an attested client.

**Highest-impact single issue:** an **admin of one cafe can grant themselves access to another
cafe's orders and audit records** by editing their own `cafeName` (F-01). This breaks the
multi-tenant boundary the whole design is built on.

| Severity | Count |
|---|---|
| High | 6 |
| Medium | 11 |
| Low | 6 |

---

## 2. Trust boundaries and assets

Boundaries where untrusted data enters: (1) Firestore direct client reads/writes, guarded by
`firestore.rules`; (2) the nine callable Cloud Functions, guarded by App Check + `request.auth`;
(3) the Cloudflare release proxy, which is unauthenticated but serves only public GitHub release
data; (4) FCM/Cloudinary provider responses; (5) the app self-update channel.

Assets worth protecting: the admin role and per-cafe tenant scope, order integrity and pricing,
the reliability/strike engine (it gates a student's ability to order), proof-of-purchase for
reviews, customer PII (`users`), and admin audit records.

**Cookie/session note:** this is a Flutter mobile app — there are **no cookies**. The session is a
Firebase ID token held by the native SDK. There is no plaintext token storage, no token logging,
and `android:allowBackup="false"` prevents app-data exfiltration via device backup. The realistic
session risk here is therefore **not token theft but account takeover via the privilege and
phishing findings below (F-01, F-11, F-12, F-16)**.

---

## 3. Findings

### 3.1 Business-logic abuse and access control (CWE-284, CWE-863, CWE-639)

| ID | Title | CWE | Severity | Confidence | Location |
|---|---|---|---|---|---|
| F-01 | Admin can re-scope themselves to any cafe (`cafeName` self-editable) | CWE-284/269/639 | **High** | High | `firestore.rules:293-320`, `:899-901`, `:43-50`, `:60` |
| F-02 | Client-supplied `foodIds` is authoritative proof of purchase for reviews | CWE-863/639 | **High** | High | `functions/index.js:2276-2281`, `:2424-2426`; `firestore.rules:488-496` |
| F-03 | Manual NO_SHOW applies a strike with no server-side deadline/grace check | CWE-863/693/284 | **High** | High | `functions/index.js:3636-3667`; `firestore.rules:286-288` |
| F-04 | Admin can rewrite order identity, line items and billing fields | CWE-863/639 | **High** | High | `firestore.rules:148-216`, `:782-784` |
| F-05 | `cafes` derived from client `selectedCafe`; omitting it grants every admin | CWE-639/284 | Medium | High | `functions/index.js:2328-2330`, `:2660-2670`, `:2441`; `firestore.rules:43-50` |
| F-06 | Admin can suspend/reactivate any user (incl. other admins), cross-cafe, unaudited | CWE-863/269 | Medium-High | High | `firestore.rules:410-431`, `:899-901` |
| F-07 | Order `delete` allowed for admins — evidence destruction | CWE-284/862 | Medium | High | `firestore.rules:785` |
| F-08 | Review "revive" bypasses the one-live-review guard | CWE-863 | Medium | High | `firestore.rules:542-577`, `:822-824`; `functions/index.js` review trigger |
| F-09 | Client-chosen `pickupWindowMinutes`/`distanceMeters` drive the pickup deadline | CWE-20/693 | Medium | High | `functions/index.js:2251-2273`, `:3543-3553` |
| F-10 | `pickupGracePeriodNotExpired()` fails open (comment says the opposite) | CWE-693 | Medium | High | `firestore.rules:255-266`, `:286-288` |
| F-11 | Notification rules allow arbitrary recipient/type/title/message (phishing) | CWE-863/20 | Medium | High | `firestore.rules:709-721`, `:868` |
| F-12 | Unscoped `/users` read — any admin bulk-reads all users' PII | CWE-200/863 | Medium | High | `firestore.rules:897`, `:937` |

#### F-01 — Admin can re-scope themselves to any cafe **(High)**

`cafeName` on the caller's own user document is the *sole* input to per-cafe authorization — in
rules (`adminServesOrder()` at `:43-50`, `adminCanReadAudit()` at `:60`) and in Cloud Functions
(`functions/index.js:4464`, `:4951`). Yet `cafeName` sits in the student-writable allowlist:

```
// firestore.rules:294
let allowed = ['fullName', 'email', 'phoneNumber', 'cafeName', 'updatedAt'];
```

and the update rule applies that helper to **any** owner, with no role gate:

```
// firestore.rules:899-901
allow update: if (isOwner(userId) && (studentNotModifyingProtectedFields()
  || validFavoriteMenuUpdate())) || (isAdmin() && validAdminStrikeUpdate());
```

`cafeName` is only type/size-checked (`:318-320`) — never pinned to the caller's real cafe.

**Exploit** (any admin, using the plain Firebase SDK):

```dart
await users.doc(myUid).update({'cafeName': 'Rival Cafe'});           // allowed
final o = await orders.where('cafes', arrayContains: 'Rival Cafe').get();
await orders.doc(id).update({'status': 'collected'});                // cross-tenant write
await audit_logs.where('cafeId', isEqualTo: 'Rival Cafe').get();     // cross-tenant audit read
```

**Impact:** full cross-tenant access to orders and audit logs; the multi-tenant model is defeated.
Suspension of a rival admin is also possible (see F-06).

**Fix:** remove `cafeName` from the student allowlist and make it admin-only and immutable by the
owner; require `isAdmin() && targetIsStudent() && sameCafe()` on `allow update`. If admins must be
able to change it, route it through an audited callable.

#### F-02 — Client-supplied `foodIds` is authoritative proof of purchase **(High)**

```
// functions/index.js:2276-2281 — elements are never validated as strings
function validateFoodIds(foodIds) {
  if (foodIds === undefined || foodIds === null) return;
  if (!Array.isArray(foodIds) || foodIds.length > 50) { throw ... }
}
// functions/index.js:2424-2426 — written verbatim when the client supplies it
foodIds: Array.isArray(ctx.foodIds) && ctx.foodIds.length > 0
  ? ctx.foodIds
  : ctx.lineItems.map((i) => i.foodItemId),
```

Review eligibility then trusts that field:

```
// firestore.rules:493-496
&& order.data.foodIds is list
&& order.data.foodIds.size() < 50
&& order.data.foodIds.hasAny([request.resource.data.foodId]);
```

**Exploit:** order one cheap item, pass ~40 arbitrary `foodIds`, collect the order, then publish
"verified purchase" reviews/ratings for food that was never bought. This corrupts the rating
system and inflates `reviewCount`.

**Fix:** ignore the client `foodIds` entirely and derive it from `lineItems` (which are already
resolved against `food_items`), and validate each element is a string.

#### F-03 — Manual NO_SHOW applies a strike without verifying the deadline **(High)**

`handleOrderNoShow` (`functions/index.js:3636-3667`) sets `expiredAt`, `deadlineStatus: "EXPIRED"`,
`noShowProcessed: true` and calls the reliability engine on **any** `ready → no_show` transition,
with no check that `pickupDeadline + grace` has actually elapsed. The scheduled path *does*
re-verify server time (`:1316-1321`). The rules compound this: `ready → no_show` is unconditional
while `ready → collected` requires the grace check (`firestore.rules:286-288`).

**Impact:** an admin (or *any* admin, when `cafes == [UNASSIGNED]`) can instantly no-show a
just-ready order. The student is penalised, loses the ability to extend or collect, and the
penalty is reversible only through an explicit excuse flow.

**Fix:** reject the transition unless server-now ≥ `pickupDeadline + grace`; set `expiredAt` to
that computed instant; require the same grace check for `no_show` in the rules.

#### F-04 — Admin can rewrite order identity and billing **(High)**

`adminNotModifyingProtectedOrderFields()` (`firestore.rules:148-216`) protects `cafes`,
`pickupDeadline`, `reliabilityProcessed`, etc., but **omits** `studentId`, `items`, `totalAmount`/`price`,
`foodIds`, `userName` and contact fields. The update rule (`:782-784`) therefore permits a
metadata-only update that changes them:

```dart
await orders.doc(id).update({'studentId': victimUid});
await orders.doc(id).update({'totalAmount': 0, 'items': []});
```

**Impact:** an order can be transferred to another student so the reliability engine debits the
wrong person, or its billing/evidence fields rewritten before the engine runs.

**Fix:** add `!('studentId' in changed) && !('items' in changed) && !('totalAmount' in changed)
&& !('price' in changed) && !('foodIds' in changed) && !('userName' in changed)`.

#### F-05 — Client-chosen admin scope (Medium)

`normalizeLineItems` accepts `selectedCafe` as any length-capped string (`:2328-2330`);
`deriveOrderCafes` (`:2660-2670`) turns it into the order's `cafes`; `buildOrderData` falls back to
`[UNASSIGNED]` (`:2441`). The code comments call `cafes` "server-authoritative … cannot be forged",
but its *value* is client-chosen. A student can route an order to a chosen admin, or omit the cafe
so `UNASSIGNED` grants **every** admin read/update rights (rules `:43-50`, notifications `:3826-3833`).

**Fix:** resolve the cafe from the `food_items` record server-side and validate against a cafe allowlist.

#### F-06 — Unscoped admin user-management (Medium-High)

`validAdminStrikeUpdate()` (`firestore.rules:410-431`) never inspects the target document, and
`allow update` (`:899-901`) applies it under `isAdmin()`:

```dart
await users.doc(rivalAdminUid).update({'accountStatus': 'SUSPENDED', 'strikeCount': 0});
await users.doc(suspendedAdminUid).update({'accountStatus': 'ACTIVE'});   // reverses a suspension
```

**Impact:** admin-vs-admin denial of service, suspension reversal, unaudited strike tampering.
**Fix:** require the target to be a student in the caller's cafe, forbid transitions out of
`SUSPENDED`, and route strikes through the audited callable.

#### F-07 / F-08 / F-09 / F-10 / F-11 / F-12

- **F-07** `allow delete: if adminServesOrder();` (`rules:785`) lets an admin destroy order history
  and pending no-show evidence with no audit trail. Use a status transition instead.
- **F-08** `validReviewUpdate()` (`rules:542-577`) permits `deleted: false` without re-claiming the
  `review_guards` document, and the trigger releases the guard on soft-delete — so a determined
  user with two collected orders for the same food can end up with two live reviews, breaking the
  documented "one live review per (student, food)" invariant.
- **F-09** `pickupWindowMinutes` (client integer 10–25, `:2251-2257`) and `distanceCalculated`/
  `distanceMeters` (client-asserted, `:2260-2273`) feed the authoritative pickup deadline
  (`:3543-3553`), letting a client inflate or shrink its own no-show window.
- **F-10** This helper returns **true** (i.e. "not expired" → collection allowed) when
  `pickupDeadline` is missing or not a timestamp, directly contradicting its comment at `:255-257`
  ("Fails closed: missing or non-timestamp pickupDeadline is treated as expired and blocks
  collection"). A textbook CWE-693 fail-open.
- **F-11** `validNotificationCreate()` (`rules:709-721`) does not require the recipient to share the
  caller's cafe and caps no field, so an admin can push arbitrary `type`/`title`/`message`/`metadata`
  (e.g. a fake "account suspended — pay here" message) to any user, cross-cafe.
- **F-12** `allow read: if isOwner(userId) || isAdmin();` (`rules:897`) authorises an unconstrained
  collection read, so any admin can dump every user's name, email, phone and reliability summary
  across all cafes.

---

### 3.2 Bot-driven abuse, credential stuffing and interaction frequency (CWE-799, CWE-307, CWE-693)

| ID | Title | CWE | Severity | Confidence | Location |
|---|---|---|---|---|---|
| F-13 | No rate limiting or quota on any callable | CWE-799 | **High** | High | `functions/index.js` (whole file — zero matches) |
| F-14 | No active-order ceiling for most users | CWE-799/693 | **High** | High | `functions/index.js:2464-2468`, `:2969-2974` |
| F-15 | `accountStatus` denylist in `placeOrder` vs allowlist elsewhere | CWE-693 | Low | High | `functions/index.js:2454` vs `:4190`, `:4457`, `:5102` |

**Verified positive:** there is **no** credential-stuffing weakness in the authentication flow
itself. Login/registration/reset are handled by the Firebase Auth SDK, error messages are
deliberately generic (no user enumeration), and `placeOrder` requires a verified email. App Check
is enforced on all eight authenticated callables (`functions/index.js:63, 1829, 2055, 2493, 4160,
4632, 4701, 4860, 5067`), which is a genuine bot/attestation control.

**F-13 — No rate limiting (High).** A search for `rateLimit|rate_limit|throttle|429|too-many-requests|cooldown`
across the backend returns **nothing**. `placeOrder`, `cancelOrder`, `extendPickupDeadline`,
`excuseNoShow` and the rest can be called in an unbounded loop. App Check blocks unattested
clients, but an attacker who extracts a valid attestation (or an attested scripted client) is
unbounded. `placeOrder` in particular triggers `NEW_ORDER` push notifications to admins
(`:3870+`), so order spam is also a **notification-amplification and cost** vector.

**F-14 — No active-order ceiling (High).** The limit is only applied when non-null:

```
// functions/index.js:2464-2468
const limit = restrictionFor(summary).activeOrderLimit;
if (limit != null) { await assertActiveOrderLimit(transaction, ctx.uid, limit); }
```

and `restrictionFor` returns `activeOrderLimit: null` for `eligibleOrders < 3` (i.e. **every new
account**) and for score ≥ 50 (`:2969-2974`). Most users therefore have **no** concurrent-order
limit at all — which also amplifies F-02 (unlimited orders to farm review eligibility) and the
notification spam in F-13. The transaction write that serialises concurrent same-user calls runs
only when a limit exists (`:2480-2484`).

**Fix (F-13/F-14):** add per-uid (and per-IP at the edge) token-bucket limits to the callables,
set a non-null default `activeOrderLimit` (e.g. 3) for all users, and move the serialising
`transaction.update(userRef)` outside the `limit != null` branch.

**F-15 — Inconsistent status check (Low).** `placeOrderInTransaction` rejects only
`accountStatus === "SUSPENDED"` (`:2454`), while `createAdminAccount`, `reactivateStudent`,
`setFoodDisposition` and `deleteCloudinaryImage` all use deny-by-default `!== "ACTIVE"`
(`:4190`, `:4457`, `:5102`). A missing/non-canonical status still places orders.

---

### 3.3 Information disclosure (CWE-200, CWE-209, CWE-204)

| ID | Title | CWE | Severity | Confidence | Location |
|---|---|---|---|---|---|
| F-16 | `deleteCloudinaryImage` returns raw provider/internal error text to the caller | CWE-209 | Medium | High | `functions/index.js:5198-5213` |
| F-17 | `deleteCloudinaryImage` has no object-level (cafe) authorization | CWE-639/284 | Medium | High | `functions/index.js:5062-5220` |
| F-18 | Raw error objects logged (`createAdminAccount`, token cleanup) | CWE-532 | Low | High | `functions/index.js:4180`, `:5384` |
| F-19 | Web hosting sets no security headers / no CSP | CWE-693/1021 | Low-Medium | High | `firebase.json:44-57`; `web/index.html` |
| F-20 | Order `note`/plan `items`/cart items unbounded — resource exhaustion | CWE-400/770 | Medium | High | `firestore.rules:77-89`, `:93-123`, `:664-684`, `:789-794` |
| F-21 | No audit record for `cancelOrder` (repudiation) | CWE-778 | Low | High | `functions/index.js:2125-2161` vs `:1344-1353` |

**F-16 (Medium).** The error paths echo provider/internals to the client:

```
Cloudinary deletion failed: ${result.error?.message}     // :5198-5201
Failed to delete image: ${error.message}                 // :5210-5213
```

This violates the skill's "never `err.message`, never stack traces" rule. Return a generic
message and keep the detail in `console.error` only.

**F-17 (Medium).** The callable correctly enforces role + ACTIVE status, but never checks that the
`publicId` belongs to the caller's own cafe or records. Any active admin can delete **any**
Cloudinary asset, including a rival cafe's menu images — an inconsistency with the per-cafe scoping
applied everywhere else.

**F-18 (Low).** `console.error("[createAdminAccount] Auth user creation failed:", err)` and the
token-cleanup equivalent log whole error objects. Firebase Auth admin errors can embed the affected
email/uid. Server logs are access-controlled, so this is Low, but it is an unredacted PII path.

**F-19 (Low-Medium).** `firebase.json` has no `headers` block and `web/index.html` sets no CSP
`<meta>`, so the Flutter web build ships without CSP, `X-Frame-Options`/`frame-ancestors`,
`X-Content-Type-Options` or `Referrer-Policy`. The SPA rewrite (`:51-56`) is standard and fine.

**F-20 (Medium).** `validMealPlanWrite()` caps only `title` (plan `items` is bare `is list`, `note`
uncapped), `validCartItemWrite()` caps fields but not item count, `validDeviceTokenCreate()` caps no
token size, and `/section` has no validation at all (`:789-794`). A client can grow its own
subcollections and documents toward quota/cost exhaustion.

**F-21 (Low).** `cancelOrder` mutates state and notifies but writes no `audit_logs` entry, unlike
the auto-expiry path — a repudiation gap on a state-affecting action.

**CWE-204 (Observable Response Discrepancy) — clean.** Auth error messages are generic and
explicitly avoid revealing which field was wrong (`auth_service.dart:107-131`, `:200-215`), and the
callables map internal failures to generic `internal` messages (`functions/index.js:1950-1957`,
`:2162-2169`, `:2530-2537`). Resetting a password for an unknown address does not disclose existence.

---

### 3.4 Input handling, cryptography and transport (CWE-20, CWE-327, CWE-319)

| ID | Title | CWE | Severity | Confidence | Location |
|---|---|---|---|---|---|
| F-22 | Client `price`/line-item price stored at creation; corrected only asynchronously | CWE-20/602 | Medium | Medium-High | `functions/index.js:2427`; correction at `:2832+` |
| F-23 | `foodIds` elements not type-validated | CWE-20 | Low | High | `functions/index.js:2276-2281` |
| F-24 | `section` collection: no schema/size/docId validation | CWE-20/400 | Low | High | `firestore.rules:789-794` |

**F-22 (Medium) — corrected finding.** The order is created with the **client-supplied** total:

```
// functions/index.js:2427
price: ctx.price,
```

An earlier reading that no server-side re-derivation exists is **not** accurate: the `onNewOrder`
trigger calls `normalizeOrderPricing` (`:2832+`), which resolves every line item against
`food_items` via `resolveLineItemPrice` (`:2761-2811`), **never** falls back to the client value,
and holds the order (throws, retried) if a menu record is missing or unreadable. The residual risk
is a genuine but narrower **race/failure window**: the order exists with the tampered total from
`placeOrder` success until the async trigger corrects it, and if the trigger is disabled or
permanently holds on a missing `food_items` document, the tampered price persists and an admin can
accept/collect in that interval. **Fix:** recompute inside `placeOrderInTransaction` at the
authoritative write point.

**CWE-327 (Broken/Risky Cryptography) — clean.** No MD5, SHA-1, DES, RC4 or custom hashing exists
in the backend or client. The only `Math.random()` uses are retry jitter (`functions/index.js:312`,
`:988`), not security decisions. Cloudinary credentials are supplied through `defineSecret`
(`:5058-5060`) and never logged or returned.

**CWE-319 (Cleartext Transmission) — clean.** `android:usesCleartextTraffic="false"` is set; no
`http://` data endpoint is used (only Apache-license comment headers), and the client actively
rejects `http://` image URLs. No `badCertificateCallback`, `HttpOverrides` or `onBadCertificate`
exists anywhere. Cloudinary secrets travel in Basic-auth headers over TLS.

---

## 4. Verified strengths

These were checked and found correct — the report is deliberately balanced.

**Backend**
- App Check (`enforceAppCheck: true`) **and** `authPolicy: "required"` on all eight authenticated
  callables; explicit `request.auth` guards.
- Admin callables verify `role == 'admin'` **and** `accountStatus === 'ACTIVE'` deny-by-default.
- `/orders` has **no** client create and no student update, so `placeOrder` is the only creation
  path and the active-order limit cannot be bypassed via rules.
- `cancelOrder`: ownership checked **inside** the transaction, server-`createdAt`-based window,
  only `pending` cancellable, idempotent. `extendPickupDeadline`: ownership inside the transaction,
  once-only, Timestamp-type and server-now checks.
- `placeOrder` forces `studentId === uid`, requires `role == 'student'` and a verified email, and
  blocks duplicate `orderId` transactionally; status/`deadlineStatus`/`createdAt` are server-hardcoded.
- The scheduled expiry path re-reads and re-verifies deadline + grace against server time and is
  idempotent; the reliability engine writes `reliabilityProcessed`/`reliabilityOutcome` atomically,
  preventing double-counting.
- `deleteCloudinaryImage` validates role, ACTIVE status and strike count, and passes secrets via
  `defineSecret`.
- Client-facing errors are mapped to generic messages — no raw `err.message` on the lifecycle paths
  (the Cloudinary callable is the exception, F-16).

**Firestore rules**
- No `match /{document=**}` catch-all; every unmatched path default-denies.
- No unauthenticated reads: every `allow read` requires `isAuth()`/`isOwner()`/`isAdmin()`.
- `role` is immutable by every client path (absent from all allowlists; admin creation requires
  `isAdmin()`; no delete on users).
- Orders comprehensively protect server-owned markers (`cafes`, `pickupDeadline`, reliability
  fields, no-show markers); reviews bind a deterministic composite ID, the caller's own COLLECTED
  order, and the caller's own stored display name.
- `device_tokens` update is ownership-checked with `userId`/`role`/`createdAt` immutable;
  `review_guards` are uid-pinned with `update`/`delete: false`.
- Profile `email` updates must equal the verified ID-token email claim; `hasVerifiedEmail()` reads
  the ID-token claim, not client data.

**Client**
- **No password, OTP or token value is ever logged.** `LoggerService` sanitises messages and emits
  only `error.runtimeType` (`logger_service.dart:62-92`); debug/info are stripped from release.
- Password fields are obscured and validated (length cap + control-character rejection); login
  failures collapse to one generic message.
- `android:allowBackup="false"` and `android:usesCleartextTraffic="false"`; no exported non-launcher
  component beyond the launcher activity; FileProvider is `exported="false"`.
- **Update flow verifies SHA-256 and fails closed**: missing checksum → refuse
  (`update_service.dart:745-748`), mismatch → discard (`:779-782`), installer URL/checksum pinned to
  an `allowedHost` allowlist with a bounded redirect-hop check.

**Edge / CI**
- The Cloudflare Worker builds GitHub URLs from a strict `v[\w.-]+` tag and `[\w.-]+\.(apk|sha256)`
  filename against fixed hosts, so there is no open redirect, SSRF or path traversal.
  `Access-Control-Allow-Origin: *` is acceptable there — the data is public release metadata and no
  credentials are involved.
- CI references secrets only through `${{ secrets.* }}`; no hardcoded credentials, private keys,
  keystores or `.env` files are committed, and `.gitignore` covers them.
- The public Firebase `AIza…` web API key in `firebase_options.dart` is expected and is not a secret.

---

## 5. Prioritised remediation plan

1. **Close the tenant boundary (F-01).** Remove `cafeName` from the student-writable allowlist and
   make admin re-scoping an audited, admin-only operation. This is the single highest-value fix.
2. **Stop trusting client fields that drive authorization or entitlement (F-02, F-05).** Derive
   `foodIds` and `cafes` from the server-resolved `food_items` records, never from `request.data`.
3. **Make admin actions safe (F-03, F-04, F-06, F-07, F-16, F-17).** Server-verify the deadline
   before a manual no-show; protect `studentId`/`items`/`totalAmount`/`foodIds`; scope admin
   user-management and Cloudinary deletion to the caller's cafe; return generic errors.
4. **Add interaction-frequency controls (F-13, F-14).** Per-uid token buckets on all callables,
   a non-null default active-order limit, and edge rate limiting on the Cloudflare Worker.
5. **Repair the fail-open control and tighten validation (F-10, F-09, F-20, F-22).** Fix
   `pickupGracePeriodNotExpired()`, derive the pickup window server-side, cap document/array sizes,
   and re-price inside `placeOrderInTransaction`.
6. **Hygiene (F-18, F-19, F-21, F-08, F-11, F-12, F-15, F-23, F-24).** Redact logged error
   objects, add hosting security headers/CSP, audit `cancelOrder`, re-claim the review guard on
   revive, cafe-scope and bound notifications, add an audit record to `cancelOrder`, use the
   `!== "ACTIVE"` allowlist in `placeOrder`, validate `foodIds` element types, and add a
   `validSectionWrite()` guard.

---

## 6. Coverage and confidence notes

- Every finding marked **High** was re-read in the source by the reviewing agent (not accepted from
  a pattern match alone); line numbers refer to the reviewed revision.
- The five-component sweep was performed with parallel focused reviewers plus direct verification of
  all top-severity claims. Where a claim could not be confirmed against source, it was downgraded or
  dropped (notably the pricing finding, corrected in F-22).
- Not covered: runtime/penetration testing, Firebase project console settings (Auth providers,
  App Check enforcement mode, Cloudinary upload presets), Cloudinary account configuration, and
  dependency CVE scanning (`pubspec.lock` / `functions/package-lock.json` were not resolved against
  an advisory database). Those are recommended as a follow-up.
