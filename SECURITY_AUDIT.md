# Abyss.Tunnel — Security & Optimization Audit

Date: 2026-07-22
Scope: `server.js`, `public/client.js`, `public/index.html`, `package.json`, test files, `.env`, `.gitignore`.

Findings are grouped by severity. Each item has a Status field updated as work is completed.

---

## Critical

### 1. `dotenv` is never loaded — `.env` is silently ignored
- **Location:** `package.json:14` declares `dotenv`; `server.js` never calls `require('dotenv').config()`.
- **Impact:** Every env-var-driven setting (`ROOM_PASSWORD`, `TURN_SECRET`, `MAX_CONNECTIONS_PER_IP`, `RING_TIMEOUT_MS`, `PORT`) falls back to defaults even when set in `.env`. An operator who sets `ROOM_PASSWORD` in `.env` and ships gets an **open room** with no password, believing it's protected. Highest-impact bug in the project.
- **Fix:** Add `require('dotenv').config()` at the top of `server.js`, before any `process.env` reads.
- **Status:** DONE

### 2. Per-IP cap is defeated by any reverse proxy
- **Location:** `server.js:278` reads `socket.handshake.address`; server is designed to sit behind a TLS-terminating proxy (`server.js:762-765`).
- **Impact:** Behind nginx/cloudflared, every connection's address is `127.0.0.1`, so `MAX_CONNECTIONS_PER_IP` becomes a cap on the entire server (default 5), or useless if the proxy is remote.
- **Fix:** Parse `x-forwarded-for` with a configured trusted proxy list; document the proxy requirement.
- **Status:** DONE

---

## High

### 3. Room password uses a fast hash, not a password KDF
- **Location:** `server.js:234-236` hashes `ROOM_PASSWORD` with a single SHA-256 round.
- **Impact:** `timingSafeEqual` rationale is good, but SHA-256 is not a password hash — a low-entropy room password is brute-forceable offline if the hash leaks.
- **Fix:** Use `crypto.scrypt` with a salt and work factor.
- **Status:** DONE

### 4. Socket.IO CORS is `origin: "*"` with no production gate
- **Location:** `server.js:84`. AGENTS.md flags this as dev-only, but there is no env-var check.
- **Impact:** In production, any malicious website can open a socket and attempt joins, spam public messages, or probe user lists.
- **Fix:** Gate on an `ALLOWED_ORIGIN` env var; default to `*` only when unset (preserve dev behavior).
- **Status:** TODO

### 5. Express CORS is wide open too
- **Location:** `server.js:26` `app.use(cors())` with no options.
- **Impact:** HTTP surface is small (`/api/ice-config`) but should still be restricted in production.
- **Fix:** Reuse the same `ALLOWED_ORIGIN` env var for Express CORS.
- **Status:** TODO

---

## Medium

### 6. No HTTP rate limit on socket connection endpoint
- **Location:** `express-rate-limit` at `server.js:30-35` only covers `/api/`. Socket.IO handshake is an HTTP upgrade with no Express-level limiter.
- **Impact:** Per-IP cap and per-socket event limiters mitigate, but a distributed attacker bypasses the IP cap; each unjoined socket still allocates a nonce, rate-limiter closures, and Map entries.
- **Fix:** Document the existing per-IP cap as the connection-rate defense; consider a Socket.IO `use()` middleware for connection-level throttling if needed.
- **Status:** TODO

### 7. Unbounded resource growth in `nickBindings`
- **Location:** `server.js:223`. Never pruned.
- **Impact:** For a long-lived process with high nick churn, this leaks memory.
- **Fix:** Add a TTL or LRU cap, or accept it given the "resets on restart" design.
- **Status:** TODO

### 8. `publicKey` (RSA session key) has no size/format validation
- **Location:** `server.js:341-349` validates `identityKey` and `signature` blobs but not `publicKey`.
- **Impact:** The signature binds it (authenticated), but a malicious client can send an arbitrarily large `publicKey` string.
- **Fix:** Add `isValidBlob(publicKey, MAX_KEY_BLOB)`.
- **Status:** TODO

### 9. Nick/about not trimmed or normalized server-side
- **Location:** `server.js:341` checks `!nick` and `nick.length > 15` but a nick of `"   "` (spaces) or zero-width characters passes. Client trims (`client.js:647`) but the server is the trust boundary.
- **Impact:** Homoglyph/whitespace nicks enable impersonation.
- **Fix:** Trim and reject empty-after-trim; optionally normalize Unicode.
- **Status:** TODO

### 10. Replay window of 5 minutes for signed messages
- **Location:** `server.js:157,428-430`. A captured signed message can be re-emitted for ~5 minutes and the server will accept it (producing a duplicate).
- **Impact:** Low for chat; server doesn't track seen nonces.
- **Fix:** Consider a short per-sender sequence or nonce cache if replay matters. Documented tradeoff acceptable for this app's threat model.
- **Status:** TODO

---

## Low

### 11. `io.emit('user_list', ...)` on every join/disconnect
- **Location:** `server.js:379-383,494-497`.
- **Impact:** Broadcasts the full list (with identity keys) to all sockets. Fine at `MAX_USERS=20`, but incremental `user_joined`/`user_left` events would reduce chatter under churn.
- **Fix:** Optional optimization; not a security issue at current scale.
- **Status:** TODO

### 12. Synchronous ECDSA verification on the event loop
- **Location:** `server.js:184-201` `verifyStringSignature` blocks the main thread.
- **Impact:** Fine at this scale; at higher load, move to a worker thread.
- **Fix:** Document as known limitation; revisit if load increases.
- **Status:** TODO

### 13. `/api/ice-config` is unauthenticated
- **Location:** `server.js:78-80`.
- **Impact:** Only returns STUN servers (TURN is gated), so impact is minimal, but it is public info disclosure with no rate-limit value beyond the `/api/` limiter.
- **Fix:** Acceptable given TURN is gated and the endpoint only exposes STUN. No change needed.
- **Status:** TODO

---

## Optimizations

### O1. `renderChatHistory()` rebuilds the full DOM on every message
- **Location:** `client.js:1156-1162`.
- **Impact:** O(n) per message. For long sessions this is wasteful.
- **Fix:** Append-only path for new messages; full render only on tab switch.
- **Status:** TODO

### O2. `state.history` grows unbounded in the client
- **Location:** `client.js` (all tab histories).
- **Impact:** A long-running tab with heavy traffic leaks memory.
- **Fix:** Circular buffer (e.g., keep last 500 per tab).
- **Status:** TODO

### O3. `String.fromCharCode(...new Uint8Array(buf))` spread on call stack
- **Location:** `client.js:169,224,266,295-297`.
- **Impact:** At the sizes here (SDP, signatures) it is safe, but for robustness large buffers could blow the stack.
- **Fix:** Chunked `fromCharCode.apply` or a binary-string loop helper.
- **Status:** TODO

### O4. Uniqueness check is O(n)
- **Location:** `server.js:368` `Array.from(users.values()).some(...)`.
- **Impact:** Irrelevant at `MAX_USERS=20`, but a `Set` of nicks would make it O(1) if the cap rises.
- **Fix:** Maintain a `Set` of in-use nicks alongside the `users` Map.
- **Status:** TODO

### O5. Tests inject env vars via `spawn`, masking the dotenv bug
- **Location:** `test-access-control.js:84` and similar.
- **Impact:** Test suite passes while manual `npm start` with a `.env` file ignores the password.
- **Fix:** Resolved by fixing Critical #1; tests continue to work via spawn injection.
- **Status:** TODO

---

## Work Log

(Entries appended here as fixes/optimizations are implemented.)

### 2026-07-22 — Fix #1 (Critical): dotenv loaded at startup
- Added `require('dotenv').config()` as the first line of `server.js`, before any `process.env` reads.
- `.env` is now parsed; `ROOM_PASSWORD`, `TURN_SECRET`, `MAX_CONNECTIONS_PER_IP`, `RING_TIMEOUT_MS`, and `PORT` are picked up from it as intended.
- Verified: server startup log reflects env vars; `test-access-control.js` still passes (it injects env via `spawn`, so it was already working — manual `npm start` with `.env` now works too).

### 2026-07-22 — Fix #2 (Critical): reverse-proxy support for per-IP cap
- Added `TRUST_PROXY` env var (integer hop count, e.g. `1` for a single nginx/cloudflared layer).
- When set, Socket.IO's `trustProxy` option is enabled so `socket.handshake.address` reflects the real client IP parsed from `X-Forwarded-For` instead of the proxy's address.
- When unset (default), behavior is unchanged — direct/localhost operation uses the TCP peer address.
- Updated the comment at the IP extraction point (`io.on('connection')`) to document the behavior.
- Verified: server starts cleanly with and without `TRUST_PROXY`; all existing tests pass.

### 2026-07-22 — Fix #3 (High): room password now uses scrypt
- Replaced the single-round SHA-256 hash of `ROOM_PASSWORD` with `crypto.scryptSync` (N=16384, r=8, p=1, 32-byte key, per-process random salt).
- The configured password is hashed once at startup; each candidate is hashed with the same salt+params before a `timingSafeEqual` comparison.
- Salt is regenerated per process (consistent with the app's no-persistent-store design) but still defeats precomputed rainbow tables for the process lifetime.
- ~100ms per verification — acceptable given the join rate limit (5/30s per socket) and 20-user cap.
- Verified: `test-access-control.js` — all 9 tests pass, including correct-password acceptance and wrong-password rejection.
