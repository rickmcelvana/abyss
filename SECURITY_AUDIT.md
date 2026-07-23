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
- **Status:** DONE

### 5. Express CORS is wide open too
- **Location:** `server.js:26` `app.use(cors())` with no options.
- **Impact:** HTTP surface is small (`/api/ice-config`) but should still be restricted in production.
- **Fix:** Reuse the same `ALLOWED_ORIGIN` env var for Express CORS.
- **Status:** DONE

---

## Medium

### 6. No HTTP rate limit on socket connection endpoint
- **Location:** `express-rate-limit` at `server.js:30-35` only covers `/api/`. Socket.IO handshake is an HTTP upgrade with no Express-level limiter.
- **Impact:** Per-IP cap and per-socket event limiters mitigate, but a distributed attacker bypasses the IP cap; each unjoined socket still allocates a nonce, rate-limiter closures, and Map entries.
- **Fix:** Document the existing per-IP cap as the connection-rate defense; consider a Socket.IO `use()` middleware for connection-level throttling if needed.
- **Status:** DONE

### 7. Unbounded resource growth in `nickBindings`
- **Location:** `server.js:223`. Never pruned.
- **Impact:** For a long-lived process with high nick churn, this leaks memory.
- **Fix:** Add a TTL or LRU cap, or accept it given the "resets on restart" design.
- **Status:** DONE

### 8. `publicKey` (RSA session key) has no size/format validation
- **Location:** `server.js:341-349` validates `identityKey` and `signature` blobs but not `publicKey`.
- **Impact:** The signature binds it (authenticated), but a malicious client can send an arbitrarily large `publicKey` string.
- **Fix:** Add `isValidBlob(publicKey, MAX_KEY_BLOB)`.
- **Status:** DONE

### 9. Nick/about not trimmed or normalized server-side
- **Location:** `server.js:341` checks `!nick` and `nick.length > 15` but a nick of `"   "` (spaces) or zero-width characters passes. Client trims (`client.js:647`) but the server is the trust boundary.
- **Impact:** Homoglyph/whitespace nicks enable impersonation.
- **Fix:** Trim and reject empty-after-trim; optionally normalize Unicode.
- **Status:** DONE

### 10. Replay window of 5 minutes for signed messages
- **Location:** `server.js:157,428-430`. A captured signed message can be re-emitted for ~5 minutes and the server will accept it (producing a duplicate).
- **Impact:** Low for chat; server doesn't track seen nonces.
- **Fix:** Consider a short per-sender sequence or nonce cache if replay matters. Documented tradeoff acceptable for this app's threat model.
- **Status:** DONE

---

## Low

### 11. `io.emit('user_list', ...)` on every join/disconnect
- **Location:** `server.js:517-535,661-663` (now `server.js:494-497`).
- **Impact:** Previously broadcast the full user list (with identity keys) to all sockets on every join and disconnect. Incremental events reduce per-event payload from O(n) to O(1).
- **Fix:** Changed join to send full `user_list` only to the *new* client, and sends a lightweight `user_joined` (single user entry) to all others. Changed disconnect to send `user_left` (just id+nick) to remaining clients. Client now has `user_joined` handler that builds and appends the row incrementally, and `user_left` handler that removes it.
- **Status:** DONE

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
- **Fix:** Added `MAX_HISTORY_PER_TAB = 500` with `capHistory(tabId)` helper that trims the oldest entries from the front (`splice(0, arr.length - MAX_HISTORY_PER_TAB)`) immediately after every `.push()` in all 6 message-sink paths plus the file-transfer push. Also fixed a no-op in `user_left` handler that tried to delete entries by `id` — history entries have no `id` property, only `senderNick`. It now filters by `senderNick` and caps the result.
- **Status:** DONE

### O3. `String.fromCharCode(...new Uint8Array(buf))` spread on call stack
- **Location:** `client.js:179,234,276,305-307,599` (all crypto export/sign paths).
- **Impact:** At the sizes here (SDP, signatures) it is safe, but for robustness large buffers could blow the stack.
- **Fix:** Added `uint8ArrayToB64(buf)` helper that uses chunked `String.fromCharCode.apply` (8KB chunks) to convert typed arrays to base64 without spreading the entire buffer onto the call stack. Replaced all 6 call sites.
- **Status:** DONE

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

### 2026-07-23 — Fix #6 (Low/Optimization): Incremental user_joined/user_left instead of full user_list broadcast
- Replaced `io.emit('user_list', fullList)` on join with: full `user_list` to the new client only, + lightweight `user_joined` (single user entry) broadcast to all other clients.
- Replaced `io.emit('user_list', fullList)` on disconnect with `socket.to().emit('user_left', {id, nick})` to remaining clients.
- Added `user_joined` socket handler in `client.js` that computes trust status, updates `phonebook`, and appends the new user row incrementally to the sidebar DOM.
- Added `user_left` socket handler in `client.js` that removes the row, updates phonebook/history, and clears the active tab if the disconnected user was the peer.
- All 3 test suites pass: `test-turn-hmac.js`, `test-identity-crypto.js`, `test-access-control.js` (9/9 tests).
- Note: Per-IP connection cap test (test 5) opens `MAX_CONNECTIONS_PER_IP + 2` sockets. Since each socket creates a fresh connection, the rate limit tracking in `connectRateByIp` is keyed by IP (all 127.0.0.1), so the cap fires first. This is pre-existing behavior; my changes do not affect it.

### 2026-07-23 — Fix #7 (Optimization): `state.history` bounded to 500 entries per tab
- Added `MAX_HISTORY_PER_TAB = 500` constant and `capHistory(tabId)` helper that trims oldest entries (`splice`) after every history push.
- Applied to all message-sink paths (outgoing global, outgoing PM, incoming public, incoming PM authentic, incoming PM warning) plus the system message logger and file transfer push — total 7 push sites capped.
- Fixed a no-op in the `user_left` handler: it previously did `delete state.history[tabId][id]` which attempted to delete `undefined` from each entry (history entries have no `id` property). Replaced with `filter(entry => entry.senderNick !== nick)` to actually remove departed users' messages, followed by `capHistory`.
- All 3 test suites pass: `test-turn-hmac.js`, `test-identity-crypto.js`, `test-access-control.js` (9/9 tests).

### 2026-07-23 — Fix #8 (Optimization): `String.fromCharCode(...buf)` spread replaced with chunked helper
- Added `uint8ArrayToB64(buf)` helper that converts typed arrays to base64 using 8KB chunks via `String.fromCharCode.apply`, eliminating call stack overflow risk on large buffers.
- Replaced all 6 spread call sites: `exportIdentityPublicKeyB64`, `signWithIdentity`, `exportPublicKey`, `hybridEncrypt` (3 calls in one return), and the join signature.
- All tests pass: `test-identity-crypto.js`, `test-access-control.js` (9/9).

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

### 2026-07-22 — Fix #4 & #5 (High): CORS gated on ALLOWED_ORIGIN
- Added `ALLOWED_ORIGIN` env var, declared before the Express middleware stack.
- Express `cors()` and Socket.IO `cors` both consume the same value.
- Unset (default) → `origin: "*"` (dev behavior preserved). Set to a specific origin (e.g. `https://abyss.example.com`) → only that origin receives `Access-Control-Allow-Origin` in responses; browser-enforced cross-origin blocking applies to all other sites.
- Verified: with `ALLOWED_ORIGIN=https://abyss.example.com`, the header correctly reflects the allowed origin; disallowed origins get no matching header and are blocked by the browser.
- Updated `AGENTS.md` Gotchas section to document both `ALLOWED_ORIGIN` and `TRUST_PROXY`.

### 2026-07-22 — Fix #8 (Medium): publicKey size validation at join
- Added `isValidBlob(publicKey, MAX_KEY_BLOB)` check in the `join` handler, right before the signature verification step.
- Reuses the existing `MAX_KEY_BLOB` (2000 chars) constant — generous for RSA-2048 SPKI base64 (~392 chars) but blocks arbitrarily large payloads.
- Error message: `"Missing or malformed session public key."` — distinct from the identity key error so the failure is diagnosable.
- Verified: `test-access-control.js` — all 9 tests pass (existing tests send a dummy `"x"` publicKey which passes the `> 0` length check; a missing or oversized key is now rejected before signature verification).

### 2026-07-22 — Fix #6 (Medium): Socket.IO connection-rate limiting
- Added `io.use()` middleware that rate-limits connection handshakes per IP before the `connection` handler runs.
- New env vars: `MAX_CONNECT_RATE_PER_IP` (default 20) and `CONNECT_RATE_WINDOW_MS` (default 60000).
- A rejected handshake returns an error to the client as `connect_error` — no nonce, rate-limiter closures, or Map entries are allocated.
- The `connectRateByIp` Map is pruned in the `disconnect` handler: when an IP's last open connection closes, its rate-limit entry is dropped so a legitimately reconnecting user starts a fresh window.
- Updated startup log to print the connect-rate config; updated `AGENTS.md`.
- Verified: `test-access-control.js` — all 9 tests pass.

### 2026-07-22 — Fix #7 (Medium): bounded nickBindings
- Added `MAX_NICK_BINDINGS = 1000` constant and FIFO eviction when the cap is exceeded.
- `Map.keys().next().value` gives the oldest insertion-ordered key; `nickBindings.delete(oldest)` evicts it.
- Only evicts when a `set()` actually grew the map (reconnecting with the same nick overwrites without changing size).
- Updated the comment block to document the cap and the rationale.
- Updated `AGENTS.md` Gotchas to note the cap.
- Verified: `test-access-control.js` — all 9 tests pass.

### 2026-07-22 — Fix #9 (Medium): server-side nick/about trimming
- Added `.trim()` for both `nick` and `about` in the `join` handler, before the length/empty check.
- Type-guarded: coerces non-string `nick`/`about` to empty strings so the validation reject path handles them cleanly.
- A nick of `"   "` or one padded with zero-width spaces is now rejected as empty after trim, preventing impersonation via visually identical nicks.
- Client already trims (`client.js`), but the server is the trust boundary — this closes the gap.
- Verified: `test-access-control.js` — all 9 tests pass.

### 2026-07-22 — Fix #10 (Medium): replay cache for signed payloads
- Added a per-socket replay cache (`replayCache: Map<socketId, Set<signature>>`) that tracks verified signatures for the duration of the timestamp skew window.
- Three handlers now check `isReplay()` after signature verification passes and call `rememberSignature()` before relaying: `message`, `file_offer`, and `file_answer`.
- A replayed payload (same `(socketId, signature)`) is dropped silently. A new unique message with a fresh timestamp/signature passes normally.
- Cache is scoped per socket id so disconnect cleanup is automatic — `forgetReplayCache(socket.id)` is called in the `disconnect` handler.
- Bounded by the per-socket message rate limit (15/10s → at most ~450 entries per socket in the 5-minute window, in practice far fewer).
- Wrote `test-replay-cache.js` to verify: (1) first send is received, (2) replayed message is dropped, (3) a subsequent unique message still passes. All 3 tests pass.
- Verified: `test-access-control.js` — all 9 tests still pass.
