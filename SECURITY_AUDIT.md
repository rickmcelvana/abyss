# Security Audit — Abyss.Tunnel

Audit performed on the current tree (`server.js`, `public/client.js`, `public/index.html`, `package.json`, config). Findings are grouped by severity. Each item references the file and line(s) where the issue lives, explains the risk, and proposes a concrete fix. The codebase is generally well-considered (E2EE, identity proof-of-possession at join, replay cache, per-socket rate limits, scrypt room password) — the items below are gaps in that surface, not a condemnation of it.

The threat model this app assumes (and documents in the README) is: **an honest-but-curious or fully malicious server**, plus unauthenticated peers sharing a single room. Memory-only state, resets on restart, and a 20-user cap are deliberate. Findings are judged against that model.

---

## Critical

### C1. `socket.to().emit(...)` broadcasts to nobody — join/leave notifications are silently dropped  ✅ FIXED
`server.js:530` and `server.js:660`

```js
socket.to().emit('user_joined', userEntry);   // line 530
socket.to().emit('user_left', { id: socket.id, nick: leavingUser?.nick });  // line 660
```

`socket.to(room)` adds `room` to the broadcast target set. Called with **no argument**, `room` is `undefined`; the Socket.IO in-memory adapter (`socket.io-adapter/dist/in-memory-adapter.js`, `apply()`) takes the `rooms.size` truthy branch and iterates `this.rooms.get(undefined)` — a room no socket ever joins — so the packet is delivered to **zero clients**. `socket.to()` is *not* a synonym for `socket.broadcast`; `newBroadcastOperator()` already excludes the sender, and the empty-arg `.to()` then narrows to an empty room on top of that. Verified against the installed `socket.io@4.8.3` adapter source.

**Security impact:** When a user joins, existing clients never receive `user_joined` (with the newcomer's `identityKey`). They only learn about the new user on the next `user_list` broadcast — which only fires on a fresh join (sent to the joiner itself, `server.js:524`) and never re-broadcast to the room. In practice the sidebar relies on these events, so peers' phonebooks and TOFU pins can lag, widening the window before a key-change/impersonation is flagged. It is also a plain availability/correctness bug: the user list drifts out of sync.

**Fix:** use `socket.broadcast.emit(...)`, which is the documented "everyone except me" primitive:
```js
socket.broadcast.emit('user_joined', userEntry);
socket.broadcast.emit('user_left', { id: socket.id, nick: leavingUser?.nick });
```
Add a regression assertion to one of the e2e presence tests that a *third* tab sees `user_joined`.

**Resolution (applied in this change):** Both `socket.to().emit(...)` calls in `server.js` were replaced with `socket.broadcast.emit(...)`, with an inline comment explaining why `to()` with no argument is a no-op so the regression is unlikely to be reintroduced. `socket.broadcast` is Socket.IO's intended "every connected socket except the sender" primitive — exactly what these two events need. After the fix:
- `user_joined` now reaches every other client on join, so peers receive the newcomer's `identityKey` immediately and can run their TOFU pin / key-change check without waiting for a re-broadcast. This closes the widened impersonation-detection window described above.
- `user_left` now reaches every remaining client on disconnect, keeping sidebars and phonebooks in sync without a full re-render.

No new state, no protocol change, no migration — purely a one-method swap on two lines. Behavior is otherwise identical (sender still excluded, payload unchanged).

---

## High

### H1. Replay cache is per-socket only — replay across two sockets of the same identity is not stopped  ✅ FIXED
`server.js:202-221`, message/file handlers at `server.js:582`, `server.js:875`, `server.js:889`

`isReplay(socketId, signature)` keys on the emitting socket id. A signature is a function of `<timestamp>:<content>` signed by the identity private key, and a single identity can open multiple sockets (different tabs, or an attacker who legitimately holds the key). The 5-minute timestamp skew window (`MESSAGE_TIMESTAMP_SKEW_MS`) bounds this, but within that window a captured signed payload can be re-injected from a *different* socket of the same identity and the server will accept it (a different `socketId` → empty cache entry). For private/file messages this produces a spurious duplicate on the recipient; for public messages it re-broadcasts.

This is a defense-in-depth layer (the client re-verifies signatures independently), so it is not a primary trust failure, but it weakens the stated goal of the cache.

**Fix options:**
- Key the replay cache on the identity fingerprint rather than (or in addition to) the socket id:
  `replayCache.get(fingerprint)?.has(signature)`. The fingerprint is already computed at join (`server.js:484`) and available from `users.get(socket.id)`.
- Alternatively, include the socket id in the signed string so a signature is bound to one connection (heavier change, breaks rejoin replay).

**Resolution (applied in this change):** Option 1 — the replay cache is now keyed on the identity fingerprint instead of the socket id. A signature is produced by an *identity* key, not any one socket, so deduplicating by fingerprint matches the actual trust unit and closes the cross-socket hole.

Changes in `server.js`:
- `replayCache` is now `Map<fingerprint, Set<signature>>`. `isReplay`/`rememberSignature` take a fingerprint instead of a socket id.
- The fingerprint is computed once at join (`fingerprintOf(identityKey)`, already done for the nick-binding check) and stored on the user record (`users.set(socket.id, { ..., fingerprint, ... })`), so the message/file handlers read `user.fingerprint` / `sender.fingerprint` with no extra hashing per event.
- The cache entry's lifetime is now tied to the *identity*, not a single socket, via a reference count (`identityRefCount: Map<fingerprint, number>`). `identityJoined(fingerprint)` increments on join; `identityLeft(fingerprint)` decrements on disconnect and only drops the cache when the last socket for that identity leaves. This keeps a second tab protected while the first disconnects, and prevents the cache from leaking after a real disconnect.
- A `MAX_REPLAY_BINDINGS = 1000` FIFO cap mirrors the existing `nickBindings` cap as defense-in-depth against pathological churn (the per-IP cap already bounds concurrent identities, but an explicit ceiling is cheap insurance).
- The old `forgetReplayCache(socketId)` on disconnect is replaced by `identityLeft(leavingUser.fingerprint)` inside the `if (leavingUser)` block, so a socket that never successfully joined doesn't touch the refcount.

Verification:
- `node test-replay-cache.js` — the existing same-socket replay checks still pass, and a new cross-socket regression block was added: socket A sends a signed message, a second socket B joined under the *same identity key* replays the exact payload, and the test asserts it is rejected while a genuinely new message from B still goes through. (6/6 checks pass.)
- `node test-access-control.js` — all 9 join/disconnect/rate-limit tests pass, confirming the refcount bookkeeping doesn't break join or disconnect.
- `node test-identity-crypto.js`, `node test-turn-hmac.js` — unaffected, still pass.

No protocol change, no client change, no migration. The cache is an internal server-side deduplication layer; its keying strategy is invisible to clients.

### H2. CSP allows `blob:` in `connect-src` but not the WebSocket origin for TURN/STUN — and lacks `wss:`/`ws:` clarity  ✅ FIXED
`server.js:19-26`

The custom CSP adds `'blob:'` to `connect-src` for file downloads. That is correct and well-reasoned. However:
- WebRTC's own media/ICE connections (`stun:`, `turn:`, `turns:`, `udp`) are **not** governed by `connect-src`, so they are unaffected — good. But `RTCDataChannel`/ICE that falls back to relaying over the TURN server using TCP/`wss`-style transports is also not blocked by CSP, so nothing is broken here; this is a note, not a defect.
- The Socket.IO transport uses the same origin as the page (`/socket.io/...`), covered by `'self'`. Fine.

The real gap: **`object-src` and `base-uri` inherit from `helmet`'s defaults**, which is good, but there is no explicit `frame-ancestors 'none'` / `frame-src 'none'`. The app is not designed to be embedded, and a malicious page could `<iframe>` it and attempt clickjacking on the call/file-accept dialogs (which have real consequences — accepting a call/file is a consent action). `helmet` sets `frame-ancestors` via `crossOriginResourcePolicy`? No — it sets it through `frameguard` only when enabled. Default `helmet()` includes `frameguard: { action: 'sameorigin' }`? Actually helmet's default `frameguard` sets `X-Frame-Options: SAMEORIGIN`, which protects against cross-origin framing; this is acceptable. Still, an explicit CSP `frame-ancestors 'none'` is stronger and survives if `frameguard` is ever disabled.

**Fix (minor):** add `'frame-ancestors': ['none']` to the CSP directives for defense in depth, since accept/call buttons are consent-gated.

**Resolution (applied in this change):** Added `'frame-ancestors': ["'none'"]` to the CSP `directives` block in `server.js`. Confirmed via `helmet.contentSecurityPolicy.getDefaultDirectives()` that the helmet default was `frame-ancestors: ["'self'"]` — i.e. same-origin framing was permitted, not denied. The app is never embedded and its call/file-accept buttons are consent-gated actions, so `'none'` is the correct policy: it forbids all framing (same- and cross-origin) and takes precedence over helmet's `frameguard` (`X-Frame-Options: SAMEORIGIN`) in browsers that support both CSP and XFO, while also remaining effective on the off chance `frameguard` is ever disabled.

No change to `connect-src` was needed: WebRTC ICE/TURN (`stun:`/`turn:`/`turns:`/udp) is not governed by `connect-src`, and Socket.IO runs on the page's own origin (`'self'`). The existing `connect-src: ['self', 'blob:']` is correct for the file-download path it was designed for.

Verification:
- `node --check server.js` — passes.
- `node test-access-control.js` — all 9 tests pass; the server boots with the updated helmet middleware stack and responds normally.

No client change, no protocol change, no migration. The CSP header is the only thing that changed.

### H3. Public-key import does not validate that the key is actually an RSA key, or the right size  ✅ FIXED
`public/client.js:331-337`

`importPublicKey` imports any SPKI blob as `RSA-OAEP` with `hash: SHA-256` and `modulusLength` not re-checked. Web Crypto will throw on malformed input (so it fails closed — good), but a 1024-bit RSA key supplied by a malicious peer would import and be used for `hybridEncrypt`. The session encryption layer is forward-secure-ish (fresh AES key per message), but a weak peer RSA key means an attacker who records ciphertext could later brute-force the RSA-wrapped AES key. There is no server-side enforcement of RSA key strength either; the join only checks `MAX_KEY_BLOB` size (`server.js:472`).

The client generates its own key at 2048 bits (`RSA_PARAMS`, `client.js:110`), but accepts whatever a peer presents.

**Fix:** after importing, export the key and check `algorithm.modulusLength >= 2048`; reject smaller. Or have the server verify key parameters at join (parse the SPKI DER, assert modulus length). Low-effort, high-value.

**Resolution (applied in this change):** Defense-in-depth on **both** sides, matching the app's "each client independently verifies; the server may be malicious" trust model.

**Server (`server.js`):**
- Added `isAcceptableRsaPublicKey(publicKeyB64)` (near `fingerprintOf`). It parses the SPKI DER via `crypto.createPublicKey` and asserts `asymmetricKeyType === 'rsa'` AND `asymmetricKeyDetails.modulusLength >= 2048`. Malformed keys are caught and fail closed (`return false`). `MIN_RSA_MODULUS = 2048`.
- Wired into the `join` handler right after the `publicKey` blob-size check, before signature verification: a sub-2048 or non-RSA session key is rejected with `"Session encryption key must be RSA-2048 or stronger."` and never enters the phonebook. This is the primary gate — a weak key can't reach any peer.
- Node's `createPublicKey` exposes `asymmetricKeyType` and `asymmetricKeyDetails.modulusLength` directly (verified for 512/1024/2048/3072-bit keys), so no manual DER parsing is needed.

**Client (`public/client.js`):**
- `importPublicKey` now imports the key, then checks `keyObj.algorithm.modulusLength >= 2048` and `throw`s if it's smaller (or if `algorithm` is missing). This is the client-side trust anchor: even a fully malicious server that relays a crafted weak key can't make a recipient encrypt to one. Every caller already wraps `importPublicKey` in a `try` (message send, call initiation, file transfer) or fire-and-forgets it (a console error is the right outcome for an unrecoverable malicious-server case). The error message includes the actual modulus length for debugging.

`connect-src` CSP is unaffected; this is a crypto-strength check, not a network policy change.

Verification:
- New `node test-rsa-key-strength.js` — 7/7 checks: rejects RSA-512, RSA-1024, EC P-256, garbage, empty string; accepts RSA-2048 and RSA-3072.
- `node test-identity-crypto.js`, `node test-turn-hmac.js` — unaffected, pass.
- `node test-access-control.js` — all 9 tests pass. Updated the test harness to generate a real RSA-2048 session key (the old `"x"` stand-in now correctly fails the strength check); the intentional-garbage flood test (Test 6) still produces a validation error as expected.
- `node test-replay-cache.js` — all 6 tests pass. Same harness update; the cross-socket block uses a real RSA-2048 key for the second socket's join.
- `test-calls.js` — harness updated to use real RSA-2048 session keys so legitimate joins and the stale-nonce-rejection test (0g) exercise their intended code paths (the stale-nonce test now actually tests signature rejection, not key-strength rejection).

No protocol change. A client that was somehow generating a <2048-bit RSA session key would now be rejected at join; the client's own `RSA_PARAMS` already specifies 2048 bits (`client.js:110`), so no conforming client is affected.

---

## Medium

### M1. `typeof timestamp !== 'number'` accepts `Infinity`, `NaN`, and very large numbers  ✅ FIXED
`server.js:572-575`, `server.js:872-873`, `server.js:886-887`

The check is `typeof timestamp !== 'number'` followed by `Math.abs(Date.now() - timestamp) > SKEW`. `Infinity`/`NaN`:
- `Math.abs(Date.now() - NaN)` → `NaN`; `NaN > SKEW` is `false`, so the skew check **passes** for `NaN` and the message proceeds to signature verification. A signature over `NaN:<content>` is meaningless, but an attacker who can sign arbitrary strings with their own identity key (they hold it) could craft a valid signature over `NaN:...`. This is not directly exploitable (it's their own key), but it lets garbage through that pollutes replay/verification semantics and can confuse clients that render `${timestamp}`.
- `Math.abs(Date.now() - Infinity)` → `Infinity`; `Infinity > SKEW` is `true` → rejected. OK.

**Fix:** tighten to `Number.isFinite(timestamp)`.

**Resolution (applied in this change):** Replaced `typeof timestamp !== 'number'` with `!Number.isFinite(timestamp)` at all three call sites (the `message` handler and the `file_offer`/`file_answer` handlers). `Number.isFinite` is strictly tighter than the `typeof` check: it returns `false` for `NaN`, `Infinity`, `-Infinity` (which `typeof 'number'` admits) *and* for non-number values (strings, `null`, `undefined`, booleans) which `typeof` already rejected — so no previously-valid payload is newly dropped, and the `NaN`-through-the-skew-check hole is closed. Verified the truth table: `Number.isFinite(NaN/Infinity/-Infinity/'now'/null/undefined) === false`, `Number.isFinite(Date.now()) === true`.

No change to the skew check itself (`Math.abs(Date.now() - timestamp) > MESSAGE_TIMESTAMP_SKEW_MS`) — it remains the second line of defense for out-of-range but finite timestamps.

Verification:
- `node test-replay-cache.js` — added a regression block that signs and sends messages with `NaN`, `Infinity`, and `-Infinity` timestamps (each with a valid identity signature, so only the timestamp check can drop them) and asserts none increment the receiver's count. All 7 checks pass (the existing 6 + the new one).
- `node test-access-control.js` — 9/9 pass; legitimate messages with real `Date.now()` timestamps still flow.
- `node test-rsa-key-strength.js`, `node test-identity-crypto.js`, `node test-turn-hmac.js` — unaffected, pass.

No protocol change. A conforming client always sends `Date.now()` (a finite integer), so no legitimate message is affected.

### M2. `isValidBlob` checks length but not content; signaling blobs are relayed verbatim to other peers
`server.js:178-180`, relay at `server.js:820-823`, `server.js:839`, `server.js:848`, `server.js:878`, `server.js:892`, `server.js:900`

SDP/ICE/answer blobs are described as "client-encrypted opaque strings" and the server "never parses them." That is a sound design. The risk: `isValidBlob` only asserts `typeof string && length <= maxLen`. The server then forwards `io.to(recipientId).emit(...)` to a single peer, which is fine. But for `file_offer`/`file_answer` the relayed blob is what the *recipient* decrypts with RSA-OAEP; a malicious sender can send a 100 KB blob that, once RSA-decrypted, yields a crafted JSON with an oversized `size` or a hostile `name`/`mimeType`.

The client does bound `payload.size` against `MAX_FILE_SIZE` (`client.js:3522`), and the download path uses `textContent`/`download` attribute (no HTML injection — see G1). However:
- `payload.name` is rendered via `textContent` (safe) **and** used as the `<a download>` attribute and as the OS-suggested filename. A name like `"../../...."` or with embedded NULs/newlines is browser-handled safely for `download`, but a name with a misleading extension combined with a chosen `mimeType` (e.g. `application/pdf` with a `.txt`-looking name) is a classic social-engineering vector for "open after download."
- The blob's `type` is taken verbatim from the sender (`t.historyRef.mimeType`, `client.js:3322`). A sender can set `mimeType: 'text/html'`; if a recipient were ever to navigate to the blob URL (not just download), it would render. The app uses `<a download>`, which forces download, so this is contained — but the CSP allowing `blob:` in `connect-src` plus an `<img>`/`<iframe>` future use of `downloadUrl` could turn it into a stored-XSS-in-blob. Today it is safe; it is a latent footgun.

**Fix (defense-in-depth):**
- On the receiver, strip/restrict `mimeType` to a known-safe set, or force `application/octet-stream` and ignore the sender's type. The `download` attribute already prevents navigation, so this is belt-and-suspenders.
- Sanitize `payload.name` to a basename (strip path separators, control chars) before using it for `download`.
- Consider signing the *offer metadata* (`name`/`size`/`mimeType`) rather than only the SDP offer, so a tampered relayed blob can't substitute different metadata. Currently the signature is over `${timestamp}:${offer}` where `offer` is the encrypted SDP, not the decrypted metadata — so a malicious server *could* re-encrypt a different metadata payload? No — the server can't re-encrypt (it lacks the peer's RSA key). But it could drop and replay; the metadata is inside the encrypted envelope, so integrity of metadata relies on RSA/OAEP correctness, which is sound. The main residual is a *malicious sender*, which is the threat model's peer-not-server case, and the sender is the one who chose the metadata anyway. Net: low risk, keep the receiver-side `mimeType`/`name` hardening.

### M3. `socket.handshake.address` is used for the per-IP cap and rate limit, but TRUST_PROXY defaults to off
`server.js:379-385`, `server.js:395-402`

Without `TRUST_PROXY`, every connection behind a reverse proxy appears to come from the proxy's IP, so the per-IP cap collapses to "max `MAX_CONNECTIONS_PER_IP` sockets across the *entire* proxied user base." The README documents `TRUST_PROXY`, but the default is the insecure-for-production value, and there is no startup warning when `ALLOWED_ORIGIN` is set (implying production) but `TRUST_PROXY` is not.

**Fix:** at startup, if `ALLOWED_ORIGIN` is set (production-looking) and `TRUST_PROXY` is unset, log a prominent warning that the per-IP cap is ineffective behind a proxy unless `TRUST_PROXY` is configured. Low-effort, prevents a silent misconfiguration.

### M4. No `pingTimeout`/`pingInterval` or `maxHttpBufferSize` hardening on Socket.IO
`server.js:104-112`

The `Server` constructor sets only `cors` and optionally `trustProxy`. Defaults:
- `maxHttpBufferSize` defaults to 1 MB. Signaling blobs are capped server-side (`MAX_SDP_BLOB = 100000`), but a malicious client can still send a 1 MB Engine.IO frame before the `isValidBlob` check runs; the buffer is allocated and parsed. With the 20-user cap this is bounded, but tightening `maxHttpBufferSize` to ~256 KB matches the actual max payload (100 KB SDP + envelope) and reduces memory pressure during a flood.
- No explicit `pingTimeout`/`pingInterval`; defaults are usually fine but not tuned for a mobile-friendly app (the README stresses mobile).

**Fix:** set `maxHttpBufferSize: 256 * 1024` and consider `pingInterval: 10000`, `pingTimeout: 20000`.

### M5. `express.json()` has no `limit`
`server.js:38`

`express.json()` with no `limit` defaults to 100 KB, which is fine — but the only JSON endpoint is `/api/ice-config` (GET, no body). `express.json()` is therefore dead middleware (no POST/PUT routes) that still parses any POST body up to 100 KB. Harmless, but remove it (or set an explicit small `limit: '1kb'`) to avoid surprise.

### M6. `generateTurnCredential` uses `socket.id` as the identifier — predictable and per-session
`server.js:75-83`, used at `server.js:548`

The TURN username is `<expiry>:<socket.id>`. `socket.id` is public (relayed to peers in `user_list`/call signaling) and predictable. That's fine for coturn REST auth (the credential is HMAC'd with the secret, and the username is meant to be public), but it means a credential issued to socket A is valid for *any* TURN allocation under that username until expiry — and the username is just the socket id, which a peer knows. A peer could use A's TURN credential from a different machine within the TTL window. coturn REST credentials are not bound to an IP by default.

**Fix:** include a random component in the identifier (e.g. `${expiry}:${socket.id}:${crypto.randomBytes(8).toString('hex')}`) so the username is not guessable/observable from signaling traffic, and/or configure coturn with an IP allowlist. Low severity (TURN bandwidth is the resource at risk, and TTL is bounded), but worth noting.

---

## Low / Hardening

### L1. No `Strict-Transport-Security` header, and the server binds to plain HTTP on `127.0.0.1`
`server.js:933`

Intended for a TLS-terminating proxy in front. HSTS must be set by the proxy (or by helmet once TLS is terminated). If someone runs `node server.js` directly exposed (e.g. via a port forward) without TLS, calls silently fail (getUserMedia needs secure context) but chat still works in the clear. Document loudly; consider refusing to start if `PORT`-bound on a non-loopback interface without `ALLOWED_ORIGIN` set.

### L2. `console.log` of join attempts includes the nick but not PII; disconnect logs include socket ids
`server.js:388`, `server.js:450`, `server.js:661`
Acceptable for a local dev server. In a multi-tenant/proxy deployment these logs could correlate nicks to IPs (behind the proxy). Ensure the deployment guide notes log retention.

### L3. `MAX_NICK_BINDINGS = 1000` FIFO eviction can free a *used* nick's binding, allowing takeover
`server.js:292`, `server.js:508-511`

When the map reaches 1000 entries, the oldest binding is evicted. If that oldest entry is a nick that is currently *in use* by an active user, eviction removes the nick→fingerprint binding, after which a different identity could claim that nick on join. With only 20 concurrent users this is very unlikely to be hit organically, but a churn-flood attack (rapid joins under many nicks, within the per-IP cap) could push a target's binding out and then steal the nick.

**Fix:** never evict a binding for a nick that is currently in `nicksInUse`. On eviction, skip entries whose nick is in `nicksInUse`.

### L4. Identity fingerprint truncated to 16 bytes (128 bits) for display — fine — but the *binding* key is the full SHA-256
`server.js:271-273` (full hash) vs `client.js:239` (16-byte display)
Consistent and correct; just noting the display fingerprint (16 bytes / 32 hex chars shown as 8 groups of 4) is shorter than the bound fingerprint. No issue.

### L5. `verifyStringSignature` returns `false` on any parse error, but does not distinguish key-parse failure from signature mismatch
`server.js:247-264`
Correct fail-closed behavior. No change needed; noted for clarity.

### L6. No CSRF protection on the single REST endpoint
`server.js:89` — `GET /api/ice-config` returns STUN servers only (no TURN, no secret). GET is not CSRF-exploitable for state changes, and there is no state to change. Fine.

### L7. `.env` is gitignored (verified) — good. The committed `.env` is empty.
No secret leakage in the repo.

### L8. `puppeteer-core` and `socket.io-client` are in `dependencies` not `devDependencies`
`package.json:13-20`. Documented in AGENTS.md as intentional-ish ("only needed for tests"). For a production install (`npm install --omit=dev`) these ship anyway. Move to `devDependencies` to slim the production footprint and reduce attack surface from test-only packages in prod. (AGENTS.md already flags this; restating as an optimization.)

---

## Optimizations (non-security, or security-adjacent perf)

### O1. `replayCache` Set is never pruned per-socket
`server.js:202-217`
Bounded implicitly by the 15-msg/10s rate limit (~450 entries in 5 min). For 20 users this is ~9 KB. No action needed; the comment is accurate. Noted only to confirm the bound holds.

### O2. `uint8ArrayToB64` uses `String.fromCharCode.apply` in 8 KB chunks
`public/client.js:57-69`
Correct and avoids stack overflow. For very large blobs (file chunks) a `FileReader`/`btoa` over a `Blob` slice would be faster, but the current path is for keys/signatures (small). File chunks are sent as `ArrayBuffer` over the data channel, not base64-encoded, so this is not on the hot path. Fine.

### O3. `appendMessage` rebuilds DOM per message; `renderChatHistory` does a full `innerHTML = ''` + re-render
`public/client.js:1333-1338`, `client.js:1463-1499`
For 500-message tabs the re-render is O(n) and acceptable. The append path is already O(1) (per the recent commit `3487d76`). The only optimization: `renderChatHistory` could use a `DocumentFragment` instead of repeated `appendChild` to `messageDisplay` to avoid layout thrash. Minor.

### O4. `user_list`/`user_joined` handlers `await Promise.all` over trust checks before rendering
`public/client.js:891-897`
Correct (prevents a "trusted → warning" flicker). If a contact's IndexedDB read is slow this serializes the whole list render; acceptable for ≤20 users.

### O5. The `createLimiter` fixed-window counter resets the window on first call *after* the boundary
`server.js:340-352`
Documented. A burst at the boundary allows ~2x in a brief window. At these limits (message 15/10s) it is harmless. If you want exactness, a token bucket (or `express-rate-limit`'s sliding window) is a drop-in, but the comment correctly judges the tradeoff. No change.

### O6. `callSessions` cleanup on disconnect iterates all sessions
`server.js:167-173`
Bounded by `MAX_GROUP_SIZE = 4` per socket. Fine.

---

## Summary table

| ID | Severity | Area | One-liner |
|----|----------|------|-----------|
| C1 | Critical (✅ fixed) | `server.js:530,660` | `socket.to().emit` sends to nobody; now uses `socket.broadcast.emit` |
| H1 | High (✅ fixed) | `server.js:202` | Replay cache now keyed on identity fingerprint (was per-socket) |
| H2 | High (✅ fixed) | `server.js:19-26` | Added explicit `frame-ancestors 'none'` to CSP (was helmet's `'self'`) |
| H3 | High (✅ fixed) | `client.js:331`, `server.js` join | Server rejects <RSA-2048 session keys at join; client throws on import |
| M1 | Medium (✅ fixed) | `server.js:572` | `timestamp` now checked with `Number.isFinite` (rejects NaN/±Infinity) |
| M2 | Medium | `client.js:3522,3322` | Harden receiver-side `name`/`mimeType` for file transfers |
| M3 | Medium | `server.js:100` | Warn when `ALLOWED_ORIGIN` set but `TRUST_PROXY` unset |
| M4 | Medium | `server.js:104` | Set `maxHttpBufferSize`, `pingInterval`, `pingTimeout` |
| M5 | Medium | `server.js:38` | `express.json()` is unused; remove or set `limit` |
| M6 | Medium | `server.js:75` | TURN username is the public socket id; add randomness |
| L1–L8 | Low | various | HSTS guidance, nick-binding eviction, dev-deps cleanup, etc. |
| O1–O6 | Opt | various | Documented/bounded; optional `DocumentFragment` render, etc. |

---

## What's done well (so it isn't "fixed" away)

- **E2EE of messages and signaling**: RSA-OAEP/AES-GCM hybrid, signatures over ciphertext, verify-before-decrypt (`client.js:1644-1656`).
- **Identity proof-of-possession at join** with a single-use nonce binding the session key to the long-term identity (`server.js:440-477`, `client.js:642-653`).
- **TOFU pinning + explicit verification** with a "blocked until resolved" path on key change (`client.js:250-277`, `client.js:317-323`, `client.js:1146-1176`).
- **Defense-in-depth signature verification** on both server and client, where the client's pin is the actual trust anchor.
- **Constant-time room password** comparison with scrypt (`server.js:319-324`).
- **All untrusted content rendered via `textContent`** — no `innerHTML` interpolation of nicks/abouts/messages (verified across `client.js`). No XSS sink found in the message/call-log/file paths.
- **Per-socket, per-event rate limits** with escalating strikes → disconnect (`server.js:410-438`).
- **TURN credentials gated behind joined sockets** and never exposed to the unauthenticated REST endpoint (`server.js:89-91`, `server.js:542-551`).
- **Nonce/HMAC TURN credential** derivation, short-lived (`server.js:75-83`).
- **`.env` gitignored**, empty in the repo.