# Abyss.Tunnel

A small, ephemeral, end-to-end encrypted chat room with encrypted voice calls. No accounts, no database, no message history on disk — pick a nickname, talk, close the tab, it's gone.

Built as a single flat chat room (`#twistedminds`) for up to 20 concurrent users, with private messaging, WebRTC voice calls, and a persistent per-device identity used to detect if someone's encryption key changes underneath you.

## Features

- **Group chat** in one shared room, plus **private 1:1 messages** in separate tabs
- **End-to-end encrypted messages** — hybrid RSA-OAEP/AES-GCM, so the server only ever relays ciphertext
- **Encrypted voice calls** over WebRTC (DTLS-SRTP), with call signaling itself also end-to-end encrypted so the server can't read or tamper with call setup
- **Verbal safety codes** per call — a short number both people read aloud to confirm nobody's in the middle
- **Call features**: mute, live duration timer, connection-quality indicator, ringtones, a call log with missed/declined/no-answer history and one-click callback, and glare handling for simultaneous mutual calls
- **TURN support** with time-limited, HMAC-signed credentials (works with any [coturn](https://github.com/coturn/coturn)-compatible server) for callers behind restrictive NATs
- **Persistent device identity** — a long-term signing key, generated once per browser, used to detect if a contact's key changes later (see [Security & Trust Model](#security--trust-model))
- **Typing indicators and presence** — see who's actively typing in a conversation, and an active/idle dot next to each name in the room
- **Graceful reconnection** — a dropped connection (wifi blip, brief server hiccup) silently rejoins in the background; chat history and open tabs survive it
- **Per-user message coloring** and **opt-in desktop notifications** — an unread badge in the tab title always works, and click-to-enable browser notifications for messages/calls when the tab isn't focused
- **Video calling** — turn your camera on mid-call from either side, independently; the call itself starts as audio, video is an in-call upgrade
- **Encrypted peer-to-peer file transfer** — send a file directly to someone in a private conversation; it flows over its own WebRTC data channel, never through the server
- **A real mobile layout** — a slide-out drawer for the user list instead of a fixed desktop sidebar, a call bar and video panel sized for a phone screen, no horizontal overflow
- **Keyboard and screen reader support** — every custom control (tabs, user rows, the sidebar drawer, incoming-call/file modals) is fully keyboard-operable with proper ARIA roles, live-region announcements, and focus management
- **Group calls** — add someone to a call you're already on; everyone connects directly to everyone else (mesh), capped at 4 people, with video and a verbal safety code for every pairwise connection, not just the original pair

## Requirements

- **Node.js 18+** (developed and tested on Node 22). The server uses Node's built-in `crypto.webcrypto` for identity signature verification, which needs a reasonably modern Node version.
- **npm** (comes with Node)
- **A modern browser** — the client uses Web Crypto, WebRTC, and IndexedDB. Any current Chrome, Firefox, Safari, or Edge works.
- **HTTPS, for calls to work beyond your own machine.** `getUserMedia()` (microphone access) is only allowed in a [secure context](https://developer.mozilla.org/en-US/docs/Web/Security/Secure_Contexts): `https://` or `http://localhost`. The server itself only speaks plain HTTP and binds to `127.0.0.1`, so any real deployment needs a TLS-terminating reverse proxy or tunnel in front of it — nginx + Let's Encrypt/certbot, Caddy, [cloudflared](https://github.com/cloudflare/cloudflared), or [ngrok](https://ngrok.com/) all work. Chat still works without this; only voice calls require it.
- **(Optional) A TURN server**, e.g. [coturn](https://github.com/coturn/coturn), if you want calls to succeed between users on restrictive/symmetric NATs (common on mobile networks and some corporate/campus Wi-Fi). Without one, calls fall back to STUN only, which works for most home networks but not all.

## Setup

```bash
git clone <this-repo>
cd abyss
npm install
npm start
```

The server starts on `http://127.0.0.1:3000` by default. Open it in a browser, pick a nickname, and you're in.

To talk to someone else, they need to reach the same server — either you're both on the same machine/network, or you've put it behind a reverse proxy/tunnel as described above.

### Environment variables

All optional; the app runs with sensible defaults if you set none of them.

| Variable | Default | Purpose |
|---|---|---|
| `PORT` | `3000` | Port the server listens on |
| `RING_TIMEOUT_MS` | `30000` | How long an unanswered call rings before auto-resolving to "no answer" / "missed" |
| `TURN_URL` | *(unset)* | URL of your TURN server, e.g. `turn:turn.example.com:3478`. Leave unset to use STUN only. |
| `TURN_SECRET` | *(unset)* | Shared secret with your coturn instance's `static-auth-secret`. Required if `TURN_URL` is set. **Never** the TURN username/password directly — the server derives short-lived credentials from this. |
| `TURN_TTL_SECONDS` | `14400` (4h) | How long each generated TURN credential stays valid |
| `ROOM_PASSWORD` | *(unset)* | If set, joining requires this password. Leave unset for an open room (the default for every prior phase). Compared via hashed, constant-time comparison — the plaintext is never stored. |
| `MAX_CONNECTIONS_PER_IP` | `5` | Max simultaneous sockets allowed from one IP address. A best-effort abuse deterrent, not strong access control (see [Security & Trust Model](#security--trust-model)). |

Example with TURN and a room password configured:

```bash
TURN_URL="turn:turn.example.com:3478" \
TURN_SECRET="your-coturn-static-auth-secret" \
ROOM_PASSWORD="letmein" \
npm start
```

### Running the tests

The test suite isn't wired into `npm test` (there's no test runner config); run the files directly with Node. A running server is required for everything except the two crypto unit tests.

```bash
# Unit tests (no server needed)
node test-turn-hmac.js          # TURN credential HMAC generation, independent of server.js
node test-identity-crypto.js    # Identity signature verification, independent of server.js

# Integration tests (start the server first, in another terminal)
npm start
node test-calls.js              # Signaling, identity join flow, ring timeout, glare, etc.

# Self-contained (spawns and manages its own server instance - just run it)
node test-access-control.js     # Room password, per-IP connection cap, per-socket rate limits

# Browser end-to-end tests (require Chrome + puppeteer-core; server must be running)
node test-audio-e2e.js              # Real two-browser WebRTC call, audio, mute, quality, glare
node test-identity-e2e.js           # Identity persistence, verify flow, key-change blocking
node test-message-signing-e2e.js    # Signed chat messages, and the unverifiable-message warning
node test-reconnection-e2e.js       # Network drop, silent rejoin, no reload, active call ends cleanly
node test-presence-e2e.js           # Typing indicators and active/idle presence dots
node test-message-polish-e2e.js     # Per-user nick colors, unread badge, desktop notifications
node test-video-call-e2e.js         # Mid-call video toggle, renegotiation, bidirectional video
node test-file-transfer-e2e.js      # Real file transfer, byte-for-byte hash verification, decline/cancel
node test-mobile-responsive-e2e.js  # Phone-width layout: sidebar drawer, no overflow, scaled video panel
node test-accessibility-e2e.js      # Real keyboard-only navigation, focus trapping, ARIA, XSS fix proof
node test-group-call-e2e.js         # Real 3-way mesh call, partial hangup, decline, size cap
node test-group-video-safety-e2e.js # Video and matching safety codes for every pairwise connection
```

`test-calls.js` specifically needs a higher `MAX_CONNECTIONS_PER_IP` than the default when you run it, since its group-call tests alone open 6 simultaneous connections from one machine:

```bash
RING_TIMEOUT_MS=3000 MAX_CONNECTIONS_PER_IP=20 npm start   # in one terminal
RING_TIMEOUT_MS=3000 node test-calls.js                    # in another
```

The browser tests launch Chrome via `puppeteer-core` and expect a Chrome binary at a hardcoded path (see `CHROME` at the top of each file) — update that path if yours differs, or point it at a system Chrome/Chromium install. `puppeteer-core` and `socket.io-client` are currently listed as regular `dependencies` in `package.json` even though only the test suite needs them; if you're trimming a production install, they (along with the `test-*.js` files) can be left out.

## Project structure

```
server.js           Signaling + relay server (Express + Socket.IO)
public/
  index.html         App shell
  client.js          All client-side logic: crypto, WebRTC, UI, IndexedDB
  style.css          Styling
test-turn-hmac.js         Unit: TURN credential generation
test-identity-crypto.js   Unit: identity signature verification
test-calls.js             Integration: signaling, identity, calls, ring timeout, glare
test-access-control.js    Self-contained: room password, IP cap, per-socket rate limits
test-audio-e2e.js         Browser E2E: real encrypted call over two Chrome instances
test-identity-e2e.js      Browser E2E: identity persistence, verification, key-change blocking
test-message-signing-e2e.js  Browser E2E: signed chat messages, unverifiable-message warning
test-reconnection-e2e.js     Browser E2E: network drop, silent rejoin, active call ends cleanly
test-presence-e2e.js         Browser E2E: typing indicators, active/idle presence dots
test-message-polish-e2e.js   Browser E2E: nick colors, unread badge, desktop notifications
test-video-call-e2e.js       Browser E2E: mid-call video toggle, renegotiation, bidirectional
test-file-transfer-e2e.js    Browser E2E: real P2P file transfer, byte-for-byte hash verification
test-mobile-responsive-e2e.js  Browser E2E: phone-viewport layout, sidebar drawer, no overflow
test-accessibility-e2e.js    Browser E2E: keyboard navigation, focus trapping, ARIA, XSS fix proof
test-group-call-e2e.js       Browser E2E: real 3-way mesh call, partial hangup, decline, size cap
test-group-video-safety-e2e.js  Browser E2E: group video + matching safety codes on every pairwise leg
```

The server holds no database and no files on disk for app data — everything (connected users, active calls, ring timers) lives in memory and is gone on restart. The client persists exactly two things in `IndexedDB`, both local to that browser: your own identity keypair, and the fingerprints you've pinned for people you've talked to.

## Security & Trust Model

This section is the important one if you're deciding whether to actually use this for anything sensitive. Short version: it's solid for casual, ephemeral, small-group use; it is **not** a Signal-grade protocol, and there are specific gaps below worth knowing about.

### What's encrypted, and how

- **Chat messages** use hybrid encryption: each session generates an RSA-OAEP keypair; to send a message, the client generates a fresh AES-GCM key, encrypts the message with it, then wraps the AES key with the recipient's RSA public key. The server relays only these encrypted blobs — it can see who's messaging whom and when (metadata), but not private-message content. Public/global messages aren't encrypted (there's no secret to protect in a message everyone in the room can already read), but every message — public or private — is **signed with the sender's long-term identity key** before it's sent, and independently re-verified by each recipient against the fingerprint they've pinned for that nick. This closes a gap that existed through the earlier phases: without it, a fully malicious server (which already holds everyone's public keys, since it relayed them) could fabricate a message and attribute it to someone else. Signing means the server can no longer do that — it never holds anyone's identity *private* key. Verification happens before decryption, not after, so a forged or tampered private message is rejected without ever being decrypted; a message that fails verification renders as a plain "unverifiable" bubble with no content shown, rather than displaying content the app can't actually vouch for. Messages also carry a timestamp and are rejected if too old — a basic blunt-force replay guard, not a full anti-replay nonce cache (see limitations below).
- **Voice and video calls** are encrypted twice over. The media itself uses DTLS-SRTP, which is mandatory in WebRTC and flows directly peer-to-peer, never through the server — this applies equally to audio and video, since video is just another track on the same encrypted connection. On top of that, the *call setup* (SDP offers/answers, ICE candidates) is also encrypted with the same hybrid RSA/AES scheme before being relayed, so the server can't read or tamper with call negotiation either — it only ever sees opaque, size-checked blobs. Turning a camera on mid-call re-negotiates the same connection (a second signed, encrypted offer/answer exchange over the same session) rather than starting a new one, so nothing about the video path is less protected than the audio that was already flowing.
- **File transfers** work the same way calls do, and deliberately don't add a third layer of encryption on top: the file itself flows over its own dedicated WebRTC data channel — independent of any call, established on demand when you send a file — which runs over mandatory DTLS just like call media does. The *offer that establishes it* (which also carries the filename and size, since those are private too) is signed and encrypted exactly like a call's SDP or a private message, so the server can't fabricate a fake "incoming file" appearing to be from someone, and can't read the filename before you've even decided whether to accept it. The server never sees file content at any point — not even in passing, not even encrypted — since it's never in the path once the connection is up.
- **Group calls are mesh, not relayed through a server** — every participant connects directly to every other participant, so a 4-person call is 6 independent, individually encrypted peer-to-peer connections, each with its own signed SDP exchange, its own video (if either side turns their camera on), and its own safety code. This is deliberate: an SFU (a media server that routes everyone's streams through one place) would scale to far more participants, but would mean *something* — even if it's just encrypted packets it can't decrypt — flows through infrastructure you control, which is a real departure from how every other part of this app is built to keep the server out of the media path entirely. Mesh doesn't have that tradeoff, at the cost of not scaling past a handful of people, hence the 4-person cap. Adding someone to a call reuses the exact same signed, encrypted call-offer mechanism as a normal 1:1 call, and video toggling reuses the exact same renegotiation mechanism per pair — there's no separate, weaker protocol for anyone beyond the original two people.
- **Safety codes**: after a call connects, both sides compute a short number from both ends' DTLS certificate fingerprints. If you read this aloud to each other and it matches, nobody is in the middle of the call. This is the same idea as Signal's safety numbers.

### Persistent identity and the trust-on-first-use model

Every browser generates a long-term ECDSA P-256 identity keypair the first time it loads the app, stored in IndexedDB with the private key marked non-extractable (JavaScript can ask it to sign things, but can never read the raw private key back out — this holds even against a same-page XSS, though not against a compromised browser or OS). This key is separate from the per-session RSA encryption key: the encryption key rotates every time you join, limiting what a single compromised session exposes, while the identity key persists and is what contacts recognize you by.

At join, you sign a server-issued nonce with your identity key, proving you hold the private key for the identity you're presenting. The server also enforces **nick-to-identity binding**: once a nickname has been used by a given identity, only that same identity may use it again for as long as the server process runs. This closes a real gap that pure client-side pinning leaves open — without it, someone could grab your nickname the moment you disconnect and be fully live under it until your contacts' clients happen to notice the key mismatch on their next presence update; with it, the impostor is rejected at the door instead. Reconnecting under your own nick (a page reload, a dropped connection) still works fine, since the fingerprint matches what's already bound.

On top of the server-side binding, every client independently checks your identity key too, every time it sees your nickname (via the user list):

- **First time seeing a nickname** → the fingerprint is silently pinned (classic trust-on-first-use).
- **Same fingerprint as before** → nothing happens, business as usual.
- **Different fingerprint under a nickname you've seen before** → loud warning, and **calling and messaging that person are both blocked** until you explicitly decide to trust the new key or leave it blocked. This is the "with teeth" part — the app never silently re-pins.

On top of that automatic pinning, you can explicitly **verify** anyone: click the key icon next to their name to reveal their fingerprint, compare it with them out loud or over another channel, and mark it verified. This is a stronger claim than "it just never changed" — it means you actively confirmed it.

### Graceful reconnection

A dropped connection — wifi blip, a brief server hiccup, a laptop waking from sleep — no longer sends you back to the welcome screen. Chat history, open tabs, and your identity all live in the browser's memory and IndexedDB independent of the socket connection, so when the underlying transport comes back, the app silently redoes the join handshake (a fresh session encryption key, same nick, same identity signature) and picks up right where it left off. While disconnected, a banner says so and the message input and call buttons are disabled — partly for clarity, partly because Socket.IO buffers anything you `emit()` while offline and fires it the moment the connection returns, which could otherwise let a call or message slip out before the silent rejoin has actually completed.

Two things this does *not* try to survive: a deliberate reload/tab-close (that's still a clean slate, by design — see "everything is ephemeral" below), and an active call. WebRTC audio is peer-to-peer and technically independent of the signaling socket once connected, but without that socket there's no way to hang up, renegotiate, or learn that the other person hung up — so a dropped connection always ends any in-progress call cleanly rather than leaving it in an ambiguous state. And if the reconnect attempt itself fails at the application level (someone else claimed your nickname while you were gone, most likely) there's no silent recovery from that either — you'll see why, and the app falls back to a full reload.

### Known limitations and honest caveats

- **The very first contact is unverified by construction.** Trust-on-first-use means the *first* time you see someone's key, there's nothing to check it against — a server that was already malicious before you ever talked to them could substitute a key at that first moment and you'd have no way to know without an out-of-band comparison. Explicit verification (above) is the mitigation, but it's opt-in and requires comparing fingerprints through some channel other than this app.
- **A stored XSS via nicknames was found and fixed during the accessibility pass.** Conversation tabs used to be built with `innerHTML` and an interpolated nickname; since nicknames are only validated for length server-side, not content, a nickname containing HTML would have executed for anyone who ever opened a tab with that person. It's fixed now (tabs are built with safe DOM APIs, matching how the rest of the app already handled untrusted text) and covered by an automated test that actually joins with an HTML-bearing nickname and confirms it renders as literal text. Mentioned here because it's the kind of bug that's worth being upfront about rather than quietly patching.
- **Identity is per-browser, not per-person.** Clear your site data, switch browsers, or switch devices, and you get a brand-new identity — contacts will see a key-changed warning, and you'll need to be re-verified from scratch. There is no cross-device sync or backup/export of the identity key.
- **No forward secrecy within a session.** The RSA session key is generated fresh each time you join, but it doesn't rotate per-message or per-call — if a given session's key were somehow compromised, everything encrypted to it during that session is exposed. This is closer to SSH's trust model than to Signal's double-ratchet.
- **Message replay protection is a blunt timestamp window, not a real anti-replay cache.** A signed message is rejected if its timestamp is more than five minutes old, but a captured, validly-signed message *replayed within that window* isn't independently detected — low real-world impact for a live chat, but worth knowing if you're reasoning about the threat model precisely.
- **Nick-to-identity bindings never expire for the life of the server process.** Once someone's used a nickname, nobody else can take it — including if they leave and never come back — until the server restarts. This is a deliberate tradeoff (it's what closes the impersonation window described above), but it means a popular nickname can become permanently unavailable to everyone else for as long as the server stays up if its original holder disappears.
- **Video renegotiation collision handling is simplified, not the full W3C "perfect negotiation" pattern.** If both people toggle video at the exact same instant, the app resolves it with the same directional rule already used for the "both click Call simultaneously" case (the original callee yields to the original caller) rather than proper offer/answer rollback. This is a genuinely rare edge case — unlike two people both clicking Call, which happens often enough to matter — so the simpler rule is a reasonable tradeoff, but it's worth knowing this isn't spec-complete renegotiation.
- **Group call video and safety codes now cover every participant, capped at 4, and connection quality is the one thing still scoped to the original pair.** Turning your camera on sends it to everyone you're connected to, not just whoever you originally called, and every pairwise connection gets its own safety code (shown in a participant list once a call actually has more than two people). The one deliberately unextended piece is the connection-quality indicator — it still only reflects the original pair's connection, not a summary across the whole mesh, since surfacing per-pair quality for every leg would clutter the UI more than it would help for a first version. If the original two-person pair leaves a group call while others remain, the call continues for them (including their camera, if it was on - the shared capture isn't stopped just because the pair that started the call happens to be who left), but that specific pairing's own video/safety-code slot goes away since there's no longer a distinguished "primary" relationship for it to describe.
- **File transfers have no server-side session tracking**, unlike calls. There's no busy state, no way to see "someone has a transfer in progress" from the server's point of view, and the server's disconnect handling doesn't specifically notify a transfer partner if you vanish mid-transfer — that's instead detected client-side, the same way a stalled call connection is: the browser's own WebRTC connection-state events. This was a deliberate scope simplification given file transfers can reasonably happen several at once with different people (unlike the one-call-at-a-time model), but it does mean the server relays signaling for a `transferId` to whoever's specified as the recipient without maintaining a record of which transfers are legitimately in progress between which two people — the real check is the recipient's own client verifying the sender's signature and matching the transferId against a transfer it's actually expecting, not anything the server enforces.
- **File size is capped at 200MB**, a practical UX limit rather than a protocol one — everything happens in-browser memory (the received file is assembled as a `Blob` before it can be downloaded), so there's no streaming-to-disk for very large files.
- **The server sees metadata even though it can't see content:** who's online, who's messaging or calling whom, nicknames, and call timing/duration. Nothing here hides *that* a conversation happened, only its contents. Typing indicators and active/idle presence are part of this same category — deliberately unauthenticated and unencrypted, since there's no message content to protect there and a fabricated "X is typing" from a malicious server is a minor annoyance, not a security issue worth the overhead of signing.
- **Desktop notifications never include message content**, by design. An OS-level notification can surface on a lock screen, sit in notification history, or sync to other devices — showing decrypted content there would quietly undo the confidentiality the encryption is providing everywhere else. Notifications say who a message is from, not what it says; the unread count in the tab title works the same way, as a count with no content attached.
- **Everything is ephemeral and in-memory, but only truly gone on a deliberate reload or the server restarting.** Chat history, the call log, and the online user list all live in the server's or browser's memory only — no persistence, no search, no export. A transient network drop no longer causes any of this to be lost (see "Graceful reconnection" above), but closing the tab, reloading on purpose, or the server restarting still means a clean slate.
- **Access control is opt-in and modest.** By default the room is open — anyone with the URL can join with any available nickname. Setting `ROOM_PASSWORD` gates joining behind a shared password (compared via hashed, constant-time comparison), but it's a single shared secret, not per-user accounts — anyone who has it can join, and there's no way to revoke one person's access without changing it for everyone. There's still no invite system, no admin/kick tooling, and no way to remove someone from the room once they're in short of them disconnecting.
- **Per-socket rate limiting covers the obvious abuse vectors** — join attempts, chat messages, call attempts, ICE candidates, and ICE-config requests are all capped per socket, with a strike system that disconnects a socket outright after repeated violations. A companion **per-IP connection cap** (`MAX_CONNECTIONS_PER_IP`, default 5) stops one script from opening dozens of sockets to route around the per-socket limits or fill the room's user cap alone. Neither is airtight: the IP cap is trivially bypassed by anyone with multiple IPs (VPN, mobile data + Wi-Fi, a botnet), and the rate limits bound *how fast* someone can misbehave, not whether a sufficiently distributed attacker can still cause trouble. These are deterrents against casual abuse and runaway bugs, not defenses against a determined, resourced attacker.
- **Hardcoded room capacity** of 20 concurrent users and 15-character nickname/about limits — small tweaks in `server.js`/`index.html` if you need different values, not currently configurable via environment variables.
- **TURN credentials depend on `TURN_SECRET` staying secret.** If configured, it's a shared secret with your TURN server; anyone with it can mint valid (if short-lived) relay credentials. Rotate it periodically like any other server secret. Without a TURN server, calls between two users on strict/symmetric NATs (common on mobile data) may simply fail to connect — that's a normal, disclosed limitation, not a bug.
- **Accessibility has had a real pass, with a couple of known gaps.** Every custom widget — the tab list, user rows, the sidebar drawer, the incoming-call and incoming-file modals — is keyboard-operable with proper ARIA roles, roving tabindex where relevant, focus trapping in overlays, and focus restoration on close. A shared live region announces call/message/identity events for screen reader users, alongside the chat log's own `role="log"`. What's *not* covered: no dedicated screen-reader testing beyond automated checks (real NVDA/VoiceOver verification would likely surface phrasing issues automation can't catch), and color contrast hasn't been audited against WCAG ratios — the dark cyberpunk theme's muted grays in particular are worth checking if this matters for your deployment.

If you're building on this or deploying it for a real group, the room password gives you a single shared gate, but there's no per-person revocation — the natural next step would be lightweight per-user invite tokens (or a real auth layer) if you need to remove one person's access without rotating the password for everyone.
