require('dotenv').config();
const express = require('express');
const http = require('http');
const { Server } = require('socket.io');
const cors = require('cors');
const rateLimit = require('express-rate-limit');
const helmet = require('helmet');
const crypto = require('crypto');

const app = express();
// Explicit CSP rather than helmet's bare defaults: file transfers build
// downloadable content as blob: URLs (see client.js), and fetching or
// otherwise processing a blob: URL from a script counts as a "connect" for
// CSP purposes - Helmet's default connect-src falls back to default-src
// 'self', which does not include blob:, and would silently block any
// future in-page use of a received file (image preview, integrity checks,
// etc.) even though clicking the actual download link still works fine
// (link navigation isn't governed by connect-src).
app.use(helmet({
    contentSecurityPolicy: {
        directives: {
            ...helmet.contentSecurityPolicy.getDefaultDirectives(),
            'connect-src': ["'self'", 'blob:']
        }
    }
}));
// CORS origin allowlist. Unset = open (origin: "*"), matching the original
// dev behavior. In production, set ALLOWED_ORIGIN to the exact origin that
// serves the client (e.g. "https://abyss.example.com") so a malicious site
// can't open a Socket.IO connection or hit the REST endpoints from a
// browser. Applies to both Express (app.use(cors())) and Socket.IO below.
const ALLOWED_ORIGIN = process.env.ALLOWED_ORIGIN || '*';
const corsOptions = ALLOWED_ORIGIN === '*'
    ? { origin: '*' }                       // dev: reflect anything
    : { origin: ALLOWED_ORIGIN, optionsSuccessStatus: 204 };

app.use(cors(corsOptions));
app.use(express.json());
app.use(express.static('public'));

const limiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 100,
    message: { error: "Too many requests." }
});
app.use('/api/', limiter);

// --- ICE server configuration (Phase 4 STUN, Phase 5 time-limited TURN) ---
// STUN alone (default). A TURN relay (e.g. coturn) can be added via env vars
// for symmetric-NAT pairs where STUN can't establish a path:
//   TURN_URL=turn:turn.example.com:3478
//   TURN_SECRET=<same value as coturn's static-auth-secret>
//   TURN_TTL_SECONDS=14400   (optional, default 4 hours)
//
// TURN_SECRET is a shared secret with the TURN server, never a credential
// itself. We generate short-lived username/password pairs from it using
// coturn's REST API convention (https://github.com/coturn/coturn/wiki/turnserver),
// so a leaked credential expires instead of granting permanent relay access,
// and nothing has to be provisioned per-user on the TURN server.
const STUN_SERVERS = [
    { urls: 'stun:stun.l.google.com:19302' },
    { urls: 'stun:stun1.l.google.com:19302' }
];

function turnConfigured() {
    return Boolean(process.env.TURN_URL && process.env.TURN_SECRET);
}

/**
 * Generates a time-limited TURN credential per coturn's REST API convention:
 * username = "<unix expiry>:<identifier>", password = base64(HMAC-SHA1(secret, username)).
 * coturn verifies this itself at allocation time - no round trip to this
 * server or shared session state required.
 */
function generateTurnCredential(identifier) {
    const ttl = parseInt(process.env.TURN_TTL_SECONDS, 10) || 14400; // 4h default
    const expiry = Math.floor(Date.now() / 1000) + ttl;
    const username = `${expiry}:${identifier}`;
    const password = crypto.createHmac('sha1', process.env.TURN_SECRET)
        .update(username)
        .digest('base64');
    return { urls: process.env.TURN_URL, username, credential: password };
}

// Pre-join fallback: STUN only. Full credentials (including TURN) are only
// ever issued to authenticated, joined sockets - see the 'get_ice_config'
// handler below - so this endpoint intentionally never exposes TURN_SECRET
// or a derived credential, even if TURN is configured.
app.get('/api/ice-config', (req, res) => {
    res.json({ iceServers: STUN_SERVERS });
});

// Trusted reverse-proxy hop count. When the server sits behind nginx,
// cloudflared, ngrok, etc. (as documented at the bottom of this file),
// socket.handshake.address is the proxy's address (e.g. 127.0.0.1), not the
// real client's. Socket.IO honors the X-Forwarded-For header when `trustProxy`
// is set on the Server constructor; the value is the number of trusted proxies
// in front of us (1 for a single reverse proxy). Leave unset for direct/
// localhost operation - socket.handshake.address is already correct then.
const TRUST_PROXY = parseInt(process.env.TRUST_PROXY, 10);
const trustProxyConfig = Number.isNaN(TRUST_PROXY) ? false : TRUST_PROXY;

const server = http.createServer(app);
const io = new Server(server, {
    // Same ALLOWED_ORIGIN gate as Express CORS above. Unset = open (dev).
    cors: { origin: ALLOWED_ORIGIN },
    // Honor X-Forwarded-For when a trusted reverse proxy is configured
    // (see TRUST_PROXY above). Disabled by default so direct/localhost
    // operation is unaffected. When enabled, socket.handshake.address
    // reflects the real client IP instead of the proxy's address.
    ...(trustProxyConfig !== false ? { trustProxy: trustProxyConfig } : {})
});

// State Management
const users = new Map(); // socketId -> {nick, about, publicKey}
const MAX_USERS = 20;

// Call Session Management
// socketId -> Map<peerId, { peerId, groupId, status: 'ringing'|'connected', timer }>
// A socket can hold MULTIPLE sessions simultaneously now (group calls are
// mesh: every pair of participants has its own pairwise session, same as a
// 1:1 call), but only if they all share the same groupId - you still can't
// be in two unrelated calls at once. Every call, even an ordinary 1:1 one,
// gets a groupId; a "group call" is just what you get when a third person
// is invited into that same groupId later.
const callSessions = new Map();
const MAX_GROUP_SIZE = 4; // mesh connections scale badly beyond a handful of people

function getSession(socketId, peerId) {
    const m = callSessions.get(socketId);
    return m ? m.get(peerId) : undefined;
}
function setSession(socketId, peerId, info) {
    if (!callSessions.has(socketId)) callSessions.set(socketId, new Map());
    callSessions.get(socketId).set(peerId, info);
}
function mySessions(socketId) {
    return callSessions.get(socketId) || new Map();
}
/** The groupId a socket is currently part of, or null if it's in no call. */
function currentGroupId(socketId) {
    const sessions = callSessions.get(socketId);
    if (!sessions || sessions.size === 0) return null;
    return [...sessions.values()][0].groupId;
}
/** Every peerId a socket currently shares the given groupId's call with. */
function groupPeersOf(socketId, groupId) {
    const sessions = callSessions.get(socketId);
    if (!sessions) return [];
    return [...sessions.entries()].filter(([, s]) => s.groupId === groupId).map(([peerId]) => peerId);
}

/** Ends exactly one pairwise session (both sides), clearing its timer. Returns the peerId, or null if there was no such session. */
function endPairSession(socketId, peerId) {
    const session = getSession(socketId, peerId);
    if (!session) return null;
    if (session.timer) clearTimeout(session.timer); // same handle on both sides; clearing once is enough
    const mine = callSessions.get(socketId);
    if (mine) { mine.delete(peerId); if (mine.size === 0) callSessions.delete(socketId); }
    const theirs = callSessions.get(peerId);
    if (theirs) { theirs.delete(socketId); if (theirs.size === 0) callSessions.delete(peerId); }
    return peerId;
}

/** Ends every session a socket currently has (leaving a call entirely - hangup or disconnect). Returns the list of peerIds that need to be told. */
function endAllSessionsFor(socketId) {
    const sessions = callSessions.get(socketId);
    if (!sessions) return [];
    const peerIds = [...sessions.keys()];
    peerIds.forEach(peerId => endPairSession(socketId, peerId));
    return peerIds;
}

// Signaling payloads (SDP offers/answers, ICE candidates) arrive as
// client-encrypted opaque strings. The server never parses them - it only
// sanity-checks type and size before relaying.
function isValidBlob(payload, maxLen) {
    return typeof payload === 'string' && payload.length > 0 && payload.length <= maxLen;
}
const MAX_SDP_BLOB = 100000;   // encrypted SDP: typically 5-30 KB
const MAX_CAND_BLOB = 20000;   // encrypted ICE candidate: typically ~1 KB
const MAX_MESSAGE_BLOB = 10000; // plaintext (public) or encrypted (private) chat message
const MAX_TRANSFER_ID = 100;    // client-generated UUID, generous buffer
const MESSAGE_TIMESTAMP_SKEW_MS = 5 * 60 * 1000; // reject signed messages older/newer than this
const RING_TIMEOUT_MS = parseInt(process.env.RING_TIMEOUT_MS, 10) || 30000; // Phase 6: unanswered calls auto-resolve

// Replay cache for signed payloads (chat messages, file offers/answers).
// The timestamp skew check above blunts naive replay by rejecting anything
// older than 5 minutes, but within that window a captured signed payload can
// still be re-emitted and the server will accept it (producing a duplicate
// message or a spurious file-transfer signal). This cache closes that gap:
// every verified signature is remembered for the lifetime of the socket,
// and a second arrival of the same signature from the same socket is
// dropped as a replay.
//
// Scoped per socket id so disconnect cleanup is automatic (the entry and its
// Set of seen signatures are GC'd when the socket's closure goes away). The
// Set is never explicitly pruned, but is bounded by the per-socket message
// rate limit (15/10s = at most ~450 entries in the 5-minute window, in
// practice far fewer), so it never grows without limit.
const replayCache = new Map(); // socketId -> Set<signature>

function isReplay(socketId, signature) {
    let seen = replayCache.get(socketId);
    if (!seen) return false; // first sighting - not a replay
    return seen.has(signature);
}

/** Records a signature after verification passes. Call only AFTER
    isReplay() returns false. The Set is bounded by the per-socket rate
    limit and cleaned up on disconnect, so no per-entry pruning is needed. */
function rememberSignature(socketId, signature) {
    let seen = replayCache.get(socketId);
    if (!seen) { seen = new Set(); replayCache.set(socketId, seen); }
    seen.add(signature);
}

function forgetReplayCache(socketId) {
    replayCache.delete(socketId);
}

// --- Phase 7: persistent identity keys (proof-of-possession at join) ---
// Each client holds a long-term ECDSA P-256 identity keypair (generated once,
// stored unextractably in the browser - see client.js). At join, the client
// signs "<server nonce>:<this session's RSA encryption key>" with its
// identity private key. We verify that signature here before admitting the
// user, which proves two things at once: (1) they actually hold the private
// key for the identityKey they're presenting - so nobody can just relay a
// public key they scraped from someone else - and (2) THIS session's
// encryption key is genuinely bound to that identity, not substituted by a
// man-in-the-middle server. The nonce prevents replaying a signature
// captured from a different connection.
//
// Signature format: Web Crypto's ECDSA sign() produces a raw r||s signature
// (IEEE P1363), not the DER format Node's crypto module defaults to, so we
// tell Node's verifier to expect that encoding explicitly.
const MAX_KEY_BLOB = 2000;   // ECDSA P-256 SPKI, base64: ~124 chars typically
const MAX_SIG_BLOB = 500;    // ECDSA P-256 signature, base64: ~88 chars typically

/**
 * Verifies an ECDSA P-256/SHA-256 signature over an arbitrary string,
 * against a base64 SPKI-encoded public key. Shared primitive for both the
 * join proof-of-possession check and (Phase 1 of the second hardening
 * round) message signing below.
 */
function verifyStringSignature(identityKeyB64, message, signatureB64) {
    try {
        const identityKeyObj = crypto.createPublicKey({
            key: Buffer.from(identityKeyB64, 'base64'),
            format: 'der',
            type: 'spki'
        });
        const verifier = crypto.createVerify('SHA256');
        verifier.update(message);
        verifier.end();
        return verifier.verify(
            { key: identityKeyObj, dsaEncoding: 'ieee-p1363' },
            Buffer.from(signatureB64, 'base64')
        );
    } catch (err) {
        return false; // malformed key/signature - treat as verification failure, not a crash
    }
}

function verifyIdentitySignature(nonce, sessionPublicKeyB64, identityKeyB64, signatureB64) {
    return verifyStringSignature(identityKeyB64, `${nonce}:${sessionPublicKeyB64}`, signatureB64);
}

/** SHA-256 fingerprint of a base64 SPKI identity key - same value each client independently derives. */
function fingerprintOf(identityKeyB64) {
    return crypto.createHash('sha256').update(Buffer.from(identityKeyB64, 'base64')).digest('hex').toUpperCase();
}

// --- Phase 2 (second hardening round): server-side nick-to-identity binding ---
// The per-connection uniqueness check below only prevents two people from
// holding the same nick AT THE SAME TIME - it says nothing about someone
// else claiming your nick five minutes after you disconnect. Client-side
// TOFU pinning (see client.js) already catches an impostor on their NEXT
// user_list broadcast, but that leaves one exposed window where the
// impostor is fully live under a stolen nick before anyone's client flags
// it. This map closes that window at the door: once a nick has been used
// by a given identity, only that identity may use it again for as long as
// this server process runs (consistent with the app's everything-resets-
// on-restart design - see the README for the tradeoff this implies).
//
// Bounded: a long-lived process with high nick churn would leak memory
// indefinitely otherwise. The cap is generous relative to MAX_USERS (20)
// - in practice the map never grows past the number of distinct nicks
// that have ever joined, but a hard ceiling protects against pathological
// cases. When the cap is reached, the oldest entries are evicted (FIFO).
const MAX_NICK_BINDINGS = 1000;
const nickBindings = new Map(); // nick -> identity fingerprint (insertion-ordered)

// --- Phase 8: access control & abuse hardening ---

// Optional room password. Off by default (open room, matching every prior
// phase's behavior) - set ROOM_PASSWORD to require one. We never store or
// compare the plaintext: the configured password is hashed once at startup
// with scrypt (a memory-hard password-based KDF) and a random salt, and each
// candidate is hashed the same way before a constant-time comparison. This
// replaces an earlier single-round SHA-256 hash: scrypt's work factor makes
// offline brute-force of a low-entropy room password impractical if the hash
// ever leaks, while SHA-256 is fast enough to crack trivially.
//
// The salt is generated once per process at startup. This is intentional:
// there is no persistent store to keep a salt in (everything resets on
// restart), and a per-process salt still defeats precomputed rainbow tables
// for the lifetime of this process. The work factor (N=16384, r=8, p=1) is
// the OWASP minimum; it costs ~100ms per verification, acceptable given the
// join rate limit (5/30s per socket) and the 20-user room cap.
const ROOM_PASSWORD_SALT = process.env.ROOM_PASSWORD ? crypto.randomBytes(16) : null;
const SCRYPT_PARAMS = { N: 16384, r: 8, p: 1, maxmem: 32 * 1024 * 1024 };
const SCRYPT_KEYLEN = 32;
const ROOM_PASSWORD_HASH = process.env.ROOM_PASSWORD
    ? crypto.scryptSync(process.env.ROOM_PASSWORD, ROOM_PASSWORD_SALT, SCRYPT_KEYLEN, SCRYPT_PARAMS)
    : null;

function checkRoomPassword(candidate) {
    if (!ROOM_PASSWORD_HASH) return true; // no password configured - open room
    if (typeof candidate !== 'string' || candidate.length === 0) return false;
    const candidateHash = crypto.scryptSync(candidate, ROOM_PASSWORD_SALT, SCRYPT_KEYLEN, SCRYPT_PARAMS);
    return crypto.timingSafeEqual(candidateHash, ROOM_PASSWORD_HASH);
}

// Per-IP concurrent connection cap. This is a best-effort deterrent, not a
// strong access-control primitive - anyone with multiple IPs (VPN, mobile
// data + wifi, a botnet) sails past it trivially. What it actually stops is
// the common case: one script opening dozens of sockets to dodge the
// per-socket join rate limit below or to fill the room's 20-user cap alone.
const MAX_CONNECTIONS_PER_IP = parseInt(process.env.MAX_CONNECTIONS_PER_IP, 10) || 5;
const connectionsByIp = new Map(); // ip -> open socket count

/**
 * Fixed-window rate limiter. Not token-bucket-smooth (a burst right at a
 * window boundary can momentarily allow ~2x max), but it's O(1), allocates
 * nothing per call, and that imprecision doesn't matter at these limits -
 * simplicity wins here over a sliding-window implementation.
 */
function createLimiter(max, windowMs) {
    let count = 0;
    let windowStart = Date.now();
    return function tryConsume() {
        const now = Date.now();
        if (now - windowStart >= windowMs) {
            windowStart = now;
            count = 0;
        }
        count++;
        return count <= max;
    };
}

// Per-IP connection-rate limit. The concurrent cap above stops someone from
// holding many sockets at once; this stops them from rapidly cycling
// connections (connect/disconnect/reconnect) to dodge the concurrent cap or
// to burn server resources allocating nonces, rate-limiter closures, and Map
// entries for sockets that never join. Generous enough for a real user
// reloading a tab or recovering a flaky connection, but catches a script
// spinning up sockets in a tight loop.
const MAX_CONNECT_RATE_PER_IP = parseInt(process.env.MAX_CONNECT_RATE_PER_IP, 10) || 20;
const CONNECT_RATE_WINDOW_MS = parseInt(process.env.CONNECT_RATE_WINDOW_MS, 10) || 60000;
const connectRateByIp = new Map(); // ip -> { count, windowStart }

function connectRateOk(ip) {
    const now = Date.now();
    let entry = connectRateByIp.get(ip);
    if (!entry || now - entry.windowStart >= CONNECT_RATE_WINDOW_MS) {
        entry = { count: 0, windowStart: now };
        connectRateByIp.set(ip, entry);
    }
    entry.count++;
    return entry.count <= MAX_CONNECT_RATE_PER_IP;
}

// Socket.IO middleware: runs before the 'connection' handler, so a rejected
// handshake never even enters the connection lifecycle. The error message
// reaches the client as a connect_error.
io.use((socket, next) => {
    const ip = socket.handshake.address;
    if (!connectRateOk(ip)) {
        return next(new Error('Too many connections from your network. Try again shortly.'));
    }
    next();
});

io.on('connection', (socket) => {
    console.log(`> New connection request: ${socket.id}`);

    // Phase 8: per-IP cap, checked before anything else - no point setting
    // up rate limiters or issuing a nonce for a connection we're about to drop.
    // When TRUST_PROXY is configured, socket.handshake.address already
    // reflects the real client IP parsed from X-Forwarded-For; otherwise it
    // is the direct TCP peer address.
    const ip = socket.handshake.address;
    const ipConnections = connectionsByIp.get(ip) || 0;
    if (ipConnections >= MAX_CONNECTIONS_PER_IP) {
        socket.emit('kicked', 'Too many connections from your network. Try again shortly.');
        socket.disconnect(true);
        return;
    }
    connectionsByIp.set(ip, ipConnections + 1);

    // Phase 8: per-socket rate limits. Scoped to this connection's closure
    // rather than a global Map keyed by socket.id - state is naturally
    // cleaned up when the socket disconnects, nothing to garbage-collect
    // by hand. Limits are generous enough for real usage (ICE candidates in
    // particular arrive in bursts as a normal part of connecting a call)
    // but bound how much damage a single misbehaving or hostile socket can do.
    const limits = {
        join: createLimiter(5, 30000),          // 5 join attempts / 30s
        message: createLimiter(15, 10000),      // 15 chat messages / 10s
        callUser: createLimiter(6, 30000),      // 6 call attempts / 30s
        answerCall: createLimiter(15, 30000),
        declineCall: createLimiter(15, 30000),
        iceCandidate: createLimiter(80, 10000), // generous - real calls burst these
        iceConfig: createLimiter(10, 60000),
        hangup: createLimiter(15, 10000),
        typing: createLimiter(30, 10000),       // client already throttles to ~1/2s while typing
        presence: createLimiter(10, 10000),     // only fires on actual state changes, rarely this often
        renegotiate: createLimiter(20, 30000),  // toggling video a couple times a minute is plenty generous
        fileOffer: createLimiter(10, 60000),    // starting a file transfer is an infrequent, deliberate action
        fileSignal: createLimiter(100, 30000)   // answer/decline/cancel/ICE candidates for transfers in progress
    };

    // Escalating consequence: individual violations are just dropped, but a
    // socket that keeps tripping limits gets disconnected outright rather
    // than left to keep trying forever.
    let strikes = 0;
    const MAX_STRIKES = 15;
    function strike(reason) {
        strikes++;
        if (strikes >= MAX_STRIKES) {
            console.log(`> Kicking ${socket.id} for repeated rate-limit violations (last: ${reason})`);
            socket.emit('kicked', 'Disconnected for excessive activity.');
            socket.disconnect(true);
        }
    }

    // Fresh, single-use-per-connection challenge for the identity proof above
    const joinNonce = crypto.randomBytes(24).toString('base64');
    socket.emit('join_nonce', joinNonce);
    socket.emit('room_info', { passwordRequired: Boolean(ROOM_PASSWORD_HASH) });

    socket.on('join', ({ nick, about, publicKey, identityKey, signature, password }) => {
        if (!limits.join()) {
            strike('join');
            return socket.emit('error', 'Too many join attempts - please wait a moment.');
        }
        console.log(`> Join attempt: Nick="${nick}"`);

        // 0. Room password (if configured) - cheapest check, do it first
        if (!checkRoomPassword(password)) {
            return socket.emit('error', 'Incorrect room password.');
        }

        // 1. Validation
        // Trim whitespace first - a nick of "   " or one padded with spaces
        // would otherwise pass the length check and enable impersonation via
        // visually identical nicks. The client trims too (client.js), but the
        // server is the trust boundary.
        if (typeof nick !== 'string') nick = '';
        if (typeof about !== 'string') about = '';
        nick = nick.trim();
        about = about.trim();
        if (!nick || nick.length > 15 || !about || about.length > 15) {
            return socket.emit('error', 'Nick/About must be 1-15 chars.');
        }
        if (!isValidBlob(identityKey, MAX_KEY_BLOB) || !isValidBlob(signature, MAX_SIG_BLOB)) {
            return socket.emit('error', 'Missing or malformed identity key.');
        }
        if (!isValidBlob(publicKey, MAX_KEY_BLOB)) {
            return socket.emit('error', 'Missing or malformed session public key.');
        }
        if (!verifyIdentitySignature(joinNonce, publicKey, identityKey, signature)) {
            return socket.emit('error', 'Identity verification failed - could not prove ownership of the identity key.');
        }

        // Phase 2: nick-to-identity binding. Once we've verified they hold
        // the identity key they're presenting (above), check it against
        // whoever last legitimately used this nick. A matching fingerprint
        // means this is the same person reconnecting - fine. A mismatch
        // means someone else is trying to use a nick that isn't theirs.
        const fingerprint = fingerprintOf(identityKey);
        const boundFingerprint = nickBindings.get(nick);
        if (boundFingerprint && boundFingerprint !== fingerprint) {
            return socket.emit('error', 'This nickname belongs to a different identity on this server. Choose another nickname.');
        }

        // 2. Max User Constraint
        if (users.size >= MAX_USERS) {
            return socket.emit('error', 'The abyss is full (Max 20 users).');
        }

        // 3. Uniqueness Check
        const exists = Array.from(users.values()).some(u => u.nick === nick);
        if (exists) {
            return socket.emit('nick_taken', true);
        }

        // 4. Success State
        users.set(socket.id, { nick, about, publicKey, identityKey, presence: 'active' });
        nickBindings.set(nick, fingerprint);
        // Evict oldest entry if the binding cap is reached. Map iteration is
        // insertion-ordered, so the first key is the oldest. Only evicts when
        // this set actually grew the map (reconnecting with the same nick
        // just overwrites the existing entry without changing its size).
        if (nickBindings.size > MAX_NICK_BINDINGS) {
            const oldest = nickBindings.keys().next().value;
            nickBindings.delete(oldest);
        }

        const userEntry = {
            nick, about, publicKey, identityKey, presence: 'active',
            id: socket.id
        };

        // Send the full user list (with ids and identity keys) to the new
        // client so its sidebar and phonebook are populated.
        const userList = Array.from(users.entries()).map(([id, data]) => ({
            ...data,
            id
        }));
        socket.emit('user_list', userList);

        // Notify *other* clients about the newcomer with a lightweight event
        // instead of re-broadcasting the full list. Every connected client
        // already knows its own identityKey, so only the new user's identity
        // key needs to travel.
        socket.to().emit('user_joined', userEntry);

        // Tell this specific client they are in
        socket.emit('joined_success');
        console.log(`> User joined successfully: ${nick}`);
    });

    // Phase 5: authenticated ICE config. TURN credentials (when configured)
    // are only ever generated for sockets that have successfully joined -
    // gating issuance here, not just at the REST layer, closes off the
    // unauthenticated path entirely. Uses an ack callback so the client can
    // await a fresh set of credentials right before starting a call.
    socket.on('get_ice_config', (callback) => {
        if (typeof callback !== 'function') return; // malformed/hostile client
        if (!limits.iceConfig()) { strike('get_ice_config'); return; } // client's 3s fallback timeout covers this

        const iceServers = [...STUN_SERVERS];
        if (turnConfigured() && users.has(socket.id)) {
            iceServers.push(generateTurnCredential(socket.id));
        }
        callback({ iceServers });
    });

    socket.on('message', ({ recipientId, content, isPrivate, timestamp, signature }) => {
        if (!limits.message()) { strike('message'); return; } // silent drop - flood protection, not feedback-worthy

        // SECURITY: identity comes from the authenticated socket, never
        // from a client-supplied senderId (prevents impersonation).
        const user = users.get(socket.id);
        if (!user) return;

        // Phase 1 (second hardening round): every message is signed with
        // the sender's identity key before it ever reaches us. We verify it
        // here as defense-in-depth (rejects anything a compromised/buggy
        // client sends that doesn't match the identity it proved possession
        // of at join) - but this is NOT the primary trust anchor. That's
        // each recipient independently re-verifying against the fingerprint
        // THEY pinned for this nick, client-side, same as the call safety
        // codes. This check just means a fully malicious server can no
        // longer fabricate a message and attribute it to someone else: it
        // never holds anyone's identity private key, so it can't produce a
        // signature that passes verification here either.
        if (!isValidBlob(content, MAX_MESSAGE_BLOB) || !isValidBlob(signature, MAX_SIG_BLOB) || typeof timestamp !== 'number') {
            return; // malformed - drop silently, same treatment as other bad payloads
        }
        if (Math.abs(Date.now() - timestamp) > MESSAGE_TIMESTAMP_SKEW_MS) {
            return; // too old/future to be a live message - drop (blunts naive replay)
        }
        if (!verifyStringSignature(user.identityKey, `${timestamp}:${content}`, signature)) {
            console.log(`> Rejected message with invalid signature from ${user.nick}`);
            return;
        }
        if (isReplay(socket.id, signature)) {
            console.log(`> Rejected replayed message from ${user.nick}`);
            return;
        }
        rememberSignature(socket.id, signature);

        if (isPrivate && recipientId) {
            io.to(recipientId).emit('private_message', {
                senderId: socket.id,
                content, // Encrypted blob from client
                nick: user.nick,
                timestamp,
                signature
            });
        } else {
            io.emit('public_message', {
                content,
                nick: user.nick,
                timestamp,
                signature
            });
        }
    });

    // --- Presence features (typing indicators, active/idle status) ---
    // Deliberately unauthenticated, unencrypted metadata - there's no
    // message content here to protect, and a fabricated "X is typing" from
    // a malicious server is a minor annoyance, not a security issue. Kept
    // separate from the signed/encrypted message path on purpose so we
    // don't pretend this needs (or has) the same guarantees.

    socket.on('typing', ({ isPrivate, recipientId }) => {
        if (!limits.typing()) { strike('typing'); return; }
        const user = users.get(socket.id);
        if (!user) return;

        if (isPrivate && recipientId) {
            io.to(recipientId).emit('user_typing', { nick: user.nick, isPrivate: true });
        } else {
            socket.broadcast.emit('user_typing', { nick: user.nick, isPrivate: false });
        }
    });

    socket.on('presence', (status) => {
        if (!limits.presence()) { strike('presence'); return; }
        if (status !== 'active' && status !== 'idle') return; // malformed - ignore
        const user = users.get(socket.id);
        if (!user || user.presence === status) return; // not joined yet, or no real change

        user.presence = status;
        io.emit('presence_update', { nick: user.nick, status });
    });

    socket.on('disconnect', () => {
        // Phase 8: release this connection's slot in the per-IP cap
        const remaining = (connectionsByIp.get(ip) || 1) - 1;
        if (remaining <= 0) {
            connectionsByIp.delete(ip);
            // No more open connections from this IP - drop the connection-rate
            // entry too, so a reconnecting user starts a fresh window.
            connectRateByIp.delete(ip);
        } else {
            connectionsByIp.set(ip, remaining);
        }

        // Drop this socket's replay cache - its signatures are no longer
        // valid after disconnect (the identity binding resets on rejoin).
        forgetReplayCache(socket.id);

        // If they were mid-call (or mid-ring), tell everyone they were
        // connected to - could be several people now, in a group call
        const peerIds = endAllSessionsFor(socket.id);
        peerIds.forEach(peerId => io.to(peerId).emit('call_ended', { senderId: socket.id }));

        const leavingUser = users.get(socket.id);

        users.delete(socket.id);
        socket.to().emit('user_left', { id: socket.id, nick: leavingUser?.nick });
        console.log(`> Disconnected: ${socket.id}`);
    });
//call
// Signaling events for WebRTC Voice Calls
socket.on('call_user', ({ recipientId, offer, groupId }) => {
    if (!limits.callUser()) {
        strike('call_user');
        return socket.emit('call_error', 'Too many calls - please wait a moment.');
    }
    const caller = users.get(socket.id);
    const recipient = users.get(recipientId);

    // Must be a joined user calling another joined user
    if (!caller) return;
    if (!recipient) {
        return socket.emit('call_error', 'That user is offline.');
    }
    if (!isValidBlob(offer, MAX_SDP_BLOB)) {
        return socket.emit('call_error', 'Malformed call payload.');
    }
    if (recipientId === socket.id) {
        return socket.emit('call_error', 'You cannot call yourself.');
    }
    // Glare: the recipient already called US (both clicked Call at ~the
    // same time). Their offer is already in flight to this socket, so we
    // silently drop this second offer - the client resolves the collision
    // by answering theirs instead. Must be checked BEFORE the busy checks.
    const existing = getSession(socket.id, recipientId);
    if (existing) {
        console.log(`> Glare: ${caller.nick} <-> ${recipient.nick} (mutual call)`);
        return;
    }

    const myGroupId = currentGroupId(socket.id);
    const theirGroupId = currentGroupId(recipientId);

    if (groupId) {
        // Inviting a new member into a call I'm already in. Only valid if
        // the groupId actually matches the call I'm currently part of -
        // otherwise a client could claim any groupId, real or made up.
        if (myGroupId !== groupId) {
            return socket.emit('call_error', 'You are not part of that call.');
        }
        // Busy only if they're in a DIFFERENT call - if they're already in
        // THIS group (the mesh-completion case: an existing member calling
        // a just-joined member to complete the mesh), that's expected.
        if (theirGroupId && theirGroupId !== groupId) {
            return socket.emit('call_error', `${recipient.nick} is on another call.`);
        }
        const currentSize = mySessions(socket.id).size + 1; // +1 for me
        if (currentSize >= MAX_GROUP_SIZE) {
            return socket.emit('call_error', `Group calls are limited to ${MAX_GROUP_SIZE} people.`);
        }
    } else {
        // A plain 1:1 call attempt - I must not already be in any call.
        if (myGroupId) {
            return socket.emit('call_error', 'You are already in a call.');
        }
        if (theirGroupId) {
            return socket.emit('call_error', `${recipient.nick} is on another call.`);
        }
    }

    // A fresh 1:1 call defines its own new groupId (every call has one,
    // even if it never grows past two people); inviting a new member
    // reuses the group's existing id so the whole mesh shares it.
    const effectiveGroupId = groupId || crypto.randomUUID();

    // Reserve both parties while the phone "rings"
    const callerId = socket.id;
    setSession(callerId, recipientId, { peerId: recipientId, groupId: effectiveGroupId, status: 'ringing', timer: null });
    setSession(recipientId, callerId, { peerId: callerId, groupId: effectiveGroupId, status: 'ringing', timer: null });

    // Auto-resolve if nobody answers in time. The same timer handle is
    // stored on both sides so endPairSession() (called from decline/answer/
    // hangup/disconnect) clears it regardless of which side acts first.
    const timer = setTimeout(() => {
        const session = getSession(callerId, recipientId);
        if (!session || session.status !== 'ringing') return; // already resolved
        endPairSession(callerId, recipientId);
        io.to(callerId).emit('call_timeout', { peerId: recipientId });
        io.to(recipientId).emit('call_missed', { peerId: callerId });
        console.log(`> Call timeout (no answer): ${caller.nick} -> ${recipient.nick}`);
    }, RING_TIMEOUT_MS);
    getSession(callerId, recipientId).timer = timer;
    getSession(recipientId, callerId).timer = timer;

    // Existing group members (nick + id), so the invitee's UI can show who
    // else is already on the call - empty for a plain 1:1 call.
    const existingMembers = groupId
        ? groupPeersOf(callerId, groupId).filter(id => id !== recipientId).map(id => ({ id, nick: users.get(id)?.nick }))
        : [];

    // Forward the offer to the recipient (Phase 2: real SDP; Phase 3: encrypted blob)
    io.to(recipientId).emit('incoming_call', {
        senderId: callerId,
        offer: offer,
        groupId: effectiveGroupId,
        groupMembers: existingMembers
    });
    console.log(`> Call: ${caller.nick} -> ${recipient.nick}${groupId ? ' (group invite)' : ''}`);
});

socket.on('answer_call', ({ recipientId, answer }) => {
    if (!limits.answerCall()) { strike('answer_call'); return; }
    // Only the callee of an actual ringing session may answer
    const session = getSession(socket.id, recipientId);
    if (!session || session.status !== 'ringing') return;
    if (!isValidBlob(answer, MAX_SDP_BLOB)) return;

    if (session.timer) clearTimeout(session.timer); // answered - ring timeout no longer applies
    session.status = 'connected';
    session.timer = null;
    const peerSession = getSession(recipientId, socket.id);
    if (peerSession) { peerSession.status = 'connected'; peerSession.timer = null; }

    // Forward the answer back to the caller
    io.to(recipientId).emit('call_accepted', {
        senderId: socket.id,
        answer: answer,
        groupId: session.groupId
    });

    // If the person I just answered (recipientId) already has OTHER
    // connected members under this groupId, I've just joined an existing
    // group call, not started a fresh 1:1 one. Each of those other members
    // needs to independently connect to me too, to complete the mesh -
    // they don't get another consent prompt, since joining the group was
    // already a single decision on my part.
    const otherMembers = groupPeersOf(recipientId, session.groupId).filter(id => id !== socket.id);
    if (otherMembers.length > 0) {
        const joinerNick = users.get(socket.id)?.nick;
        otherMembers.forEach(memberId => {
            io.to(memberId).emit('group_member_joined', {
                groupId: session.groupId,
                newMemberId: socket.id,
                newMemberNick: joinerNick
            });
        });
    }
});

socket.on('decline_call', ({ recipientId }) => {
    if (!limits.declineCall()) { strike('decline_call'); return; }
    const session = getSession(socket.id, recipientId);
    if (!session) return;

    endPairSession(socket.id, recipientId);
    io.to(recipientId).emit('call_declined', { senderId: socket.id });
});

socket.on('ice_candidate', ({ recipientId, candidate }) => {
    if (!limits.iceCandidate()) { strike('ice_candidate'); return; } // silent - bursts are normal here

    // Only relay ICE between two sockets that share a call session
    const session = getSession(socket.id, recipientId);
    if (!session) return;
    if (!isValidBlob(candidate, MAX_CAND_BLOB)) return;

    io.to(recipientId).emit('ice_candidate', {
        senderId: socket.id,
        candidate: candidate
    });
});

// Mid-call renegotiation (currently: toggling video on/off after the call
// is already connected). Unlike call_user, this doesn't create a session
// or do busy/glare checks - the call already exists; we're just relaying
// a second round of encrypted SDP over the same established session. Only
// valid once the session has actually reached 'connected' - renegotiating
// a call that's still ringing makes no sense and would only be reachable
// by a client ignoring its own state machine.
socket.on('renegotiate_offer', ({ recipientId, offer }) => {
    if (!limits.renegotiate()) { strike('renegotiate'); return; }
    const session = getSession(socket.id, recipientId);
    if (!session || session.status !== 'connected') return;
    if (!isValidBlob(offer, MAX_SDP_BLOB)) return;

    io.to(recipientId).emit('renegotiate_offer', { senderId: socket.id, offer });
});

socket.on('renegotiate_answer', ({ recipientId, answer }) => {
    if (!limits.renegotiate()) { strike('renegotiate'); return; }
    const session = getSession(socket.id, recipientId);
    if (!session || session.status !== 'connected') return;
    if (!isValidBlob(answer, MAX_SDP_BLOB)) return;

    io.to(recipientId).emit('renegotiate_answer', { senderId: socket.id, answer });
});

// --- Encrypted P2P file transfer ---
// A completely independent WebRTC connection from voice/video calls - you
// don't need to be in a call to send a file, and sending a file doesn't
// start one. Deliberately lighter-weight than call signaling: no server-
// side session tracking (no busy state, no ring timeout - a transfer just
// has an offer/answer/decline/cancel lifecycle), since file transfers can
// reasonably happen several at once with different people, unlike calls.
// The server's job here is limited to rate limiting, size-checking the
// blobs, and confirming both parties are actually joined - it never sees
// the transferId as anything more than an opaque routing token, and never
// sees file content at all (that flows peer-to-peer once the data channel
// is up). Each event still requires the recipient to currently be online;
// unlike a stored callSessions entry, there is nothing here for a client
// to inject into someone else's transfer except by guessing a transferId,
// which is a client-generated UUID - the client-side handler independently
// checks it against a transfer it's actually expecting before acting on it.
socket.on('file_offer', ({ recipientId, transferId, offer, timestamp, signature }) => {
    if (!limits.fileOffer()) { strike('file_offer'); return; }
    const sender = users.get(socket.id);
    if (!sender || !users.has(recipientId)) return;
    if (!isValidBlob(transferId, MAX_TRANSFER_ID) || !isValidBlob(offer, MAX_SDP_BLOB)) return;
    if (!isValidBlob(signature, MAX_SIG_BLOB) || typeof timestamp !== 'number') return;
    if (Math.abs(Date.now() - timestamp) > MESSAGE_TIMESTAMP_SKEW_MS) return;
    if (!verifyStringSignature(sender.identityKey, `${timestamp}:${offer}`, signature)) return;
    if (isReplay(socket.id, signature)) return;
    rememberSignature(socket.id, signature);

    io.to(recipientId).emit('file_offer', { senderId: socket.id, transferId, offer, timestamp, signature });
});

socket.on('file_answer', ({ recipientId, transferId, answer, timestamp, signature }) => {
    if (!limits.fileSignal()) { strike('file_signal'); return; }
    const sender = users.get(socket.id);
    if (!sender || !users.has(recipientId)) return;
    if (!isValidBlob(transferId, MAX_TRANSFER_ID) || !isValidBlob(answer, MAX_SDP_BLOB)) return;
    if (!isValidBlob(signature, MAX_SIG_BLOB) || typeof timestamp !== 'number') return;
    if (Math.abs(Date.now() - timestamp) > MESSAGE_TIMESTAMP_SKEW_MS) return;
    if (!verifyStringSignature(sender.identityKey, `${timestamp}:${answer}`, signature)) return;
    if (isReplay(socket.id, signature)) return;
    rememberSignature(socket.id, signature);

    io.to(recipientId).emit('file_answer', { senderId: socket.id, transferId, answer, timestamp, signature });
});

socket.on('file_ice_candidate', ({ recipientId, transferId, candidate }) => {
    if (!limits.fileSignal()) { strike('file_signal'); return; }
    if (!users.has(socket.id) || !users.has(recipientId)) return;
    if (!isValidBlob(transferId, MAX_TRANSFER_ID) || !isValidBlob(candidate, MAX_CAND_BLOB)) return;

    io.to(recipientId).emit('file_ice_candidate', { senderId: socket.id, transferId, candidate });
});

socket.on('file_decline', ({ recipientId, transferId }) => {
    if (!limits.fileSignal()) { strike('file_signal'); return; }
    if (!users.has(socket.id) || !isValidBlob(transferId, MAX_TRANSFER_ID)) return;

    io.to(recipientId).emit('file_declined', { senderId: socket.id, transferId });
});

socket.on('file_cancel', ({ recipientId, transferId }) => {
    if (!limits.fileSignal()) { strike('file_signal'); return; }
    if (!users.has(socket.id) || !isValidBlob(transferId, MAX_TRANSFER_ID)) return;

    io.to(recipientId).emit('file_canceled', { senderId: socket.id, transferId });
});

socket.on('hangup', () => {
    if (!limits.hangup()) { strike('hangup'); return; }
    // Session-based: no client-supplied recipient needed. Leaves every
    // pairwise session at once - in a group call that's everyone, not just
    // whoever happened to be first in the mesh.
    const peerIds = endAllSessionsFor(socket.id);
    peerIds.forEach(peerId => io.to(peerId).emit('call_ended', { senderId: socket.id }));
});
//call
});

const PORT = process.env.PORT || 3000;
// NOTE (Phase 0): Voice calls require a secure context. getUserMedia() only
// works on https:// origins or on http://localhost. Since we bind to
// 127.0.0.1, remote users must reach this app through a TLS-terminating
// tunnel or reverse proxy (nginx + certbot, cloudflared, ngrok, etc.).
server.listen(PORT, '127.0.0.1', () => {
    console.log(`Abyss.Tunnel activated on port ${PORT}`);
    console.log(`> Ring timeout: ${RING_TIMEOUT_MS}ms`);
    console.log(`> Room password: ${ROOM_PASSWORD_HASH ? 'required' : 'not required'}`);
    console.log(`> Max connections per IP: ${MAX_CONNECTIONS_PER_IP}`);
    console.log(`> Connect rate per IP: ${MAX_CONNECT_RATE_PER_IP}/${CONNECT_RATE_WINDOW_MS}ms`);
    console.log(`> CORS origin: ${ALLOWED_ORIGIN}`);
    console.log(`> Proxy trust: ${trustProxyConfig !== false ? trustProxyConfig : 'off'}`);
});