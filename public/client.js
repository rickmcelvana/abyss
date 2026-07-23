/**
 * Abyss.Engine
 * Production-ready client logic with Hybrid E2EE (RSA/AES)
 * and Independent Tab State Management.
 */

document.addEventListener('DOMContentLoaded', () => {
    const socket = io();

    const MAX_HISTORY_PER_TAB = 500;

    function capHistory(tabId) {
        const arr = state.history[tabId];
        if (arr && arr.length > MAX_HISTORY_PER_TAB) {
            arr.splice(0, arr.length - MAX_HISTORY_PER_TAB);
        }
    }

    /** Convert a Uint8Array (or ArrayBuffer/TypedArray) to base64 without spreading
        the buffer onto the call stack, avoiding stack overflow on large inputs. */
    function uint8ArrayToB64(buf) {
        const bytes = new Uint8Array(buf);
        // Build result in chunks of 8192 to keep the apply call stack manageable
        let result = '';
        let i = 0;
        const chunkSize = 8192;
        while (i < bytes.length) {
            const end = Math.min(i + chunkSize, bytes.length);
            result += String.fromCharCode.apply(null, bytes.subarray(i, end));
            i = end;
        }
        return btoa(result);
    }

    // Application State
    const state = {
        keys: null,               // RSA KeyPair
        activeTabs: new Map(),     // tabId -> {id, name}
        currentTabId: 'global',   // ID of the active view
        phonebook: {},             // nickname -> {publicKey, id}
        history: {},               // tabId -> Array of message objects
        callLog: [],                // Phase 6: {id, direction, peerId, peerNick, outcome, timestamp, durationSeconds}
        missedCallCount: 0,          // unread badge count on the calls tab
        myPresence: 'active',        // matches the server's default for a freshly joined socket
        notificationsEnabled: false, // opt-in, see the 🔔 toggle
        fileTransfers: {},           // transferId -> live transfer state (pc, channel, progress, etc.)
        identity: null,              // Phase 7: this device's persistent ECDSA keypair {publicKey, privateKey}
        identityFingerprint: null,   // display fingerprint of our own identity key
        trustStatus: {},             // nick -> {status: 'ok'|'new'|'changed', fingerprint, previousFingerprint?}
        lastUserList: [],            // most recent user_list payload, kept for re-render after trust decisions
        call: {                    // Voice call state machine
            status: 'idle',        // 'idle' | 'calling' | 'ringing' | 'connected'
            peerId: null,
            peerNick: null,
            direction: null,       // 'outgoing' | 'incoming' - who placed this call
            peerKeyObj: null,      // peer's imported RSA public key (for signaling encryption)
            pendingOffer: null,    // encrypted SDP offer held while ringing
            pc: null,              // RTCPeerConnection
            localStream: null,     // our microphone MediaStream
            pendingCandidates: [], // ICE candidates that arrived before remoteDescription
            muted: false,
            startedAt: null,       // timestamp for the call duration timer
            lastRtp: null,         // previous inbound-rtp sample for quality stats
            localVideoStream: null,   // our camera MediaStream, once video is toggled on
            videoSender: null,        // RTCRtpSender for the video track - needed to removeTrack() later
            videoActive: false,       // whether WE currently have our camera on
            negotiating: false,       // renegotiation lock - see the video toggle / onnegotiationneeded code
            negotiationTimeoutId: null
        }
    };


    // --- Web Crypto Constants & Utilities ---
    const RSA_PARAMS = { name: "RSA-OAEP", modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: "SHA-256" };
    const AES_PARAMS = { name: "AES-GCM", length: 256 };
    // Phase 7: long-term identity signing key, separate from the per-session
    // RSA encryption key above. ECDSA can't encrypt, so this key's only job
    // is proving "I am the same person you talked to before" via signatures -
    // the encryption key keeps rotating every join, limiting what a single
    // compromised session key exposes.
    const ECDSA_PARAMS = { name: "ECDSA", namedCurve: "P-256" };

    // --- WebRTC ICE Configuration (Phase 4 STUN, Phase 5 time-limited TURN) ---
    // STUN default. Full credentials (including any TURN relay, generated
    // fresh with a short TTL) are fetched from the server right before each
    // call via the authenticated socket - not on page load - so a tab left
    // open overnight never tries to use stale/expired TURN credentials.
    let rtcConfig = {
        iceServers: [
            { urls: "stun:stun.l.google.com:19302" },
            { urls: "stun:stun1.l.google.com:19302" }
        ]
    };

    /**
     * Requests a fresh ICE config over the joined socket and updates
     * rtcConfig in place. Falls back to the current (STUN-only) config on
     * timeout or error, so a flaky request never blocks placing a call.
     */
    function refreshIceConfig() {
        return new Promise((resolve) => {
            let settled = false;
            const finish = (cfg) => {
                if (settled) return;
                settled = true;
                if (cfg && Array.isArray(cfg.iceServers) && cfg.iceServers.length) {
                    rtcConfig = { iceServers: cfg.iceServers };
                }
                resolve(rtcConfig);
            };
            // Ack-style request; the server only attaches TURN credentials
            // if this socket has actually joined (see server's
            // get_ice_config handler)
            socket.emit('get_ice_config', finish);
            setTimeout(() => finish(null), 3000); // don't hang call setup
        });
    }

    async function generateKeys() {
        return await window.crypto.subtle.generateKey(RSA_PARAMS, true, ["encrypt", "decrypt"]);
    }

    // --- Persistent identity (Phase 7) ---
    // Two IndexedDB stores, both scoped to this browser only (never synced,
    // never sent anywhere raw):
    //   'identity' - this device's own long-term ECDSA keypair (one record)
    //   'trust'    - fingerprints pinned for other nicks we've seen (TOFU)
    const IDB_NAME = 'abyss-identity-store';
    const IDB_VERSION = 1;

    function openIdb() {
        return new Promise((resolve, reject) => {
            const req = indexedDB.open(IDB_NAME, IDB_VERSION);
            req.onupgradeneeded = () => {
                const db = req.result;
                if (!db.objectStoreNames.contains('identity')) db.createObjectStore('identity');
                if (!db.objectStoreNames.contains('trust')) db.createObjectStore('trust');
            };
            req.onsuccess = () => resolve(req.result);
            req.onerror = () => reject(req.error);
        });
    }
    async function idbGet(storeName, key) {
        const db = await openIdb();
        return new Promise((resolve, reject) => {
            const tx = db.transaction(storeName, 'readonly');
            const req = tx.objectStore(storeName).get(key);
            req.onsuccess = () => resolve(req.result);
            req.onerror = () => reject(req.error);
        });
    }
    async function idbSet(storeName, key, value) {
        const db = await openIdb();
        return new Promise((resolve, reject) => {
            const tx = db.transaction(storeName, 'readwrite');
            tx.objectStore(storeName).put(value, key);
            tx.oncomplete = () => resolve();
            tx.onerror = () => reject(tx.error);
        });
    }
    async function idbDelete(storeName, key) {
        const db = await openIdb();
        return new Promise((resolve, reject) => {
            const tx = db.transaction(storeName, 'readwrite');
            tx.objectStore(storeName).delete(key);
            tx.oncomplete = () => resolve();
            tx.onerror = () => reject(tx.error);
        });
    }

    /**
     * Loads this browser's identity keypair from IndexedDB, generating one
     * on first use. The private key is generated non-extractable - it can
     * sign, but JavaScript (including malicious injected JS) can never read
     * its raw bytes back out, even from within this same page. Per the Web
     * Crypto spec, the public half of an asymmetric pair is always
     * extractable regardless of this flag, so we can still export/display it.
     * IndexedDB supports storing CryptoKey objects directly via structured
     * clone, extractable or not.
     */
    async function loadOrCreateIdentity() {
        try {
            const rec = await idbGet('identity', 'self');
            if (rec && rec.publicKey && rec.privateKey) return rec;
        } catch (err) { /* fall through to generation */ }

        const pair = await window.crypto.subtle.generateKey(ECDSA_PARAMS, false, ['sign', 'verify']);
        const record = { publicKey: pair.publicKey, privateKey: pair.privateKey };
        await idbSet('identity', 'self', record);
        return record;
    }

    async function exportIdentityPublicKeyB64(pubKey) {
        const raw = await window.crypto.subtle.exportKey('spki', pubKey);
        return uint8ArrayToB64(raw);
    }

    /** SHA-256 fingerprint of a base64 SPKI public key, as spaced uppercase hex. */
    async function fingerprintFromSpkiB64(spkiB64) {
        const bytes = Uint8Array.from(atob(spkiB64), c => c.charCodeAt(0));
        const hash = await window.crypto.subtle.digest('SHA-256', bytes);
        const hex = [...new Uint8Array(hash)].map(b => b.toString(16).padStart(2, '0')).join('');
        return hex.slice(0, 32).toUpperCase().match(/.{1,4}/g).join(' '); // 16 bytes shown, plenty to compare aloud
    }

    /**
     * TOFU pinning check for a contact's identity key. First sighting of a
     * nick pins its fingerprint; later sightings are compared against the
     * pin. A mismatch means either they reset their identity or someone/
     * something (e.g. the server) is presenting a different key under their
     * name - we can't tell which, so we surface it rather than silently
     * trusting it.
     */
    async function checkTrust(nick, identityKeyB64) {
        const fingerprint = await fingerprintFromSpkiB64(identityKeyB64);
        let pinned;
        try { pinned = await idbGet('trust', nick); } catch (err) { pinned = undefined; }

        if (!pinned) {
            await idbSet('trust', nick, { fingerprint, verified: false });
            return { status: 'new', fingerprint, verified: false };
        }
        if (pinned.fingerprint === fingerprint) {
            return { status: 'ok', fingerprint, verified: !!pinned.verified };
        }
        return { status: 'changed', fingerprint, previousFingerprint: pinned.fingerprint, verified: false };
    }

    async function trustNewKey(nick, fingerprint) {
        // A key change always resets to unverified - "I acknowledge this is
        // a different key" is not the same claim as "I confirmed out of
        // band that this is really them"
        await idbSet('trust', nick, { fingerprint, verified: false });
        state.trustStatus[nick] = { status: 'ok', fingerprint, verified: false };
    }

    /** Explicit "I compared this fingerprint with them out of band and it matches." */
    async function markVerified(nick, fingerprint) {
        await idbSet('trust', nick, { fingerprint, verified: true });
        state.trustStatus[nick] = { status: 'ok', fingerprint, verified: true };
    }

    /** Signs an arbitrary string with our identity key - same primitive the join proof uses. */
    async function signWithIdentity(message) {
        const sigBuf = await window.crypto.subtle.sign(
            { name: 'ECDSA', hash: 'SHA-256' },
            state.identity.privateKey,
            new TextEncoder().encode(message)
        );
        return uint8ArrayToB64(sigBuf);
    }

    /** Verifies an arbitrary string's signature against a base64 SPKI public key. */
    async function verifyIdentitySignatureClient(identityKeyB64, message, signatureB64) {
        try {
            const keyBytes = Uint8Array.from(atob(identityKeyB64), c => c.charCodeAt(0));
            const pubKey = await window.crypto.subtle.importKey(
                'spki', keyBytes, ECDSA_PARAMS, false, ['verify']
            );
            const sigBytes = Uint8Array.from(atob(signatureB64), c => c.charCodeAt(0));
            return await window.crypto.subtle.verify(
                { name: 'ECDSA', hash: 'SHA-256' },
                pubKey,
                sigBytes,
                new TextEncoder().encode(message)
            );
        } catch (err) {
            return false; // malformed key/signature - fail closed
        }
    }

    /**
     * Full authenticity check for an incoming message: the signature must
     * verify against the sender's identity key, AND that key must be the
     * one we've actually pinned for their nick - not just "a" key they
     * happen to be presenting right now. This is the client-side trust
     * anchor; the server also verifies signatures (see server.js) but that
     * only proves a message matches whatever identity a socket registered
     * with, not that it's the identity WE recognize as this person.
     */
    async function verifyIncomingMessage(nick, signedString, signature) {
        const contact = state.phonebook[nick];
        const trust = state.trustStatus[nick];
        if (!contact || !contact.identityKey) return false;
        if (trust && trust.status === 'changed') return false; // unresolved key change - don't trust anything from them yet
        return verifyIdentitySignatureClient(contact.identityKey, signedString, signature);
    }


    async function exportPublicKey(key) {
        const exported = await window.crypto.subtle.exportKey("spki", key);
        return uint8ArrayToB64(exported);
    }

    async function importPublicKey(base64Key) {
        const str = atob(base64Key);
        const buf = new Uint8Array(str.length);
        for (let i = 0; i < str.length; i++) buf[i] = str.charCodeAt(i);
        // Strict "encrypt" only to satisfy browser security for public keys
        return await window.crypto.subtle.importKey("spki", buf, { name: "RSA-OAEP", hash: "SHA-256" }, true, ["encrypt"]);
    }

    /**
     * Hybrid Encryption Engine:
     * Encrypts message with AES (for length), wraps the AES key with RSA (for identity).
     */
    async function hybridEncrypt(publicKeyObj, text) {
        const enc = new TextEncoder();
        // 1. Generate temporary AES session key
        const aesKey = await window.crypto.subtle.generateKey(AES_PARAMS, true, ["encrypt", "decrypt"]);
        const iv = window.crypto.getRandomValues(new Uint8Array(12));

        // 2. Encrypt message body with AES-GCM
        const encryptedContent = await window.crypto.subtle.encrypt({ ...AES_PARAMS, iv }, aesKey, enc.encode(text));

        // 3. Export the session key and wrap it with RSA Public Key
        const exportedAesKey = await window.crypto.subtle.exportKey("raw", aesKey);
        const encryptedAesKey = await window.crypto.subtle.encrypt({ ...RSA_PARAMS, iv: new Uint8Array([0]) }, publicKeyObj, exportedAesKey);

        // 4. Package as a dot-separated Base64 string (IV.WrappedKey.Ciphertext)
        return uint8ArrayToB64(iv) + "." +
               uint8ArrayToB64(encryptedAesKey) + "." +
               uint8ArrayToB64(encryptedContent);
    }

    async function hybridDecrypt(privateKeyObj, blob) {
        const [ivBase64, keyBase64, contentBase64] = blob.split(".");
        const iv = new Uint8Array(atob(ivBase64).split("").map(c => c.charCodeAt(0)));
        const encryptedKey = new Uint8Array(atob(keyBase64).split("").map(c => c.charCodeAt(0)));
        const content = new Uint8Array(atob(contentBase64).split("").map(c => c.charCodeAt(0)));

        // 1. Unwrap the AES session key using our Private RSA Key
        const aesKeyBuffer = await window.crypto.subtle.decrypt({ ...RSA_PARAMS, iv: new Uint8Array([0]) }, privateKeyObj, encryptedKey);
        const aesKey = await window.crypto.subtle.importKey("raw", aesKeyBuffer, "AES-GCM", true, ["decrypt"]);

        // 2. Decrypt message content using the unwrapped session key
        const decrypted = await window.crypto.subtle.decrypt({ ...AES_PARAMS, iv }, aesKey, content);
        return new TextDecoder().decode(decrypted);
    }

    // --- UI Elements ---
    const welcomeScreen = document.getElementById('welcome-screen');
    const chatInterface = document.getElementById('chat-interface');
    const joinForm = document.getElementById('join-form');
    const userListElem = document.getElementById('user-list');
    const msgForm = document.getElementById('msg-form');
    const msgInput = document.getElementById('msg-input');
    const messageDisplay = document.getElementById('chat-window');

    // Mobile sidebar drawer (see the ≤768px breakpoint in style.css - the
    // sidebar is a permanent column on desktop but an overlay drawer on a
    // phone-sized viewport, since a fixed 260px column would eat most of
    // the screen there).
    const sidebarElem = document.querySelector('.sidebar');
    const sidebarBackdrop = document.getElementById('sidebar-backdrop');
    const sidebarToggle = document.getElementById('sidebar-toggle');
    const sidebarToggleCount = document.getElementById('sidebar-toggle-count');

    function openSidebar() {
        sidebarElem.classList.add('open');
        sidebarBackdrop.classList.add('open');
    }
    function closeSidebar() {
        sidebarElem.classList.remove('open');
        sidebarBackdrop.classList.remove('open');
    }
    sidebarToggle.addEventListener('click', () => {
        sidebarElem.classList.contains('open') ? closeSidebarWithFocus() : openSidebarWithFocus();
    });
    sidebarBackdrop.addEventListener('click', closeSidebarWithFocus);

    // --- Focus management (modals, the mobile drawer) ---
    // Shared across every overlay in the app: remember what had focus
    // before opening, move focus inside on open, trap Tab within it while
    // open, and restore focus to where the user was once it closes. None
    // of this is automatic for a <div> with role="alertdialog" - it has to
    // be done by hand.
    let modalReturnFocus = null;

    function focusableIn(container) {
        return [...container.querySelectorAll('button, [href], input, select, textarea, [tabindex]:not([tabindex="-1"])')]
            .filter(el => !el.disabled && el.offsetParent !== null);
    }

    function showModal(modalEl) {
        modalReturnFocus = document.activeElement;
        modalEl.classList.remove('hidden');
        const focusable = focusableIn(modalEl);
        if (focusable.length) focusable[0].focus();
    }

    function hideModal(modalEl) {
        modalEl.classList.add('hidden');
        if (modalReturnFocus && document.body.contains(modalReturnFocus)) modalReturnFocus.focus();
        modalReturnFocus = null;
    }

    function openSidebarWithFocus() {
        modalReturnFocus = document.activeElement;
        openSidebar();
        const focusable = focusableIn(sidebarElem);
        if (focusable.length) focusable[0].focus();
    }
    function closeSidebarWithFocus() {
        closeSidebar();
        if (modalReturnFocus && document.body.contains(modalReturnFocus)) modalReturnFocus.focus();
        modalReturnFocus = null;
    }

    // One global handler covers every overlay - simpler and less error-
    // prone than attaching/detaching a listener per modal on every
    // show/hide. Escape always means "back out of whatever's open, the
    // safest way" (decline for the call/file prompts, close for the
    // drawer or an open fingerprint panel); Tab is trapped within
    // whichever overlay is currently open, if any.
    document.addEventListener('keydown', (e) => {
        const openModal = !incomingModal.classList.contains('hidden') ? incomingModal
            : !incomingFileModal.classList.contains('hidden') ? incomingFileModal
            : null;

        if (e.key === 'Escape') {
            if (openModal === incomingModal) { declineCallBtn.click(); return; }
            if (openModal === incomingFileModal) { declineFileBtn.click(); return; }
            if (sidebarElem.classList.contains('open')) { closeSidebarWithFocus(); return; }
            const openReveal = document.querySelector('.fingerprint-reveal');
            if (openReveal) { openReveal.remove(); return; }
            return;
        }

        if (e.key !== 'Tab') return;
        const trapIn = openModal || (sidebarElem.classList.contains('open') ? sidebarElem : null);
        if (!trapIn) return;
        const focusable = focusableIn(trapIn);
        if (focusable.length === 0) return;
        const first = focusable[0], last = focusable[focusable.length - 1];
        if (e.shiftKey && document.activeElement === first) {
            e.preventDefault();
            last.focus();
        } else if (!e.shiftKey && document.activeElement === last) {
            e.preventDefault();
            first.focus();
        }
    });


    // Call UI elements
    const callStatusBar = document.getElementById('call-status-bar');
    const callStatusText = document.getElementById('call-status-text');
    const hangupBtn = document.getElementById('hangup-btn');
    const incomingModal = document.getElementById('incoming-call-modal');
    const incomingCallText = document.getElementById('incoming-call-text');
    const acceptCallBtn = document.getElementById('accept-call-btn');
    const declineCallBtn = document.getElementById('decline-call-btn');
    const remoteAudio = document.getElementById('remote-audio');
    const safetyCodeElem = document.getElementById('safety-code');
    const muteBtn = document.getElementById('mute-btn');
    const qualityElem = document.getElementById('call-quality');
    const videoBtn = document.getElementById('video-btn');
    const videoPanel = document.getElementById('video-panel');
    const localVideoElem = document.getElementById('local-video');
    const remoteVideoElem = document.getElementById('remote-video');
    const inputAreaElem = document.querySelector('.input-area');
    const addToCallBtn = document.getElementById('add-to-call-btn');
    const groupParticipantsElem = document.getElementById('group-participants');
    const groupInvitePicker = document.getElementById('group-invite-picker');
    const groupInviteList = document.getElementById('group-invite-list');
    const callParticipantsListElem = document.getElementById('call-participants-list');
    const extraVideoTilesElem = document.getElementById('extra-video-tiles');

    // File transfer UI elements
    const attachFileBtn = document.getElementById('attach-file-btn');
    const filePicker = document.getElementById('file-picker');
    const incomingFileModal = document.getElementById('incoming-file-modal');
    const incomingFileText = document.getElementById('incoming-file-text');
    const acceptFileBtn = document.getElementById('accept-file-btn');
    const declineFileBtn = document.getElementById('decline-file-btn');

    /**
     * Shown whenever either side has a camera on. Deliberately driven by an
     * explicit flag exchanged in the signaling payload (see
     * onnegotiationneeded / renegotiate_offer / renegotiate_answer below),
     * not by whether the video element currently has a track attached -
     * removeTrack() + renegotiation makes the sender stop sending, but the
     * receiver's MediaStreamTrack typically just freezes on its last frame
     * rather than firing 'ended', so track presence alone can't tell us
     * the camera was actually turned off.
     */
    function updateVideoPanelVisibility() {
        const show = state.call.videoActive || state.call.remoteVideoActive;
        if (!state.call.remoteVideoActive) remoteVideoElem.srcObject = null;
        videoPanel.classList.toggle('hidden', !show);
        localVideoElem.classList.toggle('hidden', !state.call.videoActive);
    }

    // --- Typing indicators (state only - handlers/rendering wired up below) ---
    // Declared here, before the first setActiveTab('global') call a few
    // lines down, since that call synchronously invokes
    // renderTypingIndicator() and a `const` referenced before its own
    // declaration line has run is a ReferenceError (temporal dead zone),
    // not just "undefined".
    const TYPING_EXPIRY_MS = 3000;
    const typingByContext = {}; // contextId -> Map<nick, timeoutId>
    const typingIndicatorElem = document.getElementById('typing-indicator');

    function contextIdFor(nick, isPrivate) {
        return isPrivate ? `pm_${nick}` : 'global';
    }

    function renderTypingIndicator() {
        const bucket = typingByContext[state.currentTabId];
        const nicks = bucket ? [...bucket.keys()] : [];
        if (nicks.length === 0) {
            typingIndicatorElem.classList.add('hidden');
            typingIndicatorElem.textContent = '';
            return;
        }
        const verb = nicks.length === 1 ? 'is' : 'are';
        const names = nicks.length <= 2 ? nicks.join(' and ') : `${nicks.length} people`;
        typingIndicatorElem.textContent = `${names} ${verb} typing…`;
        typingIndicatorElem.classList.remove('hidden');
    }

createTabUI('global', '#twistedminds');
// Phase 6: permanent, non-closable call log tab (see .tab[data-id="calls"]
// close-btn hiding in style.css)
createTabUI('calls', '☎ Calls');
const callsTabElem = document.getElementById('tab-calls');
const callsBadge = document.createElement('span');
callsBadge.id = 'calls-badge';
callsBadge.className = 'tab-badge hidden';
callsTabElem.appendChild(callsBadge);
setActiveTab('global');

function updateCallsTabBadge() {
    if (state.missedCallCount > 0) {
        callsBadge.textContent = state.missedCallCount > 9 ? '9+' : String(state.missedCallCount);
        callsBadge.classList.remove('hidden');
    } else {
        callsBadge.classList.add('hidden');
    }
}


    // --- Core Application Logic ---

    // Phase 7: load (or create) this device's persistent identity as soon as
    // the page loads - not on join - so the fingerprint can be shown before
    // the user commits to a nickname, and so join itself is never slowed
    // down by key generation.
    const identityFingerprintRow = document.getElementById('identity-fingerprint-row');
    const identityFingerprintElem = document.getElementById('identity-fingerprint');
    const resetIdentityLink = document.getElementById('reset-identity-link');
    let joinNonce = null;

    (async () => {
        state.identity = await loadOrCreateIdentity();
        const identityKeyB64 = await exportIdentityPublicKeyB64(state.identity.publicKey);
        state.identityFingerprint = await fingerprintFromSpkiB64(identityKeyB64);
        identityFingerprintElem.textContent = state.identityFingerprint;
        identityFingerprintRow.classList.remove('hidden');
    })().catch(err => console.error('Identity load error:', err));

    socket.on('join_nonce', (nonce) => { joinNonce = nonce; });

    // Phase 3 (second hardening round): graceful reconnection state. Once
    // we've successfully joined, a dropped connection shouldn't wipe chat
    // history, tabs, or identity - all of that already lives in memory/
    // IndexedDB independent of the socket. We just need to silently redo
    // the application-level join handshake when the transport comes back.
    let hasJoinedOnce = false;
    let currentRoomPassword = '';

    const connectionBanner = document.getElementById('connection-banner');
    const connectionBannerText = document.getElementById('connection-banner-text');

    function setConnectionBanner(text, cls) {
        connectionBannerText.textContent = text;
        connectionBanner.className = cls || '';
        connectionBanner.classList.remove('hidden');
    }
    function hideConnectionBanner() {
        connectionBanner.classList.add('hidden');
    }
    function setOffline(offline) {
        chatInterface.classList.toggle('offline', offline);
    }

    /**
     * Builds and sends a signed join payload from currently-stored
     * nick/about/password. Shared by the initial join (typed by the user)
     * and the silent rejoin after a reconnect (replayed from memory) - the
     * signing logic must stay identical between them.
     */
    async function performJoin(nick, about, password) {
        state.keys = await generateKeys(); // fresh session key each (re)join, on purpose
        const pubKeyBase64 = await exportPublicKey(state.keys.publicKey);

        if (!state.identity || !joinNonce) {
            await new Promise(r => setTimeout(r, 300));
        }
        if (!state.identity || !joinNonce) {
            throw new Error('Identity or server nonce not ready');
        }

        const identityKeyB64 = await exportIdentityPublicKeyB64(state.identity.publicKey);
        // Sign "<server nonce>:<this session's encryption key>" - proves we
        // hold the identity private key AND binds this session's key to it,
        // so the server (or anyone reading its traffic) can't quietly swap
        // in a different encryption key under our name.
        const signatureBuf = await window.crypto.subtle.sign(
            { name: 'ECDSA', hash: 'SHA-256' },
            state.identity.privateKey,
            new TextEncoder().encode(`${joinNonce}:${pubKeyBase64}`)
        );
        const signature = uint8ArrayToB64(signatureBuf);

        socket.emit('join', { nick, about, publicKey: pubKeyBase64, identityKey: identityKeyB64, signature, password });
    }

    /** Silent rejoin after the transport reconnects. Never shown as a form - replayed from memory. */
    async function rejoin() {
        setConnectionBanner('Reconnected - restoring session…', 'reconnecting');
        try {
            await performJoin(state.myNick, state.myAbout, currentRoomPassword);
        } catch (err) {
            console.error('Rejoin error:', err);
            setConnectionBanner('Could not restore your session automatically. Reloading…', 'lost');
            setTimeout(() => location.reload(), 1500);
        }
    }

    // Phase 8: server-side access control. The password field stays hidden
    // (and the join payload just carries an empty string, which the server
    // treats as "no password" when none is configured) unless the server
    // tells us up front that one's required - keeps the open-room default
    // looking exactly like it did before this existed.
    const roomPasswordInput = document.getElementById('room-password');
    socket.on('room_info', ({ passwordRequired }) => {
        if (passwordRequired) {
            roomPasswordInput.classList.remove('hidden');
            roomPasswordInput.required = true;
        }
    });

    // A hard server-side disconnect (IP connection cap, or too many
    // rate-limit violations). Socket.IO will NOT auto-reconnect after this
    // (see the 'disconnect' handler below), so tell the person why before
    // the page reloads, or a bare reload with no explanation just looks
    // like the app broke.
    socket.on('kicked', (reason) => alert(reason));

    // The underlying transport came back after a drop. If we'd already
    // joined before, silently redo the join - the person should never see
    // the welcome screen again just because their wifi blipped.
    socket.on('connect', () => {
        if (hasJoinedOnce) rejoin();
    });

    resetIdentityLink.addEventListener('click', async (e) => {
        e.preventDefault();
        const sure = confirm(
            'Reset your device identity? Contacts who have talked to you before ' +
            'will see a "key changed" warning next time, until they choose to ' +
            'trust your new key. This cannot be undone.'
        );
        if (!sure) return;
        await idbDelete('identity', 'self');
        location.reload();
    });

    joinForm.addEventListener('submit', async (e) => {
        e.preventDefault();
        const nick = document.getElementById('nick').value.trim();
        const about = document.getElementById('about').value.trim();
        const password = roomPasswordInput.value;

        state.myNick = nick; // Identity tracking for "Sent" style detection
        state.myAbout = about; // remembered for silent rejoin after a reconnect
        currentRoomPassword = password; // ditto

        try {
            await performJoin(nick, about, password);
        } catch (err) {
            alert('Still setting up your identity - please try again in a moment.');
        }
    });

    socket.on('joined_success', () => {
        if (!hasJoinedOnce) {
            welcomeScreen.classList.add('hidden');
            chatInterface.classList.remove('hidden');
            if (!state.history['global']) state.history['global'] = [];
            hasJoinedOnce = true;
        } else {
            // Reconnect succeeded - chat history, tabs, and identity were
            // never touched, so there's nothing left to restore but the
            // connection itself. A fresh user_list is already on its way.
            hideConnectionBanner();
            setOffline(false);
            logSystem('Reconnected.');
        }
        // The server always assumes a freshly (re)joined socket is
        // 'active'. If we were actually idle/backgrounded going into a
        // reconnect (e.g. the tab was already hidden when the drop
        // happened), resync the real status rather than silently
        // presenting as active until the next periodic check.
        checkPresence();
    });

    // --- Presence (active/idle) ---
    // Two states only, kept deliberately simple: 'active' if the tab is
    // visible and there's been real interaction recently, 'idle' otherwise.
    // Unauthenticated, like typing indicators - this is UI polish, not
    // something that needs cryptographic guarantees.
    const IDLE_THRESHOLD_MS = 3 * 60 * 1000; // 3 minutes of no interaction
    let lastActivityAt = Date.now();
    ['mousemove', 'keydown', 'mousedown', 'touchstart', 'scroll'].forEach(evt =>
        document.addEventListener(evt, () => { lastActivityAt = Date.now(); }, { passive: true })
    );

    function checkPresence() {
        if (!hasJoinedOnce) return; // nothing to report before we've actually joined
        const idle = document.hidden || (Date.now() - lastActivityAt > IDLE_THRESHOLD_MS);
        const status = idle ? 'idle' : 'active';
        if (status !== state.myPresence) {
            state.myPresence = status;
            socket.emit('presence', status);
        }
    }

    document.addEventListener('visibilitychange', checkPresence);
    setInterval(checkPresence, 15000); // catches pure inactivity (no visibility change involved)

    // --- Notifications (unread title badge + opt-in desktop notifications) ---
    // Two layers, deliberately: the title-bar badge needs no permission and
    // always works, so it's the baseline everyone gets. Desktop
    // notifications are opt-in on top of that - browsers rightly gate
    // Notification behind explicit permission, and popping that prompt
    // unprompted on page load is the kind of thing that gets a site
    // reflexively blocked, so we only ask when the person clicks the bell.
    const notifyToggle = document.getElementById('notify-toggle');
    const originalTitle = document.title;
    let unreadCount = 0;

    function isAwayFromApp() {
        return document.hidden || !document.hasFocus();
    }

    function updateTitleBadge() {
        document.title = unreadCount > 0 ? `(${unreadCount}) ${originalTitle}` : originalTitle;
    }

    function bumpUnread() {
        if (!isAwayFromApp()) return;
        unreadCount++;
        updateTitleBadge();
    }

    function clearUnread() {
        if (unreadCount === 0) return;
        unreadCount = 0;
        updateTitleBadge();
    }

    window.addEventListener('focus', clearUnread);
    document.addEventListener('visibilitychange', () => { if (!document.hidden) clearUnread(); });

    /**
     * Desktop notification, gated on both the opt-in toggle and actually
     * being away. `tag` lets repeated notifications from the same
     * conversation replace each other instead of stacking up while
     * someone's away for a while - one tag per PM partner, one shared tag
     * for the whole global room.
     */
    function notify(title, body, tag, onClick) {
        bumpUnread();
        if (!state.notificationsEnabled || !isAwayFromApp()) return;
        if (!('Notification' in window) || Notification.permission !== 'granted') return;
        try {
            const n = new Notification(title, { body, tag });
            n.onclick = () => {
                window.focus();
                if (onClick) onClick();
                n.close();
            };
        } catch (err) {
            console.warn('Notification failed:', err);
        }
    }

    notifyToggle.addEventListener('click', async () => {
        if (state.notificationsEnabled) {
            state.notificationsEnabled = false;
            notifyToggle.textContent = '🔕';
            notifyToggle.classList.remove('enabled');
            notifyToggle.title = 'Enable desktop notifications for messages and calls while this tab isn\'t focused';
            notifyToggle.setAttribute('aria-label', notifyToggle.title);
            return;
        }
        if (!('Notification' in window)) {
            alert('This browser does not support desktop notifications.');
            return;
        }
        let permission = Notification.permission;
        if (permission === 'default') permission = await Notification.requestPermission();
        if (permission !== 'granted') {
            alert('Notification permission was not granted. You can still see unread counts in the tab title.');
            return;
        }
        state.notificationsEnabled = true;
        notifyToggle.textContent = '🔔';
        notifyToggle.classList.add('enabled');
        notifyToggle.title = 'Desktop notifications are on - click to turn off';
        notifyToggle.setAttribute('aria-label', notifyToggle.title);
    });

    // Pre-join failures (bad nick/about, full room, wrong room password, or
    // Phase 7 identity verification failure) - previously silent, surfaced
    // now since these are exactly the kind of thing a user should see.
    // During a silent RECONNECT, an alert() would be jarring for something
    // the person didn't even initiate - show it in the banner instead and
    // fall back to a full reload, since we can't silently recover from
    // "someone else took your nick while you were gone" anyway.
    socket.on('error', (message) => {
        if (hasJoinedOnce) {
            setConnectionBanner(`Could not reconnect: ${message}`, 'lost');
            setTimeout(() => location.reload(), 2500);
            return;
        }
        alert(message);
        if (String(message).includes('password')) {
            roomPasswordInput.value = '';
            roomPasswordInput.focus();
        }
    });
    socket.on('nick_taken', () => {
        if (hasJoinedOnce) {
            setConnectionBanner('Could not reconnect: your nickname was taken while you were disconnected.', 'lost');
            setTimeout(() => location.reload(), 2500);
            return;
        }
        alert('That nickname is already taken.');
    });

    socket.on('user_list', async (users) => {
        state.lastUserList = users;
        state.phonebook = {};
        users.forEach(u => {
            state.phonebook[u.nick] = { publicKey: u.publicKey, id: u.id, identityKey: u.identityKey, presence: u.presence };
        });

        // Check each contact's identity fingerprint against what we've
        // pinned before. Done in parallel; rendering waits for all of it so
        // the list never flashes "trusted" before flipping to a warning.
        await Promise.all(users
            .filter(u => u.nick !== state.myNick && u.identityKey)
            .map(async (u) => {
                state.trustStatus[u.nick] = await checkTrust(u.nick, u.identityKey);
            }));

        renderUserList(users);
    });

    socket.on('user_joined', async (user) => {
        const trust = await checkTrust(user.nick, user.identityKey);
        state.trustStatus[user.nick] = trust;
        state.phonebook[user.nick] = { publicKey: user.publicKey, id: user.id, identityKey: user.identityKey, presence: user.presence };

        // Keep lastUserList in sync so trust-action re-renders (Mark
        // Verified / Trust new key) don't drop the newcomer from the sidebar.
        state.lastUserList.push(user);

        // Incrementally add the new user row to the sidebar without
        // rebuilding everything. Handles new, ok, and changed trust states.
        const isSelf = user.nick === state.myNick;
        if (!isSelf && trust.status === 'changed') {
            userListElem.appendChild(buildTrustWarningRow(user, trust));
            return;
        }

        const div = document.createElement('div');
        div.className = 'user-item';
        div.dataset.nick = user.nick;

        const presenceLabel = user.presence === 'idle' ? 'Idle' : 'Active';
        const dot = document.createElement('span');
        dot.className = `presence-dot presence-${user.presence === 'idle' ? 'idle' : 'active'}`;
        dot.setAttribute('aria-hidden', 'true');

        const openBtn = document.createElement('button');
        openBtn.type = 'button';
        openBtn.className = 'user-open-btn';
        openBtn.setAttribute('aria-label', `Open conversation with ${user.nick} (${presenceLabel.toLowerCase()})`);
        openBtn.addEventListener('click', () => openPrivateChat(user));

        const strong = document.createElement('strong');
        strong.className = 'cyan-text';
        strong.appendChild(dot);
        strong.appendChild(document.createTextNode(user.nick));
        const small = document.createElement('small');
        small.textContent = user.about;
        openBtn.appendChild(strong);
        openBtn.appendChild(small);
        div.appendChild(openBtn);

        const callBtn = document.createElement('button');
        callBtn.type = 'button';
        callBtn.className = 'call-btn';
        callBtn.textContent = 'Call';
        callBtn.setAttribute('aria-label', `Call ${user.nick}`);
        callBtn.addEventListener('click', (e) => { e.stopPropagation(); initiateCall(user); });
        div.appendChild(callBtn);

        if (user.identityKey) {
            const verifyToggle = document.createElement('button');
            verifyToggle.type = 'button';
            verifyToggle.className = 'verify-toggle';
            verifyToggle.textContent = trust.verified ? '🔒' : '🔑';
            verifyToggle.setAttribute('aria-label', trust.verified
                ? `${user.nick}'s identity is verified - view fingerprint`
                : `${user.nick}'s identity is not yet verified - compare fingerprints`);
            verifyToggle.title = trust.verified
                ? 'Verified identity - click to view fingerprint'
                : 'Not yet verified - click to compare fingerprints';
            verifyToggle.addEventListener('click', (e) => {
                e.stopPropagation();
                toggleFingerprintReveal(div, user, trust);
            });
            div.appendChild(verifyToggle);
        }

        userListElem.appendChild(div);
        sidebarToggleCount.textContent = userListElem.querySelectorAll('.user-item').length;
    });

    socket.on('user_left', (data) => {
        const { nick } = data;
        delete state.phonebook[nick];
        delete state.trustStatus[nick];

        // Remove entries from private chat histories that belong to this user,
        // then cap the arrays to the configured maximum.
        for (const tabId in state.history) {
            state.history[tabId] = state.history[tabId].filter(
                entry => entry.senderNick !== nick
            );
        }

        for (const tabId in state.typing) {
            delete state.typing[tabId][nick];
        }

        // Keep lastUserList in sync so trust-action re-renders don't
        // revive the departed user as a ghost row.
        state.lastUserList = state.lastUserList.filter(u => u.nick !== nick);

        const pmTabId = `pm_${nick}`;
        const row = userListElem.querySelector(`.user-item[data-nick="${CSS.escape(nick)}"]`);
        if (row) row.remove();
        sidebarToggleCount.textContent = userListElem.querySelectorAll('.user-item').length;

        // If the departed nick owned the active tab, switch to global
        if (state.currentTabId === pmTabId) {
            setActiveTab('global');
        }
    });

    function renderUserList(users) {
        userListElem.innerHTML = '';
        sidebarToggleCount.textContent = users.length;
        users.forEach(u => {
            const isSelf = u.nick === state.myNick;
            const trust = state.trustStatus[u.nick];

            if (!isSelf && trust && trust.status === 'changed') {
                userListElem.appendChild(buildTrustWarningRow(u, trust));
                return;
            }

            const div = document.createElement('div');
            div.className = 'user-item';
            div.dataset.nick = u.nick; // lets presence_update find this row without a full re-render

            const presenceLabel = u.presence === 'idle' ? 'Idle' : 'Active';
            const dot = document.createElement('span');
            dot.className = `presence-dot presence-${u.presence === 'idle' ? 'idle' : 'active'}`;
            dot.setAttribute('aria-hidden', 'true'); // status is conveyed via the button's accessible name instead

            // The self row (you) isn't a target for any action - a real
            // button here would just be a no-op with a confusing label -
            // so it stays as plain text, not a control.
            let nameContainer;
            if (isSelf) {
                nameContainer = document.createElement('div');
            } else {
                nameContainer = document.createElement('button');
                nameContainer.type = 'button';
                nameContainer.className = 'user-open-btn';
                nameContainer.setAttribute('aria-label', `Open conversation with ${u.nick} (${presenceLabel.toLowerCase()})`);
                nameContainer.addEventListener('click', () => openPrivateChat(u));
            }

            // Build with DOM APIs (textContent) so nick/about can't inject HTML
            const strong = document.createElement('strong');
            strong.className = 'cyan-text';
            strong.appendChild(dot);
            strong.appendChild(document.createTextNode(u.nick));
            const small = document.createElement('small');
            small.textContent = u.about;
            nameContainer.appendChild(strong);
            nameContainer.appendChild(small);
            div.appendChild(nameContainer);

            if (!isSelf) {
                const callBtn = document.createElement('button');
                callBtn.type = 'button';
                callBtn.className = 'call-btn';
                callBtn.textContent = 'Call';
                callBtn.setAttribute('aria-label', `Call ${u.nick}`);
                callBtn.addEventListener('click', (e) => {
                    e.stopPropagation(); // don't also open the PM tab
                    startCall(u);
                    closeSidebar(); // no-op on desktop
                });
                div.appendChild(callBtn);

                // Phase 7e: explicit verification, separate from silent TOFU.
                // Any contact with an identity key can be fingerprint-checked;
                // marking one verified is a stronger claim than "never changed"
                // - it means the person actively compared it out of band.
                if (trust) {
                    const verifyToggle = document.createElement('button');
                    verifyToggle.type = 'button';
                    verifyToggle.className = 'verify-toggle';
                    verifyToggle.textContent = trust.verified ? '🔒' : '🔑';
                    verifyToggle.setAttribute('aria-label', trust.verified
                        ? `${u.nick}'s identity is verified - view fingerprint`
                        : `${u.nick}'s identity is not yet verified - compare fingerprints`);
                    verifyToggle.title = trust.verified
                        ? 'Verified identity - click to view fingerprint'
                        : 'Not yet verified - click to compare fingerprints';
                    verifyToggle.addEventListener('click', (e) => {
                        e.stopPropagation();
                        toggleFingerprintReveal(div, u, trust);
                    });
                    div.appendChild(verifyToggle);
                }
            }
            userListElem.appendChild(div);
        });
    }

    /**
     * Inline expand/collapse showing a contact's pinned fingerprint, so both
     * people can read it aloud or compare it through another channel before
     * one of them clicks Mark Verified. Toggled per row, not a modal - this
     * is a routine check, not an interruption.
     */
    function toggleFingerprintReveal(rowDiv, u, trust) {
        const existing = rowDiv.querySelector('.fingerprint-reveal');
        if (existing) { existing.remove(); return; }

        const reveal = document.createElement('div');
        reveal.className = 'fingerprint-reveal';

        const fp = document.createElement('code');
        fp.textContent = trust.fingerprint;
        reveal.appendChild(fp);

        if (trust.verified) {
            const status = document.createElement('span');
            status.className = 'fingerprint-verified-label';
            status.textContent = '✓ verified';
            reveal.appendChild(status);
        } else {
            const btn = document.createElement('button');
            btn.type = 'button';
            btn.textContent = 'Mark Verified';
            btn.addEventListener('click', async (e) => {
                e.stopPropagation();
                await markVerified(u.nick, trust.fingerprint);
                logSystem(`You verified ${u.nick}'s identity.`);
                renderUserList(state.lastUserList);
            });
            reveal.appendChild(btn);
        }
        rowDiv.appendChild(reveal);
    }

    /**
     * Blocking warning row (SSH-style) shown instead of the normal user
     * entry when a contact's identity key doesn't match what we pinned
     * before. No call button, no click-to-message - just like the incoming
     * modal, we don't supply an interpretation that makes this look safer
     * than it is; the person has to actively decide.
     */
    function buildTrustWarningRow(u, trust) {
        const div = document.createElement('div');
        div.className = 'user-item trust-warning';

        const msg = document.createElement('div');
        msg.className = 'trust-warning-text';
        msg.textContent = `⚠ ${u.nick}'s identity key changed`;

        const detail = document.createElement('div');
        detail.className = 'trust-warning-detail';
        detail.textContent = 'This means they reset their identity, or someone else is presenting a different key under this name. Calls and messages are blocked until you decide.';

        const actions = document.createElement('div');
        actions.className = 'trust-warning-actions';

        const trustBtn = document.createElement('button');
        trustBtn.type = 'button';
        trustBtn.textContent = 'Trust new key';
        trustBtn.addEventListener('click', async () => {
            await trustNewKey(u.nick, trust.fingerprint);
            renderUserList(state.lastUserList);
            logSystem(`You trusted ${u.nick}'s new identity key.`);
        });

        const blockBtn = document.createElement('button');
        blockBtn.type = 'button';
        blockBtn.className = 'danger';
        blockBtn.textContent = 'Keep blocked';
        blockBtn.addEventListener('click', () => {
            blockBtn.textContent = 'Blocked';
            blockBtn.disabled = true;
        });

        actions.appendChild(trustBtn);
        actions.appendChild(blockBtn);
        div.appendChild(msg);
        div.appendChild(detail);
        div.appendChild(actions);
        return div;
    }

    // Tab Navigation via Event Delegation
    document.getElementById('tab-container').addEventListener('click', (e) => {
        const tabEl = e.target.closest('.tab');
        if (!tabEl) return;

        const id = tabEl.getAttribute('data-id');

        // Handle Close Button (global/calls are pinned and can't be closed)
        if (e.target.classList.contains('close-btn')) {
            if (id === 'global' || id === 'calls') return;
            state.activeTabs.delete(id);
            tabEl.remove();
            if (state.currentTabId === id) setActiveTab('global');
            return;
        }

        setActiveTab(id);
    });

    // role="tab" on a <div> has no native keyboard behavior - Enter/Space
    // activation and Left/Right/Home/End movement between tabs both need
    // to be wired up by hand here, per the standard ARIA tabs pattern.
    document.getElementById('tab-container').addEventListener('keydown', (e) => {
        const tabEl = e.target.closest('.tab');
        if (!tabEl) return;

        if (e.key === 'Enter' || e.key === ' ') {
            e.preventDefault();
            setActiveTab(tabEl.getAttribute('data-id'));
            return;
        }

        const tabs = [...document.querySelectorAll('#tab-container .tab')];
        const currentIndex = tabs.indexOf(tabEl);
        if (currentIndex === -1) return;

        let targetIndex = null;
        if (e.key === 'ArrowRight') targetIndex = (currentIndex + 1) % tabs.length;
        else if (e.key === 'ArrowLeft') targetIndex = (currentIndex - 1 + tabs.length) % tabs.length;
        else if (e.key === 'Home') targetIndex = 0;
        else if (e.key === 'End') targetIndex = tabs.length - 1;
        if (targetIndex === null) return;

        e.preventDefault();
        // Roving tabindex: exactly one tab is ever in the natural Tab
        // order at a time - the one that last had keyboard focus, which
        // isn't necessarily the currently-active/selected tab. Arrow keys
        // move focus only; Enter/Space (above) is what actually activates.
        tabs.forEach(t => t.setAttribute('tabindex', '-1'));
        tabs[targetIndex].setAttribute('tabindex', '0');
        tabs[targetIndex].focus();
    });

    function openPrivateChat(targetUser) {
        const tabId = `pm_${targetUser.nick}`;
        if (!state.activeTabs.has(tabId)) createTabUI(tabId, targetUser.nick);
        setActiveTab(tabId);
        closeSidebar(); // no-op on desktop where the drawer doesn't apply
    }

    function createTabUI(id, name) {
        const tabContainer = document.getElementById('tab-container');
        if (document.getElementById(`tab-${id}`)) return;

        const tab = document.createElement('div');
        tab.className = 'tab';
        tab.id = `tab-${id}`;
        tab.setAttribute('data-id', id);
        // ARIA tabs pattern: each tab is independently focusable via a
        // roving tabindex (managed in setActiveTab), activatable with
        // Enter/Space (native for role=button semantics via keydown below),
        // and Left/Right/Home/End move between tabs (see the keydown
        // handler on the tablist).
        tab.setAttribute('role', 'tab');
        tab.setAttribute('tabindex', '-1');
        tab.setAttribute('aria-selected', 'false');
        tab.setAttribute('aria-controls', 'chat-window');

        // Built with real DOM nodes rather than innerHTML - `name` is a
        // nickname, which the server only validates for LENGTH, not
        // content, so interpolating it into innerHTML would have been a
        // stored XSS (a nickname containing HTML would execute for every
        // client that ever opened a tab with them).
        tab.appendChild(document.createTextNode(name));
        const closeBtn = document.createElement('button');
        closeBtn.type = 'button';
        closeBtn.className = 'close-btn';
        closeBtn.textContent = '×';
        closeBtn.setAttribute('aria-label', `Close conversation with ${name}`);
        tab.appendChild(closeBtn);

        state.activeTabs.set(id, { id, name });
        tabContainer.appendChild(tab);
    }

/**
    function setActiveTab(id) {
        document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
        state.currentTabId = id;
        const tabElem = document.getElementById(`tab-${id}`);
        if (tabElem) tabElem.classList.add('active');

        // Initialize history array for new tabs automatically
        if (!state.history[id]) state.history[id] = [];
        renderChatHistory();
    }
*/
function setActiveTab(id) {
  document.querySelectorAll('.tab').forEach(t => {
      t.classList.remove('active');
      t.setAttribute('aria-selected', 'false');
      t.setAttribute('tabindex', '-1');
  });
  state.currentTabId = id;
  const tabElem = document.getElementById(`tab-${id}`);
  if (tabElem) {
      tabElem.classList.add('active');
      tabElem.setAttribute('aria-selected', 'true');
      tabElem.setAttribute('tabindex', '0'); // the active tab is the roving-tabindex default
  }

  // Update the dynamic title in the footer
  const activeTabData = state.activeTabs.get(id);
  const titleElem = document.getElementById('active-tab-title');
  if (activeTabData && titleElem) {
    titleElem.textContent = activeTabData.name;
  }

  // The calls tab is a log view, not a chat - there's nothing to send to
  if (id === 'calls') {
      inputAreaElem.classList.add('hidden');
      state.missedCallCount = 0;
      updateCallsTabBadge();
  } else {
      inputAreaElem.classList.remove('hidden');
  }

  // File transfer only makes sense in a private conversation - there's no
  // "send a file to the whole room" concept, consistent with encryption
  // itself being scoped to private messages only.
  attachFileBtn.classList.toggle('hidden', id === 'global' || id === 'calls');

  // Initialize history array for new tabs automatically
  if (!state.history[id]) state.history[id] = [];
  renderChatHistory();
  renderTypingIndicator();
}

    function renderChatHistory() {
        if (state.currentTabId === 'calls') return renderCallLog();
        messageDisplay.innerHTML = '';
        const history = state.history[state.currentTabId] || [];
        history.forEach(msg => appendMessageToDOM(msg));
        messageDisplay.scrollTop = messageDisplay.scrollHeight;
    }

    // Deterministic per-nick colors, picked from a curated palette rather
    // than a raw HSL hash - guarantees every color stays readable against
    // the dark background and stays clear of hues already used for meaning
    // elsewhere in the UI (danger red, success green, warning orange, the
    // app's own accent cyan).
    const NICK_COLOR_PALETTE = [
        '#ff6ec7', '#b388ff', '#ffd166', '#5b9bff', '#ff8c69',
        '#c792ea', '#ffab91', '#82b1ff', '#f48fb1', '#a3e635',
        '#fca5a5', '#93c5fd'
    ];
    function colorForNick(nick) {
        let hash = 0;
        for (let i = 0; i < nick.length; i++) {
            hash = (hash * 31 + nick.charCodeAt(i)) | 0; // |0 keeps it a 32-bit int, no overflow drift
        }
        return NICK_COLOR_PALETTE[Math.abs(hash) % NICK_COLOR_PALETTE.length];
    }

    function formatFileSize(bytes) {
        if (bytes < 1024) return `${bytes} B`;
        if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
        return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
    }

    const FILE_STATUS_LABELS = {
        pending: null, // handled specially below (direction-dependent)
        declined: 'Declined',
        canceled: 'Canceled',
        failed: 'Failed',
        complete: null // handled specially below (direction-dependent)
    };

    function fileTransferMetaText(entry) {
        const size = formatFileSize(entry.size);
        let status;
        if (entry.status === 'transferring') {
            status = `${entry.progress || 0}% - ${entry.direction === 'sent' ? 'sending' : 'receiving'}`;
        } else if (entry.status === 'pending') {
            status = entry.direction === 'sent' ? 'waiting for them to accept…' : 'incoming';
        } else if (entry.status === 'complete') {
            status = entry.direction === 'sent' ? 'sent' : 'received';
        } else {
            status = FILE_STATUS_LABELS[entry.status] || entry.status;
        }
        return `${size} · ${status}`;
    }

    /** Builds (or rebuilds) a file-transfer message bubble from its current state. */
    function buildFileBubble(entry) {
        const div = document.createElement('div');
        div.className = `msg file-transfer status-${entry.status}`;
        div.dataset.transferId = entry.transferId;

        const icon = document.createElement('span');
        icon.className = 'file-icon';
        icon.textContent = '📎';
        icon.setAttribute('aria-hidden', 'true'); // decorative - the filename/status text carries the meaning

        const info = document.createElement('div');
        info.className = 'file-info';

        const nameEl = document.createElement('div');
        nameEl.className = 'file-name';
        nameEl.textContent = entry.name;

        const metaEl = document.createElement('div');
        metaEl.className = 'file-meta';
        metaEl.textContent = fileTransferMetaText(entry);

        info.appendChild(nameEl);
        info.appendChild(metaEl);

        if (entry.status === 'transferring' || entry.status === 'pending') {
            const barWrap = document.createElement('div');
            barWrap.className = 'file-progress-wrap';
            const bar = document.createElement('div');
            bar.className = 'file-progress-bar';
            bar.style.width = `${entry.progress || 0}%`;
            barWrap.appendChild(bar);
            info.appendChild(barWrap);
        }

        if (entry.status === 'complete' && entry.direction === 'received' && entry.downloadUrl) {
            const link = document.createElement('a');
            link.href = entry.downloadUrl;
            link.download = entry.name;
            link.className = 'file-download-link';
            link.textContent = 'Download';
            info.appendChild(link);
        }

        if (entry.direction === 'sent' && (entry.status === 'pending' || entry.status === 'transferring')) {
            const cancelLink = document.createElement('button');
            cancelLink.type = 'button';
            cancelLink.className = 'file-cancel-link';
            cancelLink.textContent = 'Cancel';
            cancelLink.addEventListener('click', () => cancelFileTransfer(entry.transferId));
            info.appendChild(cancelLink);
        }

        div.appendChild(icon);
        div.appendChild(info);
        return div;
    }

    /**
     * Re-renders one file-transfer bubble in place, without touching the
     * rest of the chat - important since progress updates can fire many
     * times a second for a large file, and a full renderChatHistory() call
     * would be wasteful and janky at that rate. No-ops quietly if the
     * relevant PM tab isn't the one currently open; the record itself
     * (entry, held in state.history) is already updated regardless, so it
     * renders correctly whenever that tab is opened next.
     */
    function refreshFileBubble(transferId) {
        const transfer = state.fileTransfers[transferId];
        if (!transfer || !transfer.historyRef) return;
        const oldBubble = messageDisplay.querySelector(`[data-transfer-id="${transferId}"]`);
        if (!oldBubble) return;
        oldBubble.replaceWith(buildFileBubble(transfer.historyRef));
    }

    function appendMessageToDOM(msgData) {
        const div = document.createElement('div');

        if (msgData.fileTransfer) {
            messageDisplay.appendChild(buildFileBubble(msgData));
            return;
        }

        if (msgData.warning) {
            // Signature failed, or the key we have pinned for this nick
            // doesn't match what actually signed this message. Don't
            // render the content at all - showing it "with a warning
            // label" would still be supplying an interpretation ("probably
            // fine, just flagged") that the message hasn't earned.
            div.className = 'msg tampered';
            div.textContent = `⚠ Unverifiable message from ${msgData.senderNick} - signature did not match their identity key.`;
            messageDisplay.appendChild(div);
            return;
        }

        // Style messages correctly based on sender vs current view
        let typeClass = 'system';
        if (state.currentTabId !== 'global') {
            typeClass = msgData.senderNick === state.myNick ? 'sent' : 'private';
        }

        div.className = `msg ${typeClass}`;
        const nickSpan = document.createElement('span');
        nickSpan.className = 'nick';
        if (msgData.senderNick !== '[abyss]') {
            nickSpan.style.color = colorForNick(msgData.senderNick);
        }
        nickSpan.textContent = `${msgData.senderNick}:`;
        div.appendChild(nickSpan);
        div.appendChild(document.createTextNode(msgData.content));
        messageDisplay.appendChild(div);
    }

    // --- Messaging Logic ---

    // Outgoing typing indicator: throttled so held-down keys or a burst of
    // typing don't spam an event per keystroke. No indicator is sent while
    // viewing the calls log (nothing to type to) or once the message is
    // actually sent (the recipient will see the message itself right after).
    let lastTypingEmit = 0;
    const TYPING_EMIT_THROTTLE_MS = 2000;
    msgInput.addEventListener('input', () => {
        if (state.currentTabId === 'calls') return;
        const now = Date.now();
        if (now - lastTypingEmit < TYPING_EMIT_THROTTLE_MS) return;
        lastTypingEmit = now;

        if (state.currentTabId === 'global') {
            socket.emit('typing', { isPrivate: false });
        } else {
            const nick = state.currentTabId.replace('pm_', '');
            const targetData = state.phonebook[nick];
            if (targetData) socket.emit('typing', { isPrivate: true, recipientId: targetData.id });
        }
    });

    // Phase 8: mirrors the server's per-socket message rate limit (15/10s).
    // The server enforces this regardless - this is purely a UX honesty
    // check: without it, a flooded message would still show up in the
    // sender's own optimistic bubble even though the server silently
    // dropped it and nobody else ever saw it.
    let msgSendTimestamps = [];
    function chatRateLimitOk() {
        const now = Date.now();
        msgSendTimestamps = msgSendTimestamps.filter(t => now - t < 10000);
        if (msgSendTimestamps.length >= 15) return false;
        msgSendTimestamps.push(now);
        return true;
    }

 msgForm.addEventListener('submit', async (e) => {
        e.preventDefault();
        if (state.currentTabId === 'calls') return; // log view, nothing to send to
        const content = msgInput.value;
        if (!content) return;

        lastTypingEmit = 0; // let the next keystroke in a fresh message emit immediately

        if (!chatRateLimitOk()) {
            logSystem("You're sending messages too fast - slow down a bit.");
            return;
        }

        if (state.currentTabId === 'global') {
            // OPTIMISTIC UPDATE: Add to history immediately
            if (!state.history['global']) state.history['global'] = [];
            state.history['global'].push({
                senderNick: state.myNick,
                content: content
            });
            capHistory('global');
            renderChatHistory();

            const timestamp = Date.now();
            const signature = await signWithIdentity(`${timestamp}:${content}`);
            socket.emit('message', {
                content,
                isPrivate: false,
                timestamp,
                signature
            });
        } else {
            const nick = state.currentTabId.replace('pm_', '');
            const targetData = state.phonebook[nick];

            if (!targetData) return alert("User offline.");
            const trust = state.trustStatus[nick];
            if (trust && trust.status === 'changed') {
                return alert(`${nick}'s identity key changed and hasn't been trusted. Resolve this in the user list before messaging.`);
            }

            try {
                // OPTIMISTIC UPDATE: Add to private history immediately
                if (!state.history[state.currentTabId]) state.history[state.currentTabId] = [];
                state.history[state.currentTabId].push({
                    senderNick: state.myNick,
                    content: content
                });
                capHistory(state.currentTabId);
                renderChatHistory();

                const publicKeyObj = await importPublicKey(targetData.publicKey);
                const encryptedPayload = await hybridEncrypt(publicKeyObj, content);
                // Sign the CIPHERTEXT, not the plaintext - ties the
                // signature to these exact encrypted bytes and lets the
                // recipient verify authenticity before ever attempting to
                // decrypt (cheap rejection of garbage/tampered blobs).
                const timestamp = Date.now();
                const signature = await signWithIdentity(`${timestamp}:${encryptedPayload}`);

                socket.emit('message', {
                    recipientId: targetData.id,
                    content: encryptedPayload,
                    isPrivate: true,
                    timestamp,
                    signature
                });


            } catch (err) {
                console.error("Encryption Error:", err);
                alert("Message failed to send.");
            }
        }
        msgInput.value = '';
    });
socket.on('public_message', async (data) => {
  const historyArr = state.history['global'];
  // Only update the UI if the message was not sent by the local user
  // This prevents the broadcast from duplicating the optimistic update
  if (historyArr && data.nick !== state.myNick) {
    const signedString = `${data.timestamp}:${data.content}`;
    const authentic = await verifyIncomingMessage(data.nick, signedString, data.signature);

    historyArr.push(authentic
        ? { senderNick: data.nick, content: data.content }
        : { senderNick: data.nick, warning: true });
    capHistory('global');
    renderChatHistory();

    // Don't notify about a message that failed verification - there's no
    // confirmed sender to attribute it to, so there's nothing honest to say.
    // The notification body deliberately excludes message content: an OS
    // notification can surface on a lock screen, in notification history,
    // or synced to other devices - showing decrypted content there would
    // undercut the confidentiality this app otherwise works to provide.
    if (authentic) {
        notify('New message in #twistedminds', `${data.nick} sent a message`, 'abyss-global', () => setActiveTab('global'));
    }
  }
});

    socket.on('private_message', async (data) => {
        const targetTabId = `pm_${data.nick}`;
        if (!state.history[targetTabId]) state.history[targetTabId] = [];

        // Verify BEFORE decrypting: a signature over the ciphertext lets us
        // reject a forged/tampered blob outright without spending an RSA
        // decrypt on it, and ties the signature to these exact encrypted
        // bytes rather than to whatever plaintext might fall out of them.
        const signedString = `${data.timestamp}:${data.content}`;
        const authentic = await verifyIncomingMessage(data.nick, signedString, data.signature);

        if (!authentic) {
            state.history[targetTabId].push({ senderNick: data.nick, warning: true });
            capHistory(targetTabId);
            if (state.currentTabId !== targetTabId) createTabUI(targetTabId, data.nick);
            setActiveTab(targetTabId);
            return;
        }

        try {
            const decrypted = await hybridDecrypt(state.keys.privateKey, data.content);

            state.history[targetTabId].push({
                senderNick: data.nick,
                content: decrypted
            });
            capHistory(targetTabId);

            // UI Response: Auto-switch and update history
            if (state.currentTabId !== targetTabId) {
                createTabUI(targetTabId, data.nick);
            }
            setActiveTab(targetTabId);
            // Content deliberately excluded - see the note on the
            // public_message notification above about why.
            notify(`Private message from ${data.nick}`, 'Tap to open the conversation', `abyss-pm-${data.nick}`);
        } catch (err) {
            console.error("Decryption Error:", err);
        }
    });

    // Cheap in-place update - avoids a full user-list re-render (which
    // would collapse any open fingerprint-reveal panel) for something as
    // frequent as a presence flip.
    socket.on('presence_update', ({ nick, status }) => {
        if (state.phonebook[nick]) state.phonebook[nick].presence = status;
        const row = userListElem.querySelector(`.user-item[data-nick="${CSS.escape(nick)}"]`);
        if (!row) return; // not currently rendered (e.g. shown as a trust-warning row instead)
        const dot = row.querySelector('.presence-dot');
        if (!dot) return;
        const presenceLabel = status === 'idle' ? 'Idle' : 'Active';
        dot.className = `presence-dot presence-${status === 'idle' ? 'idle' : 'active'}`;
        dot.title = presenceLabel;
        const openBtn = row.querySelector('.user-open-btn');
        if (openBtn) openBtn.setAttribute('aria-label', `Open conversation with ${nick} (${presenceLabel.toLowerCase()})`);
    });

    // --- Typing indicators ---
    // Per-context (global, or a specific PM) set of nicks currently typing,
    // each with its own auto-expiry timer. Auto-expiry (rather than an
    // explicit "stopped typing" event) means a client that vanishes
    // mid-keystroke - closed tab, dropped connection - doesn't leave a
    // stale "X is typing…" behind forever.
    // (State and rendering are declared earlier, alongside the other UI
    // element refs - see the note there about why.)
    socket.on('user_typing', ({ nick, isPrivate }) => {
        const contextId = contextIdFor(nick, isPrivate);
        if (!typingByContext[contextId]) typingByContext[contextId] = new Map();
        const bucket = typingByContext[contextId];

        clearTimeout(bucket.get(nick));
        bucket.set(nick, setTimeout(() => {
            bucket.delete(nick);
            if (state.currentTabId === contextId) renderTypingIndicator();
        }, TYPING_EXPIRY_MS));

        if (state.currentTabId === contextId) renderTypingIndicator();
    });

    // --- Voice Call Logic (Phase 3: encrypted signaling) ---
    // Media flows peer-to-peer, encrypted with DTLS-SRTP (mandatory in
    // WebRTC). SDP offers/answers and ICE candidates are additionally
    // encrypted with the peer's RSA key before relay, so the server only
    // ever sees opaque blobs and cannot read or tamper with call setup.
    //
    // Known limit (documented in Phase 3 plan): public keys are distributed
    // by the server on join (trust-on-first-use). The spoken safety code
    // below is the user-level defense against a key-substituting server.

    function nickFromId(id) {
        for (const [nick, data] of Object.entries(state.phonebook)) {
            if (data.id === id) return nick;
        }
        return 'Unknown';
    }

    function publicKeyFromId(id) {
        for (const data of Object.values(state.phonebook)) {
            if (data.id === id) return data.publicKey;
        }
        return null;
    }

    /** Pulls the DTLS certificate fingerprint out of an SDP blob. */
    function extractFingerprint(sdp) {
        const m = sdp && sdp.match(/a=fingerprint:sha-256 ([0-9A-F:]+)/i);
        return m ? m[1].toUpperCase() : null;
    }

    /**
     * Short authentication string derived from BOTH DTLS fingerprints
     * (sorted, so both sides compute the same value). Users read it aloud;
     * a mismatch means someone is sitting in the middle of the call.
     */
    async function computeSafetyCode(pc) {
        const fps = [
            extractFingerprint(pc.localDescription && pc.localDescription.sdp),
            extractFingerprint(pc.remoteDescription && pc.remoteDescription.sdp)
        ];
        if (!fps[0] || !fps[1]) return null;
        fps.sort();
        const data = new TextEncoder().encode(fps.join('|'));
        const hash = await window.crypto.subtle.digest('SHA-256', data);
        const bytes = new Uint8Array(hash);
        const num = ((bytes[0] << 16) | (bytes[1] << 8) | bytes[2]) % 1000000;
        return String(num).padStart(6, '0').replace(/^(\d{3})(\d{3})$/, '$1 $2');
    }

    async function showSafetyCode(peerId, peerNick, pc, isPrimary) {
        try {
            const code = await computeSafetyCode(pc);
            if (!code) return;
            if (isPrimary) {
                safetyCodeElem.textContent = `safety ${code}`;
            } else {
                const entry = state.call.extraPeers[peerId];
                if (entry) entry.safetyCode = code;
            }
            logSystem(`Safety code with ${peerNick}: ${code}. Read it aloud to each other - it must match on both ends. A mismatch means the call may be intercepted.`);
            renderGroupParticipants();
        } catch (err) {
            console.error('Safety code error:', err);
        }
    }

    // --- Ringtones (Web Audio, synthesized - no audio files needed) ---
    let audioCtx = null;
    let ringIntervalId = null;

    function playRingBurst(incoming) {
        try {
            if (!audioCtx) audioCtx = new (window.AudioContext || window.webkitAudioContext)();
            audioCtx.resume().catch(() => {});
            const now = audioCtx.currentTime;
            const gain = audioCtx.createGain();
            gain.gain.value = 0.06; // quiet
            gain.connect(audioCtx.destination);

            const o1 = audioCtx.createOscillator();
            o1.frequency.value = incoming ? 880 : 440; // ring vs ringback
            o1.connect(gain);
            o1.start(now);
            o1.stop(now + (incoming ? 0.35 : 0.9));

            if (incoming) { // two-tone "ring-ring" for incoming
                const o2 = audioCtx.createOscillator();
                o2.frequency.value = 660;
                o2.connect(gain);
                o2.start(now + 0.4);
                o2.stop(now + 0.75);
            }
        } catch (err) { /* audio blocked - stay silent */ }
    }

    function startRingtone(incoming) {
        stopRingtone();
        playRingBurst(incoming);
        ringIntervalId = setInterval(() => playRingBurst(incoming), incoming ? 1600 : 3000);
    }

    function stopRingtone() {
        if (ringIntervalId) clearInterval(ringIntervalId);
        ringIntervalId = null;
    }

    // --- Call timer & connection quality ---
    let callTimerId = null;
    let statsTimerId = null;

    function renderCallStatus() {
        if (state.call.status !== 'connected' || !state.call.startedAt) return;
        const secs = Math.floor((Date.now() - state.call.startedAt) / 1000);
        const m = String(Math.floor(secs / 60)).padStart(2, '0');
        const s = String(secs % 60).padStart(2, '0');
        callStatusText.textContent =
            `In call with ${state.call.peerNick} · ${m}:${s}${state.call.muted ? ' · muted' : ''}`;
    }

    /** Samples getStats() and renders a rough good/fair/poor indicator. */
    async function pollQuality() {
        const pc = state.call.pc;
        if (!pc || state.call.status !== 'connected') return;
        try {
            const stats = await pc.getStats();
            let rtt = null, lost = 0, received = 0;
            stats.forEach(r => {
                if (r.type === 'candidate-pair' && r.state === 'succeeded' &&
                    r.currentRoundTripTime !== undefined) {
                    rtt = r.currentRoundTripTime;
                }
                if (r.type === 'inbound-rtp' && r.kind === 'audio') {
                    lost = r.packetsLost || 0;
                    received = r.packetsReceived || 0;
                }
            });

            // Loss rate over the last sampling window
            let lossRate = 0;
            const prev = state.call.lastRtp;
            if (prev) {
                const dLost = lost - prev.lost;
                const dRecv = received - prev.received;
                if (dLost + dRecv > 0) lossRate = dLost / (dLost + dRecv);
            }
            state.call.lastRtp = { lost, received };

            let level = 'good';
            if ((rtt !== null && rtt > 0.4) || lossRate > 0.08) level = 'poor';
            else if ((rtt !== null && rtt > 0.15) || lossRate > 0.02) level = 'fair';

            qualityElem.className = `q-${level}`;
            qualityElem.textContent = level === 'good' ? '▮▮▮' : level === 'fair' ? '▮▮' : '▮';
            qualityElem.title = `Connection: ${level}` + (rtt !== null ? ` (rtt ${(rtt * 1000).toFixed(0)}ms)` : '');
            qualityElem.setAttribute('aria-label', `Connection quality: ${level}`);
        } catch (err) { /* stats unavailable - skip this sample */ }
    }

    /** Shared transition into the connected state (both caller and callee). */
    function onCallConnected() {
        stopRingtone();
        state.call.startedAt = Date.now();
        state.call.lastRtp = null;
        clearInterval(callTimerId);
        callTimerId = setInterval(renderCallStatus, 1000);
        clearInterval(statsTimerId);
        statsTimerId = setInterval(pollQuality, 2000);
        updateCallUI();
        pollQuality();
    }

    // Post a system line into the global tab so call events are visible
    function logSystem(text) {
        if (!state.history['global']) state.history['global'] = [];
        state.history['global'].push({ senderNick: '[abyss]', content: text });
        capHistory('global');
        if (state.currentTabId === 'global') renderChatHistory();
        announce(text);
    }

    /**
     * Shared visually-hidden live region for status announcements that
     * aren't already covered by a more specific one (the chat log itself,
     * the typing indicator, the connection banner). Re-setting textContent
     * to the same string twice in a row wouldn't re-announce, so a tiny
     * zero-width-space suffix on alternating calls forces it to always
     * register as a change.
     */
    let announceToggle = false;
    function announce(text) {
        const el = document.getElementById('sr-announcer');
        if (!el) return;
        announceToggle = !announceToggle;
        el.textContent = text + (announceToggle ? '\u200b' : '');
    }

    /**
     * Grabs the microphone and builds an RTCPeerConnection wired to our
     * signaling channel. Throws if mic access is denied.
     */
    async function setupPeerConnection(peerId) {
        // Requires a secure context (https:// or localhost)
        const localStream = await navigator.mediaDevices.getUserMedia({
            audio: {
                echoCancellation: true,
                noiseSuppression: true,
                autoGainControl: true
            }
        });

        const pc = new RTCPeerConnection(rtcConfig);

        // Send our mic to the peer
        localStream.getTracks().forEach(track => pc.addTrack(track, localStream));

        // Trickle ICE: encrypt each candidate to the peer's key, then relay.
        // This also hides network topology (local IPs) from the server.
        pc.onicecandidate = async (e) => {
            if (!e.candidate) return;
            try {
                const blob = await hybridEncrypt(
                    state.call.peerKeyObj,
                    JSON.stringify(e.candidate.toJSON())
                );
                socket.emit('ice_candidate', {
                    recipientId: peerId,
                    candidate: blob
                });
            } catch (err) {
                console.error('Candidate encryption error:', err);
            }
        };

        // Peer audio (and, once toggled on by either side, video) arrives
        // here. Audio and video land as separate track events even though
        // they're part of the same call, since video is added later via
        // its own addTrack() call rather than being part of the original
        // mic MediaStream - so we route by track.kind rather than assuming
        // one combined stream. This only attaches the stream; VISIBILITY of
        // the video panel is driven separately by an explicit videoActive
        // flag in the signaling payload (see onnegotiationneeded below) -
        // removeTrack() on the sender's side doesn't reliably fire 'ended'
        // on the receiver's track, it typically just freezes the last
        // frame, so track presence alone can't tell us the camera turned off.
        pc.ontrack = (e) => {
            if (e.track.kind === 'video') {
                remoteVideoElem.srcObject = e.streams[0];
                remoteVideoElem.play().catch(err => console.warn('Video autoplay blocked:', err));
            } else {
                remoteAudio.srcObject = e.streams[0];
                // Autoplay is normally allowed because the user just clicked
                // Call/Accept, but guard against strict policies anyway
                remoteAudio.play().catch(err => console.warn('Audio autoplay blocked:', err));
            }
        };

        // Fires whenever a track is added/removed after the initial
        // offer/answer - currently only from toggling video mid-call. Not
        // full W3C "perfect negotiation" with rollback (see the collision
        // handling in the renegotiate_offer listener for the simplified
        // version used here) but sufficient for an infrequent, deliberate
        // user action like turning a camera on or off.
        pc.onnegotiationneeded = async () => {
            if (state.call.negotiating) return; // one in flight already; the collision path below covers the cross-side case
            state.call.negotiating = true;
            clearTimeout(state.call.negotiationTimeoutId);
            state.call.negotiationTimeoutId = setTimeout(() => { state.call.negotiating = false; }, 5000);

            try {
                const offer = await pc.createOffer();
                await pc.setLocalDescription(offer);
                const encryptedOffer = await hybridEncrypt(
                    state.call.peerKeyObj,
                    JSON.stringify({ type: offer.type, sdp: offer.sdp, videoActive: state.call.videoActive })
                );
                socket.emit('renegotiate_offer', { recipientId: peerId, offer: encryptedOffer });
            } catch (err) {
                console.error('Renegotiation offer error:', err);
                state.call.negotiating = false;
            }
        };

        pc.onconnectionstatechange = () => {
            if (pc.connectionState === 'failed') {
                // Both NATs too restrictive for STUN alone
                socket.emit('hangup');
                resetCall('Call failed: could not establish a peer connection. (Both networks may require a TURN relay.)', 'failed');
            }
        };

        state.call.pc = pc;
        state.call.localStream = localStream;
        return pc;
    }

    /** Releases the mic/camera and closes the peer connection. */
    function teardownCallMedia() {
        const { pc, localStream, localVideoStream } = state.call;
        if (localStream) {
            localStream.getTracks().forEach(track => track.stop()); // mic indicator off
        }
        if (localVideoStream) {
            localVideoStream.getTracks().forEach(track => track.stop()); // camera indicator off
        }
        clearTimeout(state.call.negotiationTimeoutId);
        if (pc) {
            pc.onicecandidate = null;
            pc.ontrack = null;
            pc.onconnectionstatechange = null;
            pc.onnegotiationneeded = null;
            pc.close();
        }
        remoteAudio.srcObject = null;
        localVideoElem.srcObject = null;
        localVideoElem.classList.add('hidden');
        remoteVideoElem.srcObject = null;
        videoPanel.classList.add('hidden');
        videoBtn.textContent = 'START VIDEO';

        // Full teardown also leaves every other mesh connection - a real
        // hangup means leaving the whole call, not just the original pair.
        Object.keys(state.call.extraPeers).forEach(peerId => {
            const entry = state.call.extraPeers[peerId];
            clearTimeout(entry.negotiationTimeoutId);
            if (entry.pc) {
                entry.pc.onicecandidate = entry.pc.ontrack = entry.pc.onconnectionstatechange = entry.pc.onnegotiationneeded = null;
                try { entry.pc.close(); } catch (err) { /* already closed */ }
            }
            if (entry.audioEl) {
                entry.audioEl.srcObject = null;
                entry.audioEl.remove();
            }
        });
        state.call.extraPeers = {};
        groupParticipantsElem.textContent = '';
        extraVideoTilesElem.innerHTML = '';
        extraVideoTilesElem.classList.add('hidden');
        callParticipantsListElem.innerHTML = '';
        callParticipantsListElem.classList.add('hidden');
        groupInvitePicker.classList.add('hidden');
    }

    /** Applies ICE candidates that arrived before the remote description was set. */
    async function flushPendingCandidates() {
        const pc = state.call.pc;
        while (pc && state.call.pendingCandidates.length > 0) {
            const candidate = state.call.pendingCandidates.shift();
            try {
                await pc.addIceCandidate(candidate);
            } catch (err) {
                console.error('ICE candidate error:', err);
            }
        }
    }

    function updateCallUI() {
        const { status, peerNick } = state.call;

        if (status === 'idle') {
            callStatusBar.classList.add('hidden');
            hideModal(incomingModal);
            groupParticipantsElem.textContent = '';
            groupInvitePicker.classList.add('hidden');
            callParticipantsListElem.classList.add('hidden');
            extraVideoTilesElem.classList.add('hidden');
            return;
        }

        callStatusBar.classList.remove('hidden');
        callStatusText.classList.remove('status-calling');

        if (status === 'calling') {
            callStatusText.textContent = `Calling ${peerNick}…`;
            callStatusText.classList.add('status-calling');
            muteBtn.classList.add('hidden');
            videoBtn.classList.add('hidden');
            addToCallBtn.classList.add('hidden');
        } else if (status === 'ringing') {
            callStatusText.textContent = `Incoming call: ${peerNick}`;
            callStatusText.classList.add('status-calling');
            muteBtn.classList.add('hidden');
            videoBtn.classList.add('hidden');
            addToCallBtn.classList.add('hidden');
        } else if (status === 'connected') {
            callStatusText.textContent = `In call with ${peerNick}`;
            renderCallStatus(); // adds duration + mute marker
            muteBtn.classList.remove('hidden');
            muteBtn.textContent = state.call.muted ? 'UNMUTE' : 'MUTE';
            videoBtn.classList.remove('hidden');
            videoBtn.textContent = state.call.videoActive ? 'STOP VIDEO' : 'START VIDEO';
            addToCallBtn.classList.remove('hidden');
            renderGroupParticipants();
        }
    }

    // --- Call log (Phase 6) ---
    // Purely client-side and in-memory, consistent with the rest of the
    // app's ephemeral state - each browser keeps its own log of calls it
    // was actually party to, and it's gone on reload just like chat history.

    function logCallEvent({ direction, peerId, peerNick, outcome, durationSeconds }) {
        const entry = {
            id: (window.crypto.randomUUID ? window.crypto.randomUUID()
                : `${Date.now()}-${Math.random().toString(36).slice(2)}`),
            direction, peerId, peerNick, outcome,
            timestamp: Date.now(),
            durationSeconds: durationSeconds != null ? durationSeconds : null
        };
        state.callLog.unshift(entry);

        if (outcome === 'missed') {
            state.missedCallCount++;
            updateCallsTabBadge();
        }
        if (state.currentTabId === 'calls') renderCallLog();
    }

    function formatDuration(secs) {
        const m = String(Math.floor(secs / 60)).padStart(2, '0');
        const s = String(secs % 60).padStart(2, '0');
        return `${m}:${s}`;
    }

    const OUTCOME_LABELS = {
        declined: 'declined',
        missed: 'missed',
        'no-answer': 'no answer',
        canceled: 'canceled',
        failed: 'call failed'
    };

    function callLogMetaText(entry) {
        const time = new Date(entry.timestamp).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
        const outcomeText = entry.outcome === 'completed' && entry.durationSeconds != null
            ? formatDuration(entry.durationSeconds)
            : (OUTCOME_LABELS[entry.outcome] || entry.outcome);
        const dirLabel = entry.direction === 'outgoing' ? 'Outgoing' : 'Incoming';
        return `${dirLabel} · ${outcomeText} · ${time}`;
    }

    function callLogIcon(entry) {
        if (entry.outcome === 'missed' || entry.outcome === 'no-answer') return '✕';
        return entry.direction === 'outgoing' ? '↗' : '↙';
    }

    function buildCallLogRow(entry) {
        const row = document.createElement('div');
        row.className = `call-log-row outcome-${entry.outcome}`;

        const icon = document.createElement('span');
        icon.className = 'call-log-icon';
        icon.textContent = callLogIcon(entry);
        icon.setAttribute('aria-hidden', 'true'); // decorative - the meta text already states direction/outcome

        const info = document.createElement('div');
        info.className = 'call-log-info';
        const nickEl = document.createElement('div');
        nickEl.className = 'call-log-nick';
        nickEl.textContent = entry.peerNick;
        const metaEl = document.createElement('div');
        metaEl.className = 'call-log-meta';
        metaEl.textContent = callLogMetaText(entry);
        info.appendChild(nickEl);
        info.appendChild(metaEl);

        row.appendChild(icon);
        row.appendChild(info);

        // Call-back button, only if the peer is still in the room
        const stillOnline = Object.values(state.phonebook).some(u => u.id === entry.peerId);
        if (stillOnline) {
            const btn = document.createElement('button');
            btn.type = 'button';
            btn.className = 'call-log-callback';
            btn.textContent = 'Call';
            btn.addEventListener('click', () => {
                const key = publicKeyFromId(entry.peerId);
                if (key) startCall({ id: entry.peerId, nick: entry.peerNick, publicKey: key });
            });
            row.appendChild(btn);
        } else {
            const offline = document.createElement('span');
            offline.className = 'call-log-offline';
            offline.textContent = 'offline';
            row.appendChild(offline);
        }

        return row;
    }

    function renderCallLog() {
        messageDisplay.innerHTML = '';
        if (state.callLog.length === 0) {
            const empty = document.createElement('div');
            empty.className = 'msg system';
            empty.textContent = 'No calls yet.';
            messageDisplay.appendChild(empty);
            return;
        }
        state.callLog.forEach(entry => messageDisplay.appendChild(buildCallLogRow(entry)));
    }

    /** Base fields shared by every call-state reset point - idle, calling, and ringing all build on this. */
    function idleCallDefaults() {
        return {
            status: 'idle', peerId: null, peerNick: null, direction: null, peerKeyObj: null,
            pendingOffer: null, pc: null, localStream: null, pendingCandidates: [],
            muted: false, startedAt: null, lastRtp: null,
            localVideoStream: null, videoSender: null, videoActive: false, remoteVideoActive: false,
            negotiating: false, negotiationTimeoutId: null,
            // Group calls: every call has a groupId once connected, even a
            // plain 1:1 one. Additional participants beyond the original
            // pair are "extra peers" - a parallel, deliberately simpler
            // mesh leg per person: audio only (no video, no renegotiation,
            // no safety code/quality UI - those stay scoped to the
            // original pair). See the "+ Add" button and
            // handleGroupMemberJoined() for how the mesh completes.
            groupId: null,
            extraPeers: {} // peerId -> { pc, peerNick, pendingCandidates, status, audioEl }
        };
    }

    function resetCall(message, outcome) {
        // Log the call that's ending, before we clear its details
        if (outcome && state.call.status !== 'idle') {
            logCallEvent({
                direction: state.call.direction || 'outgoing',
                peerId: state.call.peerId,
                peerNick: state.call.peerNick,
                outcome,
                durationSeconds: (outcome === 'completed' && state.call.startedAt)
                    ? Math.floor((Date.now() - state.call.startedAt) / 1000)
                    : null
            });
        }

        teardownCallMedia();
        stopRingtone();
        clearInterval(callTimerId);
        clearInterval(statsTimerId);
        state.call = idleCallDefaults();
        safetyCodeElem.textContent = '';
        qualityElem.textContent = '';
        qualityElem.className = '';
        updateCallUI();
        if (message) logSystem(message);
    }

    async function startCall(user) {
        if (state.call.status !== 'idle') {
            return alert('You are already in a call.');
        }
        const trust = state.trustStatus[user.nick];
        if (trust && trust.status === 'changed') {
            return alert(`${user.nick}'s identity key changed and hasn't been trusted. Resolve this in the user list before calling.`);
        }
        state.call = {
            ...idleCallDefaults(),
            status: 'calling',
            peerId: user.id,
            peerNick: user.nick,
            direction: 'outgoing'
        };
        updateCallUI();
        startRingtone(false); // outgoing ringback

        try {
            // Import the recipient's RSA key BEFORE creating the peer
            // connection, so ICE candidates can be encrypted the moment
            // gathering starts
            state.call.peerKeyObj = await importPublicKey(user.publicKey);

            // Fresh ICE config (any TURN credentials are short-lived, so
            // fetch right before use rather than relying on page-load state)
            await refreshIceConfig();

            const pc = await setupPeerConnection(user.id);
            const offer = await pc.createOffer();
            // setLocalDescription starts ICE gathering; candidates found while
            // the callee's phone is still "ringing" get buffered on their side
            await pc.setLocalDescription(offer);

            // Encrypt the SDP offer so the server relays an opaque blob
            const encryptedOffer = await hybridEncrypt(
                state.call.peerKeyObj,
                JSON.stringify({ type: offer.type, sdp: offer.sdp })
            );

            socket.emit('call_user', {
                recipientId: user.id,
                offer: encryptedOffer
            });
        } catch (err) {
            console.error('Call setup error:', err);
            resetCall(err.name === 'NotAllowedError'
                ? 'Call failed: microphone access was denied.'
                : 'Call failed: could not set up an encrypted call.', 'failed');
        }
    }

    // Outgoing/active call: hang up
    hangupBtn.addEventListener('click', () => {
        if (state.call.status === 'ringing') {
            // Hanging up while being rung = declining
            socket.emit('decline_call', { recipientId: state.call.peerId });
            resetCall('Call ended.', 'declined');
        } else if (state.call.status === 'calling') {
            // We're canceling our own outgoing call before it was answered
            socket.emit('hangup');
            resetCall('Call canceled.', 'canceled');
        } else {
            socket.emit('hangup');
            resetCall('Call ended.', 'completed');
        }
    });

    // Incoming call: accept (shared by the Accept button and glare resolution)
    async function acceptIncomingCall() {
        if (state.call.status !== 'ringing') return;
        hideModal(incomingModal);
        stopRingtone();

        try {
            // Caller's key: needed to encrypt our answer + ICE candidates
            const callerKey = publicKeyFromId(state.call.peerId);
            if (!callerKey) throw new Error('Caller public key unavailable');
            state.call.peerKeyObj = await importPublicKey(callerKey);

            // The offer was held as an opaque blob until the user consented
            const offerJson = await hybridDecrypt(state.keys.privateKey, state.call.pendingOffer);
            const offer = JSON.parse(offerJson);

            // Fresh ICE config (any TURN credentials are short-lived, so
            // fetch right before use rather than relying on page-load state)
            await refreshIceConfig();

            const pc = await setupPeerConnection(state.call.peerId);
            await pc.setRemoteDescription(offer);
            // Caller's ICE candidates may have arrived while we were ringing
            await flushPendingCandidates();

            const answer = await pc.createAnswer();
            await pc.setLocalDescription(answer);

            state.call.status = 'connected';
            onCallConnected();

            // Encrypt the SDP answer back to the caller
            const encryptedAnswer = await hybridEncrypt(
                state.call.peerKeyObj,
                JSON.stringify({ type: answer.type, sdp: answer.sdp })
            );

            socket.emit('answer_call', {
                recipientId: state.call.peerId,
                answer: encryptedAnswer
            });
            logSystem(`Call connected with ${state.call.peerNick}.`);
            showSafetyCode(state.call.peerId, state.call.peerNick, pc, true);
        } catch (err) {
            console.error('Answer setup error:', err);
            // Can't take the call - tell the caller
            socket.emit('decline_call', { recipientId: state.call.peerId });
            resetCall(err.name === 'NotAllowedError'
                ? 'Call failed: microphone access was denied.'
                : 'Call failed: could not decrypt or set up the call.', 'failed');
        }
    }
    acceptCallBtn.addEventListener('click', acceptIncomingCall);

    // --- Group calls (mesh) ---
    // Every "extra peer" is its own independent RTCPeerConnection, sharing
    // the SAME captured microphone/camera tracks (the same MediaStreamTrack
    // object can be added as a sender on multiple peer connections at once
    // - no re-capturing needed). Video and per-pair safety codes now work
    // for every participant, not just the original pair - each pairwise
    // leg gets its own signed offer/answer and its own safety code, same
    // as a normal 1:1 call. Only the connection-quality indicator stays
    // scoped to the original pair; see the README for why.

    /** Resolves a peerId to its call-state entry: state.call itself for the primary, or the matching extraPeers entry. */
    function entryFor(peerId) {
        if (peerId === state.call.peerId) return state.call;
        return state.call.extraPeers[peerId];
    }
    function isPrimaryPeer(peerId) {
        return peerId === state.call.peerId;
    }

    /** Generic ICE-candidate flush, usable for the primary connection or any extra peer - both shapes carry .pc and .pendingCandidates. */
    async function flushCandidatesFor(entry) {
        if (!entry || !entry.pc) return;
        const list = entry.pendingCandidates || [];
        entry.pendingCandidates = [];
        for (const c of list) {
            try { await entry.pc.addIceCandidate(c); } catch (err) { console.error('ICE candidate flush error:', err); }
        }
    }

    /**
     * Wires up renegotiation (video on/off) for an extra peer connection,
     * mirroring the primary's onnegotiationneeded exactly - same signed,
     * encrypted offer/answer dance, same videoActive flag in the payload.
     * Not reused for the primary connection itself (that one's already
     * wired up inside setupPeerConnection) - just avoids duplicating this
     * logic for every extra peer instead.
     */
    function attachNegotiationHandler(pc, peerId) {
        pc.onnegotiationneeded = async () => {
            const entry = entryFor(peerId);
            if (!entry || entry.negotiating) return;
            entry.negotiating = true;
            clearTimeout(entry.negotiationTimeoutId);
            entry.negotiationTimeoutId = setTimeout(() => { entry.negotiating = false; }, 5000);
            try {
                const offer = await pc.createOffer();
                await pc.setLocalDescription(offer);
                const encryptedOffer = await hybridEncrypt(
                    entry.peerKeyObj,
                    JSON.stringify({ type: offer.type, sdp: offer.sdp, videoActive: state.call.videoActive })
                );
                socket.emit('renegotiate_offer', { recipientId: peerId, offer: encryptedOffer });
            } catch (err) {
                console.error('Renegotiation offer error (extra peer):', err);
                entry.negotiating = false;
            }
        };
    }

    /** Creates (if needed) the small video tile for an extra peer, alongside the main video panel. */
    function ensureExtraVideoTile(peerId, peerNick) {
        let tile = extraVideoTilesElem.querySelector(`[data-peer-id="${CSS.escape(peerId)}"]`);
        if (tile) return tile;
        tile = document.createElement('div');
        tile.className = 'extra-video-tile';
        tile.dataset.peerId = peerId;
        const video = document.createElement('video');
        video.autoplay = true;
        video.playsInline = true;
        tile.appendChild(video);
        const label = document.createElement('span');
        label.className = 'extra-video-tile-label';
        label.textContent = peerNick;
        tile.appendChild(label);
        extraVideoTilesElem.appendChild(tile);
        return tile;
    }

    /** Shows/hides an extra peer's video tile based on their current remoteVideoActive flag. */
    function updateExtraPeerVideoTile(peerId, entry) {
        if (!entry.remoteVideoActive) {
            const tile = extraVideoTilesElem.querySelector(`[data-peer-id="${CSS.escape(peerId)}"]`);
            if (tile) tile.remove();
            extraVideoTilesElem.classList.toggle('hidden', extraVideoTilesElem.children.length === 0);
            return;
        }
        ensureExtraVideoTile(peerId, entry.peerNick);
        extraVideoTilesElem.classList.remove('hidden');
    }

    function renderGroupParticipants() {
        const names = Object.values(state.call.extraPeers)
            .filter(p => p.status === 'connected')
            .map(p => p.peerNick);
        groupParticipantsElem.textContent = names.length > 0
            ? `+ ${names.join(', ')}`
            : '';

        // A full per-peer safety-code list only makes sense once it's
        // actually a group call - for a plain 1:1 call the existing
        // compact #safety-code element in the call bar already covers it.
        const extras = Object.values(state.call.extraPeers).filter(p => p.status === 'connected');
        callParticipantsListElem.innerHTML = '';
        if (extras.length === 0) {
            callParticipantsListElem.classList.add('hidden');
            return;
        }
        callParticipantsListElem.classList.remove('hidden');
        if (state.call.peerId) {
            const primaryCode = safetyCodeElem.textContent.replace(/^safety /, '');
            callParticipantsListElem.appendChild(buildParticipantRow(state.call.peerNick, primaryCode));
        }
        extras.forEach(entry => {
            callParticipantsListElem.appendChild(buildParticipantRow(entry.peerNick, entry.safetyCode));
        });
    }

    function buildParticipantRow(nick, safetyCode) {
        const row = document.createElement('div');
        row.className = 'call-participant-row';
        const nameEl = document.createElement('span');
        nameEl.className = 'call-participant-name';
        nameEl.textContent = nick;
        row.appendChild(nameEl);
        const codeEl = document.createElement('span');
        codeEl.className = 'call-participant-safety';
        codeEl.textContent = safetyCode ? `safety ${safetyCode}` : 'connecting…';
        row.appendChild(codeEl);
        return row;
    }

    /** Tears down one extra-peer connection without affecting the rest of the call. */
    function removeExtraPeer(peerId, message) {
        const entry = state.call.extraPeers[peerId];
        if (!entry) return;
        clearTimeout(entry.negotiationTimeoutId);
        if (entry.pc) {
            entry.pc.onicecandidate = entry.pc.ontrack = entry.pc.onconnectionstatechange = entry.pc.onnegotiationneeded = null;
            try { entry.pc.close(); } catch (err) { /* already closed */ }
        }
        if (entry.audioEl) {
            entry.audioEl.srcObject = null;
            entry.audioEl.remove();
        }
        const tile = extraVideoTilesElem.querySelector(`[data-peer-id="${CSS.escape(peerId)}"]`);
        if (tile) tile.remove();
        extraVideoTilesElem.classList.toggle('hidden', extraVideoTilesElem.children.length === 0);
        delete state.call.extraPeers[peerId];
        if (message) logSystem(message);
        renderGroupParticipants();
    }

    /** Invites someone new into the call I'm already on - the "+ Add" action, and also how mesh-completion auto-connects work. */
    async function inviteToGroupCall(user) {
        if (state.call.status !== 'connected') return;
        if (user.id === state.call.peerId || state.call.extraPeers[user.id]) return; // already connected to them
        const totalNow = 2 + Object.keys(state.call.extraPeers).length; // me + primary + existing extras
        if (totalNow >= 4) {
            logSystem('Group calls are limited to 4 people.');
            return;
        }
        const trust = state.trustStatus[user.nick];
        if (trust && trust.status === 'changed') {
            alert(`${user.nick}'s identity key changed and hasn't been trusted. Resolve this in the user list first.`);
            return;
        }

        const peerKeyObj = await importPublicKey(user.publicKey);
        const pc = new RTCPeerConnection(rtcConfig);
        const audioEl = document.createElement('audio');
        audioEl.autoplay = true;
        audioEl.style.display = 'none';
        document.body.appendChild(audioEl);

        const entry = {
            pc, peerNick: user.nick, pendingCandidates: [], status: 'ringing', audioEl, peerKeyObj,
            direction: 'outgoing', videoSender: null, remoteVideoActive: false,
            negotiating: false, negotiationTimeoutId: null, safetyCode: null
        };
        state.call.extraPeers[user.id] = entry;

        if (state.call.localStream) {
            state.call.localStream.getAudioTracks().forEach(track => pc.addTrack(track, state.call.localStream));
        }
        // If my camera is already on when I invite someone, they should
        // get video from the start rather than needing a separate toggle.
        if (state.call.videoActive && state.call.localVideoStream) {
            entry.videoSender = pc.addTrack(state.call.localVideoStream.getVideoTracks()[0], state.call.localVideoStream);
        }

        pc.onicecandidate = async (e) => {
            if (!e.candidate) return;
            try {
                const blob = await hybridEncrypt(peerKeyObj, JSON.stringify(e.candidate.toJSON()));
                socket.emit('ice_candidate', { recipientId: user.id, candidate: blob });
            } catch (err) { console.error('Extra peer ICE encryption error:', err); }
        };
        pc.ontrack = (e) => {
            if (e.track.kind === 'video') {
                const tile = ensureExtraVideoTile(user.id, user.nick);
                const video = tile.querySelector('video');
                video.srcObject = e.streams[0];
                video.play().catch(err => console.warn('Extra peer video autoplay blocked:', err));
            } else {
                audioEl.srcObject = e.streams[0];
                audioEl.play().catch(err => console.warn('Extra peer audio autoplay blocked:', err));
            }
        };
        pc.onconnectionstatechange = () => {
            if (pc.connectionState === 'failed') removeExtraPeer(user.id, `Lost connection to ${user.nick}.`);
        };
        attachNegotiationHandler(pc, user.id);

        try {
            const offer = await pc.createOffer();
            await pc.setLocalDescription(offer);
            const encryptedOffer = await hybridEncrypt(peerKeyObj, JSON.stringify({ type: offer.type, sdp: offer.sdp, videoActive: state.call.videoActive }));
            socket.emit('call_user', { recipientId: user.id, offer: encryptedOffer, groupId: state.call.groupId });
        } catch (err) {
            console.error('Group invite error:', err);
            removeExtraPeer(user.id, `Could not invite ${user.nick}.`);
        }
    }

    /** Mesh completion, receiving side: an existing member is auto-connecting to me. No consent prompt - I already agreed to join this group once. */
    async function acceptExtraPeerCall(peerId, encryptedOffer) {
        const peerNick = nickFromId(peerId);
        const peerPublicKeyB64 = state.phonebook[peerNick] && state.phonebook[peerNick].publicKey;
        if (!peerPublicKeyB64) return; // they're online (we're mesh-connecting within a live group) - shouldn't happen

        const trust = state.trustStatus[peerNick];
        if (trust && trust.status === 'changed') {
            socket.emit('decline_call', { recipientId: peerId });
            logSystem(`Could not connect to ${peerNick} in the group call - their identity key changed.`);
            return;
        }

        let offerJson;
        try {
            offerJson = JSON.parse(await hybridDecrypt(state.keys.privateKey, encryptedOffer));
        } catch (err) {
            console.error('Extra peer offer decrypt error:', err);
            return;
        }

        const peerKeyObj = await importPublicKey(peerPublicKeyB64);
        const pc = new RTCPeerConnection(rtcConfig);
        const audioEl = document.createElement('audio');
        audioEl.autoplay = true;
        audioEl.style.display = 'none';
        document.body.appendChild(audioEl);

        const entry = {
            pc, peerNick, pendingCandidates: [], status: 'connecting', audioEl, peerKeyObj,
            direction: 'incoming', videoSender: null, remoteVideoActive: false,
            negotiating: false, negotiationTimeoutId: null, safetyCode: null
        };
        state.call.extraPeers[peerId] = entry;

        pc.onicecandidate = async (e) => {
            if (!e.candidate) return;
            try {
                const blob = await hybridEncrypt(peerKeyObj, JSON.stringify(e.candidate.toJSON()));
                socket.emit('ice_candidate', { recipientId: peerId, candidate: blob });
            } catch (err) { console.error('Extra peer ICE encryption error:', err); }
        };
        pc.ontrack = (e) => {
            if (e.track.kind === 'video') {
                const tile = ensureExtraVideoTile(peerId, peerNick);
                const video = tile.querySelector('video');
                video.srcObject = e.streams[0];
                video.play().catch(err => console.warn('Extra peer video autoplay blocked:', err));
            } else {
                audioEl.srcObject = e.streams[0];
                audioEl.play().catch(err => console.warn('Extra peer audio autoplay blocked:', err));
            }
        };
        pc.onconnectionstatechange = () => {
            if (pc.connectionState === 'failed') removeExtraPeer(peerId, `Lost connection to ${peerNick}.`);
        };
        attachNegotiationHandler(pc, peerId);

        try {
            await pc.setRemoteDescription(offerJson);
            await flushCandidatesFor(entry);

            entry.remoteVideoActive = Boolean(offerJson.videoActive);
            updateExtraPeerVideoTile(peerId, entry);

            if (state.call.localStream) {
                state.call.localStream.getAudioTracks().forEach(track => pc.addTrack(track, state.call.localStream));
            }
            if (state.call.videoActive && state.call.localVideoStream) {
                entry.videoSender = pc.addTrack(state.call.localVideoStream.getVideoTracks()[0], state.call.localVideoStream);
            }

            const answer = await pc.createAnswer();
            await pc.setLocalDescription(answer);
            const encryptedAnswer = await hybridEncrypt(peerKeyObj, JSON.stringify({ type: answer.type, sdp: answer.sdp, videoActive: state.call.videoActive }));
            socket.emit('answer_call', { recipientId: peerId, answer: encryptedAnswer });
            entry.status = 'connected';
            logSystem(`${peerNick} joined the call.`);
            renderGroupParticipants();
            showSafetyCode(peerId, peerNick, pc, false);
        } catch (err) {
            console.error('Extra peer accept error:', err);
            removeExtraPeer(peerId, `Could not connect to ${peerNick}.`);
        }
    }


    // Mute / unmute the local microphone (track keeps running, sends silence)
    muteBtn.addEventListener('click', () => {
        if (state.call.status !== 'connected' || !state.call.localStream) return;
        state.call.muted = !state.call.muted;
        state.call.localStream.getAudioTracks().forEach(t => { t.enabled = !state.call.muted; });
        muteBtn.textContent = state.call.muted ? 'UNMUTE' : 'MUTE';
        renderCallStatus();
    });

    /**
     * Turns the camera on mid-call: grabs a video stream, adds it to the
     * already-connected peer connection (triggering onnegotiationneeded
     * above), and shows a local preview immediately - we don't wait for
     * the renegotiation round trip to complete before showing our own
     * preview, only the REMOTE side's video depends on that finishing.
     */
    async function startLocalVideo() {
        try {
            const videoStream = await navigator.mediaDevices.getUserMedia({
                video: { width: { ideal: 640 }, height: { ideal: 480 } }
            });
            if (state.call.status !== 'connected') {
                // Call ended while the camera permission prompt was open
                videoStream.getTracks().forEach(t => t.stop());
                return;
            }
            state.call.localVideoStream = videoStream;
            const track = videoStream.getVideoTracks()[0];

            // Add to the primary connection (if there still is one - see
            // clearPrimaryPeerKeepGroup for why there might not be) and to
            // every connected extra peer - one capture, added as a sender
            // on however many peer connections currently exist.
            if (state.call.pc) {
                state.call.videoSender = state.call.pc.addTrack(track, videoStream);
            }
            Object.values(state.call.extraPeers).forEach(entry => {
                if (entry.pc && entry.status === 'connected') {
                    entry.videoSender = entry.pc.addTrack(track, videoStream);
                }
            });

            state.call.videoActive = true;
            localVideoElem.srcObject = videoStream;
            updateVideoPanelVisibility();
            videoBtn.textContent = 'STOP VIDEO';
        } catch (err) {
            console.error('Camera error:', err);
            logSystem(err.name === 'NotAllowedError'
                ? 'Could not start video: camera access was denied.'
                : 'Could not start video: camera unavailable.');
        }
    }

    /** Turns the camera back off - removes the track (triggers renegotiation again) rather than just muting it, on every peer it was added to. */
    function stopLocalVideo() {
        if (state.call.videoSender && state.call.pc) {
            try { state.call.pc.removeTrack(state.call.videoSender); } catch (err) { /* connection may already be gone */ }
        }
        Object.values(state.call.extraPeers).forEach(entry => {
            if (entry.videoSender && entry.pc) {
                try { entry.pc.removeTrack(entry.videoSender); } catch (err) { /* connection may already be gone */ }
                entry.videoSender = null;
            }
        });
        if (state.call.localVideoStream) {
            state.call.localVideoStream.getTracks().forEach(t => t.stop()); // camera indicator off
        }
        state.call.localVideoStream = null;
        state.call.videoSender = null;
        state.call.videoActive = false;
        localVideoElem.srcObject = null;
        updateVideoPanelVisibility();
        videoBtn.textContent = 'START VIDEO';
    }

    videoBtn.addEventListener('click', () => {
        if (state.call.status !== 'connected') return;
        if (state.call.videoActive) {
            stopLocalVideo();
        } else {
            startLocalVideo();
        }
    });

    /** Shows a simple picker of eligible online users to invite into the active call. */
    function openGroupInvitePicker() {
        if (state.call.status !== 'connected') return;
        groupInviteList.innerHTML = '';
        const eligible = Object.entries(state.phonebook)
            .filter(([nick, u]) =>
                u.id !== state.call.peerId &&
                !state.call.extraPeers[u.id] &&
                nick !== state.myNick
            )
            .map(([nick, u]) => ({ nick, id: u.id, publicKey: u.publicKey }));
        if (eligible.length === 0) {
            const none = document.createElement('p');
            none.textContent = 'No one else is available to add right now.';
            groupInviteList.appendChild(none);
        } else {
            eligible.forEach(u => {
                const btn = document.createElement('button');
                btn.type = 'button';
                btn.className = 'group-invite-option';
                btn.textContent = u.nick;
                btn.addEventListener('click', () => {
                    inviteToGroupCall({ id: u.id, nick: u.nick, publicKey: u.publicKey });
                    groupInvitePicker.classList.add('hidden');
                });
                groupInviteList.appendChild(btn);
            });
        }
        groupInvitePicker.classList.remove('hidden');
    }
    addToCallBtn.addEventListener('click', openGroupInvitePicker);
    document.getElementById('group-invite-close-btn').addEventListener('click', () => {
        groupInvitePicker.classList.add('hidden');
    });

    socket.on('group_member_joined', ({ groupId, newMemberId, newMemberNick }) => {
        // An existing member of my group just had someone new accept -
        // I need to independently connect to that new person to complete
        // the mesh. No consent prompt: I already agreed to be in this
        // group call once.
        if (state.call.status !== 'connected' || state.call.groupId !== groupId) return;
        const publicKey = state.phonebook[newMemberNick] && state.phonebook[newMemberNick].publicKey;
        if (!publicKey) return;
        inviteToGroupCall({ id: newMemberId, nick: newMemberNick, publicKey });
    });

    // Incoming call: decline
    declineCallBtn.addEventListener('click', () => {
        if (state.call.status !== 'ringing') return;
        socket.emit('decline_call', { recipientId: state.call.peerId });
        resetCall(null, 'declined');
    });

    socket.on('incoming_call', async ({ senderId, offer, groupId, groupMembers }) => {
        // GLARE: we are currently calling the exact person who just called
        // us (both clicked Call at ~the same time). The server dropped our
        // offer, so we yield: abandon our own attempt and answer theirs.
        // No modal - both users clearly want to talk.
        if (state.call.status === 'calling' && senderId === state.call.peerId) {
            logSystem(`You and ${state.call.peerNick} called each other - connecting.`);
            stopRingtone();
            teardownCallMedia(); // discard our own offer's pc + mic grab
            state.call.pc = null;
            state.call.localStream = null;
            // keep pendingCandidates: any buffered candidates belong to THEIR
            // (kept) offer, not our discarded one
            state.call.status = 'ringing';
            state.call.direction = 'incoming'; // we're answering their surviving offer
            state.call.pendingOffer = offer;
            state.call.groupId = groupId;
            await acceptIncomingCall();
            return;
        }

        // Mesh completion: an existing member of the group call I'm
        // ALREADY in is connecting to me to complete the mesh. I already
        // consented to joining this group once - no second prompt.
        if (state.call.status === 'connected' && state.call.groupId && groupId === state.call.groupId) {
            await acceptExtraPeerCall(senderId, offer);
            return;
        }

        // Server guards against this, but be defensive
        if (state.call.status !== 'idle') return;

        state.call = {
            ...idleCallDefaults(),
            status: 'ringing',
            peerId: senderId,
            peerNick: nickFromId(senderId),
            direction: 'incoming',
            pendingOffer: offer, // opaque encrypted blob until the user accepts
            groupId: groupId
        };
        incomingCallText.textContent = (groupMembers && groupMembers.length > 0)
            ? `${state.call.peerNick} invites you to a call with ${groupMembers.map(m => m.nick).join(', ')}`
            : `${state.call.peerNick} is calling…`;
        showModal(incomingModal);
        updateCallUI();
        startRingtone(true); // incoming ring
        notify(`Incoming call from ${state.call.peerNick}`, 'Tap to open abyss', 'abyss-call');
    });

    socket.on('call_accepted', async ({ senderId, answer, groupId }) => {
        // The primary relationship (how every call, 1:1 or group, starts)
        if (state.call.status === 'calling' && senderId === state.call.peerId) {
            try {
                const answerJson = await hybridDecrypt(state.keys.privateKey, answer);
                await state.call.pc.setRemoteDescription(JSON.parse(answerJson));
                // Callee's candidates may have raced ahead of the answer
                await flushPendingCandidates();

                state.call.groupId = groupId;
                state.call.status = 'connected';
                onCallConnected();
                logSystem(`Call connected with ${state.call.peerNick}.`);
                showSafetyCode(state.call.peerId, state.call.peerNick, state.call.pc, true);
            } catch (err) {
                console.error('Answer handling error:', err);
                socket.emit('hangup');
                resetCall('Call failed: could not decrypt the connection setup.', 'failed');
            }
            return;
        }

        // An extra-peer invite I sent (via "+ Add" or auto-connecting to
        // complete a mesh) just got answered.
        const entry = state.call.extraPeers[senderId];
        if (entry && entry.status === 'ringing') {
            try {
                const answerJson = JSON.parse(await hybridDecrypt(state.keys.privateKey, answer));
                await entry.pc.setRemoteDescription(answerJson);
                await flushCandidatesFor(entry);
                entry.remoteVideoActive = Boolean(answerJson.videoActive);
                updateExtraPeerVideoTile(senderId, entry);
                entry.status = 'connected';
                logSystem(`${entry.peerNick} joined the call.`);
                renderGroupParticipants();
                showSafetyCode(senderId, entry.peerNick, entry.pc, false);
            } catch (err) {
                console.error('Extra peer answer error:', err);
                removeExtraPeer(senderId, `Could not connect to ${entry.peerNick}.`);
            }
        }
    });

    /**
     * The original two-person relationship ended, but other group members
     * are still connected. The call itself continues - only the video/
     * safety-code/quality UI, which is scoped to that original pair, goes
     * away. No attempt to "promote" an extra peer into the primary slot:
     * simpler to just show a group participant list with no single
     * distinguished pairing, at the cost of losing video/safety-code
     * ability for the rest of that call - a deliberate, documented tradeoff.
     */
    function clearPrimaryPeerKeepGroup() {
        if (state.call.pc) {
            state.call.pc.onicecandidate = state.call.pc.ontrack = state.call.pc.onconnectionstatechange = state.call.pc.onnegotiationneeded = null;
            try { state.call.pc.close(); } catch (err) { /* already closed */ }
        }
        remoteAudio.srcObject = null;
        // Deliberately NOT stopping state.call.localVideoStream or
        // touching videoActive here - that's my own camera, and the SAME
        // captured track is shared as a sender with any remaining extra
        // peers. The primary leaving doesn't mean I want to stop sending
        // video to everyone else still on the call.
        safetyCodeElem.textContent = '';
        qualityElem.textContent = '';
        qualityElem.className = '';
        clearInterval(statsTimerId);

        state.call.pc = null;
        state.call.peerId = null;
        state.call.videoSender = null; // belonged to the now-closed pc specifically
        state.call.remoteVideoActive = false; // was specifically about the primary peer's video
        updateVideoPanelVisibility(); // clears remote-video display; keeps local self-view if still active
        const remainingNicks = Object.values(state.call.extraPeers).map(p => p.peerNick);
        state.call.peerNick = remainingNicks.length > 0 ? remainingNicks.join(', ') : null;

        updateCallUI();
        renderGroupParticipants();
    }

    socket.on('call_declined', ({ senderId }) => {
        if (state.call.status === 'idle') return;
        if (senderId === state.call.peerId) {
            resetCall(`${state.call.peerNick} declined the call.`, 'declined');
            return;
        }
        const entry = state.call.extraPeers[senderId];
        if (entry) removeExtraPeer(senderId, `${entry.peerNick} declined to join.`);
    });

    socket.on('call_ended', ({ senderId }) => {
        if (state.call.status === 'idle') return;

        // An extra peer left (or their connection dropped) - remove just
        // that one leg; the rest of the call continues undisturbed...
        if (senderId !== state.call.peerId && state.call.extraPeers[senderId]) {
            const leftNick = state.call.extraPeers[senderId].peerNick;
            removeExtraPeer(senderId, `${leftNick} left the call.`);
            // ...UNLESS the primary already left earlier (peerId is null)
            // and this was the last extra remaining - then there's really
            // nobody left, and the call needs to actually end now rather
            // than sitting "connected" with zero peers.
            if (!state.call.peerId && Object.keys(state.call.extraPeers).length === 0) {
                resetCall('Call ended.', 'completed');
            }
            return;
        }

        // The PRIMARY relationship ended. If other members are still
        // connected, the call continues for them - see
        // clearPrimaryPeerKeepGroup() above for what that means in practice.
        if (Object.keys(state.call.extraPeers).length > 0) {
            const leftNick = state.call.peerNick;
            clearPrimaryPeerKeepGroup();
            logSystem(`${leftNick} left the call.`);
            return;
        }

        // Fires on peer hangup AND on peer disconnect mid-ring/mid-call
        let outcome;
        if (state.call.status === 'connected') {
            outcome = 'completed';
        } else if (state.call.direction === 'incoming') {
            // We were ringing and the caller hung up or disconnected first -
            // from our side that reads as a call we never got to answer
            outcome = 'missed';
        } else {
            // We were calling out and the recipient's socket vanished
            outcome = 'failed';
        }
        resetCall(`Call with ${state.call.peerNick} ended.`, outcome);
    });

    // Phase 6: ring timeout - fires on the CALLER's side when nobody answers
    socket.on('call_timeout', ({ peerId }) => {
        if (state.call.status === 'idle') return;
        if (peerId === state.call.peerId) {
            resetCall(`${state.call.peerNick} didn't answer.`, 'no-answer');
            return;
        }
        const entry = state.call.extraPeers[peerId];
        if (entry) removeExtraPeer(peerId, `${entry.peerNick} didn't answer.`);
    });

    // Phase 6: ring timeout - fires on the CALLEE's side when they never answered
    socket.on('call_missed', ({ peerId }) => {
        if (state.call.status === 'idle') return;
        if (peerId === state.call.peerId) {
            hideModal(incomingModal);
            resetCall(`Missed call from ${state.call.peerNick}.`, 'missed');
            return;
        }
        // Extras auto-accept near-instantly, so this is very unlikely -
        // but clean up defensively rather than leaving a stuck entry.
        const entry = state.call.extraPeers[peerId];
        if (entry) removeExtraPeer(peerId, `Connection to ${entry.peerNick} timed out.`);
    });

    socket.on('call_error', (message) => {
        resetCall(`Call failed: ${message}`, state.call.status !== 'idle' ? 'failed' : null);
    });

    socket.on('ice_candidate', async ({ senderId, candidate }) => {
        if (!candidate) return;

        // Route to whichever connection this candidate actually belongs to
        // - our primary relationship, or one of the extra (group) peers.
        const isPrimary = senderId === state.call.peerId;
        const extraEntry = state.call.extraPeers[senderId];
        if (!isPrimary && !extraEntry) return; // not from anyone we're connected to

        let parsed;
        try {
            parsed = JSON.parse(await hybridDecrypt(state.keys.privateKey, candidate));
        } catch (err) {
            console.error('Candidate decryption error:', err);
            return; // drop undecryptable candidates
        }

        const pc = isPrimary ? state.call.pc : extraEntry.pc;
        const pendingList = isPrimary ? state.call.pendingCandidates : extraEntry.pendingCandidates;
        if (pc && pc.remoteDescription) {
            try {
                await pc.addIceCandidate(parsed);
            } catch (err) {
                console.error('ICE candidate error:', err);
            }
        } else {
            // Classic race: candidates arriving before the remote description
            // is set (e.g. while still ringing). Buffer decrypted and flush later.
            pendingList.push(parsed);
        }
    });

    // Mid-call renegotiation (video on/off). Collision handling here is
    // deliberately simpler than full W3C "perfect negotiation" - which
    // needs setLocalDescription(rollback) - since a genuine cross-side
    // collision (both people toggle video at the same instant) is a rare
    // edge case, not the routine "both click Call" glare the initial
    // handshake has to handle. We reuse the same polite/impolite asymmetry
    // as that existing glare handling: the original callee (direction
    // 'incoming') yields; the original caller's offer wins.
    socket.on('renegotiate_offer', async ({ senderId, offer }) => {
        if (state.call.status !== 'connected') return;
        const entry = entryFor(senderId);
        if (!entry || !entry.pc) return;
        const isPrimary = isPrimaryPeer(senderId);
        const pc = entry.pc;

        const polite = entry.direction === 'incoming';
        const collision = entry.negotiating || pc.signalingState !== 'stable';

        if (collision && !polite) {
            return; // impolite side ignores an incoming offer while its own is in flight
        }
        if (collision && polite) {
            // Politely abandon our own in-flight attempt; when our answer
            // (if any) arrives back it'll be ignored below since
            // negotiating is already false by then.
            clearTimeout(entry.negotiationTimeoutId);
            entry.negotiating = false;
        }

        try {
            const offerJson = JSON.parse(await hybridDecrypt(state.keys.privateKey, offer));
            await pc.setRemoteDescription(offerJson);
            await flushCandidatesFor(entry); // in case candidates for the new m-line raced ahead

            // Explicit signal for whether THEY currently have video on -
            // see the note on updateVideoPanelVisibility() for why this
            // can't just be inferred from track presence.
            entry.remoteVideoActive = Boolean(offerJson.videoActive);
            if (isPrimary) {
                updateVideoPanelVisibility();
            } else {
                updateExtraPeerVideoTile(senderId, entry);
            }

            const answer = await pc.createAnswer();
            await pc.setLocalDescription(answer);
            const encryptedAnswer = await hybridEncrypt(
                entry.peerKeyObj,
                JSON.stringify({ type: answer.type, sdp: answer.sdp, videoActive: state.call.videoActive })
            );
            socket.emit('renegotiate_answer', { recipientId: senderId, answer: encryptedAnswer });
        } catch (err) {
            console.error('Renegotiate offer handling error:', err);
        }
    });

    socket.on('renegotiate_answer', async ({ senderId, answer }) => {
        if (state.call.status !== 'connected') return;
        const entry = entryFor(senderId);
        if (!entry || !entry.pc) return;
        if (!entry.negotiating) return; // abandoned (see the polite branch above) - ignore a stale answer
        const isPrimary = isPrimaryPeer(senderId);

        clearTimeout(entry.negotiationTimeoutId);
        try {
            const answerJson = JSON.parse(await hybridDecrypt(state.keys.privateKey, answer));
            await entry.pc.setRemoteDescription(answerJson);
            await flushCandidatesFor(entry);
            entry.remoteVideoActive = Boolean(answerJson.videoActive);
            if (isPrimary) {
                updateVideoPanelVisibility();
            } else {
                updateExtraPeerVideoTile(senderId, entry);
            }
        } catch (err) {
            console.error('Renegotiate answer handling error:', err);
        } finally {
            entry.negotiating = false;
        }
    });

    // --- Encrypted P2P file transfer ---
    // A dedicated, independent RTCPeerConnection per transfer - not tied to
    // any voice/video call. Reuses the exact same crypto primitives as
    // messages and calls (hybridEncrypt/hybridDecrypt for confidentiality,
    // signWithIdentity/verifyIncomingMessage for authenticity) rather than
    // inventing new ones. The file bytes themselves are never additionally
    // encrypted at the app layer - the RTCDataChannel already runs over
    // mandatory DTLS, peer-to-peer, and since the signaling that establishes
    // it is itself signed and encrypted, the channel inherits the same
    // MITM-resistance calls already have without a redundant crypto pass.

    const FILE_CHUNK_SIZE = 16 * 1024; // conservative, reliable across browsers
    const FILE_BUFFER_HIGH_WATER = 256 * 1024; // pause sending above this
    const MAX_FILE_SIZE = 200 * 1024 * 1024; // practical UX cap - everything here is in-memory
    const FILE_UI_REFRESH_THROTTLE_MS = 150; // don't repaint the progress bar on every single 16KB chunk

    function newTransferId() {
        return window.crypto.randomUUID ? window.crypto.randomUUID()
            : `${Date.now()}-${Math.random().toString(36).slice(2)}`;
    }

    /** Tears down the peer connection/channel for a transfer. The history record (if any) is left in place - it's the permanent record of what happened, same as a call log entry. */
    function cleanupTransferConnection(transferId) {
        const t = state.fileTransfers[transferId];
        if (!t) return;
        if (t.channel) {
            t.channel.onopen = t.channel.onmessage = t.channel.onclose = t.channel.onerror = t.channel.onbufferedamountlow = null;
            try { t.channel.close(); } catch (err) { /* already closed */ }
        }
        if (t.pc) {
            t.pc.onicecandidate = t.pc.ondatachannel = t.pc.onconnectionstatechange = null;
            try { t.pc.close(); } catch (err) { /* already closed */ }
        }
        delete state.fileTransfers[transferId];
    }

    function failTransfer(transferId, message) {
        const t = state.fileTransfers[transferId];
        if (t && t.historyRef) {
            t.historyRef.status = 'failed';
            refreshFileBubble(transferId);
        }
        if (t) logSystem(`File transfer with ${t.peerNick} failed: ${message}`);
        cleanupTransferConnection(transferId);
    }

    async function flushFileCandidates(transferId) {
        const t = state.fileTransfers[transferId];
        if (!t || !t.pc) return;
        const pending = t.pendingCandidates || [];
        t.pendingCandidates = [];
        for (const c of pending) {
            try { await t.pc.addIceCandidate(c); } catch (err) { console.error('File ICE flush error:', err); }
        }
    }

    /** Sender side: streams the File object over the data channel once it's open, respecting backpressure. */
    /**
     * send() only means "queued for transmission", not "delivered" - the
     * SCTP layer underneath a data channel can still have bytes in flight
     * after send() returns. Closing the connection right after the last
     * send() call is a well-known WebRTC footgun: it can abort that
     * in-flight data mid-transit and throw an OperationError on the
     * RECEIVING side, even though every byte was actually sent correctly.
     * Waiting for bufferedAmount to actually reach zero (with a safety-net
     * timeout in case the event never fires) avoids it.
     */
    function waitForDrainThenCleanup(transferId) {
        const t = state.fileTransfers[transferId];
        if (!t || !t.channel) { cleanupTransferConnection(transferId); return; }
        const channel = t.channel;
        if (channel.bufferedAmount === 0) {
            cleanupTransferConnection(transferId);
            return;
        }
        const safetyTimeout = setTimeout(() => cleanupTransferConnection(transferId), 3000);
        channel.bufferedAmountLowThreshold = 0;
        channel.onbufferedamountlow = () => {
            clearTimeout(safetyTimeout);
            cleanupTransferConnection(transferId);
        };
    }

    function sendFileChunks(transferId) {
        const t = state.fileTransfers[transferId];
        if (!t || t.role !== 'sender') return;
        const { channel, file, historyRef } = t;
        channel.bufferedAmountLowThreshold = FILE_BUFFER_HIGH_WATER;
        historyRef.status = 'transferring';
        refreshFileBubble(transferId);

        let offset = 0;
        let lastRefresh = 0;

        async function sendNext() {
            if (!state.fileTransfers[transferId]) return; // canceled/failed mid-send
            if (offset >= file.size) {
                historyRef.status = 'complete';
                historyRef.progress = 100;
                refreshFileBubble(transferId);
                logSystem(`Sent "${file.name}" to ${t.peerNick}.`);
                waitForDrainThenCleanup(transferId);
                return;
            }
            if (channel.bufferedAmount > FILE_BUFFER_HIGH_WATER) return; // onbufferedamountlow resumes us

            const slice = file.slice(offset, offset + FILE_CHUNK_SIZE);
            let buf;
            try {
                buf = await slice.arrayBuffer();
                channel.send(buf);
            } catch (err) {
                failTransfer(transferId, 'Failed to send file data.');
                return;
            }
            offset += buf.byteLength;
            historyRef.progress = Math.min(100, Math.floor((offset / file.size) * 100));
            const now = Date.now();
            if (now - lastRefresh > FILE_UI_REFRESH_THROTTLE_MS || offset >= file.size) {
                lastRefresh = now;
                refreshFileBubble(transferId);
            }
            sendNext();
        }

        channel.onbufferedamountlow = () => sendNext();
        sendNext();
    }

    /**
     * Receiver side: wired up when the data channel arrives via
     * pc.ondatachannel. Deliberately does NOT close the connection itself
     * on completion - only the sender does that (see
     * waitForDrainThenCleanup above), once it's confirmed its own send
     * buffer has actually drained. If the receiver closed first, the same
     * abort risk applies in the other direction. The receiver just marks
     * itself done and lets the eventual remote close tear things down
     * naturally (see the t.completed check in acceptFileTransfer's
     * onconnectionstatechange handler, which distinguishes "closed because
     * we're done" from "failed before we finished").
     */
    function setupReceiveChannel(transferId, channel) {
        const t = state.fileTransfers[transferId];
        if (!t) return;
        channel.binaryType = 'arraybuffer';
        t.channel = channel;
        let lastRefresh = 0;

        channel.onmessage = (e) => {
            t.receivedChunks.push(e.data);
            t.receivedBytes += e.data.byteLength;
            t.historyRef.progress = Math.min(100, Math.floor((t.receivedBytes / t.historyRef.size) * 100));

            const now = Date.now();
            const done = t.receivedBytes >= t.historyRef.size;
            if (done || now - lastRefresh > FILE_UI_REFRESH_THROTTLE_MS) {
                lastRefresh = now;
                refreshFileBubble(transferId);
            }
            if (done) {
                const blob = new Blob(t.receivedChunks, { type: t.historyRef.mimeType || 'application/octet-stream' });
                t.historyRef.downloadUrl = URL.createObjectURL(blob);
                t.historyRef.status = 'complete';
                t.historyRef.progress = 100;
                t.completed = true;
                refreshFileBubble(transferId);
                logSystem(`Received "${t.historyRef.name}" from ${t.peerNick}.`);
            }
        };
        channel.onerror = () => {
            if (t.completed) return; // connection tearing down after a successful transfer - not a failure
            failTransfer(transferId, 'Connection error during transfer.');
        };
    }

    /** Adds a file-transfer record to the given PM tab's history, creating the tab if needed. */
    function pushFileHistory(peerNick, historyRef) {
        const tabId = `pm_${peerNick}`;
        if (!state.history[tabId]) state.history[tabId] = [];
        state.history[tabId].push(historyRef);
        capHistory(tabId);
        if (!state.activeTabs.has(tabId)) createTabUI(tabId, peerNick);
        if (state.currentTabId === tabId) renderChatHistory();
    }

    /** Sender: kicks off a new transfer to peerNick. */
    async function startFileTransfer(peerNick, file) {
        const targetData = state.phonebook[peerNick];
        if (!targetData) return alert('User offline.');
        const trust = state.trustStatus[peerNick];
        if (trust && trust.status === 'changed') {
            return alert(`${peerNick}'s identity key changed and hasn't been trusted. Resolve this in the user list before sending files.`);
        }
        if (file.size > MAX_FILE_SIZE) {
            return alert(`That file is too large - the limit is ${formatFileSize(MAX_FILE_SIZE)}.`);
        }

        const transferId = newTransferId();
        const peerKeyObj = await importPublicKey(targetData.publicKey);
        const historyRef = {
            fileTransfer: true, transferId, name: file.name, size: file.size,
            mimeType: file.type || 'application/octet-stream',
            direction: 'sent', status: 'pending', progress: 0
        };
        pushFileHistory(peerNick, historyRef);

        const pc = new RTCPeerConnection(rtcConfig);
        const channel = pc.createDataChannel('file');
        channel.binaryType = 'arraybuffer';

        const t = { role: 'sender', peerId: targetData.id, peerNick, pc, channel, file, peerKeyObj, historyRef };
        state.fileTransfers[transferId] = t;

        pc.onicecandidate = async (e) => {
            if (!e.candidate) return;
            try {
                const blob = await hybridEncrypt(peerKeyObj, JSON.stringify(e.candidate.toJSON()));
                socket.emit('file_ice_candidate', { recipientId: targetData.id, transferId, candidate: blob });
            } catch (err) { console.error('File ICE encryption error:', err); }
        };
        channel.onopen = () => sendFileChunks(transferId);
        channel.onerror = () => {
            if (t.historyRef && t.historyRef.status === 'complete') return; // tearing down after success
            failTransfer(transferId, 'Connection error during transfer.');
        };
        pc.onconnectionstatechange = () => {
            if (t.historyRef && t.historyRef.status === 'complete') return; // tearing down after success
            if (pc.connectionState === 'failed') failTransfer(transferId, 'Could not establish a connection for this transfer.');
        };

        try {
            const offer = await pc.createOffer();
            await pc.setLocalDescription(offer);
            const timestamp = Date.now();
            const payload = JSON.stringify({
                type: offer.type, sdp: offer.sdp,
                name: file.name, size: file.size, mimeType: file.type || 'application/octet-stream'
            });
            const encryptedOffer = await hybridEncrypt(peerKeyObj, payload);
            const signature = await signWithIdentity(`${timestamp}:${encryptedOffer}`);
            socket.emit('file_offer', { recipientId: targetData.id, transferId, offer: encryptedOffer, timestamp, signature });
        } catch (err) {
            console.error('File offer error:', err);
            failTransfer(transferId, 'Could not start the file transfer.');
        }
    }

    /** Receiver: accepts a pending offer (shown via the incoming-file modal). */
    async function acceptFileTransfer(transferId) {
        const t = state.fileTransfers[transferId];
        if (!t || t.role !== 'receiver') return;
        hideModal(incomingFileModal);

        const senderPublicKeyB64 = state.phonebook[t.peerNick] && state.phonebook[t.peerNick].publicKey;
        if (!senderPublicKeyB64) { failTransfer(transferId, 'Sender is no longer online.'); return; }
        t.peerKeyObj = await importPublicKey(senderPublicKeyB64);

        const pc = new RTCPeerConnection(rtcConfig);
        t.pc = pc;
        t.receivedChunks = [];
        t.receivedBytes = 0;

        const historyRef = {
            fileTransfer: true, transferId, name: t.pendingOffer.name, size: t.pendingOffer.size,
            mimeType: t.pendingOffer.mimeType, direction: 'received', status: 'transferring', progress: 0
        };
        t.historyRef = historyRef;
        pushFileHistory(t.peerNick, historyRef);
        setActiveTab(`pm_${t.peerNick}`);

        pc.onicecandidate = async (e) => {
            if (!e.candidate) return;
            try {
                const blob = await hybridEncrypt(t.peerKeyObj, JSON.stringify(e.candidate.toJSON()));
                socket.emit('file_ice_candidate', { recipientId: t.peerId, transferId, candidate: blob });
            } catch (err) { console.error('File ICE encryption error:', err); }
        };
        pc.ondatachannel = (e) => setupReceiveChannel(transferId, e.channel);
        pc.onconnectionstatechange = () => {
            if (pc.connectionState === 'failed' || pc.connectionState === 'closed' || pc.connectionState === 'disconnected') {
                if (t.completed) {
                    // Expected: the sender waited for its buffer to drain,
                    // then closed its side once we'd confirmed receipt of
                    // everything. Just release our own references quietly.
                    if (state.fileTransfers[transferId]) delete state.fileTransfers[transferId];
                    return;
                }
                if (pc.connectionState === 'failed') failTransfer(transferId, 'Connection failed during transfer.');
            }
        };

        try {
            await pc.setRemoteDescription({ type: t.pendingOffer.type, sdp: t.pendingOffer.sdp });
            await flushFileCandidates(transferId);
            const answer = await pc.createAnswer();
            await pc.setLocalDescription(answer);
            const timestamp = Date.now();
            const encryptedAnswer = await hybridEncrypt(t.peerKeyObj, JSON.stringify({ type: answer.type, sdp: answer.sdp }));
            const signature = await signWithIdentity(`${timestamp}:${encryptedAnswer}`);
            socket.emit('file_answer', { recipientId: t.peerId, transferId, answer: encryptedAnswer, timestamp, signature });
        } catch (err) {
            console.error('File answer error:', err);
            failTransfer(transferId, 'Could not accept the file transfer.');
        }
    }

    function declineFileTransfer(transferId) {
        const t = state.fileTransfers[transferId];
        if (!t) return;
        hideModal(incomingFileModal);
        socket.emit('file_decline', { recipientId: t.peerId, transferId });
        delete state.fileTransfers[transferId]; // no pc exists yet at decline time - nothing to close
    }

    function cancelFileTransfer(transferId) {
        const t = state.fileTransfers[transferId];
        if (!t) return;
        socket.emit('file_cancel', { recipientId: t.peerId, transferId });
        if (t.historyRef) { t.historyRef.status = 'canceled'; refreshFileBubble(transferId); }
        cleanupTransferConnection(transferId);
    }

    // --- UI wiring ---
    attachFileBtn.addEventListener('click', () => {
        if (state.currentTabId === 'global' || state.currentTabId === 'calls') return;
        filePicker.click();
    });
    filePicker.addEventListener('change', () => {
        const file = filePicker.files[0];
        filePicker.value = ''; // allow picking the exact same file again later
        if (!file) return;
        if (state.currentTabId === 'global' || state.currentTabId === 'calls') return;
        const peerNick = state.currentTabId.replace('pm_', '');
        startFileTransfer(peerNick, file);
    });
    acceptFileBtn.addEventListener('click', () => acceptFileTransfer(incomingFileModal.dataset.transferId));
    declineFileBtn.addEventListener('click', () => declineFileTransfer(incomingFileModal.dataset.transferId));

    socket.on('file_offer', async ({ senderId, transferId, offer, timestamp, signature }) => {
        const peerNick = nickFromId(senderId);

        // Only one incoming-file prompt at a time, kept simple on purpose -
        // a second simultaneous offer is auto-declined rather than queued.
        if (!incomingFileModal.classList.contains('hidden')) {
            socket.emit('file_decline', { recipientId: senderId, transferId });
            return;
        }

        const authentic = await verifyIncomingMessage(peerNick, `${timestamp}:${offer}`, signature);
        if (!authentic) {
            console.warn(`Dropped an unverifiable file offer claiming to be from ${peerNick}`);
            return; // same treatment as an unverifiable message - no actionable UI for it
        }

        let payload;
        try {
            payload = JSON.parse(await hybridDecrypt(state.keys.privateKey, offer));
        } catch (err) {
            console.error('File offer decrypt error:', err);
            return;
        }
        if (typeof payload.size !== 'number' || payload.size > MAX_FILE_SIZE) {
            socket.emit('file_decline', { recipientId: senderId, transferId });
            return;
        }

        state.fileTransfers[transferId] = {
            role: 'receiver', peerId: senderId, peerNick,
            pendingOffer: payload, pendingCandidates: [],
            pc: null, channel: null, historyRef: null, completed: false
        };

        incomingFileText.textContent = `${peerNick} wants to send you "${payload.name}" (${formatFileSize(payload.size)})`;
        incomingFileModal.dataset.transferId = transferId;
        showModal(incomingFileModal);
        notify(`Incoming file from ${peerNick}`, 'Tap to open abyss', 'abyss-file');
    });

    socket.on('file_answer', async ({ senderId, transferId, answer, timestamp, signature }) => {
        const t = state.fileTransfers[transferId];
        if (!t || t.role !== 'sender' || t.peerId !== senderId) return;

        const authentic = await verifyIncomingMessage(t.peerNick, `${timestamp}:${answer}`, signature);
        if (!authentic) { failTransfer(transferId, 'Could not verify the response to this file transfer.'); return; }

        try {
            const answerJson = JSON.parse(await hybridDecrypt(state.keys.privateKey, answer));
            await t.pc.setRemoteDescription(answerJson);
            await flushFileCandidates(transferId);
        } catch (err) {
            console.error('File answer handling error:', err);
            failTransfer(transferId, 'Could not complete the connection for this transfer.');
        }
    });

    socket.on('file_ice_candidate', async ({ senderId, transferId, candidate }) => {
        const t = state.fileTransfers[transferId];
        if (!t || t.peerId !== senderId) return;

        let parsed;
        try {
            parsed = JSON.parse(await hybridDecrypt(state.keys.privateKey, candidate));
        } catch (err) { console.error('File ICE decrypt error:', err); return; }

        if (t.pc && t.pc.remoteDescription) {
            try { await t.pc.addIceCandidate(parsed); } catch (err) { console.error('File ICE add error:', err); }
        } else {
            if (!t.pendingCandidates) t.pendingCandidates = [];
            t.pendingCandidates.push(parsed);
        }
    });

    socket.on('file_declined', ({ senderId, transferId }) => {
        const t = state.fileTransfers[transferId];
        if (!t || t.peerId !== senderId) return;
        if (t.historyRef) { t.historyRef.status = 'declined'; refreshFileBubble(transferId); }
        cleanupTransferConnection(transferId);
    });

    socket.on('file_canceled', ({ senderId, transferId }) => {
        const t = state.fileTransfers[transferId];
        if (!t || t.peerId !== senderId) return;
        if (t.historyRef) { t.historyRef.status = 'canceled'; refreshFileBubble(transferId); }
        cleanupTransferConnection(transferId);
        if (incomingFileModal.dataset.transferId === transferId) hideModal(incomingFileModal);
    });

    socket.on('disconnect', (reason) => {
        if (!hasJoinedOnce) {
            // Dropped before we ever successfully joined (e.g. mid
            // handshake) - nothing meaningful to preserve, a clean reload
            // is the simplest correct recovery.
            location.reload();
            return;
        }

        // Any in-progress call cannot continue without the signaling
        // channel - WebRTC media is peer-to-peer, but hangup, ICE
        // renegotiation, and the peer's own disconnect notification all
        // need it. Resetting cleanly here (rather than leaving the UI
        // "stuck" showing an in-call state) matches how every other call
        // failure path in this app already behaves.
        if (state.call.status !== 'idle') {
            resetCall('Connection lost - call ended.', 'failed');
        }

        if (reason === 'io server disconnect') {
            // The server deliberately disconnected us (a kick, the IP cap,
            // etc.) - Socket.IO will NOT auto-reconnect after this, by
            // design, so there's nothing to wait for. The 'kicked' handler
            // already explained why, if applicable.
            location.reload();
            return;
        }

        // Everything else (transport close, ping timeout, a real network
        // blip) - Socket.IO will automatically retry the connection on its
        // own. Stay right here: chat history, tabs, and identity all live
        // in memory/IndexedDB and were never tied to this socket.
        setOffline(true);
        setConnectionBanner('Connection lost - reconnecting…', 'reconnecting');
    });
});
