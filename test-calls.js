// Phase 1 signaling test: join, call, ring, accept/decline, busy, hangup, disconnect
const { io } = require("socket.io-client");
const { webcrypto } = require("crypto");
const subtle = webcrypto.subtle;
const URL = "http://127.0.0.1:3000";
const RING_TIMEOUT_MS = parseInt(process.env.RING_TIMEOUT_MS, 10) || 30000;

const log = (who, msg) => console.log(`[${who}] ${msg}`);
const wait = (ms) => new Promise(r => setTimeout(r, ms));

function bufToB64(buf) { return Buffer.from(buf).toString('base64'); }

async function generateIdentity() {
    return subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify']);
}
async function exportSpkiB64(pubKey) {
    return bufToB64(await subtle.exportKey('spki', pubKey));
}
async function signString(privateKey, message) {
    const sig = await subtle.sign(
        { name: 'ECDSA', hash: 'SHA-256' }, privateKey,
        new TextEncoder().encode(message)
    );
    return bufToB64(sig);
}
async function signJoin(privateKey, nonce, sessionPublicKeyB64) {
    return signString(privateKey, `${nonce}:${sessionPublicKeyB64}`);
}

/**
 * Real Phase 7 join flow: wait for the server's nonce, sign it with a fresh
 * ECDSA identity (mirroring what client.js does with its persisted key),
 * and send it along. `mutate` lets individual tests deliberately corrupt
 * the payload to exercise the server's rejection paths.
 */
function makeClient(nick, mutate) {
    const s = io(URL, { transports: ["websocket"] });
    s.nick = nick;

    // Attach this BEFORE any await - the server sends join_nonce immediately
    // on connect, and if identity generation (async) delays attaching a
    // listener, the event fires with nobody listening and is lost.
    const nonceReceived = new Promise((resolve) => s.once("join_nonce", resolve));

    return new Promise((resolve) => {
        s.on("connect", async () => {
            const [identity, nonce] = await Promise.all([generateIdentity(), nonceReceived]);
            s.identity = identity;
            s.identityKeyB64 = await exportSpkiB64(identity.publicKey);
            s.joinNonce = nonce;

            const sessionPublicKey = "x"; // stand-in RSA session key, as before
            let signature = await signJoin(identity.privateKey, nonce, sessionPublicKey);
            let payload = { nick, about: "tester", publicKey: sessionPublicKey, identityKey: s.identityKeyB64, signature };
            if (mutate) payload = mutate(payload, { nonce, identity });
            s.emit("join", payload);
        });
        s.on("joined_success", () => { log(nick, "joined"); resolve(s); });
        s.on("error", (m) => {
            log(nick, `join error: ${m}`);
            if (mutate) { s.disconnect(); resolve(s); } // expected for negative tests - don't leak the connection
        });
        s.on("call_error", (m) => log(nick, `call_error: ${m}`));
        s.on("call_declined", () => log(nick, "call_declined"));
        s.on("call_ended", () => log(nick, "call_ended"));
        s.on("incoming_call", ({ senderId }) => {
            log(nick, `incoming_call from ${senderId}`);
            s.lastCaller = senderId;
        });
        s.on("call_accepted", () => log(nick, "call_accepted"));
    });
}

/**
 * Like makeClient, but takes a specific identity keypair instead of
 * generating one - needed to test "same person reconnecting" (same
 * identity, new socket) vs. "someone else trying to use your nick"
 * (different identity, same nick).
 */
function joinRaw(nick, identity) {
    return new Promise((resolve) => {
        const s = io(URL, { transports: ["websocket"] });
        const nonceReceived = new Promise((res) => s.once("join_nonce", res));
        s.on("connect", async () => {
            const nonce = await nonceReceived;
            const identityKeyB64 = await exportSpkiB64(identity.publicKey);
            const sessionPublicKey = "x";
            const signature = await signJoin(identity.privateKey, nonce, sessionPublicKey);
            s.emit("join", { nick, about: "x", publicKey: sessionPublicKey, identityKey: identityKeyB64, signature });
        });
        s.on("joined_success", () => resolve({ s, outcome: "joined" }));
        s.on("error", (m) => resolve({ s, outcome: "error", message: m }));
        s.on("nick_taken", () => resolve({ s, outcome: "nick_taken" }));
        setTimeout(() => resolve({ s, outcome: "timeout" }), 2000);
    });
}

(async () => {
    // --- Phase 5: ICE config gating ---
    console.log("--- Test 0a: REST /api/ice-config is STUN-only (no TURN, even if configured) ---");
    const restCfg = await fetch(URL + "/api/ice-config").then(r => r.json());
    const restHasTurn = restCfg.iceServers.some(s => String(s.urls).startsWith("turn:"));
    console.log(`REST response: ${JSON.stringify(restCfg)}`);
    console.log(`REST leaks TURN: ${restHasTurn} (expect false)`);

    console.log("\n--- Test 0b: get_ice_config before join gets STUN only ---");
    const preJoin = await new Promise((resolve) => {
        const s = io(URL, { transports: ["websocket"] });
        s.on("connect", () => {
            s.emit("get_ice_config", (cfg) => { resolve(cfg); s.disconnect(); });
        });
    });
    const preJoinHasTurn = preJoin.iceServers.some(s => String(s.urls).startsWith("turn:"));
    console.log(`Pre-join response: ${JSON.stringify(preJoin)}`);
    console.log(`Pre-join leaks TURN: ${preJoinHasTurn} (expect false)`);

    console.log("\n--- Test 0c: get_ice_config after join (TURN appears only if TURN_URL/TURN_SECRET are set) ---");
    const alice = await makeClient("alice");
    const postJoin = await new Promise((resolve) => {
        alice.emit("get_ice_config", resolve);
    });
    console.log(`Post-join response: ${JSON.stringify(postJoin)}`);
    const postJoinTurn = postJoin.iceServers.find(s => String(s.urls).startsWith("turn:"));
    if (postJoinTurn) {
        console.log(`TURN credential present: username="${postJoinTurn.username}"`);
        console.log(`username matches "<expiry>:<socketId>" pattern: ${new RegExp(`^\\d+:${alice.id}$`).test(postJoinTurn.username)}`);
    } else {
        console.log("No TURN_URL/TURN_SECRET configured in this environment - STUN-only response is correct.");
    }

    console.log("\n--- Test 0d: malformed get_ice_config call (no callback) doesn't crash the server ---");
    alice.emit("get_ice_config"); // no ack fn at all
    await wait(300);
    const stillAlive = await fetch(URL + "/api/ice-config").then(r => r.ok).catch(() => false);
    console.log(`server still responding after malformed call: ${stillAlive}`);

    console.log("\n--- Test 0e: Phase 7 - join with missing identity fields is rejected ---");
    await new Promise((resolve) => {
        const s = io(URL, { transports: ["websocket"] });
        s.once("join_nonce", () => {
            s.emit("join", { nick: "no-identity-guy", about: "x", publicKey: "y" }); // no identityKey/signature at all
        });
        s.on("error", (m) => { log("no-identity-guy", `rejected as expected: ${m}`); s.disconnect(); resolve(); });
        s.on("joined_success", () => { log("no-identity-guy", "UNEXPECTED: joined without identity!"); s.disconnect(); resolve(); });
        setTimeout(resolve, 2000);
    });

    console.log("\n--- Test 0f: Phase 7 - join with a bad signature is rejected ---");
    await makeClient("bad-sig-guy", (payload) => ({ ...payload, signature: btoa("not-a-real-signature") }));

    console.log("\n--- Test 0g: Phase 7 - signature replayed from a stale nonce is rejected ---");
    await new Promise((resolve) => {
        const s = io(URL, { transports: ["websocket"] });
        const nonceReceived = new Promise((res) => s.once("join_nonce", res));
        (async () => {
            const [identity, nonce] = await Promise.all([generateIdentity(), nonceReceived]);
            const identityKeyB64 = await exportSpkiB64(identity.publicKey);
            // Sign a DIFFERENT (stale/made-up) nonce than the one just issued
            const staleSignature = await signJoin(identity.privateKey, "some-old-stale-nonce", "x");
            s.emit("join", { nick: "replay-guy", about: "x", publicKey: "x", identityKey: identityKeyB64, signature: staleSignature });
        })();
        s.on("error", (m) => { log("replay-guy", `rejected as expected: ${m}`); s.disconnect(); resolve(); });
        s.on("joined_success", () => { log("replay-guy", "UNEXPECTED: joined with a stale-nonce signature!"); s.disconnect(); resolve(); });
        setTimeout(resolve, 2000);
    });

    console.log("\n--- Test 0h: Phase 7 - legitimate signed join succeeds ---");
    const legit = await makeClient("legit-guy");
    legit.disconnect();

    console.log("\n--- Test 0m: Phase 2 (second hardening round) - nick-to-identity binding ---");
    {
        const identityA = await generateIdentity();
        const nickToTest = "bindtest"; // must stay <= 15 chars

        const first = await joinRaw(nickToTest, identityA);
        console.log(`first join with identity A: ${first.outcome}`);
        first.s.disconnect();
        await wait(300); // let the disconnect land server-side before reconnecting

        // Same identity reconnecting under the same nick - reclaiming your
        // own nick after a disconnect must still work
        const reclaim = await joinRaw(nickToTest, identityA);
        console.log(`identity A reclaims "${nickToTest}" after disconnect: ${reclaim.outcome}`);
        reclaim.s.disconnect();
        await wait(300);

        // A different identity trying to take the now-vacated nick
        const identityB = await generateIdentity();
        const impostor = await joinRaw(nickToTest, identityB);
        console.log(`identity B tries "${nickToTest}": ${impostor.outcome} ${impostor.message || ''}`);
        impostor.s.disconnect();

        const bindingEnforced = first.outcome === "joined" &&
            reclaim.outcome === "joined" &&
            impostor.outcome === "error" &&
            /different identity/i.test(impostor.message || "");
        console.log(`nick binding correctly enforced: ${bindingEnforced}`);

        // An unrelated nick with a fresh identity should be completely unaffected
        const unrelated = await joinRaw("unrelated1", await generateIdentity());
        console.log(`unrelated nick unaffected: ${unrelated.outcome === "joined"}`);
        unrelated.s.disconnect();
        await wait(300);
    }

    const bob = await makeClient("bob");
    const carol = await makeClient("carol");
    await wait(300);

    console.log("\n--- Test 0i: message signing - valid signed public message relays ---");
    {
        const received = new Promise((resolve) => bob.once("public_message", resolve));
        const timestamp = Date.now();
        const content = "hello from alice, signed";
        const signature = await signString(alice.identity.privateKey, `${timestamp}:${content}`);
        alice.emit("message", { content, isPrivate: false, timestamp, signature });
        const data = await Promise.race([received, wait(1000).then(() => null)]);
        console.log(`bob received: ${JSON.stringify(data)}`);
        console.log(`relayed correctly: ${data && data.content === content && data.nick === "alice"}`);
    }

    console.log("\n--- Test 0j: message signing - bad signature is dropped, not relayed ---");
    {
        let gotIt = false;
        const watcher = (d) => { if (d.content === "forged content") gotIt = true; };
        bob.on("public_message", watcher);
        alice.emit("message", {
            content: "forged content", isPrivate: false,
            timestamp: Date.now(), signature: btoa("not-a-real-signature")
        });
        await wait(500);
        bob.off("public_message", watcher);
        console.log(`forged message was NOT relayed: ${!gotIt}`);
    }

    console.log("\n--- Test 0k: message signing - content tampered after signing is dropped ---");
    {
        let gotIt = false;
        const watcher = (d) => { if (d.content === "tampered content") gotIt = true; };
        bob.on("public_message", watcher);
        const timestamp = Date.now();
        // Sign one string, send DIFFERENT content - simulates a MITM/relay
        // trying to alter the message after the fact
        const signature = await signString(alice.identity.privateKey, `${timestamp}:original content`);
        alice.emit("message", { content: "tampered content", isPrivate: false, timestamp, signature });
        await wait(500);
        bob.off("public_message", watcher);
        console.log(`tampered message was NOT relayed: ${!gotIt}`);
    }

    console.log("\n--- Test 0l: message signing - stale timestamp (replay) is dropped ---");
    {
        let gotIt = false;
        const watcher = (d) => { if (d.content === "old message") gotIt = true; };
        bob.on("public_message", watcher);
        const staleTimestamp = Date.now() - (10 * 60 * 1000); // 10 minutes old
        const signature = await signString(alice.identity.privateKey, `${staleTimestamp}:old message`);
        alice.emit("message", { content: "old message", isPrivate: false, timestamp: staleTimestamp, signature });
        await wait(500);
        bob.off("public_message", watcher);
        console.log(`stale-timestamp message was NOT relayed: ${!gotIt}`);
    }

    console.log("\n--- Test 1: alice calls bob, bob declines ---");
    alice.emit("call_user", { recipientId: bob.id, offer: "enc-offer-blob" });
    await wait(300);
    bob.emit("decline_call", { recipientId: bob.lastCaller });
    await wait(300);

    console.log("\n--- Test 2: alice calls bob, bob accepts ---");
    alice.emit("call_user", { recipientId: bob.id, offer: "enc-offer-blob" });
    await wait(300);
    bob.emit("answer_call", { recipientId: bob.lastCaller, answer: "enc-answer-blob" });
    await wait(300);
    alice.emit("hangup"); // end this call before the timeout tests need a clean slate
    await wait(300);

    console.log("\n--- Test 2b: RING TIMEOUT - alice calls bob, bob never answers ---");
    let aliceTimedOut = false, bobMissed = false;
    alice.once("call_timeout", () => { aliceTimedOut = true; log("alice", "call_timeout received"); });
    bob.once("call_missed", () => { bobMissed = true; log("bob", "call_missed received"); });
    alice.emit("call_user", { recipientId: bob.id, offer: "enc-offer-blob" });
    await wait(RING_TIMEOUT_MS + 500);
    console.log(`caller got call_timeout: ${aliceTimedOut}, callee got call_missed: ${bobMissed}`);

    console.log("\n--- Test 2c: after timeout, bob is free again (not stuck busy) ---");
    let carolReachedBob = false;
    bob.once("incoming_call", () => { carolReachedBob = true; });
    carol.emit("call_user", { recipientId: bob.id, offer: "enc-offer-blob" });
    await wait(300);
    console.log(`bob reachable after timeout: ${carolReachedBob}`);
    bob.emit("decline_call", { recipientId: carol.id });
    await wait(200);

    console.log("\n--- Test 2d: answering before the timeout cancels it (no stray call_timeout) ---");
    // This leaves alice<->bob CONNECTED on purpose - Test 3 (ICE relay) reuses it.
    let strayTimeout = false;
    const timeoutWatcher = () => { strayTimeout = true; log("alice", "UNEXPECTED call_timeout after answer!"); };
    alice.on("call_timeout", timeoutWatcher);
    alice.emit("call_user", { recipientId: bob.id, offer: "enc-offer-blob" });
    await wait(200);
    bob.emit("answer_call", { recipientId: alice.id, answer: "enc-answer-blob" });
    await wait(RING_TIMEOUT_MS + 500); // wait past when the timer would have fired
    console.log(`no stray timeout after answering: ${!strayTimeout}`);
    alice.off("call_timeout", timeoutWatcher);

    console.log("\n--- Test 3: ICE relay between call peers (alice <-> bob) ---");
    let bobGotIce = false, aliceGotIce = false, bobGotForeignIce = false, bobGotBadIce = false;
    bob.on("ice_candidate", ({ senderId, candidate }) => {
        if (typeof candidate !== "string") { bobGotBadIce = true; return log("bob", "UNEXPECTED non-string candidate relayed!"); }
        if (senderId === alice.id) { bobGotIce = true; log("bob", `ice_candidate blob relayed: ${candidate}`); }
        else { bobGotForeignIce = true; log("bob", "UNEXPECTED foreign ice_candidate!"); }
    });
    alice.on("ice_candidate", ({ candidate }) => { aliceGotIce = true; log("alice", `ice_candidate blob relayed: ${candidate}`); });
    alice.emit("ice_candidate", { recipientId: bob.id, candidate: "enc-cand-a" });
    bob.emit("ice_candidate", { recipientId: alice.id, candidate: "enc-cand-b" });
    await wait(300);
    console.log(`relay a->b: ${bobGotIce}, relay b->a: ${aliceGotIce}`);

    console.log("\n--- Test 3b: carol (not in the call) sends ICE to bob (must NOT relay) ---");
    carol.emit("ice_candidate", { recipientId: bob.id, candidate: "evil-cand" });
    await wait(300);
    console.log(`foreign ICE blocked: ${!bobGotForeignIce}`);

    console.log("\n--- Test 3c: malformed payloads (must NOT relay / must error) ---");
    alice.emit("ice_candidate", { recipientId: bob.id, candidate: { object: "not-a-blob" } });
    alice.emit("ice_candidate", { recipientId: bob.id, candidate: "x".repeat(30000) });
    await wait(300);
    console.log(`malformed ICE blocked: ${!bobGotBadIce}`);
    carol.emit("call_user", { recipientId: alice.id, offer: { object: "not-a-blob" } });
    await wait(300); // expect carol call_error: Malformed call payload

    console.log("\n--- Test 4: carol calls busy bob (expect busy error) ---");
    carol.emit("call_user", { recipientId: bob.id, offer: "enc-offer-blob" });
    await wait(300);

    console.log("\n--- Test 4: alice tries a second call while in one (expect error) ---");
    alice.emit("call_user", { recipientId: carol.id, offer: "enc-offer-blob" });
    await wait(300);

    console.log("\n--- Test 5: alice hangs up (bob should get call_ended) ---");
    alice.emit("hangup");
    await wait(300);

    console.log("\n--- Test 6: carol calls alice, then carol disconnects mid-ring ---");
    carol.emit("call_user", { recipientId: alice.id, offer: "enc-offer-blob" });
    await wait(300);
    carol.disconnect();
    await wait(300);

    console.log("\n--- Test 6b: GLARE - alice and bob call each other simultaneously ---");
    const glareIncoming = [];
    let alreadyErrors = 0;
    const countBusy = (m) => { if (String(m).includes("already in a call")) alreadyErrors++; };
    alice.on("call_error", countBusy);
    bob.on("call_error", countBusy);
    alice.once("incoming_call", () => glareIncoming.push("alice"));
    bob.once("incoming_call", () => glareIncoming.push("bob"));
    alice.emit("call_user", { recipientId: bob.id, offer: "enc-offer-blob" });
    bob.emit("call_user", { recipientId: alice.id, offer: "enc-offer-blob" });
    await wait(400);
    console.log(`incoming_call went to: [${glareIncoming.join(", ")}] | busy errors: ${alreadyErrors}`);
    console.log(`glare OK: ${glareIncoming.length === 1 && alreadyErrors === 0}`);
    // Clean up: whoever got the offer declines it
    const receiver = glareIncoming[0] === "alice" ? alice : bob;
    receiver.emit("decline_call", { recipientId: receiver.lastCaller });
    await wait(300);

    console.log("\n--- Test 7: alice calls herself (expect error) ---");
    // Use a fresh client rather than alice - by this point in the suite
    // alice has made several call_user attempts already, and depending on
    // exact timing that can trip the call rate limiter first, masking the
    // self-call check this test actually wants to exercise.
    const selfCaller = await makeClient("self-caller");
    selfCaller.emit("call_user", { recipientId: selfCaller.id, offer: "enc-offer-blob" });
    await wait(300);
    selfCaller.disconnect();

    console.log("\n--- Test 8: spoof check - bob sends message with fake senderId field ---");
    alice.on("public_message", (d) => log("alice", `public_message from nick="${d.nick}"`));
    bob.emit("message", { senderId: alice.id, content: "hi", isPrivate: false });
    await wait(300);

    console.log("\nAll tests complete.");
    process.exit(0);
})();
