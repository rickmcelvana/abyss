// L3 regression test: the nickBindings FIFO cap must NEVER evict a binding
// for a nick that is currently in use (nicksInUse) by an active user. The
// old code evicted the single oldest entry unconditionally; under a churn
// flood that oldest entry could be a live user's nick, freeing it for
// takeover by a different identity.
//
// Strategy: run an isolated server with a tiny MAX_NICK_BINDINGS (5) and
// generous per-IP caps so the test can open many short-lived sockets.
//   1. Join a "target" user and KEEP its socket open - its nick is in
//      nicksInUse for the whole test, so its binding must never be evicted.
//   2. Churn-join 6 other nicks (each join then disconnect) so 6 bindings
//      accumulate while only "target" stays in use. After the 6th join the
//      map exceeds MAX_NICK_BINDINGS=5 and eviction runs.
//   3. Verify a DIFFERENT identity cannot claim "target" (binding survived)
//      and CAN claim one of the churned nicks (something WAS evicted to make
//      room - proving we didn't just disable eviction entirely).
//
// Requires its own server subprocess because MAX_NICK_BINDINGS is not
// something the shared test-calls.js server is configured for.
const { spawn } = require("child_process");
const path = require("path");
const { io } = require("socket.io-client");
const { webcrypto } = require("crypto");
const subtle = webcrypto.subtle;

const PORT = 3098;
const URL = `http://127.0.0.1:${PORT}`;
const NICK_CAP = 5;          // MAX_NICK_BINDINGS for this run
const IP_CAP = 40;           // allow many concurrent/sequential test sockets
const CONNECT_RATE = 100;    // allow the burst of churn joins

const wait = (ms) => new Promise(r => setTimeout(r, ms));
const bufToB64 = (buf) => Buffer.from(buf).toString('base64');

async function generateIdentity() {
    return subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify']);
}
async function generateSessionPublicKeyB64() {
    const pair = await subtle.generateKey(
        { name: 'RSA-OAEP', modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: 'SHA-256' },
        true, ['encrypt', 'decrypt']
    );
    return bufToB64(await subtle.exportKey('spki', pair.publicKey));
}
async function exportSpkiB64(pubKey) { return bufToB64(await subtle.exportKey('spki', pubKey)); }
async function signString(privateKey, message) {
    const sig = await subtle.sign(
        { name: 'ECDSA', hash: 'SHA-256' }, privateKey,
        new TextEncoder().encode(message)
    );
    return bufToB64(sig);
}

/** Opens a bare socket and resolves once room_info + join_nonce have both arrived. */
function connectRaw() {
    const s = io(URL, { transports: ["websocket"] });
    return new Promise((resolve) => {
        let nonce = null, passwordRequired = null;
        const maybeResolve = () => { if (nonce !== null && passwordRequired !== null) resolve({ s, nonce, passwordRequired }); };
        s.once("join_nonce", (n) => { nonce = n; maybeResolve(); });
        s.once("room_info", (info) => { passwordRequired = info.passwordRequired; maybeResolve(); });
    });
}

/** Full signed join with a freshly generated identity. Resolves with outcome. */
function joinWith(nick) {
    return new Promise(async (resolve) => {
        const { s, nonce } = await connectRaw();
        const identity = await generateIdentity();
        const identityKeyB64 = await exportSpkiB64(identity.publicKey);
        const sessionPublicKey = await generateSessionPublicKeyB64();
        const signature = await signString(identity.privateKey, `${nonce}:${sessionPublicKey}`);
        s.on("joined_success", () => resolve({ s, outcome: "joined", identity, identityKeyB64 }));
        s.on("error", (m) => resolve({ s, outcome: "error", message: m }));
        s.on("nick_taken", () => resolve({ s, outcome: "nick_taken" }));
        setTimeout(() => resolve({ s, outcome: "timeout" }), 4000);
        s.emit("join", { nick, about: "x", publicKey: sessionPublicKey, identityKey: identityKeyB64, signature, password: "" });
    });
}

let failures = 0;
function check(label, cond) {
    console.log(`${cond ? 'PASS' : 'FAIL'} - ${label}`);
    if (!cond) failures++;
}

(async () => {
    console.log(`Starting isolated server on port ${PORT} (MAX_NICK_BINDINGS=${NICK_CAP}, IP cap=${IP_CAP})...`);
    const serverProc = spawn(
        "node", ["server.js"],
        {
            cwd: path.join(__dirname),
            env: {
                ...process.env,
                PORT: String(PORT),
                MAX_NICK_BINDINGS: String(NICK_CAP),
                MAX_CONNECTIONS_PER_IP: String(IP_CAP),
                MAX_CONNECT_RATE_PER_IP: String(CONNECT_RATE),
            },
            stdio: ["ignore", "pipe", "pipe"]
        }
    );
    let serverLog = "";
    serverProc.stdout.on("data", (d) => { serverLog += d.toString(); });
    serverProc.stderr.on("data", (d) => { serverLog += d.toString(); });
    await wait(1500);

    try {
        console.log("\n--- Test 1: join the target user and keep it connected ---");
        const target = await joinWith("target");
        check("target joined", target.outcome === "joined");
        if (target.outcome !== "joined") throw new Error("target failed to join - aborting");

        console.log(`\n--- Test 2: churn ${NICK_CAP + 1} other nicks (join then disconnect) to exceed the binding cap ---`);
        // The +1th join triggers eviction (map size > NICK_CAP). The first
        // churn nick is the oldest non-target entry; with the OLD FIFO logic
        // it would be evicted (fine), but if "target" were the oldest entry
        // overall it would be evicted instead. To make that explicit: we
        // join "target" first so it IS the oldest binding in the map, which is
        // exactly the case the old code got wrong.
        for (let i = 0; i < NICK_CAP + 1; i++) {
            const churn = await joinWith(`churn${i}`);
            check(`churn${i} joined (then disconnected)`, churn.outcome === "joined");
            churn.s.disconnect();
            await wait(150); // let the server process the disconnect (nicksInUse release)
        }
        // At this point nickBindings has: target (in use) + churn0..churn5 (not in use).
        // size = 7 > NICK_CAP = 5. After the final join's eviction, two non-in-use
        // entries must have been evicted (7 -> 5), and "target" must still be bound.

        console.log("\n--- Test 3: a DIFFERENT identity cannot claim the in-use 'target' nick ---");
        const thief = await joinWith("target");
        check("thief rejected (target binding survived eviction)", thief.outcome === "error" && /belongs to a different identity/i.test(thief.message));
        thief.s.disconnect();

        console.log("\n--- Test 4: an evicted churn nick CAN be re-claimed by a new identity (eviction actually happened) ---");
        // churn0 was the oldest non-target entry; the new eviction logic walks
        // from the front and evicts the first not-in-use candidate, so churn0
        // is gone. A brand-new identity claiming it must now be allowed.
        const reclaim = await joinWith("churn0");
        check("churn0 re-claimed by a new identity (proves a binding was evicted to make room)", reclaim.outcome === "joined");
        reclaim.s.disconnect();

        console.log("\n--- Test 5: target's ORIGINAL identity can still rejoin its own nick (binding intact, not corrupted) ---");
        // Re-join target using the SAME identity key as the original target.
        const rejoinSame = await new Promise(async (resolve) => {
            const { s, nonce } = await connectRaw();
            const sessionPublicKey = await generateSessionPublicKeyB64();
            const signature = await signString(target.identity.privateKey, `${nonce}:${sessionPublicKey}`);
            s.on("joined_success", () => resolve({ s, outcome: "joined" }));
            s.on("error", (m) => resolve({ s, outcome: "error", message: m }));
            s.on("nick_taken", () => resolve({ s, outcome: "nick_taken" }));
            setTimeout(() => resolve({ s, outcome: "timeout" }), 4000);
            s.emit("join", { nick: "target", about: "x", publicKey: sessionPublicKey, identityKey: target.identityKeyB64, signature, password: "" });
        });
        // nick_taken because the original target socket is still connected
        // (nicksInUse), which is the correct, pre-existing behavior - not the
        // binding check. The point is it's NOT the "belongs to a different
        // identity" error, which would mean the binding was corrupted.
        check("same-identity rejoin is blocked only by nick_taken, not by a binding mismatch", rejoinSame.outcome === "nick_taken");
        rejoinSame.s.disconnect();

        target.s.disconnect();
        await wait(300);

        console.log("\n--- Test 6: server still healthy after the churn ---");
        const alive = await fetch(`${URL}/api/ice-config`).then(r => r.ok).catch(() => false);
        check("server still responding", alive);

    } finally {
        serverProc.kill();
        await wait(300);
        if (failures > 0) {
            console.log("\n--- server log (for debugging failures) ---");
            console.log(serverLog);
        }
    }

    console.log(failures === 0 ? "\nAll L3 nick-binding eviction tests passed." : `\n${failures} test(s) FAILED.`);
    process.exit(failures === 0 ? 0 : 1);
})();