// Phase 8 test: room password / access control, per-IP connection cap, and
// per-socket rate limiting. Runs its OWN server subprocess on a separate
// port with test-friendly env vars (a real password, a low IP cap) rather
// than sharing test-calls.js's server - room password and IP-cap behavior
// can't be exercised meaningfully against the default open-room config,
// and a low IP cap would make the other suites' many parallel test sockets
// fail for an unrelated reason.
const { spawn } = require("child_process");
const path = require("path");
const { io } = require("socket.io-client");
const { webcrypto } = require("crypto");
const subtle = webcrypto.subtle;

const PORT = 3099;
const URL = `http://127.0.0.1:${PORT}`;
const ROOM_PASSWORD = "correct-horse-battery-staple";
const IP_CAP = 3;

const log = (who, msg) => console.log(`[${who}] ${msg}`);
const wait = (ms) => new Promise(r => setTimeout(r, ms));
const bufToB64 = (buf) => Buffer.from(buf).toString('base64');

async function generateIdentity() {
    return subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify']);
}
async function exportSpkiB64(pubKey) { return bufToB64(await subtle.exportKey('spki', pubKey)); }
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

/** Full signed join, real identity, given nick/password. Resolves with outcome. */
function joinWith(nick, password) {
    return new Promise(async (resolve) => {
        const { s, nonce } = await connectRaw();
        const identity = await generateIdentity();
        const identityKeyB64 = await exportSpkiB64(identity.publicKey);
        const sessionPublicKey = "x";
        const signature = await signJoin(identity.privateKey, nonce, sessionPublicKey);
        s.identity = identity; // reusable for signing further messages after join
        s.on("joined_success", () => resolve({ s, outcome: "joined" }));
        s.on("error", (m) => resolve({ s, outcome: "error", message: m }));
        s.on("kicked", (m) => resolve({ s, outcome: "kicked", message: m }));
        setTimeout(() => resolve({ s, outcome: "timeout" }), 3000);
        s.emit("join", { nick, about: "x", publicKey: sessionPublicKey, identityKey: identityKeyB64, signature, password });
    });
}

async function signMessage(privateKey, content) {
    const timestamp = Date.now();
    const signature = await signString(privateKey, `${timestamp}:${content}`);
    return { timestamp, signature };
}

let failures = 0;
function check(label, cond) {
    console.log(`${cond ? 'PASS' : 'FAIL'} - ${label}`);
    if (!cond) failures++;
}

(async () => {
    console.log(`Starting isolated server on port ${PORT} (ROOM_PASSWORD set, MAX_CONNECTIONS_PER_IP=${IP_CAP})...`);
    const serverProc = spawn(
        "node", ["server.js"],
        {
            cwd: path.join(__dirname),
            env: { ...process.env, PORT: String(PORT), ROOM_PASSWORD, MAX_CONNECTIONS_PER_IP: String(IP_CAP) },
            stdio: ["ignore", "pipe", "pipe"]
        }
    );
    let serverLog = "";
    serverProc.stdout.on("data", (d) => { serverLog += d.toString(); });
    serverProc.stderr.on("data", (d) => { serverLog += d.toString(); });
    await wait(1500); // give it time to bind

    try {
        console.log("\n--- Test 1: room_info correctly reports a password is required ---");
        const { s: probeSocket, passwordRequired } = await connectRaw();
        check("room_info.passwordRequired === true", passwordRequired === true);
        probeSocket.disconnect();

        console.log("\n--- Test 2: join with no password is rejected ---");
        const noPass = await joinWith("nopass-guy", "");
        check("rejected with 'Incorrect room password.'", noPass.outcome === "error" && /password/i.test(noPass.message));
        noPass.s.disconnect();

        console.log("\n--- Test 3: join with the WRONG password is rejected ---");
        const wrongPass = await joinWith("wrongpass-guy", "not-the-password");
        check("rejected with 'Incorrect room password.'", wrongPass.outcome === "error" && /password/i.test(wrongPass.message));
        wrongPass.s.disconnect();

        console.log("\n--- Test 4: join with the CORRECT password succeeds ---");
        const rightPass = await joinWith("rightpass-guy", ROOM_PASSWORD);
        check("joined successfully", rightPass.outcome === "joined");
        rightPass.s.disconnect();
        await wait(300);

        console.log(`\n--- Test 5: per-IP connection cap (limit ${IP_CAP}) ---`);
        const capSockets = [];
        let kickedCount = 0;
        // Open one more than the cap, sequentially so ordering is deterministic
        for (let i = 0; i < IP_CAP + 2; i++) {
            const s = io(URL, { transports: ["websocket"] });
            capSockets.push(s);
            const wasKicked = await new Promise((resolve) => {
                s.once("kicked", () => resolve(true));
                s.once("join_nonce", () => resolve(false));
                setTimeout(() => resolve(false), 1500);
            });
            if (wasKicked) kickedCount++;
            log("cap-test", `connection ${i + 1}: ${wasKicked ? "KICKED (cap hit)" : "accepted"}`);
        }
        check(`exactly ${2} connection(s) beyond the cap were kicked`, kickedCount === 2);
        capSockets.forEach(s => s.disconnect());
        await wait(500); // let the server release the slots before the next test needs them

        console.log("\n--- Test 6: join rate limit (5 attempts / 30s) ---");
        const { s: floodSocket, nonce: floodNonce } = await connectRaw();
        const joinErrors = [];
        floodSocket.on("error", (m) => joinErrors.push(m));
        for (let i = 0; i < 6; i++) {
            // Deliberately missing identityKey/signature - we only care
            // whether the RATE LIMITER fires, which happens before any of
            // that is checked, so garbage payloads are fine here.
            floodSocket.emit("join", { nick: `flood${i}`, about: "x", publicKey: "x", password: ROOM_PASSWORD });
            await wait(50);
        }
        await wait(300);
        const rateLimitErrors = joinErrors.filter(m => /too many join/i.test(m));
        const otherErrors = joinErrors.filter(m => !/too many join/i.test(m));
        console.log(`  ${otherErrors.length} normal validation errors, ${rateLimitErrors.length} rate-limit errors (expect 5 and 1)`);
        check("exactly 1 join attempt hit the rate limit", rateLimitErrors.length === 1);
        floodSocket.disconnect();
        await wait(300);

        console.log("\n--- Test 7: message rate limit (15 / 10s) doesn't break the server, excess is dropped ---");
        const sender = await joinWith("flooder", ROOM_PASSWORD);
        check("flooder joined", sender.outcome === "joined");
        let receivedCount = 0;
        sender.s.on("public_message", () => receivedCount++);
        for (let i = 0; i < 20; i++) {
            const content = `spam ${i}`;
            const { timestamp, signature } = await signMessage(sender.s.identity.privateKey, content);
            sender.s.emit("message", { content, isPrivate: false, timestamp, signature });
        }
        await wait(500);
        console.log(`  ${receivedCount} of 20 messages were relayed (expect 15, the limit)`);
        check("excess messages were silently dropped, not relayed", receivedCount === 15);

        console.log("\n--- Test 8: server survives all of the above and still answers normally ---");
        const stillAlive = await fetch(`${URL}/api/ice-config`).then(r => r.ok).catch(() => false);
        check("server still responding after the flood tests", stillAlive);
        sender.s.disconnect();
        await wait(300);

        console.log("\n--- Test 9: call_user rate limit (6 / 30s) ---");
        const caller = await joinWith("caller-guy", ROOM_PASSWORD);
        const target = await joinWith("target-guy", ROOM_PASSWORD);
        check("caller and target both joined", caller.outcome === "joined" && target.outcome === "joined");
        const callErrors = [];
        caller.s.on("call_error", (m) => callErrors.push(m));
        for (let i = 0; i < 7; i++) {
            caller.s.emit("call_user", { recipientId: target.s.id, offer: "enc-offer-blob" });
            await wait(150);
            caller.s.emit("hangup"); // cancel before the next attempt, so only the RATE LIMITER can block us, not the busy check
            await wait(150);
        }
        await wait(300);
        const callRateLimitErrors = callErrors.filter(m => /too many calls/i.test(m));
        console.log(`  call errors seen: ${JSON.stringify(callErrors)}`);
        check("exactly 1 call attempt hit the rate limit", callRateLimitErrors.length === 1);
        caller.s.disconnect();
        target.s.disconnect();

    } finally {
        serverProc.kill();
        await wait(300);
        if (failures > 0) {
            console.log("\n--- server log (for debugging failures) ---");
            console.log(serverLog);
        }
    }

    console.log(failures === 0 ? "\nAll Phase 8 hardening tests passed." : `\n${failures} test(s) FAILED.`);
    process.exit(failures === 0 ? 0 : 1);
})();
