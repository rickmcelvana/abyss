// Replay cache test: verifies that a re-emitted signed message is rejected
// by the server's replay cache within the timestamp skew window.
//
// Requires socket.io-client. Run with a server on port 3098:
//   node test-replay-cache.js
// (spawns its own server subprocess, same pattern as test-access-control.js)
const { spawn } = require("child_process");
const path = require("path");
const { io } = require("socket.io-client");
const { webcrypto } = require("crypto");
const subtle = webcrypto.subtle;

const PORT = 3098;
const URL = `http://127.0.0.1:${PORT}`;
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

function connectRaw() {
    const s = io(URL, { transports: ["websocket"] });
    return new Promise((resolve) => {
        let nonce = null, passwordRequired = null;
        const maybeResolve = () => { if (nonce !== null && passwordRequired !== null) resolve({ s, nonce, passwordRequired }); };
        s.once("join_nonce", (n) => { nonce = n; maybeResolve(); });
        s.once("room_info", (info) => { passwordRequired = info.passwordRequired; maybeResolve(); });
    });
}

async function joinWith(nick) {
    const { s, nonce } = await connectRaw();
    const identity = await generateIdentity();
    const identityKeyB64 = await exportSpkiB64(identity.publicKey);
    const sessionPublicKey = "x";
    const signature = await signString(identity.privateKey, `${nonce}:${sessionPublicKey}`);
    s.identity = identity;
    await new Promise((resolve, reject) => {
        const errTimer = setTimeout(() => reject(new Error(`join timed out for nick "${nick}"`)), 5000);
        s.once("error", (e) => { clearTimeout(errTimer); reject(new Error(`join rejected for "${nick}": ${e}`)); });
        s.once("joined_success", () => { clearTimeout(errTimer); resolve(); });
        s.emit("join", { nick, about: "x", publicKey: sessionPublicKey, identityKey: identityKeyB64, signature, password: "" });
    });
    return s;
}

let failures = 0;
function check(label, cond) {
    console.log(`${cond ? 'PASS' : 'FAIL'} - ${label}`);
    if (!cond) failures++;
}

(async () => {
    console.log(`Starting isolated server on port ${PORT}...`);
    const serverProc = spawn(
        "node", ["server.js"],
        { cwd: path.join(__dirname), env: { ...process.env, PORT: String(PORT) }, stdio: ["ignore", "pipe", "pipe"] }
    );
    let serverLog = "";
    serverProc.stdout.on("data", (d) => { serverLog += d.toString(); });
    serverProc.stderr.on("data", (d) => { serverLog += d.toString(); });
    await wait(1500);

    try {
        // Join a sender and a receiver
        const sender = await joinWith("replay-sender");
        const receiver = await joinWith("replay-recv");

        // Listen for public messages on the receiver
        let recvCount = 0;
        receiver.on("public_message", () => { recvCount++; });

        // Send one signed message
        const timestamp = Date.now();
        const content = "test-replay-message";
        const signature = await signString(sender.identity.privateKey, `${timestamp}:${content}`);
        sender.emit("message", { content, isPrivate: false, timestamp, signature });

        await wait(500);
        check("first send was received", recvCount === 1);

        // Replay the exact same signed message
        sender.emit("message", { content, isPrivate: false, timestamp, signature });
        await wait(500);
        check("replayed message was NOT received (dropped by replay cache)", recvCount === 1);

        // Send a different message - should pass
        const timestamp2 = Date.now();
        const content2 = "test-replay-message-2";
        const signature2 = await signString(sender.identity.privateKey, `${timestamp2}:${content2}`);
        sender.emit("message", { content: content2, isPrivate: false, timestamp: timestamp2, signature: signature2 });
        await wait(500);
        check("second unique message was received", recvCount === 2);

        sender.disconnect();
        receiver.disconnect();

        // --- Cross-socket replay regression (H1) ---
        // The replay cache is keyed on the identity fingerprint, not the
        // socket id. A signature produced by one socket of an identity must
        // still be rejected when replayed from a *different* socket of that
        // same identity (e.g. a second tab, or an attacker who captured a
        // signed payload and re-emits it). Before the fix this passed because
        // the second socket had an empty cache entry.
        const senderA = await joinWith("rcs-a");
        const crossReceiver = await joinWith("rcr");
        let crossRecvCount = 0;
        crossReceiver.on("public_message", () => { crossRecvCount++; });

        // Socket A sends one signed message.
        const tsA = Date.now();
        const msgA = "cross-socket-replay-msg";
        const sigA = await signString(senderA.identity.privateKey, `${tsA}:${msgA}`);
        senderA.emit("message", { content: msgA, isPrivate: false, timestamp: tsA, signature: sigA });
        await wait(500);
        check("cross-socket: first send from socket A was received", crossRecvCount === 1);

        // Open a SECOND socket under the SAME identity key, join as a
        // different nick (allowed - the binding is nick->fingerprint, and a
        // fingerprint may use multiple nicks across sockets).
        const { s: secondSock, nonce: nonceB } = await connectRaw();
        const sameIdentityKeyB64 = await exportSpkiB64(senderA.identity.publicKey);
        const sigJoinB = await signString(senderA.identity.privateKey, `${nonceB}:x`);
        await new Promise((resolve, reject) => {
            secondSock.once("error", (e) => reject(new Error("second socket join failed: " + e)));
            secondSock.once("joined_success", () => resolve());
            secondSock.emit("join", { nick: "rcs-b", about: "x", publicKey: "x", identityKey: sameIdentityKeyB64, signature: sigJoinB, password: "" });
        });
        await wait(200);

        // Socket B replays the EXACT payload socket A already sent. The
        // fingerprint-keyed cache must reject it.
        secondSock.emit("message", { content: msgA, isPrivate: false, timestamp: tsA, signature: sigA });
        await wait(500);
        check("cross-socket: replayed signature from a different socket of the same identity was rejected", crossRecvCount === 1);

        // A genuinely new message from socket B must still go through.
        const tsB = Date.now();
        const msgB = "cross-socket-unique-msg";
        const sigB = await signString(senderA.identity.privateKey, `${tsB}:${msgB}`);
        secondSock.emit("message", { content: msgB, isPrivate: false, timestamp: tsB, signature: sigB });
        await wait(500);
        check("cross-socket: a fresh message from socket B was received", crossRecvCount === 2);

        senderA.disconnect();
        secondSock.disconnect();
        crossReceiver.disconnect();
    } catch (err) {
        console.error("Test error:", err);
        failures++;
    } finally {
        serverProc.kill();
    }

    console.log(failures === 0 ? "\nAll replay cache tests passed." : `\n${failures} test(s) failed.`);
    process.exit(failures === 0 ? 0 : 1);
})();
