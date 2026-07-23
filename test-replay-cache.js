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
    await new Promise((resolve) => {
        s.once("joined_success", () => resolve());
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
    } catch (err) {
        console.error("Test error:", err);
        failures++;
    } finally {
        serverProc.kill();
    }

    console.log(failures === 0 ? "\nAll replay cache tests passed." : `\n${failures} test(s) failed.`);
    process.exit(failures === 0 ? 0 : 1);
})();
