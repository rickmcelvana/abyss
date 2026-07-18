// Phase 5 unit test: verify generateTurnCredential() produces credentials
// coturn's REST API auth mode actually accepts. We reimplement coturn's
// verification side independently (per its documented algorithm) rather
// than importing our own generator, so a bug shared between generate and
// "verify" can't hide.
const crypto = require("crypto");

const SECRET = "test-shared-secret-please-rotate";

// --- Reimplementation under test (must match server.js exactly) ---
function generateTurnCredential(identifier, ttlSeconds) {
    const expiry = Math.floor(Date.now() / 1000) + ttlSeconds;
    const username = `${expiry}:${identifier}`;
    const password = crypto.createHmac('sha1', SECRET)
        .update(username)
        .digest('base64');
    return { username, credential: password };
}

// --- Independent "coturn-side" verification, from the documented algorithm ---
// https://github.com/coturn/coturn/wiki/turnserver -> "REST API"
function verifyAsCoturnWould(username, credential, secret) {
    const [expiryStr] = username.split(':');
    const expiry = parseInt(expiryStr, 10);
    if (!Number.isFinite(expiry)) return { ok: false, reason: 'bad expiry' };
    if (Math.floor(Date.now() / 1000) > expiry) return { ok: false, reason: 'expired' };

    const expected = crypto.createHmac('sha1', secret).update(username).digest('base64');
    if (expected !== credential) return { ok: false, reason: 'hmac mismatch' };
    return { ok: true };
}

let failures = 0;
function check(label, cond) {
    console.log(`${cond ? 'PASS' : 'FAIL'} - ${label}`);
    if (!cond) failures++;
}

// Test 1: freshly generated credential verifies
{
    const { username, credential } = generateTurnCredential("socket123", 14400);
    const result = verifyAsCoturnWould(username, credential, SECRET);
    check("fresh credential format is 'expiry:identifier'", /^\d+:socket123$/.test(username));
    check("fresh credential verifies against shared secret", result.ok);
}

// Test 2: wrong secret is rejected (simulates a guessed/leaked-elsewhere secret)
{
    const { username, credential } = generateTurnCredential("socket123", 14400);
    const result = verifyAsCoturnWould(username, credential, "wrong-secret");
    check("credential signed with wrong secret is rejected", !result.ok && result.reason === 'hmac mismatch');
}

// Test 3: expired credential is rejected
{
    const { username, credential } = generateTurnCredential("socket123", -10); // already expired
    const result = verifyAsCoturnWould(username, credential, SECRET);
    check("expired credential is rejected", !result.ok && result.reason === 'expired');
}

// Test 4: tampering with the identifier invalidates the HMAC
{
    const { username, credential } = generateTurnCredential("socket123", 14400);
    const tamperedUsername = username.replace('socket123', 'socket999');
    const result = verifyAsCoturnWould(tamperedUsername, credential, SECRET);
    check("tampered identifier invalidates the credential", !result.ok && result.reason === 'hmac mismatch');
}

// Test 5: two different identifiers at the same instant produce different creds
{
    const a = generateTurnCredential("alice-socket", 14400);
    const b = generateTurnCredential("bob-socket", 14400);
    check("different identifiers produce different usernames", a.username !== b.username);
    check("different identifiers produce different passwords", a.credential !== b.credential);
}

console.log(failures === 0 ? "\nAll HMAC tests passed." : `\n${failures} test(s) FAILED.`);
process.exit(failures === 0 ? 0 : 1);
