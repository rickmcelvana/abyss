// Phase 7 unit test: confirms the browser-side signing path (simulated here
// with Node's webcrypto, which implements the identical W3C Web Crypto API)
// produces signatures that verifyIdentitySignature() actually accepts - the
// classic bug here is a raw-vs-DER signature encoding mismatch between
// SubtleCrypto.sign() and Node's crypto.verify().
const { webcrypto } = require("crypto");
const nodeCrypto = require("crypto");
const subtle = webcrypto.subtle;

// --- Reimplementation under test (must match server.js exactly) ---
function verifyIdentitySignature(nonce, sessionPublicKeyB64, identityKeyB64, signatureB64) {
    try {
        const identityKeyObj = nodeCrypto.createPublicKey({
            key: Buffer.from(identityKeyB64, 'base64'),
            format: 'der',
            type: 'spki'
        });
        const message = `${nonce}:${sessionPublicKeyB64}`;
        const verifier = nodeCrypto.createVerify('SHA256');
        verifier.update(message);
        verifier.end();
        return verifier.verify(
            { key: identityKeyObj, dsaEncoding: 'ieee-p1363' },
            Buffer.from(signatureB64, 'base64')
        );
    } catch (err) {
        return false;
    }
}

function bufToB64(buf) {
    return Buffer.from(buf).toString('base64');
}

let failures = 0;
function check(label, cond) {
    console.log(`${cond ? 'PASS' : 'FAIL'} - ${label}`);
    if (!cond) failures++;
}

(async () => {
    // Simulates exactly what client.js does: generateKey -> exportKey('spki')
    // -> sign() over "<nonce>:<sessionPublicKey>"
    const identity = await subtle.generateKey(
        { name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify']
    );
    const identityKeyB64 = bufToB64(await subtle.exportKey('spki', identity.publicKey));
    const sessionPublicKeyB64 = "fake-rsa-session-key-base64==="; // stand-in for the real RSA-OAEP export
    const nonce = "server-issued-nonce-abc123";

    async function sign(msg) {
        const sig = await subtle.sign(
            { name: 'ECDSA', hash: 'SHA-256' },
            identity.privateKey,
            new TextEncoder().encode(msg)
        );
        return bufToB64(sig);
    }

    // Test 1: a genuine signature over the real message verifies
    {
        const signature = await sign(`${nonce}:${sessionPublicKeyB64}`);
        check("genuine signature verifies", verifyIdentitySignature(nonce, sessionPublicKeyB64, identityKeyB64, signature));
    }

    // Test 2: signature over the WRONG session key fails (binding actually matters)
    {
        const signature = await sign(`${nonce}:${sessionPublicKeyB64}`);
        check("signature rejected for a different session key",
            !verifyIdentitySignature(nonce, "different-session-key", identityKeyB64, signature));
    }

    // Test 3: replaying a signature from a different nonce fails
    {
        const signature = await sign(`old-nonce:${sessionPublicKeyB64}`);
        check("signature rejected when nonce doesn't match (anti-replay)",
            !verifyIdentitySignature(nonce, sessionPublicKeyB64, identityKeyB64, signature));
    }

    // Test 4: a signature from a DIFFERENT identity key is rejected (can't
    // present someone else's public key without owning the matching private key)
    {
        const otherIdentity = await subtle.generateKey(
            { name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify']
        );
        const signature = await sign(`${nonce}:${sessionPublicKeyB64}`); // signed with the WRONG key on purpose... 
        // actually sign with otherIdentity's private key but claim identityKeyB64 (the first identity's public key)
        const otherSigRaw = await subtle.sign(
            { name: 'ECDSA', hash: 'SHA-256' }, otherIdentity.privateKey,
            new TextEncoder().encode(`${nonce}:${sessionPublicKeyB64}`)
        );
        const otherSig = bufToB64(otherSigRaw);
        check("signature from a different private key is rejected",
            !verifyIdentitySignature(nonce, sessionPublicKeyB64, identityKeyB64, otherSig));
    }

    // Test 5: malformed inputs don't crash the verifier, just fail closed
    {
        check("garbage identity key fails closed, no throw",
            verifyIdentitySignature(nonce, sessionPublicKeyB64, "not-a-real-key", "not-a-real-sig") === false);
        check("empty signature fails closed, no throw",
            verifyIdentitySignature(nonce, sessionPublicKeyB64, identityKeyB64, "") === false);
    }

    // Test 6: fingerprint stability - same public key bytes always hash the same
    // (sanity check for the client-side pinning logic, computed the same way)
    {
        const raw = Buffer.from(identityKeyB64, 'base64');
        const h1 = nodeCrypto.createHash('sha256').update(raw).digest('hex');
        const h2 = nodeCrypto.createHash('sha256').update(raw).digest('hex');
        check("fingerprint hashing is deterministic", h1 === h2 && h1.length === 64);
    }

    console.log(failures === 0 ? "\nAll identity crypto tests passed." : `\n${failures} test(s) FAILED.`);
    process.exit(failures === 0 ? 0 : 1);
})();
