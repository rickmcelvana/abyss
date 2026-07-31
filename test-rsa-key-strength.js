// Unit test for H3: server-side RSA session-key strength enforcement.
// Confirms isAcceptableRsaPublicKey rejects sub-2048-bit RSA keys and
// non-RSA keys, and accepts RSA-2048+. Mirrors the server's helper using
// Node's crypto (same module the server uses), so no server process needed.
//
// Run: node test-rsa-key-strength.js
const nodeCrypto = require("crypto");

const MIN_RSA_MODULUS = 2048;

// --- Reimplementation under test (must match server.js exactly) ---
function isAcceptableRsaPublicKey(publicKeyB64) {
    try {
        const keyObj = nodeCrypto.createPublicKey({
            key: Buffer.from(publicKeyB64, "base64"),
            format: "der",
            type: "spki",
        });
        if (keyObj.asymmetricKeyType !== "rsa") return false;
        return (keyObj.asymmetricKeyDetails?.modulusLength || 0) >= MIN_RSA_MODULUS;
    } catch (err) {
        return false;
    }
}

function rsaSpkiB64(bits) {
    const { publicKey } = nodeCrypto.generateKeyPairSync("rsa", {
        modulusLength: bits,
        publicKeyEncoding: { type: "spki", format: "der" },
    });
    return Buffer.from(publicKey).toString("base64");
}

function ecSpkiB64() {
    const { publicKey } = nodeCrypto.generateKeyPairSync("ec", {
        namedCurve: "P-256",
        publicKeyEncoding: { type: "spki", format: "der" },
    });
    return Buffer.from(publicKey).toString("base64");
}

let failures = 0;
function check(label, cond) {
    console.log(`${cond ? "PASS" : "FAIL"} - ${label}`);
    if (!cond) failures++;
}

(async () => {
    check("RSA-512 rejected (< 2048)", isAcceptableRsaPublicKey(rsaSpkiB64(512)) === false);
    check("RSA-1024 rejected (< 2048)", isAcceptableRsaPublicKey(rsaSpkiB64(1024)) === false);
    check("RSA-2048 accepted", isAcceptableRsaPublicKey(rsaSpkiB64(2048)) === true);
    check("RSA-3072 accepted", isAcceptableRsaPublicKey(rsaSpkiB64(3072)) === true);
    check("EC P-256 key rejected (not RSA)", isAcceptableRsaPublicKey(ecSpkiB64()) === false);
    check("garbage blob fails closed", isAcceptableRsaPublicKey("not-a-real-key") === false);
    check("empty string fails closed", isAcceptableRsaPublicKey("") === false);

    console.log(
        failures === 0
            ? "\nAll RSA key-strength tests passed."
            : `\n${failures} test(s) failed.`
    );
    process.exit(failures === 0 ? 0 : 1);
})();