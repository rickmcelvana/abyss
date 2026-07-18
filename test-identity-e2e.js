// Phase 7 E2E: real browsers, persistent IndexedDB identity, TOFU pinning,
// explicit verification, and key-change detection/blocking - all through
// the actual UI, not internal test hooks.
const puppeteer = require("puppeteer-core");

const CHROME = "/home/claude/.cache/puppeteer/chrome/linux-131.0.6778.204/chrome-linux64/chrome";
const URL = "http://127.0.0.1:3000";
const wait = (ms) => new Promise(r => setTimeout(r, ms));
const FP_RE = /^[0-9A-F]{4}( [0-9A-F]{4}){7}$/; // 16 bytes, spaced

async function join(page, nick) {
    await page.goto(URL, { waitUntil: "networkidle2" });
    await page.waitForFunction(
        () => !document.getElementById('identity-fingerprint-row').classList.contains('hidden'),
        { timeout: 5000 }
    );
    await page.type("#nick", nick);
    await page.type("#about", "e2e-bot");
    await page.click("#join-form button[type=submit]");
    await page.waitForSelector("#chat-interface:not(.hidden)", { timeout: 5000 });
    console.log(`[${nick}] joined via UI`);
}

const getOwnFingerprint = (page) => page.$eval("#identity-fingerprint", el => el.textContent);

(async () => {
    const browser = await puppeteer.launch({
        executablePath: CHROME,
        headless: "new",
        args: ["--no-sandbox", "--autoplay-policy=no-user-gesture-required"]
    });

    const ctxA = await browser.createBrowserContext();
    const ctxB = await browser.createBrowserContext();
    const alice = await ctxA.newPage();
    const bob = await ctxB.newPage();
    alice.on("pageerror", e => console.log("[alice pageerror]", e.message));
    bob.on("pageerror", e => console.log("[bob pageerror]", e.message));
    alice.on("dialog", d => d.dismiss().catch(() => {}));
    bob.on("dialog", d => d.dismiss().catch(() => {}));

    console.log("--- Setup: alice and bob join, each gets a device identity fingerprint ---");
    await join(alice, "alice");
    await join(bob, "bob");
    await wait(500);

    const aliceFp1 = await getOwnFingerprint(alice);
    const bobFp1 = await getOwnFingerprint(bob);
    console.log(`[alice] own fingerprint: "${aliceFp1}"`);
    console.log(`[bob]   own fingerprint: "${bobFp1}"`);
    const fingerprintsWellFormed = FP_RE.test(aliceFp1) && FP_RE.test(bobFp1) && aliceFp1 !== bobFp1;
    console.log(`fingerprints well-formed and distinct: ${fingerprintsWellFormed}`);

    console.log("\n--- Test 1: new contacts show the unverified (key) toggle, not verified (lock) ---");
    const bobsViewOfAliceBadge1 = await bob.$eval(
        '#user-list .user-item .verify-toggle', el => el.textContent
    ).catch(() => null);
    console.log(`[bob] verify toggle for alice: "${bobsViewOfAliceBadge1}" (expect key emoji, unverified)`);
    const startsUnverified = bobsViewOfAliceBadge1 === '\u{1F511}';

    console.log("\n--- Test 2: bob reveals alice's fingerprint and marks her verified ---");
    await bob.click('#user-list .user-item .verify-toggle');
    await bob.waitForSelector('.fingerprint-reveal code', { timeout: 3000 });
    const revealedFp = await bob.$eval('.fingerprint-reveal code', el => el.textContent);
    console.log(`[bob] revealed fingerprint for alice: "${revealedFp}"`);
    const revealMatchesAlice = revealedFp === aliceFp1;
    console.log(`revealed fingerprint matches alice's own reported fingerprint: ${revealMatchesAlice}`);

    await bob.click('.fingerprint-reveal button'); // "Mark Verified"
    await wait(300);
    const bobsViewOfAliceBadge2 = await bob.$eval(
        '#user-list .user-item .verify-toggle', el => el.textContent
    ).catch(() => null);
    console.log(`[bob] verify toggle for alice after marking verified: "${bobsViewOfAliceBadge2}" (expect lock emoji)`);
    const nowVerified = bobsViewOfAliceBadge2 === '\u{1F512}';

    console.log("\n--- Test 3: identity persists across reload (same browser context = same IndexedDB) ---");
    await bob.reload({ waitUntil: "networkidle2" });
    await bob.waitForFunction(
        () => !document.getElementById('identity-fingerprint-row').classList.contains('hidden'),
        { timeout: 5000 }
    );
    const bobFpBeforeRejoin = await getOwnFingerprint(bob);
    console.log(`[bob] fingerprint before rejoining: "${bobFpBeforeRejoin}" (expect same as "${bobFp1}")`);
    const identityPersisted = bobFpBeforeRejoin === bobFp1;

    await bob.type("#nick", "bob");
    await bob.type("#about", "e2e-bot");
    await bob.click("#join-form button[type=submit]");
    await bob.waitForSelector("#chat-interface:not(.hidden)", { timeout: 5000 });
    console.log("[bob] rejoined after reload");
    await wait(500);

    // Alice's pin for bob shouldn't have changed (same key before/after reload),
    // so alice should NOT see a key-changed warning for bob now.
    const aliceSeesWarningForBob = await alice.evaluate(() =>
        [...document.querySelectorAll('.trust-warning-text')].some(el => el.textContent.includes('bob')));
    console.log(`[alice] false-positive key-changed warning for bob after his reload: ${aliceSeesWarningForBob} (expect false)`);

    console.log("\n--- Test 4: simulated key change is detected and blocks calling ---");
    // We don't fake a server-side impersonation (the server's signature
    // checks already prevent that at the protocol level, covered in
    // test-calls.js). Instead we exercise the CLIENT'S detection path
    // directly and honestly: seed alice's own IndexedDB pin for "bob" with a
    // fingerprint that doesn't match his real key, mark it previously
    // verified (the case we most want to protect), then force a fresh
    // user_list evaluation the same way a real rejoin would - this runs the
    // exact same checkTrust()/renderUserList() code a genuine key change
    // would trigger, just with a seeded starting condition instead of a
    // staged impersonation.
    await alice.evaluate(() => {
        return new Promise((resolve, reject) => {
            const req = indexedDB.open('abyss-identity-store', 1);
            req.onsuccess = () => {
                const db = req.result;
                const tx = db.transaction('trust', 'readwrite');
                tx.objectStore('trust').put({ fingerprint: '0000 0000 0000 0000 0000 0000 0000 0000', verified: true }, 'bob');
                tx.oncomplete = resolve;
                tx.onerror = () => reject(tx.error);
            };
            req.onerror = () => reject(req.error);
        });
    });
    console.log("[alice] tampered her own pinned fingerprint for bob (simulating a genuine key change)");

    // Trigger a fresh user_list without a page reload, the way a real change
    // would arrive: someone else's presence change broadcasts to everyone.
    const ctxC = await browser.createBrowserContext();
    const carol = await ctxC.newPage();
    carol.on("dialog", d => d.dismiss().catch(() => {}));
    await join(carol, "carol");
    await wait(600);

    const aliceWarningRow = await alice.$eval('.trust-warning-text', el => el.textContent).catch(() => null);
    console.log(`[alice] warning row text: "${aliceWarningRow}"`);
    const warningShown = Boolean(aliceWarningRow && aliceWarningRow.includes('bob'));

    // No normal row (with Call button) should exist for bob while blocked -
    // the warning row replaces it entirely, so there's no way to call him
    const bobCallButtonGone = await alice.evaluate(() => {
        const rows = [...document.querySelectorAll('#user-list .user-item')];
        const bobRow = rows.find(r => r.querySelector('strong')?.textContent === 'bob');
        return !bobRow;
    });
    console.log(`[alice] bob's normal row (with Call button) absent while blocked: ${bobCallButtonGone}`);

    console.log("\n--- Test 5: re-verifying clears the block ---");
    await alice.click('.trust-warning-actions button:not(.danger)'); // "Trust new key"
    await wait(300);
    const aliceWarningGoneAfterTrust = await alice.evaluate(() =>
        ![...document.querySelectorAll('.trust-warning-text')].some(el => el.textContent.includes('bob')));
    console.log(`[alice] warning cleared after clicking "Trust new key": ${aliceWarningGoneAfterTrust}`);
    const bobRowRestored = await alice.evaluate(() =>
        [...document.querySelectorAll('#user-list .user-item')].some(r => r.querySelector('strong')?.textContent === 'bob'));
    console.log(`[alice] bob's normal row (with Call button) restored: ${bobRowRestored}`);

    await browser.close();

    const allOk = fingerprintsWellFormed && startsUnverified && revealMatchesAlice && nowVerified &&
        identityPersisted && !aliceSeesWarningForBob && warningShown && bobCallButtonGone &&
        aliceWarningGoneAfterTrust && bobRowRestored;

    if (allOk) {
        console.log("\nRESULT: PASS - identity persistence, verify flow, and key-change blocking all verified.");
        process.exit(0);
    } else {
        console.log(`\nRESULT: FAIL (wellFormed=${fingerprintsWellFormed} startsUnverified=${startsUnverified} revealMatches=${revealMatchesAlice} nowVerified=${nowVerified} persisted=${identityPersisted} noFalsePositive=${!aliceSeesWarningForBob} warningShown=${warningShown} callBtnGone=${bobCallButtonGone} warningCleared=${aliceWarningGoneAfterTrust} rowRestored=${bobRowRestored})`);
        process.exit(1);
    }
})().catch(err => { console.error("E2E error:", err.message); process.exit(1); });
