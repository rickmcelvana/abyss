// Extends group calling: video and safety codes for every participant,
// not just the original pair. Verifies real video frames reach extra
// peers (not just UI flags), and that a pairwise safety code computed
// independently on both ends of that SAME connection actually matches -
// the whole point of a safety code is it's derived identically from both
// sides' DTLS fingerprints, so a mismatch would mean something is wrong.
const puppeteer = require("puppeteer-core");

const CHROME = "/home/claude/.cache/puppeteer/chrome/linux-131.0.6778.204/chrome-linux64/chrome";
const URL = "http://127.0.0.1:3000";
const wait = (ms) => new Promise(r => setTimeout(r, ms));

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

const clickCall = (page, targetNick) => page.evaluate((nick) => {
    const row = [...document.querySelectorAll('#user-list .user-item')].find(r => r.dataset.nick === nick);
    row.querySelector('.call-btn').click();
}, targetNick);

const participantRow = (page, nick) => page.evaluate((n) => {
    const rows = [...document.querySelectorAll('.call-participant-row')];
    const row = rows.find(r => r.querySelector('.call-participant-name').textContent === n);
    if (!row) return null;
    return row.querySelector('.call-participant-safety').textContent;
}, nick);

const primarySafetyCode = (page) => page.$eval('#safety-code', el => el.textContent);

let failures = 0;
function check(label, cond) {
    console.log(`${cond ? 'PASS' : 'FAIL'} - ${label}`);
    if (!cond) failures++;
}

(async () => {
    const browser = await puppeteer.launch({
        executablePath: CHROME,
        headless: "new",
        args: [
            "--no-sandbox",
            "--use-fake-ui-for-media-stream",
            "--use-fake-device-for-media-stream",
            "--autoplay-policy=no-user-gesture-required"
        ]
    });

    const ctxA = await browser.createBrowserContext();
    const ctxB = await browser.createBrowserContext();
    const ctxC = await browser.createBrowserContext();
    const alice = await ctxA.newPage();
    const bob = await ctxB.newPage();
    const carol = await ctxC.newPage();
    for (const [p, name] of [[alice, "alice"], [bob, "bob"], [carol, "carol"]]) {
        p.on("pageerror", e => console.log(`[${name} pageerror]`, e.message));
        p.on("dialog", d => d.dismiss().catch(() => {}));
    }

    await join(alice, "alice");
    await join(bob, "bob");
    await join(carol, "carol");
    await wait(500);

    console.log("\n--- Setup: alice calls bob, bob starts video, then alice adds carol ---");
    await clickCall(alice, "bob");
    await bob.waitForSelector('#incoming-call-modal:not(.hidden)', { timeout: 5000 });
    await bob.click('#accept-call-btn');
    await alice.waitForFunction(
        () => document.getElementById('call-status-text').textContent.includes('In call with'),
        { timeout: 8000 }
    );
    console.log("alice <-> bob connected");

    // Bob turns his camera on BEFORE carol joins - the new video track
    // should be included in the very first offer bob sends carol once the
    // mesh completes, not require a second renegotiation afterward.
    await bob.click('#video-btn');
    await alice.waitForFunction(
        () => { const v = document.getElementById('remote-video'); return v.srcObject && v.videoWidth > 0; },
        { timeout: 8000 }
    );
    console.log("bob's video reaches alice (the original pair) as expected");

    await alice.click('#add-to-call-btn');
    await alice.waitForSelector('#group-invite-picker:not(.hidden)', { timeout: 3000 });
    await alice.evaluate(() => {
        const btn = [...document.querySelectorAll('.group-invite-option')].find(b => b.textContent === 'carol');
        btn.click();
    });
    await carol.waitForSelector('#incoming-call-modal:not(.hidden)', { timeout: 5000 });
    await carol.click('#accept-call-btn');
    await wait(2000); // mesh completion round trip

    console.log("\n--- Test 1: bob's video (already on) reaches carol via the mesh, as an extra-peer tile ---");
    await carol.waitForFunction(
        () => {
            const tile = document.querySelector('.extra-video-tile video');
            return tile && tile.srcObject && tile.videoWidth > 0;
        },
        { timeout: 10000 }
    );
    const carolExtraTile = await carol.evaluate(() => {
        const tile = document.querySelector('.extra-video-tile');
        return {
            label: tile.querySelector('.extra-video-tile-label').textContent,
            width: tile.querySelector('video').videoWidth,
            height: tile.querySelector('video').videoHeight
        };
    });
    console.log(`[carol] extra video tile: ${JSON.stringify(carolExtraTile)}`);
    check("carol's extra-peer tile is labeled 'bob'", carolExtraTile.label === 'bob');
    check("carol actually receives real video frames from bob (not just a flag)", carolExtraTile.width > 0 && carolExtraTile.height > 0);

    console.log("\n--- Test 2: alice also has a video tile for carol's connection scenario reversed - carol starts video too ---");
    await carol.click('#video-btn');
    // Carol's video should reach BOTH alice (as carol is alice's primary
    // invite target... wait, carol is alice's EXTRA since alice invited
    // her - so this should appear as an extra tile on alice's side, and
    // as carol's own PRIMARY relationship on carol's side, so bob and
    // alice both see it as an extra tile too since carol is extra for both.
    await alice.waitForFunction(
        () => {
            const tiles = [...document.querySelectorAll('.extra-video-tile')];
            const carolTile = tiles.find(t => t.querySelector('.extra-video-tile-label').textContent === 'carol');
            return carolTile && carolTile.querySelector('video').videoWidth > 0;
        },
        { timeout: 10000 }
    );
    console.log("alice sees carol's video in an extra-peer tile");
    check("alice's extra-tile video from carol has real frames", true); // waitForFunction above already confirmed this

    console.log("\n--- Test 3: safety codes are shown for every pairwise connection and match on both ends ---");
    // alice's code WITH bob (her primary) should match bob's code with alice (his primary)
    const aliceCodeForBob = await primarySafetyCode(alice);
    const bobCodeForAlice = await primarySafetyCode(bob);
    console.log(`alice<->bob: alice sees "${aliceCodeForBob}", bob sees "${bobCodeForAlice}"`);
    check("alice's and bob's safety codes for their own connection match", aliceCodeForBob === bobCodeForAlice && aliceCodeForBob.length > 0);

    // alice's code WITH carol (shown in alice's participant list, since
    // carol is alice's extra) should match carol's code with alice (her
    // primary, shown in carol's compact display)
    const aliceCodeForCarol = await participantRow(alice, "carol");
    const carolCodeForAlice = await primarySafetyCode(carol);
    console.log(`alice<->carol: alice's list shows "${aliceCodeForCarol}", carol sees "${carolCodeForAlice}"`);
    check("alice's and carol's safety codes for their connection match",
        Boolean(aliceCodeForCarol) && carolCodeForAlice.includes(aliceCodeForCarol.replace('safety ', '')));

    // bob's code WITH carol (both see it as an extra-peer relationship,
    // shown in each other's participant list) should match
    const bobCodeForCarol = await participantRow(bob, "carol");
    const carolCodeForBob = await participantRow(carol, "bob");
    console.log(`bob<->carol: bob's list shows "${bobCodeForCarol}", carol's list shows "${carolCodeForBob}"`);
    check("bob's and carol's safety codes for their connection match",
        Boolean(bobCodeForCarol) && Boolean(carolCodeForBob) && bobCodeForCarol === carolCodeForBob);

    console.log("\n--- Test 4: participant list shows every OTHER person, primary and extras alike ---");
    const aliceListNicks = await alice.evaluate(() =>
        [...document.querySelectorAll('.call-participant-name')].map(el => el.textContent).sort()
    );
    console.log(`[alice] participant list: ${JSON.stringify(aliceListNicks)}`);
    check("alice's list shows both bob (primary) and carol (extra)", JSON.stringify(aliceListNicks) === JSON.stringify(['bob', 'carol']));

    console.log("\n--- Test 5: turning video off removes the tile cleanly ---");
    await bob.click('#video-btn'); // bob stops his camera
    await carol.waitForFunction(
        () => document.querySelectorAll('.extra-video-tile').length === 1, // only carol's own video-to-alice/bob tile situation remains on alice/bob side, but on CAROL's side bob's tile should be gone
        { timeout: 8000 }
    ).catch(() => {}); // best-effort; verified more precisely below
    await wait(1000);
    const carolTilesAfterBobStops = await carol.evaluate(() =>
        [...document.querySelectorAll('.extra-video-tile-label')].map(el => el.textContent)
    );
    console.log(`[carol] remaining extra tiles after bob stops video: ${JSON.stringify(carolTilesAfterBobStops)}`);
    check("bob's tile is gone from carol's view once he stops video", !carolTilesAfterBobStops.includes('bob'));

    await browser.close();

    console.log(failures === 0 ? "\nAll group video/safety-code tests passed." : `\n${failures} test(s) FAILED.`);
    process.exit(failures === 0 ? 0 : 1);
})().catch(err => { console.error("E2E error:", err.message); process.exit(1); });
