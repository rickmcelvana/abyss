// Group calls E2E: alice calls bob (normal 1:1), then adds carol via
// "+ Add". Verifies the mesh actually completes (bob auto-connects to
// carol without a second prompt), that audio is flowing on every pairwise
// leg, and that one person leaving doesn't end the call for the others.
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

/** Counts live remote audio elements (the primary #remote-audio plus any dynamically-created extra-peer ones) that actually have a real stream attached. */
const liveAudioCount = (page) => page.evaluate(() => {
    return [...document.querySelectorAll('audio')].filter(a => {
        if (!a.srcObject) return false;
        const tracks = a.srcObject.getAudioTracks ? a.srcObject.getAudioTracks() : [];
        return tracks.length > 0 && tracks[0].readyState === 'live';
    }).length;
});

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
        p.on("dialog", d => { console.log(`[${name} dialog]`, d.message()); d.dismiss().catch(() => {}); });
    }

    await join(alice, "alice");
    await join(bob, "bob");
    await join(carol, "carol");
    await wait(500);

    console.log("\n--- Setup: alice calls bob, a normal 1:1 call ---");
    await clickCall(alice, "bob");
    await bob.waitForSelector('#incoming-call-modal:not(.hidden)', { timeout: 5000 });
    await bob.click('#accept-call-btn');
    await alice.waitForFunction(
        () => document.getElementById('call-status-text').textContent.includes('In call with'),
        { timeout: 8000 }
    );
    console.log("alice <-> bob connected");
    check("+ADD button visible now that the call is connected",
        await alice.$eval('#add-to-call-btn', el => !el.classList.contains('hidden')));

    console.log("\n--- Test 1: alice adds carol to the call ---");
    await alice.click('#add-to-call-btn');
    await alice.waitForSelector('#group-invite-picker:not(.hidden)', { timeout: 3000 });
    await alice.evaluate(() => {
        const btn = [...document.querySelectorAll('.group-invite-option')].find(b => b.textContent === 'carol');
        btn.click();
    });

    // carol should see an invite mentioning both alice (inviter) and bob (existing member)
    await carol.waitForSelector('#incoming-call-modal:not(.hidden)', { timeout: 5000 });
    const inviteText = await carol.$eval('#incoming-call-text', el => el.textContent);
    console.log(`[carol] invite text: "${inviteText}"`);
    check("invite mentions the inviter and existing member", /alice/.test(inviteText) && /bob/.test(inviteText));

    await carol.click('#accept-call-btn');

    console.log("\n--- Test 2: the mesh completes - bob auto-connects to carol with no second prompt ---");
    // Give the mesh-completion round trip (bob -> carol call_user/answer_call) a moment
    await wait(2000);

    const bobGotSecondModal = await bob.$eval('#incoming-call-modal', el => !el.classList.contains('hidden'));
    check("bob never saw a second incoming-call prompt (auto-connected)", !bobGotSecondModal);

    const aliceParticipants = await alice.$eval('#group-participants', el => el.textContent);
    const bobParticipants = await bob.$eval('#group-participants', el => el.textContent);
    const carolStillInCall = await carol.$eval('#call-status-bar', el => !el.classList.contains('hidden'));
    console.log(`[alice] participants: "${aliceParticipants}"`);
    console.log(`[bob]   participants: "${bobParticipants}"`);
    check("alice's participant list shows carol", aliceParticipants.includes('carol'));
    check("bob's participant list shows carol (mesh completed independently)", bobParticipants.includes('carol'));
    check("carol is still in the call", carolStillInCall);

    console.log("\n--- Test 3: audio is actually flowing on every pairwise leg ---");
    // Each of the 3 people should have exactly 2 live remote audio streams:
    // one from each of the other two participants.
    const aliceAudio = await liveAudioCount(alice);
    const bobAudio = await liveAudioCount(bob);
    const carolAudio = await liveAudioCount(carol);
    console.log(`live audio streams - alice: ${aliceAudio}, bob: ${bobAudio}, carol: ${carolAudio}`);
    check("alice has 2 live audio streams (from bob and carol)", aliceAudio === 2);
    check("bob has 2 live audio streams (from alice and carol)", bobAudio === 2);
    check("carol has 2 live audio streams (from alice and bob)", carolAudio === 2);

    console.log("\n--- Test 4: a 4th person declining doesn't break anything ---");
    const ctxD = await browser.createBrowserContext();
    const dave = await ctxD.newPage();
    dave.on("pageerror", e => console.log("[dave pageerror]", e.message));
    await join(dave, "dave");
    await wait(300);

    await alice.click('#add-to-call-btn');
    await alice.waitForSelector('#group-invite-picker:not(.hidden)', { timeout: 3000 });
    await alice.evaluate(() => {
        const btn = [...document.querySelectorAll('.group-invite-option')].find(b => b.textContent === 'dave');
        btn.click();
    });
    await dave.waitForSelector('#incoming-call-modal:not(.hidden)', { timeout: 5000 });
    await dave.click('#decline-call-btn');
    await wait(500);

    const aliceParticipantsAfterDecline = await alice.$eval('#group-participants', el => el.textContent);
    console.log(`[alice] participants after dave declined: "${aliceParticipantsAfterDecline}"`);
    check("dave does not appear in alice's participant list", !aliceParticipantsAfterDecline.includes('dave'));
    check("bob and carol are unaffected by dave's decline", await liveAudioCount(alice) === 2);
    await dave.close();

    console.log("\n--- Test 5: bob leaves - the call continues for alice and carol ---");
    await bob.click('#hangup-btn');
    await wait(800);

    const bobCallEnded = await bob.$eval('#call-status-bar', el => el.classList.contains('hidden'));
    check("bob's own call bar is now hidden", bobCallEnded);

    const aliceStillInCall = await alice.$eval('#call-status-bar', el => !el.classList.contains('hidden'));
    const carolStillInCall2 = await carol.$eval('#call-status-bar', el => !el.classList.contains('hidden'));
    console.log(`[alice] still in call: ${aliceStillInCall}, [carol] still in call: ${carolStillInCall2}`);
    check("alice's call continues after bob leaves", aliceStillInCall);
    check("carol's call continues after bob leaves", carolStillInCall2);

    // alice and carol should now each have exactly 1 live audio stream (each other) - bob's is gone
    await wait(500);
    const aliceAudioAfter = await liveAudioCount(alice);
    const carolAudioAfter = await liveAudioCount(carol);
    console.log(`live audio after bob left - alice: ${aliceAudioAfter}, carol: ${carolAudioAfter}`);
    check("alice has exactly 1 live audio stream left (carol)", aliceAudioAfter === 1);
    check("carol has exactly 1 live audio stream left (alice)", carolAudioAfter === 1);

    console.log("\n--- Test 6: the remaining two hang up and the call fully ends ---");
    await carol.click('#hangup-btn');
    await wait(500);
    const aliceEndedToo = await alice.$eval('#call-status-bar', el => el.classList.contains('hidden'));
    check("alice's call ends once carol (the last other participant) leaves too", aliceEndedToo);

    await browser.close();

    console.log(failures === 0 ? "\nAll group call tests passed." : `\n${failures} test(s) FAILED.`);
    process.exit(failures === 0 ? 0 : 1);
})().catch(err => { console.error("E2E error:", err.message); process.exit(1); });
