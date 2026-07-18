// Feature phase 3 E2E: video calling. Starts as a normal audio call (the
// existing flow, untouched), then toggles video on mid-call - this is the
// new capability: adding a camera track to an already-connected
// RTCPeerConnection via renegotiation, not a separate "video call" mode.
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

const videoState = (page, id) => page.evaluate((elId) => {
    const el = document.getElementById(elId);
    return {
        hasStream: !!el.srcObject,
        hidden: el.classList.contains('hidden'),
        width: el.videoWidth, height: el.videoHeight
    };
}, id);

const panelHidden = (page) => page.$eval('#video-panel', el => el.classList.contains('hidden'));

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
            "--use-fake-device-for-media-stream", // fake mic AND fake camera (a synthetic test pattern)
            "--autoplay-policy=no-user-gesture-required"
        ]
    });

    const ctxA = await browser.createBrowserContext();
    const ctxB = await browser.createBrowserContext();
    const alice = await ctxA.newPage();
    const bob = await ctxB.newPage();
    alice.on("pageerror", e => console.log("[alice pageerror]", e.message));
    bob.on("pageerror", e => console.log("[bob pageerror]", e.message));
    alice.on("dialog", d => d.dismiss().catch(() => {}));
    bob.on("dialog", d => d.dismiss().catch(() => {}));

    await join(alice, "alice");
    await join(bob, "bob");
    await wait(500);

    console.log("\n--- Setup: place a normal audio call and connect it (video panel should stay hidden) ---");
    await alice.evaluate(() => {
        const row = [...document.querySelectorAll('#user-list .user-item')].find(r => r.dataset.nick === 'bob');
        row.querySelector('.call-btn').click();
    });
    await bob.waitForSelector('#incoming-call-modal:not(.hidden)', { timeout: 5000 });
    await bob.click('#accept-call-btn');
    await alice.waitForFunction(
        () => document.getElementById('call-status-text').textContent.includes('In call with'),
        { timeout: 8000 }
    );
    console.log("call connected (audio only)");
    check("video panel hidden on alice before any video is toggled on", await panelHidden(alice));
    check("video panel hidden on bob before any video is toggled on", await panelHidden(bob));

    console.log("\n--- Test 1: alice starts her camera; both sides should end up seeing video ---");
    await alice.click('#video-btn');
    await alice.waitForFunction(
        () => !document.getElementById('local-video').classList.contains('hidden'),
        { timeout: 5000 }
    );
    const aliceLocal = await videoState(alice, 'local-video');
    console.log(`[alice] local video: ${JSON.stringify(aliceLocal)}`);
    check("alice's own local preview shows immediately", aliceLocal.hasStream && !aliceLocal.hidden);

    const aliceBtnText = await alice.$eval('#video-btn', el => el.textContent);
    check("alice's video button now says STOP VIDEO", aliceBtnText === 'STOP VIDEO');

    // Renegotiation is a round trip - give bob's side a moment to receive
    // the new offer, answer it, and actually start rendering frames.
    await bob.waitForFunction(
        () => { const v = document.getElementById('remote-video'); return v.srcObject && v.videoWidth > 0; },
        { timeout: 8000 }
    );
    const bobRemote = await videoState(bob, 'remote-video');
    console.log(`[bob] remote video: ${JSON.stringify(bobRemote)}`);
    check("bob receives alice's video with real dimensions", bobRemote.hasStream && bobRemote.width > 0 && bobRemote.height > 0);
    check("bob's video panel is now visible", !(await panelHidden(bob)));
    check("alice's video panel is visible (her own local preview)", !(await panelHidden(alice)));

    // Confirm it's actually live video, not a single frozen frame - sample
    // twice and check the frame count advanced.
    const frames1 = await bob.$eval('#remote-video', v => v.getVideoPlaybackQuality ? v.getVideoPlaybackQuality().totalVideoFrames : v.currentTime);
    await wait(700);
    const frames2 = await bob.$eval('#remote-video', v => v.getVideoPlaybackQuality ? v.getVideoPlaybackQuality().totalVideoFrames : v.currentTime);
    console.log(`[bob] frame/time progress: ${frames1} -> ${frames2}`);
    check("remote video is actually playing (frames/time advanced)", frames2 > frames1);

    console.log("\n--- Test 2: audio call features (mute, quality, timer) still work alongside video ---");
    const stillHasCallBar = await alice.$eval('#call-status-bar', el => !el.classList.contains('hidden'));
    const muteBtnVisible = await alice.$eval('#mute-btn', el => !el.classList.contains('hidden'));
    check("call status bar still showing", stillHasCallBar);
    check("mute button still available with video active", muteBtnVisible);

    console.log("\n--- Test 3: alice stops her camera; video should disappear on both sides ---");
    await alice.click('#video-btn');
    await alice.waitForFunction(
        () => document.getElementById('local-video').classList.contains('hidden'),
        { timeout: 5000 }
    );
    const aliceLocalAfterStop = await videoState(alice, 'local-video');
    console.log(`[alice] local video after stopping: ${JSON.stringify(aliceLocalAfterStop)}`);
    check("alice's local preview is gone", !aliceLocalAfterStop.hasStream && aliceLocalAfterStop.hidden);

    await bob.waitForFunction(
        () => document.getElementById('remote-video').srcObject === null,
        { timeout: 8000 }
    );
    console.log("[bob] remote video cleared after alice stopped her camera");
    check("bob's video panel hides again (neither side has video now)", await panelHidden(bob));
    check("alice's video panel hides again", await panelHidden(alice));

    const aliceBtnTextAfterStop = await alice.$eval('#video-btn', el => el.textContent);
    check("alice's video button reverted to START VIDEO", aliceBtnTextAfterStop === 'START VIDEO');

    console.log("\n--- Test 4: the OTHER direction works too - bob starts video this time ---");
    await bob.click('#video-btn');
    await alice.waitForFunction(
        () => { const v = document.getElementById('remote-video'); return v.srcObject && v.videoWidth > 0; },
        { timeout: 8000 }
    );
    const aliceSeesBob = await videoState(alice, 'remote-video');
    console.log(`[alice] remote video (from bob): ${JSON.stringify(aliceSeesBob)}`);
    check("alice receives bob's video", aliceSeesBob.hasStream && aliceSeesBob.width > 0);

    console.log("\n--- Test 5: hanging up tears down video cleanly ---");
    await alice.click('#hangup-btn');
    await wait(800);
    const aliceCallBarHidden = await alice.$eval('#call-status-bar', el => el.classList.contains('hidden'));
    check("call bar hidden after hangup", aliceCallBarHidden);
    check("alice's video panel hidden after hangup", await panelHidden(alice));

    await browser.close();

    console.log(failures === 0 ? "\nAll video calling tests passed." : `\n${failures} test(s) FAILED.`);
    process.exit(failures === 0 ? 0 : 1);
})().catch(err => { console.error("E2E error:", err.message); process.exit(1); });
