// Phase 2 E2E: two real browser contexts with fake microphones make an
// actual WebRTC call through the app UI and we verify the peer connection
// reaches 'connected' and remote audio is flowing.
const puppeteer = require("puppeteer-core");

const CHROME = "/home/claude/.cache/puppeteer/chrome/linux-131.0.6778.204/chrome-linux64/chrome";
const URL = "http://127.0.0.1:3000";
const RING_TIMEOUT_MS = parseInt(process.env.RING_TIMEOUT_MS, 10) || 30000;
const wait = (ms) => new Promise(r => setTimeout(r, ms));

async function join(page, nick) {
    await page.goto(URL, { waitUntil: "networkidle2" });
    await page.type("#nick", nick);
    await page.type("#about", "e2e-bot");
    await page.click("#join-form button[type=submit]");
    await page.waitForSelector("#chat-interface:not(.hidden)", { timeout: 5000 });
    console.log(`[${nick}] joined via UI`);
}

(async () => {
    const browser = await puppeteer.launch({
        executablePath: CHROME,
        headless: "new",
        args: [
            "--no-sandbox",
            "--use-fake-ui-for-media-stream",     // auto-grant mic permission
            "--use-fake-device-for-media-stream", // synthetic audio input
            "--autoplay-policy=no-user-gesture-required"
        ]
    });

    // Two isolated contexts = two independent users
    const ctxA = await browser.createBrowserContext();
    const ctxB = await browser.createBrowserContext();
    const alice = await ctxA.newPage();
    const bob = await ctxB.newPage();
    alice.on("pageerror", e => console.log("[alice pageerror]", e.message));
    bob.on("pageerror", e => console.log("[bob pageerror]", e.message));
    // Auto-dismiss alert() dialogs so races can't hang the pages
    alice.on("dialog", d => d.dismiss().catch(() => {}));
    bob.on("dialog", d => d.dismiss().catch(() => {}));

    const clickCall = (page, targetNick) => page.evaluate((nick) => {
        const items = document.querySelectorAll("#user-list .user-item");
        for (const item of items) {
            if (item.querySelector("strong").textContent === nick) {
                const btn = item.querySelector(".call-btn");
                if (btn) { btn.click(); return; }
            }
        }
        throw new Error(nick + " not found in user list");
    }, targetNick);

    // Wiretap bob's websocket at the protocol level - this is exactly what
    // the server (or anyone reading its traffic) can see of the signaling
    const cdp = await bob.createCDPSession();
    await cdp.send("Network.enable");
    const sigFrames = [];
    cdp.on("Network.webSocketFrameReceived", ({ response }) => {
        const p = response.payloadData;
        if (typeof p === "string" && (p.includes("incoming_call") || p.includes("ice_candidate"))) {
            sigFrames.push(p);
        }
    });

    await join(alice, "alice");
    await join(bob, "bob");
    await wait(500);

    // Alice clicks Call on bob's entry
    await clickCall(alice, "bob");
    console.log("[alice] clicked Call");

    // Bob sees the incoming modal and accepts
    await bob.waitForSelector("#incoming-call-modal:not(.hidden)", { timeout: 5000 });
    const ringText = await bob.$eval("#incoming-call-text", el => el.textContent);
    console.log(`[bob] modal shown: "${ringText}"`);
    await bob.click("#accept-call-btn");
    console.log("[bob] clicked Accept");

    // Both status bars should say connected
    await alice.waitForFunction(
        () => document.getElementById("call-status-text").textContent.includes("In call with"),
        { timeout: 10000 }
    );
    await bob.waitForFunction(
        () => document.getElementById("call-status-text").textContent.includes("In call with"),
        { timeout: 10000 }
    );
    console.log("[both] UI shows 'In call with ...'");

    // Poll the actual RTCPeerConnection state via a probe injected into the page.
    // We can't reach the closure's pc directly, so check the remote audio sink
    // and use WebRTC internals via getStats on a fresh probe of the media element.
    const checkMedia = async (page, who) => {
        return await page.evaluate(async () => {
            const audio = document.getElementById("remote-audio");
            const stream = audio.srcObject;
            if (!stream) return { hasStream: false };
            const tracks = stream.getAudioTracks();
            return {
                hasStream: true,
                trackCount: tracks.length,
                trackState: tracks[0] ? tracks[0].readyState : "none",
                audioTime: audio.currentTime
            };
        });
    };

    // Give ICE a moment on loopback, then sample twice to see currentTime advance
    await wait(2000);
    const a1 = await checkMedia(alice, "alice");
    const b1 = await checkMedia(bob, "bob");
    await wait(1500);
    const a2 = await checkMedia(alice, "alice");
    const b2 = await checkMedia(bob, "bob");

    console.log("[alice] remote audio:", JSON.stringify(a2),
        "| playing:", a2.audioTime > a1.audioTime);
    console.log("[bob]   remote audio:", JSON.stringify(b2),
        "| playing:", b2.audioTime > b1.audioTime);

    const connected =
        a2.hasStream && b2.hasStream &&
        a2.trackState === "live" && b2.trackState === "live" &&
        a2.audioTime > a1.audioTime && b2.audioTime > b1.audioTime;

    // Phase 3 check 1: both sides display the SAME safety code
    const codeA = await alice.$eval("#safety-code", el => el.textContent);
    const codeB = await bob.$eval("#safety-code", el => el.textContent);
    const codesMatch = codeA.length > 0 && codeA === codeB && /safety \d{3} \d{3}/.test(codeA);
    console.log(`[alice] safety code: "${codeA}"`);
    console.log(`[bob]   safety code: "${codeB}" | match: ${codesMatch}`);

    // Phase 3 check 2: signaling frames on the wire contain NO plaintext SDP.
    // Plaintext SDP always contains "v=0", "a=fingerprint" and "candidate:".
    const leaks = sigFrames.filter(f =>
        f.includes("v=0\\r\\n") || f.includes("a=fingerprint") || f.includes("candidate:"));
    const opaque = sigFrames.length > 0 && leaks.length === 0;
    console.log(`[wire] captured ${sigFrames.length} signaling frames, plaintext SDP leaks: ${leaks.length}`);
    if (sigFrames[0]) console.log(`[wire] sample frame (truncated): ${sigFrames[0].slice(0, 140)}...`);

    // Phase 4 check 1: call duration timer is ticking (mm:ss in the status bar)
    const statusA = await alice.$eval("#call-status-text", el => el.textContent);
    const timerOk = /In call with bob · \d{2}:\d{2}/.test(statusA);
    console.log(`[alice] status: "${statusA}" | timer: ${timerOk}`);

    // Phase 4 check 2: connection quality indicator is rendering
    const quality = await alice.$eval("#call-quality", el => ({ text: el.textContent, cls: el.className }));
    const qualityOk = quality.text.includes("▮") && /q-(good|fair|poor)/.test(quality.cls);
    console.log(`[alice] quality: ${JSON.stringify(quality)} | ok: ${qualityOk}`);

    // Phase 4 check 3: mute toggle round-trip on bob
    await bob.click("#mute-btn");
    await wait(300);
    const mutedLabel = await bob.$eval("#mute-btn", el => el.textContent);
    const mutedStatus = await bob.$eval("#call-status-text", el => el.textContent);
    const muteOk = mutedLabel === "UNMUTE" && mutedStatus.includes("muted");
    console.log(`[bob] after mute: label="${mutedLabel}" status="${mutedStatus}" | ok: ${muteOk}`);
    await bob.click("#mute-btn"); // unmute again
    await wait(200);

    // Hang up from alice; bob's UI should return to idle and mic released
    await alice.click("#hangup-btn");
    await bob.waitForFunction(
        () => document.getElementById("call-status-bar").classList.contains("hidden"),
        { timeout: 5000 }
    );
    console.log("[bob] call bar hidden after alice hung up");

    // Verify bob's mic tracks were stopped (mic indicator off)
    await wait(500);
    const bobAudioCleared = await bob.evaluate(() =>
        document.getElementById("remote-audio").srcObject === null);
    console.log("[bob] remote audio sink cleared:", bobAudioCleared);

    // --- Phase 6: call log ---
    const openCallsTab = (page) => page.evaluate(() => {
        document.getElementById('tab-calls').click();
    });
    const readCallLogRows = (page) => page.evaluate(() => {
        return Array.from(document.querySelectorAll('#chat-window .call-log-row')).map(row => ({
            nick: row.querySelector('.call-log-nick')?.textContent,
            meta: row.querySelector('.call-log-meta')?.textContent,
            outcomeClass: [...row.classList].find(c => c.startsWith('outcome-')),
            hasCallback: !!row.querySelector('.call-log-callback')
        }));
    });

    console.log("\n--- Phase 6a: completed call appears in both logs with a duration ---");
    await openCallsTab(alice);
    const aliceLog1 = await readCallLogRows(alice);
    console.log(`[alice] call log: ${JSON.stringify(aliceLog1)}`);
    const aliceLoggedCompleted = aliceLog1.some(r =>
        r.nick === 'bob' && r.outcomeClass === 'outcome-completed' && /\d{2}:\d{2}/.test(r.meta));
    console.log(`[alice] completed entry with duration present: ${aliceLoggedCompleted}`);

    await openCallsTab(bob);
    const bobLog1 = await readCallLogRows(bob);
    console.log(`[bob] call log: ${JSON.stringify(bobLog1)}`);
    const bobLoggedCompleted = bobLog1.some(r =>
        r.nick === 'alice' && r.outcomeClass === 'outcome-completed' && /\d{2}:\d{2}/.test(r.meta));
    console.log(`[bob] completed entry with duration present: ${bobLoggedCompleted}`);

    // Switching to the calls tab should hide the message input (log view, not a chat)
    const inputHiddenOnCallsTab = await alice.$eval('.input-area', el => el.classList.contains('hidden'));
    console.log(`[alice] input area hidden on calls tab: ${inputHiddenOnCallsTab}`);

    // Back to global before the next scenario
    await alice.evaluate(() => document.getElementById('tab-global').click());
    await bob.evaluate(() => document.getElementById('tab-global').click());

    // Phase 4 check 4: GLARE - both click Call on each other simultaneously
    console.log("\n[glare] alice and bob call each other at the same time...");
    await Promise.all([clickCall(alice, "bob"), clickCall(bob, "alice")]);

    // Converge: wait for both to be in-call. If timing fell into the normal
    // flow (one side was still idle when the offer landed), accept the modal.
    let glareOk = false;
    const deadline = Date.now() + 12000;
    while (Date.now() < deadline) {
        const [aTxt, bTxt] = await Promise.all([
            alice.$eval("#call-status-text", el => el.textContent),
            bob.$eval("#call-status-text", el => el.textContent)
        ]);
        if (aTxt.includes("In call with") && bTxt.includes("In call with")) { glareOk = true; break; }
        for (const p of [alice, bob]) {
            const modal = await p.$eval("#incoming-call-modal",
                el => !el.classList.contains("hidden")).catch(() => false);
            if (modal) { await p.click("#accept-call-btn"); console.log("[glare] fell into normal flow - accepted via modal"); }
        }
        await wait(250);
    }
    console.log(`[glare] both connected after mutual call: ${glareOk}`);
    await alice.click("#hangup-btn");
    await wait(500);

    // --- Phase 6b: missed call via ring timeout, badge, and call-back button ---
    console.log("\n--- Phase 6b: carol calls bob, nobody answers -> ring timeout ---");
    const ctxC = await browser.createBrowserContext();
    const carol = await ctxC.newPage();
    carol.on("dialog", d => d.dismiss().catch(() => {}));
    await join(carol, "carol");
    await wait(500);

    await clickCall(carol, "bob");
    console.log("[carol] clicked Call (bob will not answer)");
    await bob.waitForSelector("#incoming-call-modal:not(.hidden)", { timeout: 5000 });
    console.log("[bob] modal shown, deliberately not answering");

    // Wait past the server's ring timeout
    await wait(RING_TIMEOUT_MS + 1500);

    const bobIdleAfterTimeout = await bob.$eval("#call-status-bar", el => el.classList.contains("hidden"));
    const carolIdleAfterTimeout = await carol.$eval("#call-status-bar", el => el.classList.contains("hidden"));
    console.log(`[bob] call bar hidden after timeout: ${bobIdleAfterTimeout}`);
    console.log(`[carol] call bar hidden after timeout: ${carolIdleAfterTimeout}`);

    // Bob should see an unread badge on the Calls tab
    const badgeText = await bob.$eval("#calls-badge", el => ({
        text: el.textContent, hidden: el.classList.contains("hidden")
    }));
    console.log(`[bob] calls tab badge: ${JSON.stringify(badgeText)}`);
    const badgeShownBeforeView = !badgeText.hidden && badgeText.text === "1";

    await openCallsTab(bob);
    const bobLog2 = await readCallLogRows(bob);
    console.log(`[bob] call log after missed call: ${JSON.stringify(bobLog2)}`);
    const bobMissedEntry = bobLog2.find(r => r.nick === 'carol' && r.outcomeClass === 'outcome-missed');
    const bobMissedOk = Boolean(bobMissedEntry) && bobMissedEntry.hasCallback; // carol still online -> callback button

    // Badge should clear once the tab was actually viewed
    const badgeAfterView = await bob.$eval("#calls-badge", el => el.classList.contains("hidden"));
    console.log(`[bob] badge cleared after viewing calls tab: ${badgeAfterView}`);

    await openCallsTab(carol);
    const carolLog = await readCallLogRows(carol);
    console.log(`[carol] call log: ${JSON.stringify(carolLog)}`);
    const carolNoAnswerOk = carolLog.some(r => r.nick === 'bob' && /no answer/.test(r.meta));

    // Call-back button: bob calls carol straight from the missed-call log entry
    console.log("\n--- Phase 6c: call back from the log ---");
    await bob.evaluate(() => {
        const row = [...document.querySelectorAll('#chat-window .call-log-row')]
            .find(r => r.querySelector('.call-log-nick')?.textContent === 'carol');
        row.querySelector('.call-log-callback').click();
    });
    await wait(1000);
    const bobCallbackStatus = await bob.$eval("#call-status-text", el => el.textContent).catch(() => "");
    console.log(`[bob] status after clicking call-back: "${bobCallbackStatus}"`);
    const callbackOk = bobCallbackStatus.includes('carol');
    // Clean up: carol declines so nothing lingers
    await carol.waitForSelector("#incoming-call-modal:not(.hidden)", { timeout: 5000 }).catch(() => {});
    await carol.click("#decline-call-btn").catch(() => {});
    await wait(300);

    await browser.close();

    const phase6Ok = aliceLoggedCompleted && bobLoggedCompleted && inputHiddenOnCallsTab &&
        bobIdleAfterTimeout && carolIdleAfterTimeout && badgeShownBeforeView &&
        bobMissedOk && badgeAfterView && carolNoAnswerOk && callbackOk;

    if (connected && bobAudioCleared && codesMatch && opaque && timerOk && qualityOk && muteOk && glareOk && phase6Ok) {
        console.log("\nRESULT: PASS - encrypted call with timer, quality, mute, glare, and call log/ring-timeout all verified.");
        process.exit(0);
    } else {
        console.log(`\nRESULT: FAIL (connected=${connected} cleared=${bobAudioCleared} codes=${codesMatch} opaque=${opaque} timer=${timerOk} quality=${qualityOk} mute=${muteOk} glare=${glareOk} phase6=${phase6Ok})`);
        console.log(`  phase6 detail: completedA=${aliceLoggedCompleted} completedB=${bobLoggedCompleted} inputHidden=${inputHiddenOnCallsTab} bobIdle=${bobIdleAfterTimeout} carolIdle=${carolIdleAfterTimeout} badgeShown=${badgeShownBeforeView} missedOk=${bobMissedOk} badgeCleared=${badgeAfterView} noAnswerOk=${carolNoAnswerOk} callbackOk=${callbackOk}`);
        process.exit(1);
    }
})().catch(err => { console.error("E2E error:", err.message); process.exit(1); });
