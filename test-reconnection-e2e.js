// Phase 3 (second hardening round) E2E: graceful reconnection. Simulates a
// real network drop with Chrome DevTools Protocol (Network.emulateNetworkConditions),
// not a test hook in the app - this exercises exactly what a real wifi
// blip or brief server hiccup looks like from the browser's side.
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

async function sendGlobalMessage(page, text) {
    await page.click("#msg-input");
    await page.type("#msg-input", text);
    await page.click("#send-btn");
}

async function goOffline(cdp) {
    await cdp.send("Network.emulateNetworkConditions", { offline: true, latency: 0, downloadThroughput: 0, uploadThroughput: 0 });
}
async function goOnline(cdp) {
    await cdp.send("Network.emulateNetworkConditions", { offline: false, latency: 0, downloadThroughput: -1, uploadThroughput: -1 });
}

let failures = 0;
function check(label, cond) {
    console.log(`${cond ? 'PASS' : 'FAIL'} - ${label}`);
    if (!cond) failures++;
}

(async () => {
    const browser = await puppeteer.launch({
        executablePath: CHROME,
        headless: "new",
        args: ["--no-sandbox", "--use-fake-ui-for-media-stream", "--use-fake-device-for-media-stream", "--autoplay-policy=no-user-gesture-required"]
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

    const cdp = await alice.createCDPSession();
    await cdp.send("Network.enable");

    console.log("\n--- Test 1: send a message, then drop alice's connection ---");
    await sendGlobalMessage(alice, "before the drop");
    await bob.waitForFunction(
        (t) => [...document.querySelectorAll('#chat-window .msg')].some(m => m.textContent.includes(t)),
        { timeout: 3000 }, "before the drop"
    );
    await goOffline(cdp);
    await alice.waitForFunction(
        () => !document.getElementById('connection-banner').classList.contains('hidden'),
        { timeout: 3000 }
    );
    const bannerDuringDrop = await alice.$eval('#connection-banner-text', el => el.textContent);
    console.log(`[alice] banner during drop: "${bannerDuringDrop}"`);
    check("banner shows a reconnecting message", /reconnect/i.test(bannerDuringDrop));

    console.log("\n--- Test 2: welcome screen must NOT reappear, chat interface stays up ---");
    const welcomeHiddenDuringDrop = await alice.$eval('#welcome-screen', el => el.classList.contains('hidden'));
    const chatVisibleDuringDrop = await alice.$eval('#chat-interface', el => !el.classList.contains('hidden'));
    check("welcome screen stayed hidden while offline", welcomeHiddenDuringDrop);
    check("chat interface stayed visible while offline", chatVisibleDuringDrop);

    console.log("\n--- Test 3: chat history from before the drop is still in the DOM ---");
    const historyStillPresent = await alice.evaluate(() =>
        [...document.querySelectorAll('#chat-window .msg')].some(m => m.textContent.includes('before the drop')));
    check("pre-drop message still visible (no reload occurred)", historyStillPresent);

    console.log("\n--- Test 4: input is disabled while offline ---");
    const inputDisabledWhileOffline = await alice.evaluate(() => {
        const style = getComputedStyle(document.querySelector('.input-area'));
        return style.pointerEvents === 'none';
    });
    check("message input is non-interactive while offline", inputDisabledWhileOffline);

    console.log("\n--- Test 5: reconnect and confirm the session was silently restored ---");
    await goOnline(cdp);
    await alice.waitForFunction(
        () => document.getElementById('connection-banner').classList.contains('hidden'),
        { timeout: 10000 }
    );
    console.log("[alice] banner hidden - reconnect flow completed");

    const reconnectedLogPresent = await alice.evaluate(() =>
        [...document.querySelectorAll('#chat-window .msg.system')].some(m => m.textContent.includes('Reconnected')));
    check("system log shows 'Reconnected'", reconnectedLogPresent);

    const identityStillSame = await alice.$eval('#identity-fingerprint', el => el.textContent);
    check("identity fingerprint still populated after reconnect", identityStillSame.length > 0);

    console.log("\n--- Test 6: a NEW message after reconnecting actually relays (proves real rejoin, not just a hidden banner) ---");
    await sendGlobalMessage(alice, "after reconnecting");
    await bob.waitForFunction(
        (t) => [...document.querySelectorAll('#chat-window .msg')].some(m => m.textContent.includes(t)),
        { timeout: 5000 }, "after reconnecting"
    ).catch(() => {});
    const bobGotPostReconnectMsg = await bob.evaluate(() =>
        [...document.querySelectorAll('#chat-window .msg')].some(m => m.textContent.includes('after reconnecting')));
    check("bob received the post-reconnect message", bobGotPostReconnectMsg);

    console.log("\n--- Test 7: an active call ends cleanly (not stuck) when the connection drops mid-call ---");
    await alice.evaluate(() => {
        const items = document.querySelectorAll('#user-list .user-item');
        for (const item of items) {
            if (item.querySelector('strong')?.textContent === 'bob') {
                item.querySelector('.call-btn').click();
                return;
            }
        }
    });
    await bob.waitForSelector('#incoming-call-modal:not(.hidden)', { timeout: 5000 });
    await bob.click('#accept-call-btn');
    await alice.waitForFunction(
        () => document.getElementById('call-status-text').textContent.includes('In call with'),
        { timeout: 8000 }
    );
    console.log("[alice] call connected, now dropping connection mid-call");

    await goOffline(cdp);
    await wait(500);
    const callBarHiddenAfterDrop = await alice.$eval('#call-status-bar', el => el.classList.contains('hidden'));
    check("call status bar hidden after connection dropped mid-call", callBarHiddenAfterDrop);

    await goOnline(cdp);
    await alice.waitForFunction(
        () => document.getElementById('connection-banner').classList.contains('hidden'),
        { timeout: 10000 }
    );
    console.log("[alice] reconnected after the mid-call drop");

    await browser.close();

    console.log(failures === 0 ? "\nAll reconnection tests passed." : `\n${failures} test(s) FAILED.`);
    process.exit(failures === 0 ? 0 : 1);
})().catch(err => { console.error("E2E error:", err.message); process.exit(1); });
