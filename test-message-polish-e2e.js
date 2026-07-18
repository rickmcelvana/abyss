// Feature phase 2 E2E: per-user message coloring and notifications
// (title-bar unread badge + opt-in desktop notifications). Notification
// permission prompts don't behave reliably/observably in a headless,
// display-less environment, so we inject a controllable fake
// window.Notification before the app loads (via evaluateOnNewDocument) -
// this tests the APP'S logic (when it decides to notify, what it puts in
// the notification, when it clears the badge) rather than the browser's
// own permission UI, which isn't this app's code to test.
const puppeteer = require("puppeteer-core");

const CHROME = "/home/claude/.cache/puppeteer/chrome/linux-131.0.6778.204/chrome-linux64/chrome";
const URL = "http://127.0.0.1:3000";
const wait = (ms) => new Promise(r => setTimeout(r, ms));

async function installFakeNotifications(page) {
    await page.evaluateOnNewDocument(() => {
        window.__firedNotifications = [];
        class FakeNotification {
            constructor(title, options) {
                window.__firedNotifications.push({ title, body: (options && options.body) || '', tag: options && options.tag });
            }
            close() {}
        }
        FakeNotification.requestPermission = () => Promise.resolve('granted');
        FakeNotification.permission = 'granted';
        Object.defineProperty(window, 'Notification', { value: FakeNotification, writable: true, configurable: true });
    });
}

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

/** Simulates the tab being backgrounded: hidden + unfocused. */
async function simulateAway(page) {
    await page.evaluate(() => {
        Object.defineProperty(document, 'hidden', { value: true, configurable: true });
        document.hasFocus = () => false;
        document.dispatchEvent(new Event('visibilitychange'));
    });
}
/** Simulates coming back to the tab: visible + focused. */
async function simulateBack(page) {
    await page.evaluate(() => {
        Object.defineProperty(document, 'hidden', { value: false, configurable: true });
        document.hasFocus = () => true;
        document.dispatchEvent(new Event('visibilitychange'));
        window.dispatchEvent(new Event('focus'));
    });
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
        args: ["--no-sandbox"]
    });

    const ctxA = await browser.createBrowserContext();
    const ctxB = await browser.createBrowserContext();
    const alice = await ctxA.newPage();
    const bob = await ctxB.newPage();
    alice.on("pageerror", e => console.log("[alice pageerror]", e.message));
    bob.on("pageerror", e => console.log("[bob pageerror]", e.message));
    alice.on("dialog", d => d.dismiss().catch(() => {}));
    bob.on("dialog", d => d.dismiss().catch(() => {}));

    await installFakeNotifications(alice);
    await installFakeNotifications(bob);

    await join(alice, "alice");
    await join(bob, "bob");
    await wait(500);

    console.log("\n--- Test 1: per-user nick coloring is applied and consistent ---");
    await sendGlobalMessage(alice, "first message from alice");
    await bob.waitForFunction(
        (t) => [...document.querySelectorAll('#chat-window .msg')].some(m => m.textContent.includes(t)),
        { timeout: 3000 }, "first message from alice"
    );
    await sendGlobalMessage(bob, "hello back from bob");
    await alice.waitForFunction(
        (t) => [...document.querySelectorAll('#chat-window .msg')].some(m => m.textContent.includes(t)),
        { timeout: 3000 }, "hello back from bob"
    );
    await sendGlobalMessage(alice, "second message from alice");
    await bob.waitForFunction(
        (t) => [...document.querySelectorAll('#chat-window .msg')].some(m => m.textContent.includes(t)),
        { timeout: 3000 }, "second message from alice"
    );

    const colors = await bob.evaluate(() => {
        const nicks = [...document.querySelectorAll('#chat-window .msg .nick')];
        return nicks.map(n => ({ text: n.textContent, color: n.style.color }));
    });
    console.log(`[bob] nick colors seen: ${JSON.stringify(colors)}`);
    const aliceColors = colors.filter(c => c.text.includes('alice')).map(c => c.color);
    const bobColors = colors.filter(c => c.text.includes('bob')).map(c => c.color);
    check("alice's nick color is non-empty and consistent across her messages",
        aliceColors.length >= 2 && aliceColors.every(c => c && c === aliceColors[0]));
    check("bob's nick color differs from alice's", bobColors[0] && bobColors[0] !== aliceColors[0]);

    console.log("\n--- Test 2: notification toggle button reflects state ---");
    const beforeClick = await bob.$eval('#notify-toggle', el => ({ text: el.textContent, enabled: el.classList.contains('enabled') }));
    console.log(`[bob] toggle before: ${JSON.stringify(beforeClick)}`);
    check("starts disabled", !beforeClick.enabled && beforeClick.text === '🔕');

    await bob.click('#notify-toggle');
    await wait(200);
    const afterClick = await bob.$eval('#notify-toggle', el => ({ text: el.textContent, enabled: el.classList.contains('enabled') }));
    console.log(`[bob] toggle after enabling: ${JSON.stringify(afterClick)}`);
    check("flips to enabled after click (fake Notification auto-grants)", afterClick.enabled && afterClick.text === '🔔');

    console.log("\n--- Test 3: title badge and desktop notification fire for a message while away, content excluded ---");
    const originalTitle = await bob.evaluate(() => document.title);
    await simulateAway(bob);
    await sendGlobalMessage(alice, "SECRET CONTENT should not leak into notification");
    await bob.waitForFunction(
        (t) => [...document.querySelectorAll('#chat-window .msg')].some(m => m.textContent.includes(t)),
        { timeout: 3000 }, "SECRET CONTENT should not leak into notification"
    );
    await wait(300);

    const titleWhileAway = await bob.evaluate(() => document.title);
    console.log(`[bob] title while away: "${titleWhileAway}" (was "${originalTitle}")`);
    check("title shows an unread badge", titleWhileAway.startsWith('(1)') && titleWhileAway !== originalTitle);

    const fired = await bob.evaluate(() => window.__firedNotifications);
    console.log(`[bob] fired notifications: ${JSON.stringify(fired)}`);
    const globalNotif = fired.find(n => n.tag === 'abyss-global');
    check("a notification fired with the global chat tag", Boolean(globalNotif));
    check("notification does NOT contain the message content",
        Boolean(globalNotif) && !globalNotif.title.includes('SECRET') && !globalNotif.body.includes('SECRET'));

    console.log("\n--- Test 4: coming back clears the title badge ---");
    await simulateBack(bob);
    await wait(200);
    const titleAfterReturn = await bob.evaluate(() => document.title);
    console.log(`[bob] title after returning: "${titleAfterReturn}"`);
    check("title badge cleared on return", titleAfterReturn === originalTitle);

    console.log("\n--- Test 5: private message notification also excludes content, uses a per-sender tag ---");
    await simulateAway(bob);
    await alice.click('#user-list .user-item strong'); // opens a PM tab with bob... actually need alice to click on BOB's row
    await alice.evaluate(() => {
        const row = [...document.querySelectorAll('#user-list .user-item')].find(r => r.dataset.nick === 'bob');
        row.click();
    });
    await alice.waitForSelector('#msg-input', { timeout: 3000 });
    await alice.click('#msg-input');
    await alice.type('#msg-input', 'PRIVATE SECRET here');
    await alice.click('#send-btn');
    await wait(500);

    const firedAfterPm = await bob.evaluate(() => window.__firedNotifications);
    const pmNotif = firedAfterPm.find(n => n.tag === 'abyss-pm-alice');
    console.log(`[bob] pm notification: ${JSON.stringify(pmNotif)}`);
    check("a notification fired with a per-sender PM tag", Boolean(pmNotif));
    check("PM notification does NOT contain the message content",
        Boolean(pmNotif) && !pmNotif.title.includes('PRIVATE SECRET') && !pmNotif.body.includes('PRIVATE SECRET'));

    await browser.close();

    console.log(failures === 0 ? "\nAll message-polish tests passed." : `\n${failures} test(s) FAILED.`);
    process.exit(failures === 0 ? 0 : 1);
})().catch(err => { console.error("E2E error:", err.message); process.exit(1); });
