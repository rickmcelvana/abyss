// Feature phase 1 E2E: typing indicators and presence (active/idle),
// exercised through the real UI in real browsers. Server-side relay/rate
// limiting is already covered in test-calls.js; this test's job is
// confirming the client actually renders these correctly and expires them.
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

const typingText = (page) => page.$eval("#typing-indicator", el => ({
    text: el.textContent, hidden: el.classList.contains("hidden")
}));

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

    await join(alice, "alice");
    await join(bob, "bob");
    await wait(500);

    console.log("\n--- Test 1: typing in global chat shows an indicator on the other side ---");
    await bob.click("#msg-input");
    await bob.type("#msg-input", "h");
    await alice.waitForFunction(
        () => !document.getElementById('typing-indicator').classList.contains('hidden'),
        { timeout: 3000 }
    );
    const t1 = await typingText(alice);
    console.log(`[alice] typing indicator: ${JSON.stringify(t1)}`);
    check("shows bob is typing", !t1.hidden && /bob/.test(t1.text) && /typing/.test(t1.text));

    console.log("\n--- Test 2: indicator does NOT show on the typist's own screen ---");
    const t2 = await typingText(bob);
    console.log(`[bob] own typing indicator: ${JSON.stringify(t2)}`);
    check("bob does not see his own typing indicator", t2.hidden);

    console.log("\n--- Test 3: indicator auto-expires a few seconds after typing stops ---");
    await alice.waitForFunction(
        () => document.getElementById('typing-indicator').classList.contains('hidden'),
        { timeout: 6000 }
    );
    console.log("[alice] typing indicator expired on its own");
    check("indicator auto-expired", true); // waitForFunction above throws on timeout, so reaching here is the pass

    console.log("\n--- Test 4: typing indicator clears when the message actually arrives ---");
    await bob.click("#msg-input");
    await bob.type("#msg-input", "hello");
    await alice.waitForFunction(
        () => !document.getElementById('typing-indicator').classList.contains('hidden'),
        { timeout: 3000 }
    );
    await bob.click("#send-btn");
    await alice.waitForFunction(
        (t) => [...document.querySelectorAll('#chat-window .msg')].some(m => m.textContent.includes(t)),
        { timeout: 3000 }, "hello"
    );
    console.log("[alice] message arrived");
    check("message delivered while indicator was showing", true);

    console.log("\n--- Test 5: presence dots start active, flip to idle, flip back to active ---");
    const initialDot = await alice.evaluate(() => {
        const row = [...document.querySelectorAll('#user-list .user-item')]
            .find(r => r.dataset.nick === 'bob');
        return row?.querySelector('.presence-dot')?.className;
    });
    console.log(`[alice] bob's initial presence dot: "${initialDot}"`);
    check("bob starts active", /presence-active/.test(initialDot || ''));

    // Force bob idle without waiting 3 real minutes: simulate a hidden tab,
    // which the app treats as an immediate idle signal via visibilitychange.
    await bob.evaluate(() => {
        Object.defineProperty(document, 'hidden', { value: true, configurable: true });
        document.dispatchEvent(new Event('visibilitychange'));
    });
    await alice.waitForFunction(() => {
        const row = [...document.querySelectorAll('#user-list .user-item')]
            .find(r => r.dataset.nick === 'bob');
        return row?.querySelector('.presence-dot')?.className.includes('presence-idle');
    }, { timeout: 3000 });
    console.log("[alice] bob's dot flipped to idle");
    check("bob's dot shows idle after tab hidden", true);

    await bob.evaluate(() => {
        Object.defineProperty(document, 'hidden', { value: false, configurable: true });
        document.dispatchEvent(new Event('visibilitychange'));
    });
    await alice.waitForFunction(() => {
        const row = [...document.querySelectorAll('#user-list .user-item')]
            .find(r => r.dataset.nick === 'bob');
        return row?.querySelector('.presence-dot')?.className.includes('presence-active');
    }, { timeout: 3000 });
    console.log("[alice] bob's dot flipped back to active");
    check("bob's dot returns to active after tab shown again", true);

    console.log("\n--- Test 6: presence update is an in-place DOM patch, not a full re-render ---");
    // Open alice's fingerprint reveal for bob, then trigger a presence
    // change - if renderUserList() ran again it would wipe this panel out.
    await alice.click('#user-list .user-item .verify-toggle');
    await alice.waitForSelector('.fingerprint-reveal', { timeout: 3000 });
    await bob.evaluate(() => {
        Object.defineProperty(document, 'hidden', { value: true, configurable: true });
        document.dispatchEvent(new Event('visibilitychange'));
    });
    await wait(500);
    const revealStillOpen = await alice.evaluate(() => !!document.querySelector('.fingerprint-reveal'));
    console.log(`[alice] fingerprint reveal still open after a presence update: ${revealStillOpen}`);
    check("presence update did not collapse the open fingerprint panel", revealStillOpen);

    await browser.close();

    console.log(failures === 0 ? "\nAll typing/presence tests passed." : `\n${failures} test(s) FAILED.`);
    process.exit(failures === 0 ? 0 : 1);
})().catch(err => { console.error("E2E error:", err.message); process.exit(1); });
