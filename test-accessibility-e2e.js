// Accessibility pass E2E: real keyboard-only interaction via
// page.keyboard, not just checking that ARIA attributes exist in markup.
// Also includes a direct proof-of-fix for a real XSS bug found while doing
// this pass: createTabUI() used to build tabs via innerHTML with an
// untrusted nickname interpolated directly in.
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

const activeElementInfo = (page) => page.evaluate(() => {
    const el = document.activeElement;
    if (!el) return null;
    return { tag: el.tagName, id: el.id, cls: el.className, role: el.getAttribute('role'), text: el.textContent?.trim().slice(0, 40) };
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
    const alice = await ctxA.newPage();
    const bob = await ctxB.newPage();
    alice.on("pageerror", e => console.log("[alice pageerror]", e.message));
    bob.on("pageerror", e => console.log("[bob pageerror]", e.message));
    alice.on("dialog", d => { console.log("[alice UNEXPECTED DIALOG]", d.message()); d.dismiss().catch(() => {}); });
    bob.on("dialog", d => { console.log("[bob UNEXPECTED DIALOG]", d.message()); d.dismiss().catch(() => {}); });

    console.log("\n--- Test 1: join form inputs have real accessible labels ---");
    await alice.goto(URL, { waitUntil: "networkidle2" });
    const labelCheck = await alice.evaluate(() => {
        const nick = document.getElementById('nick');
        const about = document.getElementById('about');
        return {
            nickHasLabel: nick.labels && nick.labels.length > 0,
            aboutHasLabel: about.labels && about.labels.length > 0
        };
    });
    check("nickname input has an associated <label>", labelCheck.nickHasLabel);
    check("about input has an associated <label>", labelCheck.aboutHasLabel);

    console.log("\n--- Test 2: nickname containing HTML is rendered as text, not markup (XSS fix) ---");
    const maliciousNick = "<b>hack</b>"; // 11 chars, fits the 15-char limit
    await alice.type("#nick", maliciousNick);
    await alice.type("#about", "e2e-bot");
    await alice.click("#join-form button[type=submit]");
    await alice.waitForSelector("#chat-interface:not(.hidden)", { timeout: 5000 });
    console.log(`[alice] joined with nickname: ${maliciousNick}`);

    await join(bob, "bob");
    await wait(500);

    await bob.evaluate(() => {
        const row = [...document.querySelectorAll('#user-list .user-item')].find(r => r.dataset.nick === '<b>hack</b>');
        row.querySelector('.user-open-btn').click();
    });
    await wait(300);
    const tabRendering = await bob.evaluate(() => {
        const tab = [...document.querySelectorAll('#tab-container .tab')].find(t => t.textContent.includes('hack'));
        if (!tab) return null;
        return { textContent: tab.textContent, hasBoldChild: !!tab.querySelector('b'), innerHTML: tab.innerHTML };
    });
    console.log(`[bob] resulting tab: ${JSON.stringify(tabRendering)}`);
    check("tab exists for the malicious nickname", Boolean(tabRendering));
    check("nickname rendered as literal text (contains the angle brackets)",
        Boolean(tabRendering) && tabRendering.textContent.includes('<b>hack</b>'));
    check("no actual <b> element was created (no HTML injection)",
        Boolean(tabRendering) && !tabRendering.hasBoldChild);

    console.log("\n--- Test 3: tab keyboard navigation (Tab, Arrow keys, Enter) ---");
    // bob now has two tabs: global and pm_<b>hack</b>. Tab into the tablist
    // from a known starting point, then use arrow keys to move and Enter
    // to activate - no mouse involved at all from here on.
    await bob.evaluate(() => document.getElementById('tab-global').focus());
    let info = await activeElementInfo(bob);
    check("focus starts on the global tab", info && info.id === 'tab-global');

    await bob.keyboard.press('ArrowRight');
    info = await activeElementInfo(bob);
    console.log(`[bob] focus after ArrowRight: ${JSON.stringify(info)}`);
    check("ArrowRight moves focus to the next tab", info && info.id !== 'tab-global' && info.role === 'tab');

    await bob.keyboard.press('Enter');
    await wait(200);
    const activeTabAfterEnter = await bob.evaluate(() => {
        const active = document.querySelector('#tab-container .tab.active');
        return { id: active?.id, ariaSelected: active?.getAttribute('aria-selected') };
    });
    console.log(`[bob] active tab after Enter: ${JSON.stringify(activeTabAfterEnter)}`);
    check("Enter activates the focused tab", activeTabAfterEnter.id !== 'tab-global');
    check("aria-selected reflects the newly active tab", activeTabAfterEnter.ariaSelected === 'true');

    console.log("\n--- Test 4: user row 'open conversation' button is keyboard-activatable ---");
    // Fresh check with alice's real (non-malicious) row for a clean read
    await bob.evaluate(() => document.getElementById('tab-global').click());
    await wait(200);
    const openBtnFocusable = await bob.evaluate(() => {
        const row = [...document.querySelectorAll('#user-list .user-item')].find(r => r.dataset.nick === 'bob') // bob won't see himself; check any non-self row exists
            || document.querySelector('#user-list .user-open-btn')?.closest('.user-item');
        const btn = document.querySelector('#user-list .user-open-btn');
        if (!btn) return null;
        btn.focus();
        return document.activeElement === btn;
    });
    check("the open-conversation button can receive keyboard focus", openBtnFocusable);

    console.log("\n--- Test 5: incoming call modal traps focus and Escape declines ---");
    await bob.evaluate(() => document.getElementById('tab-global').focus());
    await alice.evaluate(() => {
        const row = [...document.querySelectorAll('#user-list .user-item')].find(r => r.dataset.nick === 'bob');
        row.querySelector('.call-btn').click();
    });
    await bob.waitForSelector('#incoming-call-modal:not(.hidden)', { timeout: 5000 });
    await wait(200);

    const modalFocusInfo = await activeElementInfo(bob);
    console.log(`[bob] focus after modal opens: ${JSON.stringify(modalFocusInfo)}`);
    check("focus moved into the modal automatically", modalFocusInfo && modalFocusInfo.id === 'accept-call-btn');

    const modalRole = await bob.$eval('#incoming-call-modal', el => el.getAttribute('role'));
    check("modal has role=alertdialog", modalRole === 'alertdialog');

    // Tab from the last focusable element should wrap back to the first
    await bob.keyboard.press('Tab'); // accept -> decline
    await bob.keyboard.press('Tab'); // decline -> should wrap to accept
    const wrappedFocus = await activeElementInfo(bob);
    console.log(`[bob] focus after wrapping Tab: ${JSON.stringify(wrappedFocus)}`);
    check("Tab wraps back to the first element (focus trapped)", wrappedFocus && wrappedFocus.id === 'accept-call-btn');

    // Escape should decline the call and restore focus to whatever had it before
    await bob.keyboard.press('Escape');
    await wait(300);
    const modalHiddenAfterEscape = await bob.$eval('#incoming-call-modal', el => el.classList.contains('hidden'));
    check("Escape closes the modal (declines the call)", modalHiddenAfterEscape);

    const focusAfterEscape = await activeElementInfo(bob);
    console.log(`[bob] focus restored to: ${JSON.stringify(focusAfterEscape)}`);
    check("focus was restored to where it was before the modal opened", focusAfterEscape && focusAfterEscape.id === 'tab-global');

    console.log("\n--- Test 6: live regions exist and are configured correctly ---");
    const liveRegions = await bob.evaluate(() => ({
        announcer: document.getElementById('sr-announcer')?.getAttribute('aria-live'),
        chatLog: document.getElementById('chat-window')?.getAttribute('aria-live'),
        chatLogRole: document.getElementById('chat-window')?.getAttribute('role'),
        typingIndicator: document.getElementById('typing-indicator')?.getAttribute('aria-live'),
        connectionBanner: document.getElementById('connection-banner')?.getAttribute('aria-live')
    }));
    console.log(`[bob] live regions: ${JSON.stringify(liveRegions)}`);
    check("shared announcer is a polite live region", liveRegions.announcer === 'polite');
    check("chat window is role=log with aria-live", liveRegions.chatLogRole === 'log' && liveRegions.chatLog === 'polite');
    check("typing indicator is a live region", liveRegions.typingIndicator === 'polite');
    check("connection banner is a live region", liveRegions.connectionBanner === 'polite');

    console.log("\n--- Test 7: a real event (call connecting) actually reaches the shared announcer ---");
    await bob.evaluate(() => { document.getElementById('sr-announcer').textContent = ''; });
    await alice.evaluate(() => {
        const row = [...document.querySelectorAll('#user-list .user-item')].find(r => r.dataset.nick === 'bob');
        row.querySelector('.call-btn').click();
    });
    await bob.waitForSelector('#incoming-call-modal:not(.hidden)', { timeout: 5000 });
    await bob.click('#accept-call-btn');
    await bob.waitForFunction(
        () => document.getElementById('call-status-text').textContent.includes('In call with'),
        { timeout: 8000 }
    );
    await wait(300);
    const announcerText = await bob.$eval('#sr-announcer', el => el.textContent);
    console.log(`[bob] announcer text after the call connected: "${announcerText}"`);
    check("connecting a call produced a real announcement",
        announcerText.includes('connected') || announcerText.includes('Safety code'));
    await bob.click('#hangup-btn');
    await wait(300);

    await browser.close();

    console.log(failures === 0 ? "\nAll accessibility tests passed." : `\n${failures} test(s) FAILED.`);
    process.exit(failures === 0 ? 0 : 1);
})().catch(err => { console.error("E2E error:", err.message); process.exit(1); });
