// Feature phase (mobile/responsive) E2E: real viewport emulation, not just
// "the CSS parses". Checks the sidebar drawer actually opens/closes, the
// desktop layout is untouched, nothing causes horizontal overflow at a
// phone width, and the video panel is meaningfully smaller on a small screen.
const puppeteer = require("puppeteer-core");

const CHROME = "/home/claude/.cache/puppeteer/chrome/linux-131.0.6778.204/chrome-linux64/chrome";
const URL = "http://127.0.0.1:3000";
const wait = (ms) => new Promise(r => setTimeout(r, ms));

const PHONE_VIEWPORT = { width: 375, height: 667 }; // iPhone SE-ish
const DESKTOP_VIEWPORT = { width: 1280, height: 800 };

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

const noHorizontalOverflow = (page) => page.evaluate(
    () => document.documentElement.scrollWidth <= window.innerWidth + 1 // +1 for subpixel rounding
);

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
    alice.on("dialog", d => d.dismiss().catch(() => {}));
    bob.on("dialog", d => d.dismiss().catch(() => {}));

    await alice.setViewport(PHONE_VIEWPORT);
    await bob.setViewport(DESKTOP_VIEWPORT);

    await join(alice, "alice");
    await join(bob, "bob");
    await wait(500);

    console.log("\n--- Test 1: welcome screen doesn't overflow at phone width ---");
    // (checked implicitly by having joined without a broken layout, but
    // let's actually measure - reload and check pre-join too)
    const aliceCtx2 = await browser.createBrowserContext();
    const prejoinPage = await aliceCtx2.newPage();
    await prejoinPage.setViewport(PHONE_VIEWPORT);
    await prejoinPage.goto(URL, { waitUntil: "networkidle2" });
    check("no horizontal overflow on the welcome screen at 375px wide", await noHorizontalOverflow(prejoinPage));
    await aliceCtx2.close();

    console.log("\n--- Test 2: mobile sidebar drawer - hidden by default, toggle visible ---");
    const toggleVisible = await alice.$eval('#sidebar-toggle', el => getComputedStyle(el).display !== 'none');
    check("sidebar toggle button is visible at phone width", toggleVisible);

    const sidebarInitiallyOffscreen = await alice.evaluate(() => {
        const sidebar = document.querySelector('.sidebar');
        const rect = sidebar.getBoundingClientRect();
        return rect.right <= 0; // translated fully off the left edge
    });
    check("sidebar starts off-screen (closed) on a phone", sidebarInitiallyOffscreen);

    console.log("\n--- Test 3: opening and closing the drawer ---");
    await alice.click('#sidebar-toggle');
    await wait(350); // transition
    const sidebarVisibleAfterOpen = await alice.evaluate(() => {
        const rect = document.querySelector('.sidebar').getBoundingClientRect();
        return rect.left >= 0 && rect.width > 0;
    });
    check("sidebar slides into view after tapping the toggle", sidebarVisibleAfterOpen);

    const backdropVisible = await alice.$eval('#sidebar-backdrop', el => getComputedStyle(el).opacity !== '0');
    check("backdrop appears behind the open drawer", backdropVisible);

    await alice.evaluate(() => document.getElementById('sidebar-backdrop').click());
    await wait(350);
    const sidebarClosedAgain = await alice.evaluate(() => {
        const rect = document.querySelector('.sidebar').getBoundingClientRect();
        return rect.right <= 0;
    });
    check("tapping the backdrop closes the drawer", sidebarClosedAgain);

    console.log("\n--- Test 4: tapping a user closes the drawer and opens the PM ---");
    await alice.click('#sidebar-toggle');
    await wait(350);
    await alice.evaluate(() => {
        const row = [...document.querySelectorAll('#user-list .user-item')].find(r => r.dataset.nick === 'bob');
        row.click();
    });
    await wait(350);
    const drawerClosedAfterUserTap = await alice.evaluate(() => {
        const rect = document.querySelector('.sidebar').getBoundingClientRect();
        return rect.right <= 0;
    });
    const pmTabOpened = await alice.evaluate(() => document.getElementById('tab-pm_bob') !== null);
    check("drawer auto-closes after tapping a user", drawerClosedAfterUserTap);
    check("PM tab actually opened", pmTabOpened);

    console.log("\n--- Test 5: desktop viewport is untouched - sidebar always visible, no toggle ---");
    const desktopToggleHidden = await bob.$eval('#sidebar-toggle', el => getComputedStyle(el).display === 'none');
    const desktopSidebarVisible = await bob.evaluate(() => {
        const rect = document.querySelector('.sidebar').getBoundingClientRect();
        return rect.left >= 0 && rect.width > 100; // the real ~260px column, not a collapsed drawer
    });
    check("sidebar toggle stays hidden on desktop", desktopToggleHidden);
    check("sidebar is a normal, always-visible column on desktop", desktopSidebarVisible);

    console.log("\n--- Test 6: no horizontal overflow anywhere in the chat UI at phone width ---");
    check("no horizontal overflow in the chat interface at 375px wide", await noHorizontalOverflow(alice));

    console.log("\n--- Test 7: video panel is scaled down on a phone vs. full-size on desktop ---");
    await alice.evaluate(() => {
        const row = [...document.querySelectorAll('#user-list .user-item')].find(r => r.dataset.nick === 'bob');
        row.querySelector('.call-btn').click();
    });
    await bob.waitForSelector('#incoming-call-modal:not(.hidden)', { timeout: 5000 });

    const modalWidthOk = await bob.evaluate(() => {
        const modal = document.querySelector('.call-modal');
        return modal.getBoundingClientRect().width <= window.innerWidth;
    });
    check("incoming-call modal fits within the viewport", modalWidthOk);

    await bob.click('#accept-call-btn');
    await alice.waitForFunction(
        () => document.getElementById('call-status-text').textContent.includes('In call with'),
        { timeout: 8000 }
    );
    check("call bar itself doesn't cause horizontal overflow on a phone", await noHorizontalOverflow(alice));

    await alice.click('#video-btn');
    await alice.waitForFunction(
        () => !document.getElementById('local-video').classList.contains('hidden'),
        { timeout: 5000 }
    );
    await bob.waitForFunction(
        () => { const v = document.getElementById('remote-video'); return v.srcObject && v.videoWidth > 0; },
        { timeout: 8000 }
    );

    const alicePanelWidth = await alice.$eval('#video-panel', el => el.getBoundingClientRect().width);
    const bobPanelWidth = await bob.$eval('#video-panel', el => el.getBoundingClientRect().width);
    console.log(`[alice/phone] video panel width: ${alicePanelWidth}px, [bob/desktop] video panel width: ${bobPanelWidth}px`);
    check("video panel is meaningfully smaller on the phone than on desktop", alicePanelWidth < bobPanelWidth * 0.7);
    check("video panel doesn't itself cause horizontal overflow on the phone", await noHorizontalOverflow(alice));

    await alice.click('#hangup-btn');
    await wait(500);

    await browser.close();

    console.log(failures === 0 ? "\nAll mobile/responsive tests passed." : `\n${failures} test(s) FAILED.`);
    process.exit(failures === 0 ? 0 : 1);
})().catch(err => { console.error("E2E error:", err.message); process.exit(1); });
