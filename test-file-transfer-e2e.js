// Feature phase 4 E2E: encrypted P2P file transfer. Uploads a REAL file
// with random content, transfers it peer-to-peer over a WebRTC data
// channel, and verifies the received bytes hash identically to the
// original - not just "something arrived", but that it arrived correct.
const puppeteer = require("puppeteer-core");
const crypto = require("crypto");
const fs = require("fs");
const path = require("path");

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

async function openPmTab(page, nick) {
    await page.evaluate((n) => {
        const row = [...document.querySelectorAll('#user-list .user-item')].find(r => r.dataset.nick === n);
        row.click();
    }, nick);
    await wait(300);
}

let failures = 0;
function check(label, cond) {
    console.log(`${cond ? 'PASS' : 'FAIL'} - ${label}`);
    if (!cond) failures++;
}

(async () => {
    // A real file with random content - large enough to require several
    // hundred 16KB chunks, so this actually exercises the chunking and
    // backpressure logic, not just a one-packet transfer.
    const fileBytes = crypto.randomBytes(300 * 1024);
    const expectedHash = crypto.createHash("sha256").update(fileBytes).digest("hex");
    const tmpFilePath = path.join(require("os").tmpdir(), `abyss-test-file-${Date.now()}.bin`);
    fs.writeFileSync(tmpFilePath, fileBytes);
    console.log(`Test file: ${tmpFilePath} (${fileBytes.length} bytes, sha256 ${expectedHash.slice(0, 16)}...)`);

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
    bob.on("console", m => { if (m.type() === 'error') console.log("[bob console error]", m.text()); });
    alice.on("dialog", d => d.dismiss().catch(() => {}));
    bob.on("dialog", d => d.dismiss().catch(() => {}));

    await join(alice, "alice");
    await join(bob, "bob");
    await wait(500);

    console.log("\n--- Test 1: attach button is hidden on global, visible in a PM ---");
    const attachHiddenOnGlobal = await alice.$eval('#attach-file-btn', el => el.classList.contains('hidden'));
    check("attach button hidden while viewing global chat", attachHiddenOnGlobal);

    await openPmTab(alice, "bob");
    const attachVisibleInPm = await alice.$eval('#attach-file-btn', el => !el.classList.contains('hidden'));
    check("attach button visible in a PM tab", attachVisibleInPm);

    console.log("\n--- Test 2: alice sends a real file, bob accepts, and it arrives byte-identical ---");
    const filePickerHandle = await alice.$('#file-picker');
    await filePickerHandle.uploadFile(tmpFilePath);

    await bob.waitForSelector('#incoming-file-modal:not(.hidden)', { timeout: 5000 });
    const incomingText = await bob.$eval('#incoming-file-text', el => el.textContent);
    console.log(`[bob] incoming file prompt: "${incomingText}"`);
    check("incoming prompt names alice and the file size", /alice/.test(incomingText) && /KB|MB/.test(incomingText));

    await bob.click('#accept-file-btn');

    // Wait for completion on both sides
    await alice.waitForFunction(
        () => { const b = document.querySelector('.msg.file-transfer'); return b && b.classList.contains('status-complete'); },
        { timeout: 20000 }
    );
    await bob.waitForFunction(
        () => { const b = document.querySelector('.msg.file-transfer'); return b && b.classList.contains('status-complete'); },
        { timeout: 20000 }
    );
    console.log("transfer completed on both sides");

    const bobBubble = await bob.$eval('.msg.file-transfer', el => ({
        meta: el.querySelector('.file-meta').textContent,
        hasDownload: !!el.querySelector('.file-download-link')
    }));
    console.log(`[bob] bubble: ${JSON.stringify(bobBubble)}`);
    check("bob's bubble shows 'received' and a download link", /received/.test(bobBubble.meta) && bobBubble.hasDownload);

    const aliceBubbleMeta = await alice.$eval('.msg.file-transfer .file-meta', el => el.textContent);
    console.log(`[alice] bubble meta: "${aliceBubbleMeta}"`);
    check("alice's bubble shows 'sent'", /sent/.test(aliceBubbleMeta));

    // The real correctness check: fetch the blob: URL from inside bob's
    // page and hash it there, then compare to the hash computed in Node
    // from the original bytes before it ever touched the browser.
    const receivedHash = await bob.evaluate(async () => {
        const link = document.querySelector('.file-download-link');
        try {
            const resp = await fetch(link.href);
            const buf = await resp.arrayBuffer();
            const digest = await crypto.subtle.digest('SHA-256', buf);
            return [...new Uint8Array(digest)].map(b => b.toString(16).padStart(2, '0')).join('');
        } catch (err) {
            return `ERROR: ${err.name}: ${err.message} (href was: ${link.href})`;
        }
    });
    console.log(`expected: ${expectedHash}`);
    console.log(`received: ${receivedHash}`);
    check("received file is byte-identical to the original (hash match)", receivedHash === expectedHash);

    console.log("\n--- Test 3: decline flow ---");
    const filePickerHandle2 = await alice.$('#file-picker');
    await filePickerHandle2.uploadFile(tmpFilePath);
    await bob.waitForSelector('#incoming-file-modal:not(.hidden)', { timeout: 5000 });
    await bob.click('#decline-file-btn');
    await alice.waitForFunction(
        () => [...document.querySelectorAll('.msg.file-transfer')].some(b => b.classList.contains('status-declined')),
        { timeout: 5000 }
    );
    console.log("alice's bubble shows declined");
    check("declined transfer shows no lingering incoming modal on bob's side",
        await bob.$eval('#incoming-file-modal', el => el.classList.contains('hidden')));

    console.log("\n--- Test 4: sender cancels before acceptance ---");
    const filePickerHandle3 = await alice.$('#file-picker');
    await filePickerHandle3.uploadFile(tmpFilePath);
    await bob.waitForSelector('#incoming-file-modal:not(.hidden)', { timeout: 5000 });
    // Cancel from alice's side while bob still has the prompt open
    await alice.evaluate(() => {
        const bubbles = [...document.querySelectorAll('.msg.file-transfer')];
        const pending = bubbles[bubbles.length - 1];
        pending.querySelector('.file-cancel-link').click();
    });
    await alice.waitForFunction(
        () => {
            const bubbles = [...document.querySelectorAll('.msg.file-transfer')];
            return bubbles[bubbles.length - 1].classList.contains('status-canceled');
        },
        { timeout: 5000 }
    );
    console.log("alice's bubble shows canceled");
    check("canceled transfer shown correctly", true);

    fs.unlinkSync(tmpFilePath);
    await browser.close();

    console.log(failures === 0 ? "\nAll file transfer tests passed." : `\n${failures} test(s) FAILED.`);
    process.exit(failures === 0 ? 0 : 1);
})().catch(err => { console.error("E2E error:", err.message); process.exit(1); });
