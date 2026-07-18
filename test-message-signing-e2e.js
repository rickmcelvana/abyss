// Phase 1 (second hardening round) E2E: chat message signing, exercised
// through the real UI in real browsers. Server-side signature/replay
// rejection is already covered thoroughly in test-calls.js; this test's
// job is the client-side trust anchor - does a message actually render as
// unverifiable when the sender's pinned identity key doesn't match, using
// the real appendMessageToDOM/verifyIncomingMessage code paths.
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

const lastMsgBubble = (page) => page.evaluate(() => {
    const bubbles = [...document.querySelectorAll('#chat-window .msg')];
    const last = bubbles[bubbles.length - 1];
    if (!last) return null;
    return { text: last.textContent, tampered: last.classList.contains('tampered') };
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

    console.log("\n--- Test 1: a genuinely signed message renders normally ---");
    await sendGlobalMessage(alice, "hello bob, this is really me");
    await bob.waitForFunction(
        (text) => [...document.querySelectorAll('#chat-window .msg')].some(m => m.textContent.includes(text)),
        { timeout: 3000 },
        "hello bob, this is really me"
    );
    const bubble1 = await lastMsgBubble(bob);
    console.log(`[bob] last message bubble: ${JSON.stringify(bubble1)}`);
    check("message rendered normally, not flagged tampered", bubble1 && !bubble1.tampered && bubble1.text.includes("hello bob"));

    console.log("\n--- Test 2: simulate a key change for alice (from bob's point of view) ---");
    // Same honest technique as test-identity-e2e.js: seed bob's own pinned
    // fingerprint for "alice" with a value that won't match her real key,
    // then force a fresh user_list so bob's client actually recomputes
    // trust status against it - exactly what a genuine key change looks
    // like from the inside, without needing to stage real impersonation
    // (which the server's join-time checks already prevent - see test-calls.js).
    await bob.evaluate(() => {
        return new Promise((resolve, reject) => {
            const req = indexedDB.open('abyss-identity-store', 1);
            req.onsuccess = () => {
                const db = req.result;
                const tx = db.transaction('trust', 'readwrite');
                tx.objectStore('trust').put({ fingerprint: '0000 0000 0000 0000 0000 0000 0000 0000', verified: false }, 'alice');
                tx.oncomplete = resolve;
                tx.onerror = () => reject(tx.error);
            };
            req.onerror = () => reject(req.error);
        });
    });

    const ctxC = await browser.createBrowserContext();
    const carol = await ctxC.newPage();
    carol.on("dialog", d => d.dismiss().catch(() => {}));
    await join(carol, "carol"); // broadcasts a fresh user_list to everyone, including bob
    await wait(600);

    console.log("\n--- Test 3: a validly-signed message from alice now renders as unverifiable ---");
    await sendGlobalMessage(alice, "still me, nothing changed on my end");
    await bob.waitForFunction(
        () => {
            const bubbles = [...document.querySelectorAll('#chat-window .msg')];
            const last = bubbles[bubbles.length - 1];
            return last && (last.classList.contains('tampered') || last.textContent.includes('still me'));
        },
        { timeout: 3000 }
    );
    const bubble2 = await lastMsgBubble(bob);
    console.log(`[bob] last message bubble: ${JSON.stringify(bubble2)}`);
    check("message flagged as unverifiable", bubble2 && bubble2.tampered);
    check("original content NOT shown in the warning bubble", bubble2 && !bubble2.text.includes("still me"));

    await browser.close();

    console.log(failures === 0 ? "\nAll message signing E2E tests passed." : `\n${failures} test(s) FAILED.`);
    process.exit(failures === 0 ? 0 : 1);
})().catch(err => { console.error("E2E error:", err.message); process.exit(1); });
