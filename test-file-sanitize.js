// Unit test for M2: receiver-side filename sanitization and file-offer
// metadata validation. Confirms sanitizeFileName strips path traversal,
// control chars, leading dots, and coerces non-strings; and that the
// file-offer validation rejects bad size values. Mirrors the client helper
// (which runs in the browser) using plain JS - no DOM, no server needed.
//
// Run: node test-file-sanitize.js

const MAX_FILE_NAME_LEN = 255;
function sanitizeFileName(name) {
    if (typeof name !== 'string') return 'file';
    let clean = name
        .replace(/[\\/]/g, '')          // strip path separators
        .replace(/[\x00-\x1F\x7F]/g, '') // strip control chars
        .replace(/^\.+/g, '')           // strip leading dots
        .replace(/\s+/g, ' ')           // collapse whitespace
        .trim()
        .slice(0, MAX_FILE_NAME_LEN);
    return clean || 'file';
}

// Mirror of the size validation added to the file_offer handler.
const MAX_FILE_SIZE = 200 * 1024 * 1024;
function isAcceptableSize(size) {
    return typeof size === 'number' && Number.isFinite(size) && size >= 0 && size <= MAX_FILE_SIZE;
}

let failures = 0;
function check(label, cond) {
    console.log(`${cond ? "PASS" : "FAIL"} - ${label}`);
    if (!cond) failures++;
}

(function () {
    // --- sanitizeFileName ---
    check("path traversal (unix) stripped", sanitizeFileName("../../etc/passwd") === "etcpasswd");
    check("path traversal (windows) stripped", sanitizeFileName("..\\..\\windows\\system32") === "windowssystem32");
    check("normal name preserved", sanitizeFileName("report.pdf") === "report.pdf");
    check("leading dots stripped (dotfile)", sanitizeFileName(".bashrc") === "bashrc");
    check("NUL byte stripped", sanitizeFileName("hello\x00world") === "helloworld");
    check("newline stripped", sanitizeFileName("line\nbreak") === "linebreak");
    check("del char stripped", sanitizeFileName("del\x7Fete") === "delete");
    check("whitespace collapsed", sanitizeFileName("   spaced   ") === "spaced");
    check("empty -> 'file'", sanitizeFileName("") === "file");
    check("whitespace-only -> 'file'", sanitizeFileName("   ") === "file");
    check("null -> 'file'", sanitizeFileName(null) === "file");
    check("undefined -> 'file'", sanitizeFileName(undefined) === "file");
    check("number -> 'file'", sanitizeFileName(123) === "file");
    check("long name capped at 255", sanitizeFileName("a".repeat(300)).length === 255);
    check("trailing slash stripped", sanitizeFileName("folder/") === "folder");
    check("mixed traversal + control", sanitizeFileName("../\x00evil.exe") === "evil.exe");

    // --- size validation ---
    check("valid size accepted", isAcceptableSize(1024) === true);
    check("zero size accepted", isAcceptableSize(0) === true);
    check("max size accepted", isAcceptableSize(MAX_FILE_SIZE) === true);
    check("negative size rejected", isAcceptableSize(-1) === false);
    check("NaN size rejected", isAcceptableSize(NaN) === false);
    check("Infinity size rejected", isAcceptableSize(Infinity) === false);
    check("over-max size rejected", isAcceptableSize(MAX_FILE_SIZE + 1) === false);
    check("string size rejected", isAcceptableSize("1024") === false);
    check("null size rejected", isAcceptableSize(null) === false);

    console.log(
        failures === 0
            ? "\nAll file-sanitize tests passed."
            : `\n${failures} test(s) failed.`
    );
    process.exit(failures === 0 ? 0 : 1);
})();