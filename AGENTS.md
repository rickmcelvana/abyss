# AGENTS.md — Abyss.Tunnel

Single-file encrypted chat room (Express + Socket.IO server, vanilla JS client). No build step, no bundler, no TypeScript, no test runner.

## Structure

- `server.js` — signaling + relay server (all backend logic)
- `public/client.js` — all client-side logic (crypto, WebRTC, UI, IndexedDB)
- `public/index.html`, `public/style.css` — shell and styling
- `test-*.js` — flat test files, no framework, run directly with `node`

All state is in-memory. No database, no migrations, no codegen.

## Commands

```bash
npm start                        # starts server on http://127.0.0.1:3000
node test-turn-hmac.js           # unit test (no server needed)
node test-identity-crypto.js     # unit test (no server needed)
node test-access-control.js      # self-contained (spawns its own server)
node test-calls.js               # needs server running + special env vars
```

`npm test` is a stub that exits with error. There is no test runner config.

### Running test-calls.js

Requires higher connection cap than the default:

```bash
# Terminal 1
RING_TIMEOUT_MS=3000 MAX_CONNECTIONS_PER_IP=20 npm start
# Terminal 2
RING_TIMEOUT_MS=3000 node test-calls.js
```

### E2E browser tests (test-*-e2e.js)

Require `puppeteer-core` and Chrome. The `CHROME` constant at the top of each file is hardcoded to a Linux path — update it before running on Windows or a different install. Server must be running.

## Gotchas

- No lint, no formatter, no typecheck commands exist.
- `puppeteer-core` and `socket.io-client` are in `dependencies` (not `devDependencies`) — only needed for tests.
- Express v5 is used (not v4) — routing and middleware APIs differ.
- Nicknames are capped at 15 characters server-side (`server.js`).
- Room password and per-IP cap are env-var driven, not config-file driven.
- `dotenv` is loaded at the top of `server.js` — `.env` is picked up automatically.
- Socket.IO and Express CORS default to `origin: "*"` (open, for local dev). Set `ALLOWED_ORIGIN=https://your.domain` in production to restrict cross-origin access.
- Per-IP connection cap reads `socket.handshake.address`. Behind a reverse proxy (nginx, cloudflared), set `TRUST_PROXY=1` so it honors `X-Forwarded-For`; otherwise every connection appears to come from the proxy's IP.
