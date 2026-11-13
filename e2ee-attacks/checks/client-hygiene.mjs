// Where keys and meeting data can end up on the client, answering checklist rows
// KEY-04 (keys in logs or on disk), CLI-02 (telemetry), CLI-03 (debug features
// expose keys) and CLI-06 (data stored after a meeting).
//
// Alice and Bob hold an end-to-end encrypted meeting for 30 s, then leave. The
// published Inspector records every media key each browser held. The script then
// looks for those keys, as raw bytes, hex, base64 at any alignment, or a list of
// byte values (extension/inspector/leak-scan.js), in:
//
//   - everything the browsers sent: every HTTP request (URL and body), and every
//     WebSocket and data-channel message (the Inspector's own scan);
//   - every console message of the page, its frames and workers (what a log
//     upload or a debug session would see);
//   - everything the page's code can reach: a walk of the objects reachable from
//     the page's global scope (the key vault keeps keys out of it);
//   - the browser storage the meeting leaves behind: localStorage, sessionStorage,
//     IndexedDB, Cache Storage, cookies and service workers.
//
// It also lists every host the browsers contacted (telemetry inventory) and checks
// that the deployment serves no source maps.
//
//   node checks/client-hygiene.mjs [--url <meeting URL>] [--lib <dir>] [--headed]
//
// Keep the room empty apart from the two browsers this opens.

import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { chromium } from 'playwright-core';
import { joinMeeting, leaveMeeting, meetingTarget, waitInPage } from '../harness/meeting.mjs';
import '../../extension/inspector/leak-scan.js';

const { scan } = globalThis.E2EELeakScan;
const HERE = path.dirname(fileURLToPath(import.meta.url));
const argv = process.argv.slice(2);
const arg = name => (argv.includes(name) ? argv[argv.indexOf(name) + 1] : null);
const headed = argv.includes('--headed');
const libDir = arg('--lib');
const libFiles = libDir ? [
    [ 'lib-jitsi-meet.min.js', 'text/javascript' ],
    [ 'lib-jitsi-meet.e2ee-worker.js', 'text/javascript' ],
    [ 'lib-jitsi-meet.e2ee-vault.js', 'text/javascript' ],
    [ 'lib-jitsi-meet.e2ee-vault.html', 'text/html' ],
    [ 'olm.js', 'text/javascript' ]
].filter(([ file ]) => fs.existsSync(path.join(libDir, file)))
    .map(([ file, contentType ]) => [ file, fs.readFileSync(path.join(libDir, file)), contentType ]) : [];
const target = meetingTarget(argv, 'hygiene');
const sleep = ms => new Promise(r => setTimeout(r, ms));
const log = m => console.log(`[${new Date().toISOString().slice(11, 19)}] ${m}`);
const results = [];
const check = (id, name, ok, detail) => results.push({ id, name, ok, detail });

setTimeout(() => {
    console.error('run exceeded 5 minutes, aborting');
    process.exit(1);
}, 300000).unref();

const browser = await chromium.launch({ channel: 'chrome', headless: !headed, args: [
    '--use-fake-ui-for-media-stream',
    '--use-fake-device-for-media-stream',
    '--autoplay-policy=no-user-gesture-required',
    '--disable-features=LocalNetworkAccessChecks,PrivateNetworkAccessRespectPreflightResults,BlockInsecurePrivateNetworkRequests'
] });

const requests = []; // { who, method, url, body }
const consoleText = []; // { who, text }

async function join(name) {
    const context = await browser.newContext({ ignoreHTTPSErrors: true });

    for (const [ file, body, contentType ] of libFiles) {
        await context.route(new RegExp(`/libs/${file.replace(/\./g, '\\.')}(\\?|$)`),
            r => r.fulfill({ body, contentType }));
    }
    context.on('request', r => requests.push({ who: name, method: r.method(), url: r.url(), body: r.postDataBuffer() }));
    const page = await context.newPage();

    page.on('console', m => consoleText.push({ who: name, text: m.text() }));
    await page.addInitScript({ path: path.join(HERE, '../../extension/inspector/leak-scan.js') });
    await page.addInitScript({ path: path.join(HERE, '../../extension/inspector/hook.js') });
    await joinMeeting(page, target.url({
        'config.startWithAudioMuted': false,
        'config.startWithVideoMuted': false,
        'userInfo.displayName': name
    }), name);

    return page;
}

// Every 32-byte Uint8Array or ArrayBuffer reachable from the page's global scope
// that equals one of `keys`; the Inspector's own state is skipped.
const reachable = (page, keys) => page.evaluate(keyList => {
    const wanted = new Set(keyList.map(k => k.join(',')));
    const skip = new Set([ '__e2eeInspector', 'E2EELeakScan', '__replayTap' ]);
    const seen = new WeakSet();
    const queue = [ [ window, 'window' ] ];
    const found = [];
    let visited = 0;
    let cryptoKeys = 0;

    while (queue.length && visited < 400000) {
        const [ obj, where ] = queue.shift();

        if (!obj || (typeof obj !== 'object' && typeof obj !== 'function') || seen.has(obj)) {
            continue;
        }
        seen.add(obj);
        visited++;
        if (typeof CryptoKey !== 'undefined' && obj instanceof CryptoKey) {
            cryptoKeys++;
            continue;
        }
        if (obj instanceof ArrayBuffer || ArrayBuffer.isView(obj)) {
            const bytes = obj instanceof ArrayBuffer ? new Uint8Array(obj)
                : new Uint8Array(obj.buffer, obj.byteOffset, obj.byteLength);

            bytes.length === 32 && wanted.has(Array.from(bytes).join(',')) && found.push(where);
            continue;
        }
        if (obj instanceof Node || obj === document) {
            continue;
        }
        let names = [];

        try {
            names = Reflect.ownKeys(obj);
        } catch {}
        for (const n of names) {
            if (obj === window && skip.has(n)) {
                continue;
            }
            let v;

            try {
                const d = Object.getOwnPropertyDescriptor(obj, n);

                v = d && 'value' in d ? d.value : undefined;
            } catch {}
            v && (typeof v === 'object' || typeof v === 'function')
                && queue.push([ v, `${where}.${String(n)}`.slice(0, 160) ]);
        }
        if (obj instanceof Map || obj instanceof Set) {
            let i = 0;

            for (const v of obj.values()) {
                queue.push([ v, `${where}[${i++}]` ]);
            }
        }
    }

    return { found, visited, cryptoKeys };
}, keys);

// What the meeting left in this origin's storage, as name/value text to scan.
const storage = async page => {
    const inPage = await page.evaluate(async () => {
        const entries = [];

        for (const [ kind, store ] of [ [ 'localStorage', localStorage ], [ 'sessionStorage', sessionStorage ] ]) {
            for (let i = 0; i < store.length; i++) {
                const k = store.key(i);

                entries.push({ kind, name: k, value: store.getItem(k) });
            }
        }
        const dbs = indexedDB.databases ? await indexedDB.databases() : [];

        for (const db of dbs) {
            entries.push({ kind: 'IndexedDB', name: db.name, value: '' });
        }
        for (const name of await caches.keys()) {
            entries.push({ kind: 'Cache Storage', name, value: '' });
        }
        for (const reg of await navigator.serviceWorker?.getRegistrations?.() ?? []) {
            entries.push({ kind: 'service worker', name: reg.scope, value: '' });
        }

        return entries;
    });
    const cookies = (await page.context().cookies()).map(c => ({ kind: 'cookie', name: `${c.domain} ${c.name}`,
        value: c.value }));

    return [ ...inPage, ...cookies ];
};

// ---- The meeting ------------------------------------------------------------

log(`room ${target.room}`);
const alice = await join('alice');
const bob = await join('bob');

await sleep(3000);
await alice.evaluate(() => APP.store.dispatch({ type: 'TOGGLE_E2EE', enabled: true }));
await waitInPage(alice, () => APP.conference._room.isE2EEEnabled(), null, 30000);
await waitInPage(bob, () => APP.conference._room.isE2EEEnabled(), null, 30000);
log('E2EE on; meeting for 30 s');
await sleep(30000);

const metas = { alice: await alice.evaluate(() => window.__e2eeInspector.exportMeta()),
    bob: await bob.evaluate(() => window.__e2eeInspector.exportMeta()) };
const keys = Object.values(metas).flatMap(m => m.keys.filter(k => k.key));
const uniqueKeys = [ ...new Map(keys.map(k => [ k.key.join(','), k ])).values() ];
const walks = { alice: await reachable(alice, uniqueKeys.map(k => k.key)),
    bob: await reachable(bob, uniqueKeys.map(k => k.key)) };
const leaks = { alice: await alice.evaluate(() => window.__e2eeInspector.leakCheck()),
    bob: await bob.evaluate(() => window.__e2eeInspector.leakCheck()) };

await Promise.all([ alice, bob ].map(leaveMeeting));
await sleep(3000);
const stored = { alice: await storage(alice), bob: await storage(bob) };

// Source maps: the bundles name them, the server must not serve them.
const origin = new URL(target.url({})).origin;
const maps = [];

for (const file of [ 'app.bundle.min.js.map', 'lib-jitsi-meet.min.map', 'external_api.min.map' ]) {
    const r = await alice.evaluate(async u => (await fetch(u)).status, `${origin}/libs/${file}`).catch(() => 'error');

    maps.push(`${file}: ${r}`);
}
await browser.close();

// ---- Results ------------------------------------------------------------------

const findIn = (items, text) => items.flatMap(it => scan(text(it), uniqueKeys).map(f => ({ ...f, where: it })));

const requestHits = findIn(requests, r => `${r.url}\n${r.body ? r.body.toString('latin1') : ''}`);
const consoleHits = findIn(consoleText, c => c.text);
const storageHits = findIn([ ...stored.alice, ...stored.bob ], s => `${s.name}\n${s.value ?? ''}`);

check('KEY-04', 'keys held during the meeting (control)', uniqueKeys.length >= 2, `${uniqueKeys.length} distinct media keys`);
check('KEY-04', 'no media key in any console message (page, frames, workers)', consoleHits.length === 0,
    `${consoleText.length} messages scanned, ${consoleHits.length} with a key`);
check('KEY-04', 'no media key in browser storage after the meeting', storageHits.length === 0,
    `${stored.alice.length + stored.bob.length} entries scanned, ${storageHits.length} with a key`);
check('CLI-02', 'no media key in any HTTP request (URL or body)', requestHits.length === 0,
    `${requests.length} requests scanned, ${requestHits.length} with a key`);
for (const [ who, l ] of Object.entries(leaks)) {
    check('CLI-02', `${who}: no media key in any WebSocket or data-channel message`, l.findings.length === 0,
        `${l.scanned.websocket} WebSocket and ${l.scanned.datachannel} data-channel messages, ${l.keysChecked} keys`);
}
for (const [ who, w ] of Object.entries(walks)) {
    check('CLI-03', `${who}: no media key reachable from the page's code`, w.found.length === 0,
        `${w.visited} objects walked${w.found.length ? `; found at ${w.found.slice(0, 3).join(', ')}` : ''}`);
}
check('CLI-03', 'the deployment serves no source maps', maps.every(m => /: 404$/.test(m)), maps.join(', '));

console.log('\nHosts contacted (method, requests, example path):');
const byHost = new Map();

for (const r of requests) {
    const u = new URL(r.url);

    if (!/^https?:|^wss?:/.test(u.protocol)) {
        continue;
    }
    const e = byHost.get(u.host) ?? { n: 0, methods: new Set(), paths: new Set() };

    e.n++;
    e.methods.add(r.method);
    e.paths.size < 3 && e.paths.add(u.pathname.slice(0, 60));
    byHost.set(u.host, e);
}
for (const [ host, e ] of [ ...byHost ].sort((a, b) => b[1].n - a[1].n)) {
    console.log(`  ${host.padEnd(48)} ${[ ...e.methods ].join('/').padEnd(10)} ${String(e.n).padStart(5)}  ${[ ...e.paths ].join(' ')}`);
}

console.log('\nStorage left after the meeting (names only):');
for (const [ who, entries ] of Object.entries(stored)) {
    console.log(`  ${who}: ${entries.map(e => `${e.kind} ${e.name}`).join('; ') || 'nothing'}`);
}

console.log('');
for (const r of results) {
    console.log(`${r.ok ? 'PASS' : 'FAIL'}  ${r.id}  ${r.name}  (${r.detail})`);
}
const ok = results.every(r => r.ok);

console.log(ok ? '\nVERDICT: secure — no media key in logs, storage, outgoing traffic or the page\'s reach.'
    : '\nVERDICT: INSECURE — a media key was found (see FAIL lines).');
process.exit(ok ? 0 : 1);
