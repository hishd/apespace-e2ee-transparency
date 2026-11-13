// Frame counter and replay checks, answering checklist rows ENC-03 and ENC-04.
//
// Alice and Bob hold an end-to-end encrypted meeting. Bob's browser carries a tap
// (harness/replay-tap.js) on the encrypted frames between the network and his
// decryption: exactly where a malicious media server sits.
//
//   ENC-03  The IV never repeats under one key: every encrypted frame Bob receives
//           has a distinct IV, each stream's counter goes up by one per frame,
//           and the counter uses its full 32 bits.
//   ENC-04  Replays are rejected: the tap replaces the payload of later audio
//           frames with genuine frames Alice sent earlier, as a server replaying
//           them would. Those frames still decrypt with Alice's key, so only a
//           replay check stops them. The check counts how many come out of Bob's
//           decryption to be played:
//             - frames from about 1 s earlier (already seen: exact replays);
//             - frames from about 30 s earlier (far behind: stale).
//
//   node checks/frame-counter-replay.mjs [--url <meeting URL>] [--lib <dir>] [--headed] [--slowmo <ms>]
//
// --lib <dir> serves the encryption library from <dir> (as in key-lifecycle.mjs),
// e.g. a build without replay protection, to see the replays played.
//
// Keep the room empty apart from the two browsers this opens.

import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { chromium } from 'playwright-core';
import { joinMeeting, leaveMeeting, meetingTarget, waitInPage } from '../harness/meeting.mjs';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const argv = process.argv.slice(2);
const headed = argv.includes('--headed');
const slowMo = argv.includes('--slowmo') ? Number(argv[argv.indexOf('--slowmo') + 1]) : 0;
const libDir = argv.includes('--lib') ? argv[argv.indexOf('--lib') + 1] : null;
const libFiles = libDir ? [
    [ 'lib-jitsi-meet.min.js', 'text/javascript' ],
    [ 'lib-jitsi-meet.e2ee-worker.js', 'text/javascript' ],
    [ 'lib-jitsi-meet.e2ee-vault.js', 'text/javascript' ],
    [ 'lib-jitsi-meet.e2ee-vault.html', 'text/html' ],
    [ 'olm.js', 'text/javascript' ]
].filter(([ file ]) => fs.existsSync(path.join(libDir, file)))
    .map(([ file, contentType ]) => [ file, fs.readFileSync(path.join(libDir, file)), contentType ]) : [];
const target = meetingTarget(argv, 'replay');
const sleep = ms => new Promise(r => setTimeout(r, ms));
const log = m => console.log(`[${new Date().toISOString().slice(11, 19)}] ${m}`);
const results = [];
const check = (id, name, ok, detail) => results.push({ id, name, ok, detail });
const REPLAYS = 20;

setTimeout(() => {
    console.error('run exceeded 5 minutes, aborting');
    process.exit(1);
}, 300000).unref();

const browser = await chromium.launch({ channel: 'chrome', headless: !headed, slowMo, args: [
    '--use-fake-ui-for-media-stream',
    '--use-fake-device-for-media-stream',
    `--use-file-for-fake-audio-capture=${path.join(HERE, '../harness/media/tone440.wav')}`,
    '--autoplay-policy=no-user-gesture-required',

    // For a server on this machine (localhost), see key-lifecycle.mjs.
    '--disable-features=LocalNetworkAccessChecks,PrivateNetworkAccessRespectPreflightResults,BlockInsecurePrivateNetworkRequests'
] });

async function join(name, tap) {
    const context = await browser.newContext({ ignoreHTTPSErrors: true });

    for (const [ file, body, contentType ] of libFiles) {
        await context.route(new RegExp(`/libs/${file.replace(/\./g, '\\.')}(\\?|$)`),
            r => r.fulfill({ body, contentType }));
    }
    const page = await context.newPage();

    if (tap) {
        await page.addInitScript({ path: path.join(HERE, '../harness/replay-tap.js') });
    }
    await joinMeeting(page, target.url({
        'config.p2p.enabled': false,
        'config.startWithAudioMuted': false,
        'config.startWithVideoMuted': false,
        'userInfo.displayName': name
    }), name);

    return page;
}

const e2eeOn = page => waitInPage(page, () => APP.conference._room.isE2EEEnabled(), null, 30000);
const tap = (page, fn, ...args) => page.evaluate(([ f, a ]) => window.__replayTap[f](...a), [ fn, args ]);

// ---- The meeting ------------------------------------------------------------

log(`room ${target.room}`);
const alice = await join('alice', false);
const bob = await join('bob', true);

await sleep(3000);
await alice.evaluate(() => APP.store.dispatch({ type: 'TOGGLE_E2EE', enabled: true }));
await e2eeOn(alice);
await e2eeOn(bob);

// Let the join ratchet settle, then record IVs and build up 30+ s of audio history.
await sleep(8000);
await tap(bob, 'resetIvs');
log('E2EE on; recording 40 s of encrypted frames');
await sleep(40000);

// ---- ENC-04: replays ------------------------------------------------------------

for (const ageMs of [ 1000, 30000 ]) {
    await tap(bob, 'replay', REPLAYS, ageMs);
    for (let i = 0; i < 50 && await tap(bob, 'pending'); i++) {
        await sleep(100);
    }
    await sleep(2000);
}
await sleep(3000);

const { ivs, replays, genuineAudio, genuinePlayed } = await tap(bob, 'report');

await Promise.all([ alice, bob ].map(leaveMeeting));
await browser.close();

const recent = replays.filter(r => r.ageMs < 10000);
const stale = replays.filter(r => r.ageMs >= 25000);
const played = list => list.filter(r => r.played).length;

// Controls: genuine frames do come out of decryption, and the replays were made.
check('ENC-04', 'Bob\'s decryption lets through Alice\'s genuine audio frames (control)',
    genuinePlayed >= genuineAudio * 0.98 && genuineAudio > 0, `${genuinePlayed}/${genuineAudio} played`);
check('ENC-04', 'replays were injected (control)', recent.length === REPLAYS && stale.length === REPLAYS,
    `${recent.length} recent, ${stale.length} stale`);
check('ENC-04', 'Bob\'s decryption lets through none of the frames replayed from ~1 s earlier', played(recent) === 0
    && recent.length > 0, `${played(recent)}/${recent.length} played`);
check('ENC-04', 'Bob\'s decryption lets through none of the frames replayed from ~30 s earlier', played(stale) === 0
    && stale.length > 0, `${played(stale)}/${stale.length} played`);

// ---- ENC-03: IVs ------------------------------------------------------------------

const ivKey = f => `${f.ssrc}:${f.timestamp}:${f.counter}`;
const distinct = new Set(ivs.map(ivKey)).size;

// Counter steps per stream (SSRC in the IV), in the order received.
const seen = new Set();
const lastCounter = new Map();
let steps = 0;
let unitSteps = 0;

for (const f of ivs) {
    const k = ivKey(f);

    if (seen.has(k)) {
        continue;
    }
    seen.add(k);
    if (lastCounter.has(f.ssrc)) {
        steps++;
        unitSteps += ((f.counter - lastCounter.get(f.ssrc)) >>> 0) === 1 ? 1 : 0;
    }
    lastCounter.set(f.ssrc, f.counter);
}
const streams = new Set(ivs.map(f => f.ssrc)).size;
const above16 = [ ...new Set(ivs.filter(f => f.counter >= 0xFFFF).map(f => f.ssrc)) ].length;

// The tap records each frame's IV as Alice sent it, before any replay is swapped in.
check('ENC-03', 'every frame Alice sent has a distinct IV', distinct === ivs.length && ivs.length > 0,
    `${distinct} distinct of ${ivs.length}`);
check('ENC-03', 'each stream\'s counter goes up by one per frame (gaps = frames not forwarded)',
    unitSteps >= steps * 0.95 && steps > 0, `${unitSteps}/${steps} steps of +1`);
check('ENC-03', 'the counter uses its full 32 bits (at least one stream starts at or above 0xFFFF)',
    above16 > 0, `${above16} of ${streams} streams`);

console.log('');
console.log(`encrypted frames received: ${ivs.length} in ${streams} streams`);
for (const r of results) {
    console.log(`${r.ok ? 'PASS' : 'FAIL'}  ${r.id}  ${r.name}  (${r.detail})`);
}
const ok = results.every(r => r.ok);

console.log(ok ? '\nVERDICT: secure — IVs are unique and replayed frames were rejected.'
    : '\nVERDICT: INSECURE — at least one check failed (see FAIL lines).');
process.exit(ok ? 0 : 1);
