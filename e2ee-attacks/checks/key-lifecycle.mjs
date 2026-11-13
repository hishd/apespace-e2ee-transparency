// Key lifecycle checks, answering checklist rows KEY-05, KEY-06 and ENC-05.
//
// Alice and Bob start an end-to-end encrypted meeting. Carol joins later and
// then leaves. Every browser records, with the published Inspector, the media
// keys it holds and the encrypted frames it receives. The checks then try the
// keys against real captured frames:
//
//   KEY-06  A late joiner can't read earlier content: Carol's keys must open
//           none of the frames Alice sent before Carol joined.
//   KEY-05  A departed participant can't keep decrypting: Carol's keys must
//           open none of the frames Alice sent once the key changed after
//           Carol left. Also reports how long her old key kept working.
//   ENC-05  Tampering is rejected: one flipped bit in the readable header, the
//           encrypted payload, the IV or the authentication tag of a frame
//           Bob can decrypt must make decryption fail.
//
// Keys are tried at every key index and every allowed ratchet step, so a check
// passes only because the key material differs, not because of bookkeeping.
//
//   node checks/key-lifecycle.mjs [--url <meeting URL>] [--headed] [--slowmo <ms>]
//
// Keep the room empty apart from the three browsers this opens.

import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { chromium } from 'playwright-core';
import { createDecryptor } from '../../extension/inspector/frame-crypto.js';
import { joinMeeting, leaveMeeting, meetingTarget, waitInPage } from '../harness/meeting.mjs';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const argv = process.argv.slice(2);
const headed = argv.includes('--headed');
const slowMo = argv.includes('--slowmo') ? Number(argv[argv.indexOf('--slowmo') + 1]) : 0;
const target = meetingTarget(argv, 'keys');
const sleep = ms => new Promise(r => setTimeout(r, ms));
const log = m => console.log(`[${new Date().toISOString().slice(11, 19)}] ${m}`);
const results = [];
const check = (id, name, ok, detail) => results.push({ id, name, ok, detail });

setTimeout(() => {
    console.error('run exceeded 6 minutes, aborting');
    process.exit(1);
}, 360000).unref();

const browser = await chromium.launch({ channel: 'chrome', headless: !headed, slowMo, args: [
    '--use-fake-ui-for-media-stream',
    '--use-fake-device-for-media-stream',
    `--use-file-for-fake-audio-capture=${path.join(HERE, '../harness/media/tone440.wav')}`,
    '--autoplay-policy=no-user-gesture-required'
] });

async function join(name) {
    const page = await (await browser.newContext({ ignoreHTTPSErrors: true })).newPage();

    await page.addInitScript({ path: path.join(HERE, '../../extension/inspector/leak-scan.js') });
    await page.addInitScript({ path: path.join(HERE, '../../extension/inspector/hook.js') });
    await joinMeeting(page, target.url({
        'config.p2p.enabled': false,
        'config.startWithAudioMuted': false,
        'config.startWithVideoMuted': false,
        'config.videoQuality.codecPreferenceOrder': [ 'VP8' ],
        'userInfo.displayName': name
    }), name);

    return page;
}

const meta = page => page.evaluate(() => window.__e2eeInspector.exportMeta());
const idOf = page => page.evaluate(() => APP.conference._room.myUserId());
const e2eeOn = page => waitInPage(page, () => APP.conference._room.isE2EEEnabled(), null, 30000);

// Every key a browser held, offered at every key index and with no time limit.
const anyIndex = keys => keys.filter(k => k.key)
    .flatMap(k => Array.from({ length: 16 }, (_, keyIndex) => ({ ...k, keyIndex, t: 0 })));

// Encrypted frames `page` received from participant `fromId`, sent in [t0, t1).
async function framesFrom(page, fromId, t0, t1, limit = 300) {
    const { streams } = await meta(page);
    const out = [];

    for (const s of streams.filter(st => st.participantId === fromId && st.mode === 'e2ee')) {
        const frames = await page.evaluate(([ id, n ]) => window.__e2eeInspector.exportFrames(id, 0, n),
            [ s.id, s.frameCount ]);

        for (const f of frames) {
            if (f.t >= t0 && f.t < t1) {
                out.push({ stream: s, frame: { ...f, data: new Uint8Array(Buffer.from(f.data, 'base64')) } });
            }
        }
    }

    // An even sample across the window keeps the run short.
    const step = Math.max(1, Math.floor(out.length / limit));

    return out.filter((_, i) => i % step === 0).slice(0, limit);
}

async function opened(samples, keys) {
    const decrypt = createDecryptor(anyIndex(keys));
    let n = 0;

    for (const { stream, frame } of samples) {
        n += (await decrypt(stream, frame)) ? 1 : 0;
    }

    return n;
}

// ---- The meeting ------------------------------------------------------------

log(`room ${target.room}`);
const alice = await join('alice');
const bob = await join('bob');
const aliceId = await idOf(alice);

await sleep(3000);
await alice.evaluate(() => APP.store.dispatch({ type: 'TOGGLE_E2EE', enabled: true }));
await e2eeOn(alice);
await e2eeOn(bob);
log('E2EE on for Alice and Bob; media for 15 s before Carol joins');
await sleep(15000);

const beforeJoin = Date.now();
const carol = await join('carol');

await e2eeOn(carol);
log('Carol joined; waiting for the key change and media');
await sleep(15000);
const afterJoin = Date.now();

await sleep(10000);
const carolKeys = (await meta(carol)).keys;
const left = Date.now();

await leaveMeeting(carol);
await carol.context().close();
log('Carol left; media for 30 s');
await sleep(30000);
const end = Date.now();

const bobKeys = (await meta(bob)).keys;

// ---- KEY-06: the late joiner and earlier content --------------------------------

const early = await framesFrom(bob, aliceId, 0, beforeJoin);
const whileCarolIn = await framesFrom(bob, aliceId, afterJoin, left);

const earlyByCarol = await opened(early, carolKeys);
const earlyByBob = await opened(early, bobKeys);
const lateByCarol = await opened(whileCarolIn, carolKeys);

check('KEY-06', 'Carol\'s keys open frames sent while she was in (control)', lateByCarol > 0,
    `${lateByCarol}/${whileCarolIn.length}`);
check('KEY-06', 'Bob opens the frames sent before Carol joined (control)', earlyByBob === early.length && early.length > 0,
    `${earlyByBob}/${early.length}`);
check('KEY-06', 'Carol\'s keys open none of the frames sent before she joined', earlyByCarol === 0,
    `${earlyByCarol}/${early.length}`);

// ---- KEY-05: the departed participant and later content -------------------------

const settled = left + 15000;
const later = await framesFrom(bob, aliceId, settled, end);
const laterByCarol = await opened(later, carolKeys);
const laterByBob = await opened(later, bobKeys);

check('KEY-05', 'Bob opens the frames sent after Carol left (control)', laterByBob === later.length && later.length > 0,
    `${laterByBob}/${later.length}`);
check('KEY-05', 'Carol\'s keys open none of the frames sent 15 s or more after she left', laterByCarol === 0,
    `${laterByCarol}/${later.length}`);

// How long her old key kept working: the last second, after she left, in which it opened a frame.
let lastOpen = null;

for (let s = 0; s < 15; s++) {
    const bucket = await framesFrom(bob, aliceId, left + (s * 1000), left + ((s + 1) * 1000), 30);

    if (bucket.length && await opened(bucket, carolKeys)) {
        lastOpen = s + 1;
    }
}
log(`Carol's old key opened frames up to ${lastOpen === null ? '0' : `${lastOpen}`} s after she left `
    + '(the key changes about 5 s after a departure)');

// ---- ENC-05: tampered frames ----------------------------------------------------

const sample = [];
const decryptAsBob = createDecryptor(anyIndex(bobKeys));

for (const s of await framesFrom(bob, aliceId, afterJoin, end, 400)) {
    if (sample.length < 60 && await decryptAsBob(s.stream, s.frame)) {
        sample.push(s);
    }
}

// Byte offsets: readable header, middle of the encrypted payload, IV, last tag byte.
const header = f => (f.type === 'key' ? 10 : f.type === 'delta' ? 3 : 1);
const spots = {
    'readable header': () => 0,
    'encrypted payload': f => header(f) + Math.floor((f.data.length - header(f) - 2 - 12 - 16) / 2),
    'IV': f => f.data.length - 2 - 12,
    'authentication tag': f => f.data.length - 2 - 12 - 1
};

for (const [ where, at ] of Object.entries(spots)) {
    let rejected = 0;

    for (const { stream, frame } of sample) {
        const data = frame.data.slice();

        data[at(frame)] ^= 0x01;
        rejected += (await createDecryptor(anyIndex(bobKeys))(stream, { ...frame, data })) ? 0 : 1;
    }
    check('ENC-05', `one flipped bit in the ${where} is rejected`, rejected === sample.length && sample.length > 0,
        `${rejected}/${sample.length} rejected`);
}

await Promise.all([ alice, bob ].map(leaveMeeting));
await browser.close();

console.log('');
for (const r of results) {
    console.log(`${r.ok ? 'PASS' : 'FAIL'}  ${r.id}  ${r.name}  (${r.detail})`);
}
const ok = results.every(r => r.ok);

console.log(ok ? '\nVERDICT: secure — every key-lifecycle and tamper check passed.'
    : '\nVERDICT: INSECURE — at least one check failed (see FAIL lines).');
process.exit(ok ? 0 : 1);
