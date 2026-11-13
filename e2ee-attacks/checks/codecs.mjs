// Video codec and readable bytes under E2EE, answering checklist row ENC-07.
//
// The published frame layout (VP8: 10 readable bytes in a keyframe, 3 in a delta
// frame; Opus: 1) holds only if encrypted meetings send VP8 video. The library
// forces VP8 when E2EE is switched on. This checks it in a real meeting that
// prefers other codecs (AV1 first, as the deployment's own setting may), in two
// sequences:
//
//   first-on   Alice and Bob meet; the moderator switches E2EE on.
//   re-on      E2EE is switched off, Carol joins (the codec is chosen again), and
//              E2EE is switched back on.
//
// After each, it reads the video codec every participant sends, and decrypts a
// sample of captured video frames (from 2 s after switching on) with the
// receiver's keys using the published layout (header bytes as additional data,
// then ciphertext, IV, trailer), which succeeds only if the frame has exactly
// that layout. It also reports how many video frames Bob decodes from each
// sender: encrypted AV1 or VP9 can't be played.
//
//   node checks/codecs.mjs [--url <meeting URL>] [--lib <dir>] [--prefer AV1,VP9,VP8,H264] [--headed]
//
// Keep the room empty apart from the three browsers this opens.

import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { chromium } from 'playwright-core';
import { createDecryptor } from '../../extension/inspector/frame-crypto.js';
import { joinMeeting, leaveMeeting, meetingTarget, waitInPage } from '../harness/meeting.mjs';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const argv = process.argv.slice(2);
const arg = name => (argv.includes(name) ? argv[argv.indexOf(name) + 1] : null);
const headed = argv.includes('--headed');
const prefer = (arg('--prefer') ?? 'AV1,VP9,VP8,H264').split(',');
const libDir = arg('--lib');
const libFiles = libDir ? [
    [ 'lib-jitsi-meet.min.js', 'text/javascript' ],
    [ 'lib-jitsi-meet.e2ee-worker.js', 'text/javascript' ],
    [ 'lib-jitsi-meet.e2ee-vault.js', 'text/javascript' ],
    [ 'lib-jitsi-meet.e2ee-vault.html', 'text/html' ],
    [ 'olm.js', 'text/javascript' ]
].filter(([ file ]) => fs.existsSync(path.join(libDir, file)))
    .map(([ file, contentType ]) => [ file, fs.readFileSync(path.join(libDir, file)), contentType ]) : [];
const target = meetingTarget(argv, 'codecs');
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

async function join(name) {
    const context = await browser.newContext({ ignoreHTTPSErrors: true });

    for (const [ file, body, contentType ] of libFiles) {
        await context.route(new RegExp(`/libs/${file.replace(/\./g, '\\.')}(\\?|$)`),
            r => r.fulfill({ body, contentType }));
    }
    const page = await context.newPage();

    if (argv.includes('--debug')) {
        page.on('console', m => /codec|e2ee:KeyHandler|restart/i.test(m.text())
            && console.log(`${name}: ${m.text().slice(0, 220)}`));
    }
    await page.addInitScript({ path: path.join(HERE, '../../extension/inspector/leak-scan.js') });
    await page.addInitScript({ path: path.join(HERE, '../../extension/inspector/hook.js') });
    await joinMeeting(page, target.url({
        'config.startWithAudioMuted': false,
        'config.startWithVideoMuted': false,
        'config.videoQuality.codecPreferenceOrder': prefer,
        'config.p2p.codecPreferenceOrder': prefer,
        'userInfo.displayName': name
    }), name);

    return page;
}

// The codec of the video this participant sends, and whether the call runs peer to peer.
const sending = page => page.evaluate(async () => {
    const room = APP.conference._room;
    const session = room.getActiveMediaSession?.() ?? room.jvbJingleSession;
    const stats = await session.peerconnection.peerconnection.getStats();
    const codecs = new Set();

    stats.forEach(s => {
        if (s.type === 'outbound-rtp' && s.kind === 'video' && s.codecId && (s.framesEncoded ?? 0) > 0) {
            const c = stats.get(s.codecId);

            c && codecs.add(c.mimeType.replace('video/', ''));
        }
    });

    return { codecs: [ ...codecs ], p2p: room.isP2PActive() };
});

const e2ee = (page, on) => waitInPage(page, v => APP.conference._room.isE2EEEnabled() === v, on, 30000);
const toggle = (page, on) => page.evaluate(v => APP.store.dispatch({ type: 'TOGGLE_E2EE', enabled: v }), on);

// Decrypts a sample of the video frames `receiver` captured from `senderId` since t0.
async function layoutHolds(receiver, senderId, t0) {
    const { streams, keys } = await receiver.evaluate(() => window.__e2eeInspector.exportMeta());
    const decrypt = createDecryptor(keys.filter(k => k.key)
        .flatMap(k => Array.from({ length: 16 }, (_, keyIndex) => ({ ...k, keyIndex, t: 0 }))));
    let tried = 0;
    let opened = 0;
    let trailers = 0;

    for (const s of streams.filter(st => st.participantId === senderId && st.mode === 'e2ee' && st.kind === 'video')) {
        const frames = await receiver.evaluate(([ id, n ]) => window.__e2eeInspector.exportFrames(id, 0, n),
            [ s.id, s.frameCount ]);

        // From 2 s after E2EE is on: the app holds local media (black frames, silence) while switching
        // over, and that window is checked by switch-on.mjs (ENC-08), not here.
        for (const f of frames.filter(fr => fr.t >= t0 + 2000).slice(-40)) {
            const data = new Uint8Array(Buffer.from(f.data, 'base64'));

            const ok = await decrypt(s, { ...f, data });

            tried++;
            trailers += data.length > 14 && data[data.length - 2] === 12 ? 1 : 0;
            opened += ok ? 1 : 0;
            ok || log(`  not decrypted: ${f.type} frame, ${data.length} bytes, ${f.t - t0} ms after E2EE on, `
                + `stream ${s.id}, trailer byte ${data[data.length - 2]}`);
        }
    }

    return { tried, opened, trailers };
}

async function inspect(label, pages, ids, t0) {
    for (const [ name, page ] of Object.entries(pages)) {
        const { codecs, p2p } = await sending(page);

        check('ENC-07', `${label}: ${name} sends VP8 video`, codecs.length > 0 && codecs.every(c => c === 'VP8'),
            `${codecs.join(', ') || 'no video'}${p2p ? ', peer to peer' : ', via the bridge'}`);
    }
    const { tried, opened, trailers } = await layoutHolds(pages.bob, ids.alice, t0);
    // Video frames Bob decodes from each sender in 3 s (by the remote track's id).
    const decoding = await pages.bob.evaluate(async () => {
        const room = APP.conference._room;
        const pc = room.jvbJingleSession.peerconnection.peerconnection;
        const names = {};

        for (const p of room.getParticipants()) {
            for (const t of p.getTracksByMediaType('video')) {
                names[t.getTrack().id] = p.getDisplayName();
            }
        }
        const sample = async () => {
            const out = {};

            (await pc.getStats()).forEach(st => {
                if (st.type === 'inbound-rtp' && st.kind === 'video' && names[st.trackIdentifier]) {
                    out[names[st.trackIdentifier]] = (out[names[st.trackIdentifier]] ?? 0) + (st.framesDecoded ?? 0);
                }
            });

            return out;
        };
        const a = await sample();

        await new Promise(r => setTimeout(r, 3000));
        const b = await sample();

        return Object.fromEntries(Object.keys(b).map(k => [ k, b[k] - (a[k] ?? 0) ]));
    });

    log(`${label}: Alice's video at Bob: ${trailers}/${tried} frames carry the encryption trailer; `
        + `video frames Bob decoded in 3 s, by sender: ${JSON.stringify(decoding)}`);

    check('ENC-07', `${label}: Alice's video frames have the published layout (decrypt with it)`,
        tried > 0 && opened === tried, `${opened}/${tried}`);
}

// ---- first-on ----------------------------------------------------------------

log(`room ${target.room}; preferring ${prefer.join(', ')}`);
const alice = await join('alice');
const bob = await join('bob');
const ids = { alice: await alice.evaluate(() => APP.conference._room.myUserId()) };

await sleep(8000);
log(`before E2EE: alice sends ${JSON.stringify(await sending(alice))}`);
await toggle(alice, true);
await e2ee(alice, true);
await e2ee(bob, true);
let t0 = Date.now();

await sleep(15000);
await inspect('first-on', { alice, bob }, ids, t0);

// ---- re-on ----------------------------------------------------------------------

await toggle(alice, false);
await e2ee(alice, false);
await e2ee(bob, false);
const carol = await join('carol');

await sleep(12000);
log(`E2EE off, Carol in: alice sends ${JSON.stringify(await sending(alice))}`);
await toggle(alice, true);
await e2ee(alice, true);
await e2ee(bob, true);
await e2ee(carol, true);
t0 = Date.now();
await sleep(15000);
await inspect('re-on', { alice, bob, carol }, ids, t0);

await Promise.all([ alice, bob, carol ].map(leaveMeeting));
await browser.close();

console.log('');
for (const r of results) {
    console.log(`${r.ok ? 'PASS' : 'FAIL'}  ${r.id}  ${r.name}  (${r.detail})`);
}
const ok = results.every(r => r.ok);

console.log(ok ? '\nVERDICT: secure — encrypted video was VP8 with the published layout throughout.'
    : '\nVERDICT: INSECURE — encrypted video used another codec or layout (see FAIL lines).');
process.exit(ok ? 0 : 1);
