// A participant without encryption support and an encrypted meeting, answering
// checklist row ENC-08 ("a participant without encryption support cannot join a
// secure meeting"; "secure meetings refuse to send or play unencrypted media").
//
// Carol's browser has the APIs end-to-end encryption needs removed
// (RTCRtpScriptTransform and createEncodedStreams), as on a browser or app that
// can't encrypt. Alice and Bob start an encrypted meeting; Carol then joins. The
// check reads, from the browsers themselves:
//
//   - whether Carol's client takes part: still in the meeting, and sending audio
//     or video;
//   - whether what Carol sends is encrypted: the frames Alice receives from her,
//     tapped before decryption (Inspector);
//   - whether anything unencrypted is played: video frames Alice and Bob decode
//     from Carol;
//   - whether Alice and Bob stay encrypted.
//
//   node checks/unsupported-participant.mjs [--url <meeting URL>] [--lib <dir>] [--app <app.bundle.min.js>] [--headed]
//
// --app serves the meeting app from a local build instead of the meeting's own.
//
// Keep the room empty apart from the three browsers this opens.

import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { chromium } from 'playwright-core';
import { joinMeeting, leaveMeeting, meetingTarget, waitInPage } from '../harness/meeting.mjs';

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

arg('--app') && libFiles.push([ 'app.bundle.min.js', fs.readFileSync(arg('--app')), 'text/javascript' ]);
const target = meetingTarget(argv, 'unsupported');
const sleep = ms => new Promise(r => setTimeout(r, ms));
const log = m => console.log(`[${new Date().toISOString().slice(11, 19)}] ${m}`);
const results = [];
const timeline = {}; // when Carol detected the encrypted meeting, from her console
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

// Removes what end-to-end encryption needs, in every frame of the page.
const NO_E2EE = `(() => {
    for (const name of [ 'RTCRtpScriptTransform' ]) { try { delete window[name]; } catch { window[name] = undefined; } }
    for (const proto of [ window.RTCRtpSender?.prototype, window.RTCRtpReceiver?.prototype ]) {
        if (proto) { try { delete proto.createEncodedStreams; } catch {} }
    }
})();`;

async function join(name, { unsupported = false } = {}) {
    const context = await browser.newContext({ ignoreHTTPSErrors: true });

    for (const [ file, body, contentType ] of libFiles) {
        await context.route(new RegExp(`/libs/${file.replace(/\./g, '\\.')}(\\?|$)`),
            r => r.fulfill({ body, contentType }));
    }
    const page = await context.newPage();

    if (unsupported) {
        page.on('console', m => /can't encrypt: leaving/.test(m.text()) && (timeline.detected ??= Date.now()));
        argv.includes('--debug') && page.on('console', m => /Joining MUC|entered|session-initiate|can't encrypt|doLeave|hangup|conference.joined|CONFERENCE_JOINED|e2ee.enabled/i.test(m.text())
            && console.log(`[${new Date().toISOString().slice(11, 23)}] carol console: ${m.text().slice(0, 160)}`));
        page.on('framenavigated', f => f === page.mainFrame() && timeline.joinedAt && (timeline.navigated ??= Date.now()));
        await page.addInitScript({ content: NO_E2EE });
    } else {
        await page.addInitScript({ path: path.join(HERE, '../../extension/inspector/leak-scan.js') });
        await page.addInitScript({ path: path.join(HERE, '../../extension/inspector/hook.js') });
    }
    const joining = joinMeeting(page, target.url({
        'config.p2p.enabled': false,
        'config.startWithAudioMuted': false,
        'config.startWithVideoMuted': false,
        'userInfo.displayName': name
    }), name);

    if (unsupported) {
        // A client that leaves an encrypted meeting at once may never look "joined" to the helper.
        await joining.catch(e => log(`${name}: ${e.message}`));
    } else {
        await joining;
    }

    return page;
}

// Media this browser sends, over 3 s: bytes of audio and video leaving it.
const sendingRate = page => page.evaluate(async () => {
    const room = APP.conference?._room;
    const pc = room?.jvbJingleSession?.peerconnection?.peerconnection;

    if (!pc) {
        return { audio: 0, video: 0 };
    }
    const sample = async () => {
        const out = { audio: 0, video: 0 };

        (await pc.getStats()).forEach(s => {
            if (s.type === 'outbound-rtp') {
                out[s.kind] += s.bytesSent ?? 0;
            }
        });

        return out;
    };
    const a = await sample();

    await new Promise(r => setTimeout(r, 3000));
    const b = await sample();

    return { audio: b.audio - a.audio, video: b.video - a.video };
});

// Video frames this browser decodes from the participant named `from`, over 3 s.
const decodedFrom = (page, from) => page.evaluate(async name => {
    const room = APP.conference._room;
    const pc = room.jvbJingleSession.peerconnection.peerconnection;
    const ids = new Set();

    for (const p of room.getParticipants().filter(x => x.getDisplayName() === name)) {
        for (const t of p.getTracksByMediaType('video')) {
            ids.add(t.getTrack().id);
        }
    }
    const sample = async () => {
        let n = 0;

        (await pc.getStats()).forEach(s => {
            if (s.type === 'inbound-rtp' && s.kind === 'video' && ids.has(s.trackIdentifier)) {
                n += s.framesDecoded ?? 0;
            }
        });

        return n;
    };
    const a = await sample();

    await new Promise(r => setTimeout(r, 3000));

    return (await sample()) - a;
}, from);

// ---- The meeting ------------------------------------------------------------

log(`room ${target.room}`);
const alice = await join('alice');
const bob = await join('bob');

await sleep(3000);
await alice.evaluate(() => APP.store.dispatch({ type: 'TOGGLE_E2EE', enabled: true }));
await waitInPage(alice, () => APP.conference._room.isE2EEEnabled(), null, 30000);
await waitInPage(bob, () => APP.conference._room.isE2EEEnabled(), null, 30000);
log('E2EE on; Carol, without encryption support, joins');

timeline.carolStarts = Date.now();
const carol = await join('carol', { unsupported: true });
const carolSupported = Boolean(await carol.evaluate(() => window.APP?.conference?._room?.isE2EESupported?.()
    ?? window.JitsiMeetJS?.isE2EESupported?.()).catch(() => false));
const bobId = await bob.evaluate(() => APP.conference._room.myUserId());

await sleep(15000);

const carolInMeeting = await carol.evaluate(() => Boolean(window.APP?.conference?._room?.isJoined?.())).catch(() => false);
const carolScreen = await carol.evaluate(() => document.body.innerText.slice(0, 300)).catch(() => '');
const carolSends = carolInMeeting ? await sendingRate(carol) : { audio: 0, video: 0 };

// Frames Alice received from anyone but Bob since Carol started joining (that is, from Carol, even after
// she left), before decryption. Earlier frames are Alice and Bob's own switch-over, on streams the
// Inspector may not have matched to Bob yet.
const { streams } = await alice.evaluate(() => window.__e2eeInspector.exportMeta());
let carolFrames = 0;
let carolEncrypted = 0;

for (const s of streams.filter(st => st.participantId !== bobId)) {
    const frames = await alice.evaluate(([ id, n ]) => window.__e2eeInspector.exportFrames(id, 0, n), [ s.id, s.frameCount ]);

    for (const f of frames.filter(fr => fr.t >= timeline.carolStarts)) {
        const data = Buffer.from(f.data, 'base64');

        carolFrames++;
        carolEncrypted += data.length > 14 && data[data.length - 2] === 12 ? 1 : 0;
        argv.includes('--debug') && log(`  frame from Carol: ${s.kind} ${f.type ?? 'audio'} ${data.length} bytes, `
            + `${timeline.detected ? `${f.t - timeline.detected} ms after she detected E2EE` : 'no detection logged'}`
            + ` (at ${new Date(f.t).toISOString().slice(11, 23)})`);
    }
}
const played = { alice: await decodedFrom(alice, 'carol'), bob: await decodedFrom(bob, 'carol') };
const stillOn = { alice: await alice.evaluate(() => APP.conference._room.isE2EEEnabled()),
    bob: await bob.evaluate(() => APP.conference._room.isE2EEEnabled()) };

await Promise.all([ alice, bob, carol ].map(p => leaveMeeting(p).catch(() => {})));
await browser.close();

check('ENC-08', 'Carol\'s client reports no encryption support (control)', carolSupported === false, `${carolSupported}`);
log(`Carol ${carolInMeeting ? 'is still in the meeting' : 'left the meeting'}; her screen: ${carolScreen.replace(/\s+/g, ' ').slice(0, 200)}`);
check('ENC-08', 'Alice and Bob stay encrypted', stillOn.alice && stillOn.bob, JSON.stringify(stillOn));
check('ENC-08', 'Carol sends no unencrypted audio or video into the encrypted meeting',
    !carolInMeeting || (carolSends.audio === 0 && carolSends.video === 0),
    carolInMeeting ? `in the meeting, sending ${carolSends.audio} audio and ${carolSends.video} video bytes in 3 s`
        : 'not in the meeting');
check('ENC-08', 'no unencrypted frame from Carol reaches Alice', carolFrames === carolEncrypted,
    `${carolFrames - carolEncrypted} of ${carolFrames} frames received from anyone but Bob unencrypted`);
check('ENC-08', 'Alice and Bob play none of Carol\'s unencrypted video', played.alice === 0 && played.bob === 0,
    `frames decoded in 3 s: ${JSON.stringify(played)}`);

console.log('');
for (const r of results) {
    console.log(`${r.ok ? 'PASS' : 'FAIL'}  ${r.id}  ${r.name}  (${r.detail})`);
}
const ok = results.every(r => r.ok);

console.log(ok ? '\nVERDICT: secure — no unencrypted media entered or was played in the encrypted meeting.'
    : '\nVERDICT: INSECURE — unencrypted media entered or was played (see FAIL lines).');
process.exit(ok ? 0 : 1);
