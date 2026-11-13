// Group safety number: one 12-digit number for the whole meeting.
//
//   node group-safety-number.mjs [--participants N] [--attack none|swap-all]
//
// none      N participants (default 3) start one group verification; everyone
//           should get the same number.
// swap-all  Two participants and a malicious server, "Mallory", on their XMPP
//           WebSockets. She runs the full key swap (her own Curve25519 and
//           Ed25519 keys in every presence and session, signed, as in
//           olm-mitm.mjs swap-all), so she holds both media keys. She then does
//           the best she can against the group verification: she replaces each
//           commitment with one to her own value, computed for the keys the
//           recipient sees, and swaps the revealed values to match, so every
//           commitment check passes. The two numbers should still differ.
//
// By default uses the library the meeting serves (the build under test);
// --lib <dir> serves a rebuilt library from that directory instead.

import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import { createRequire } from 'node:module';
import { fileURLToPath } from 'node:url';
import { chromium } from 'playwright-core';
import { joinMeeting, leaveMeeting, meetingTarget, waitInPage } from '../harness/meeting.mjs';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const require = createRequire(import.meta.url);
const Olm = require('@matrix-org/olm/olm.js');
const argv = process.argv.slice(2);
const headed = argv.includes('--headed');
const slowMo = argv.includes('--slowmo') ? Number(argv[argv.indexOf('--slowmo') + 1]) : 0;
const libDir = argv.includes('--lib') ? argv[argv.indexOf('--lib') + 1] : null;
const attack = argv.includes('--attack') ? argv[argv.indexOf('--attack') + 1] : 'none';
const count = attack === 'swap-all' ? 2
    : argv.includes('--participants') ? Number(argv[argv.indexOf('--participants') + 1]) : 3;
const sleep = ms => new Promise(r => setTimeout(r, ms));
const log = m => console.log(`[${new Date().toISOString().slice(11, 19)}] ${m}`);

setTimeout(() => {
    console.error('run exceeded 4 minutes, aborting');
    process.exit(1);
}, 240000).unref();

await Olm.init();
const target = meetingTarget(argv, 'group');
const account = new Olm.Account();

account.create();
const { curve25519: malloryKey, ed25519: malloryEd25519 } = JSON.parse(account.identity_keys());
const actions = [];

// ---- Mallory: the full key swap (as olm-mitm.mjs swap-all) ----------------------

const sessions = new Map();
const pendingInits = new Map();
const malloryNonces = new Map(); // `${round}>${from}>${to}` -> Mallory's value
const unescapeXml = s => s.replace(/&(quot|apos|lt|gt|amp);/g,
    (_, e) => ({ quot: '"', apos: '\'', lt: '<', gt: '>', amp: '&' })[e]);
const escapeXml = s => s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
const senderOf = stanza => stanza.match(/\sfrom=['"][^'"]*\/([^'"/]+)['"]/)?.[1];

// The same commitment the library computes (GroupVerification.js).
const commitmentFor = (roundId, pId, ed, curve, nonce) => crypto.createHash('sha256')
    .update([ 'apespace-group-sas-commit-v1', roundId, pId, `${ed}|${curve}|${nonce}` ].join('\n'))
    .digest('base64');

function mallory(stanza, to) {
    if (attack !== 'swap-all' || !to) {
        return stanza;
    }
    const from = senderOf(stanza);

    if (stanza.startsWith('<presence') && from && from !== to) {
        return stanza
            .replace(/(<jitsi_participant_e2ee\.idKey\.curve25519>)[^<]*/, (_, tag) => tag + malloryKey)
            .replace(/(<jitsi_participant_e2ee\.idKey\.ed25519>)[^<]*/, (_, tag) => tag + malloryEd25519);
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
            msg.data.signature = account.sign(JSON.stringify({ idKey: malloryKey, otKey: msg.data.otKey }));
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
            JSON.parse(plaintext).key && actions.push(`read a media key of ${from}`);
            msg.data.ciphertext = withRecipient.encrypt(plaintext);
            if (msg.data.idKey) {
                msg.data.idKey = malloryKey;
                msg.data.signature = account.sign(JSON.stringify({ idKey: malloryKey }));
            }
        } else if (msg.type === 'group-sas-commit') {
            // Commit to her own value for the keys the recipient sees for the sender (hers).
            const nonce = crypto.randomBytes(32).toString('base64');

            malloryNonces.set(`${msg.data.roundId}>${from}>${to}`, nonce);
            msg.data.commitment = commitmentFor(msg.data.roundId, from, malloryEd25519, malloryKey, nonce);
            actions.push(`replaced ${from}'s group commitment to ${to}`);
        } else if (msg.type === 'group-sas-reveal') {
            msg.data.nonce = malloryNonces.get(`${msg.data.roundId}>${from}>${to}`);
            actions.push(`replaced ${from}'s revealed value to ${to}`);
        } else if (msg.data?.ciphertext && sessions.has(`${from}>${to}`)) {
            const plaintext = sessions.get(`${from}>${to}`).decrypt(msg.data.ciphertext.type, msg.data.ciphertext.body);

            JSON.parse(plaintext).key && actions.push(`read a media key of ${from}`);
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

// ---- Meeting ---------------------------------------------------------------------

// By default use whatever library the meeting serves (the build under test).
// --lib <dir> serves a rebuilt library from that directory instead.
const libFiles = libDir ? {
    'lib-jitsi-meet.min.js': fs.readFileSync(path.join(libDir, 'lib-jitsi-meet.min.js'), 'utf8'),
    'lib-jitsi-meet.e2ee-worker.js': fs.readFileSync(path.join(libDir, 'lib-jitsi-meet.e2ee-worker.js'), 'utf8')
} : {};
const browser = await chromium.launch({ channel: 'chrome', headless: !headed, slowMo, args: [
    '--use-fake-ui-for-media-stream',
    '--use-fake-device-for-media-stream',
    `--use-file-for-fake-audio-capture=${path.join(HERE, '../harness/media/tone440.wav')}`
] });

async function join(name) {
    const ctx = await browser.newContext({ ignoreHTTPSErrors: true });
    const page = await ctx.newPage();
    let me;

    page.on('console', m => /group|Group/.test(m.text()) && log(`${name} console: ${m.text().slice(0, 200)}`));
    page.on('pageerror', e => log(`${name} page error: ${e.message.slice(0, 200)}`));

    // With no --lib, libFiles is empty and the meeting's own library is used, so
    // the run tests the real build. --lib serves a rebuilt library instead.
    for (const [ file, body ] of Object.entries(libFiles)) {
        await page.route(new RegExp(`/libs/${file.replace(/\./g, '\\.')}`),
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
    await joinMeeting(page, target.url({ 'config.p2p.enabled': false, 'userInfo.displayName': name }), name);
    await page.evaluate(() => {
        window.__group = { ready: null, failed: null };
        const room = APP.conference._room;

        room.on('conference.e2ee.groupVerificationReady', (roundId, code, members) => {
            window.__group.ready = { roundId, code, members };
        });
        room.on('conference.e2ee.groupVerificationFailed', (roundId, reason, ids) => {
            window.__group.failed = { roundId, reason, ids };
        });
    });

    return page;
}

log(`attack: ${attack}, ${count} participants, room ${target.room}`);
const names = [ 'alice', 'bob', 'carol', 'dave', 'erin', 'frank' ].slice(0, count);
const pages = [];

for (const name of names) {
    pages.push(await join(name));
}
await sleep(3000);
await pages[0].evaluate(() => APP.store.dispatch({ type: 'TOGGLE_E2EE', enabled: true }));
for (const page of pages) {
    await waitInPage(page, () => APP.conference._room.isE2EEEnabled());
}
await sleep(8000);

if (await pages[0].evaluate(() => typeof APP.conference._room.startGroupVerification) !== 'function') {
    console.error('This build has no group safety number (startGroupVerification is missing). '
        + 'Run against a build that includes it, or pass --lib <dir> with a library that does.');
    await Promise.all(pages.map(leaveMeeting));
    await browser.close();
    process.exit(2);
}
log('alice starts the group verification');
await pages[0].evaluate(() => APP.conference._room.startGroupVerification());
for (const page of pages) {
    await waitInPage(page, () => window.__group.ready || window.__group.failed, null, 40000).catch(() => {});
}
const results = [];

for (const [ i, page ] of pages.entries()) {
    results.push({ name: names[i], ...await page.evaluate(() => window.__group) });
}
await Promise.all(pages.map(leaveMeeting));
await browser.close();

for (const r of results) {
    console.log(`${r.name.padEnd(6)} ${r.ready ? `number ${r.ready.code} (covers ${r.ready.members.length} others)`
        : r.failed ? `FAILED: ${r.failed.reason} ${r.failed.ids.join(',')}` : 'no result'}`);
}
const codes = new Set(results.map(r => r.ready?.code));
const same = codes.size === 1 && !codes.has(undefined);

console.log(`Mallory:     ${[ ...new Set(actions) ].join('; ') || 'nothing'}`);
console.log(`Same number: ${same ? 'yes' : 'NO'}`);
fs.mkdirSync(path.join(HERE, 'results'), { recursive: true });
fs.writeFileSync(path.join(HERE, 'results', `group-${attack}-${count}-${Date.now()}.json`),
    JSON.stringify({ attack, results, mallory: [ ...new Set(actions) ], same }, null, 2));

// none: every honest participant must read the same number. swap-all: the
// server faked everyone, so the numbers must differ (that is how everyone sees
// the attack). Secure in both cases iff "same number" matches the expectation.
const secure = attack === 'none' ? same : !same;

console.log(secure
    ? `\nVERDICT: secure — ${attack === 'none' ? 'all participants read the same number.'
        : 'the faked meeting produced different numbers, so the attack is visible to everyone.'}`
    : `\nVERDICT: INSECURE — ${attack === 'none' ? 'participants disagreed on the number.'
        : 'the server steered every participant to the same number.'}`);
process.exit(secure ? 0 : 1);
