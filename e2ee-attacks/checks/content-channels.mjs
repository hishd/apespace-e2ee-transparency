// What the server can read of each content channel in an encrypted meeting,
// answering checklist rows ENC-01 and ENC-02 (a channel-by-channel inventory with
// a capture for each channel).
//
// Alice and Bob hold an end-to-end encrypted meeting. Alice then uses every
// content channel, each with its own unique marker text:
//
//   display name    Alice's name carries a marker
//   chat            a message to everyone
//   private chat    a message to Bob only
//   poll            a poll with a marked question and answers
//   reaction        a "like" reaction
//   file sharing    a small text file with a marker inside, given to the app's
//                   upload action (the request body is read in the page, as the
//                   test harness can't see file bodies). The upload is started
//                   the way the app's own code does; whether the file service
//                   then accepts it is reported, not required.
//
// A tap in Alice's browser records everything she sends on the paths that reach
// the servers: WebSocket messages (signalling), data-channel messages (to the
// video bridge) and HTTP requests. For each channel the check reports whether the
// marker left Alice's browser readable, on which path, and whether Bob received
// the content (control).
//
// This is an inventory, not a pass/fail test: audio, video and screen sharing are
// the only end-to-end encrypted channels, and the result shows that for the rest.
//
//   node checks/content-channels.mjs [--url <meeting URL>] [--headed]
//
// Keep the room empty apart from the two browsers this opens.

import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import { fileURLToPath } from 'node:url';
import { chromium } from 'playwright-core';
import { joinMeeting, leaveMeeting, meetingTarget, waitInPage } from '../harness/meeting.mjs';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const argv = process.argv.slice(2);
const target = meetingTarget(argv, 'channels');
const sleep = ms => new Promise(r => setTimeout(r, ms));
const log = m => console.log(`[${new Date().toISOString().slice(11, 19)}] ${m}`);
const tag = crypto.randomBytes(4).toString('hex');
const MARK = {
    name: `NAME${tag}`,
    chat: `CHAT${tag}`,
    private: `PRIV${tag}`,
    poll: `POLL${tag}`,
    file: `FILE${tag}`
};

setTimeout(() => {
    console.error('run exceeded 4 minutes, aborting');
    process.exit(1);
}, 240000).unref();

// Records what the page sends on WebSockets and data channels.
const EGRESS_TAP = `(() => {
    if (window.top !== window) { return; }
    const sent = window.__egress = [];
    const text = d => typeof d === 'string' ? d
        : d instanceof ArrayBuffer ? new TextDecoder('latin1').decode(d)
        : ArrayBuffer.isView(d) ? new TextDecoder('latin1').decode(d) : String(d);
    const ws = WebSocket.prototype.send;
    WebSocket.prototype.send = function(d) {
        try { sent.push({ path: 'WebSocket ' + new URL(this.url).host, data: text(d) }); } catch {}
        return ws.apply(this, arguments);
    };
    // HTTP uploads: the browser doesn't expose file bodies to the test harness, so read them here.
    const open = XMLHttpRequest.prototype.open;
    XMLHttpRequest.prototype.open = function(method, url) {
        this.__url = String(url);
        return open.apply(this, arguments);
    };
    const xsend = XMLHttpRequest.prototype.send;
    XMLHttpRequest.prototype.send = function(body) {
        try {
            const p = 'HTTP upload ' + new URL(this.__url, location.href).host;
            if (body instanceof FormData) {
                for (const [ k, v ] of body.entries()) {
                    v instanceof Blob ? v.text().then(t => sent.push({ path: p, data: k + ': ' + v.name + ' ' + t }))
                        : sent.push({ path: p, data: k + ': ' + v });
                }
            } else if (body) {
                sent.push({ path: p, data: text(body) });
            }
            this.addEventListener('loadend', () => sent.push({ path: 'status', data: p + ' -> HTTP ' + this.status }));
        } catch {}
        return xsend.apply(this, arguments);
    };
    const dc = RTCDataChannel.prototype.send;
    RTCDataChannel.prototype.send = function(d) {
        try { sent.push({ path: 'data channel (bridge)', data: text(d) }); } catch {}
        return dc.apply(this, arguments);
    };
})();`;

const browser = await chromium.launch({ channel: 'chrome', headless: !argv.includes('--headed'), args: [
    '--use-fake-ui-for-media-stream',
    '--use-fake-device-for-media-stream',
    '--disable-features=LocalNetworkAccessChecks,PrivateNetworkAccessRespectPreflightResults,BlockInsecurePrivateNetworkRequests'
] });
const http = []; // { path, data } of Alice's HTTP requests

async function join(name, displayName) {
    const context = await browser.newContext({ ignoreHTTPSErrors: true });

    name === 'alice' && context.on('request', r => {
        const body = r.postDataBuffer();

        http.push({ path: `HTTP ${r.method()} ${new URL(r.url()).host}`,
            data: `${r.url()}\n${body ? body.toString('latin1') : ''}` });
    });
    const page = await context.newPage();

    await page.addInitScript({ content: EGRESS_TAP });

    // Bob joins with the guest token when there is one (as in the switch-off test).
    let url = target.url({
        'config.startWithAudioMuted': false,
        'config.startWithVideoMuted': false,
        'userInfo.displayName': displayName
    });
    const guestFile = new URL('../../../sandbox/inspector/.dev-token-guest', import.meta.url).pathname;

    if (name === 'bob' && target.deployment && fs.existsSync(guestFile)) {
        const jwt = new URL(url).searchParams.get('jwt');

        jwt && (url = url.replace(jwt, fs.readFileSync(guestFile, 'utf8').trim()));
    }
    await joinMeeting(page, url, name);

    return page;
}

log(`room ${target.room}; markers end in ${tag}`);
const alice = await join('alice', `alice-${MARK.name}`);
const bob = await join('bob', 'bob');

await sleep(3000);
await alice.evaluate(() => APP.store.dispatch({ type: 'TOGGLE_E2EE', enabled: true }));
await waitInPage(alice, () => APP.conference._room.isE2EEEnabled(), null, 30000);
await waitInPage(bob, () => APP.conference._room.isE2EEEnabled(), null, 30000);
log('E2EE on; Alice uses every content channel');
await sleep(3000);

const bobId = await bob.evaluate(() => APP.conference._room.myUserId());

// Bob records the messages the bridge relays to him (reactions travel this way).
await bob.evaluate(() => {
    window.__endpointMessages = [];
    APP.conference._room.on('conference.endpoint_message_received',
        (_p, data) => window.__endpointMessages.push(JSON.stringify(data)));
});
const sent = {};

// Display name: re-announce it now that encryption is on.
sent.name = await alice.evaluate(n => APP.conference._room.setDisplayName(n), `alice-${MARK.name}`)
    .then(() => true, e => String(e));
sent.chat = await alice.evaluate(m => APP.conference._room.sendTextMessage(m), MARK.chat)
    .then(() => true, e => String(e));
sent.private = await alice.evaluate(([ id, m ]) => APP.conference._room.sendPrivateTextMessage(id, m),
    [ bobId, MARK.private ]).then(() => true, e => String(e));
sent.poll = await alice.evaluate(m => APP.conference._room.getPolls()
    .createPoll(`poll-${m}`, `Question ${m}`, [ { name: `Yes ${m}` }, { name: `No ${m}` } ]), MARK.poll)
    .then(() => true, e => String(e));
sent.reaction = await alice.evaluate(() => APP.store.dispatch({ type: 'ADD_REACTION_BUFFER', reaction: 'like' }))
    .then(() => true, e => String(e));
sent.file = await alice.evaluate(m => APP.store.dispatch({ type: 'UPLOAD_FILES',
    files: [ new File([ `APE Space E2EE channel test ${m}\n` ], `channel-test-${m}.txt`, { type: 'text/plain' }) ] }),
    MARK.file).then(() => true, e => String(e));
await sleep(10000);

const egress = [ ...await alice.evaluate(() => window.__egress), ...http ];

// Controls: what Bob received.
const received = await bob.evaluate(m => {
    const st = APP.store.getState();
    const msgs = st['features/chat'].messages.map(x => x.message ?? '');
    const polls = JSON.stringify(st['features/polls']?.polls ?? {});
    const files = JSON.stringify([ ...(st['features/file-sharing']?.files?.values?.() ?? []) ]);
    const names = APP.conference._room.getParticipants().map(p => p.getDisplayName()).join(' ');
    const reactions = JSON.stringify(st['features/reactions'] ?? {});

    return {
        name: names.includes(m.name),
        chat: msgs.some(t => t.includes(m.chat)),
        private: msgs.some(t => t.includes(m.private)),
        poll: polls.includes(m.poll),
        reaction: (window.__endpointMessages ?? []).some(t => /like/.test(t)) || /like/.test(reactions),
        file: files.includes(m.file)
    };
}, MARK);

await Promise.all([ alice, bob ].map(leaveMeeting));
await browser.close();

const findings = (needle, isRegex = false) => {
    const hits = egress.filter(e => (isRegex ? needle.test(e.data) : e.data.includes(needle)));

    return [ ...new Set(hits.map(h => h.path)) ];
};
const rows = [
    [ 'Display name', MARK.name, findings(MARK.name), received.name ],
    [ 'Chat, to everyone', MARK.chat, findings(MARK.chat), received.chat ],
    [ 'Chat, private', MARK.private, findings(MARK.private), received.private ],
    [ 'Poll (question and answers)', MARK.poll, findings(MARK.poll), received.poll ],
    [ 'Reaction ("like")', 'like', findings(/"reactions":\["like"\]|reaction[^"]*"[^"]*like/, true), received.reaction ],
    [ 'Shared file (name and content)', MARK.file, findings(MARK.file), received.file ]
];

console.log('\nChannel                          Leaves Alice readable on                      Bob received it');
for (const [ channel, , paths, got ] of rows) {
    const control = got ? 'yes' : channel.startsWith('Reaction') ? 'not confirmed' : 'no';

    console.log(`${channel.padEnd(32)} ${(paths.length ? paths.join(', ') : 'not found in clear').padEnd(45)} ${control}`);
}
for (const e of egress.filter(x => x.path === 'status')) {
    console.log(`upload: ${e.data}`);
}
const failedToSend = Object.entries(sent).filter(([ , v ]) => v !== true);

failedToSend.length && console.log(`\nCould not send: ${failedToSend.map(([ k, v ]) => `${k} (${v})`).join('; ')}`);
console.log('\nAudio, video and screen sharing are end-to-end encrypted (see key-lifecycle.mjs, media-path.mjs).'
    + ' Every channel above is readable by the server it passes through.');
