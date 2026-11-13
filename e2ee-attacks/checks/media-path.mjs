// The media path of an encrypted meeting, for checklist row SRV-08 (relays and
// media servers see only end-to-end encrypted traffic).
//
// Alice and Bob hold an end-to-end encrypted meeting. From inside each browser the
// check reads:
//   - the network path media actually takes: the selected ICE candidate pair
//     (direct to the bridge, or through a TURN relay), with the remote address,
//     port and protocol;
//   - the STUN/TURN servers the deployment gives the browser (addresses only, never
//     credentials);
//   - every frame that arrived from the other participant, as the bridge forwarded
//     it (tapped before decryption): whether it is end-to-end encrypted.
//
//   node checks/media-path.mjs [--url <meeting URL>] [--headed]

import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { chromium } from 'playwright-core';
import { joinMeeting, leaveMeeting, meetingTarget, waitInPage } from '../harness/meeting.mjs';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const argv = process.argv.slice(2);
const target = meetingTarget(argv, 'mediapath');
const sleep = ms => new Promise(r => setTimeout(r, ms));
const results = [];
const check = (id, name, ok, detail) => results.push({ id, name, ok, detail });

setTimeout(() => {
    console.error('run exceeded 4 minutes, aborting');
    process.exit(1);
}, 240000).unref();

const browser = await chromium.launch({ channel: 'chrome', headless: !argv.includes('--headed'), args: [
    '--use-fake-ui-for-media-stream',
    '--use-fake-device-for-media-stream',
    '--disable-features=LocalNetworkAccessChecks,PrivateNetworkAccessRespectPreflightResults,BlockInsecurePrivateNetworkRequests'
] });

async function join(name) {
    const context = await browser.newContext({ ignoreHTTPSErrors: true });
    const page = await context.newPage();

    await page.addInitScript({ path: path.join(HERE, '../../extension/inspector/leak-scan.js') });
    await page.addInitScript({ path: path.join(HERE, '../../extension/inspector/hook.js') });
    await joinMeeting(page, target.url({
        'config.startWithAudioMuted': false,
        'config.startWithVideoMuted': false,
        'userInfo.displayName': name
    }), name);

    return page;
}

const path_ = page => page.evaluate(async () => {
    const room = APP.conference._room;
    const session = room.getActiveMediaSession?.() ?? room.jvbJingleSession;
    const pc = session.peerconnection.peerconnection;
    const stats = await pc.getStats();
    let pair;

    stats.forEach(s => {
        if (s.type === 'transport' && s.selectedCandidatePairId) {
            pair = stats.get(s.selectedCandidatePairId);
        }
    });
    const local = pair && stats.get(pair.localCandidateId);
    const remote = pair && stats.get(pair.remoteCandidateId);
    const servers = (pc.getConfiguration().iceServers ?? [])
        .flatMap(s => [].concat(s.urls ?? s.url ?? []))
        .map(u => String(u).replace(/\?.*$/, ''));

    return {
        p2p: room.isP2PActive(),
        e2ee: room.isE2EEEnabled(),
        local: local && { type: local.candidateType, protocol: local.protocol, relayProtocol: local.relayProtocol },
        remote: remote && { type: remote.candidateType, address: remote.address, port: remote.port,
            protocol: remote.protocol },
        servers
    };
});

const alice = await join('alice');
const bob = await join('bob');

await sleep(3000);
await alice.evaluate(() => APP.store.dispatch({ type: 'TOGGLE_E2EE', enabled: true }));
await waitInPage(alice, () => APP.conference._room.isE2EEEnabled(), null, 30000);
await waitInPage(bob, () => APP.conference._room.isE2EEEnabled(), null, 30000);
await sleep(4000);
const t0 = Date.now();

await sleep(15000);
const paths = { alice: await path_(alice), bob: await path_(bob) };

// Every frame Bob received from Alice since t0, as the bridge forwarded it.
const aliceId = await alice.evaluate(() => APP.conference._room.myUserId());
const { streams } = await bob.evaluate(() => window.__e2eeInspector.exportMeta());
let frames = 0;
let encrypted = 0;

for (const s of streams.filter(st => st.participantId === aliceId)) {
    const list = await bob.evaluate(([ id, n ]) => window.__e2eeInspector.exportFrames(id, 0, n), [ s.id, s.frameCount ]);

    for (const f of list.filter(x => x.t >= t0)) {
        const data = Buffer.from(f.data, 'base64');

        frames++;
        encrypted += data.length > 14 && data[data.length - 2] === 12 ? 1 : 0;
    }
}

await Promise.all([ alice, bob ].map(leaveMeeting));
await browser.close();

for (const [ who, p ] of Object.entries(paths)) {
    console.log(`${who}: ${p.p2p ? 'peer to peer' : 'via the bridge'}; local ${p.local?.type}/${p.local?.protocol}`
        + `${p.local?.relayProtocol ? ` (relay over ${p.local.relayProtocol})` : ''}; remote ${p.remote?.type} `
        + `${p.remote?.address}:${p.remote?.port}/${p.remote?.protocol}`);
    console.log(`${who}: STUN/TURN servers offered: ${p.servers.join(', ') || 'none'}`);
}
check('SRV-08', 'encrypted meeting media goes via the bridge, not peer to peer', !paths.alice.p2p && !paths.bob.p2p,
    `alice ${paths.alice.p2p ? 'p2p' : 'bridge'}, bob ${paths.bob.p2p ? 'p2p' : 'bridge'}`);
check('SRV-08', 'every frame the bridge forwarded from Alice to Bob is end-to-end encrypted',
    frames > 0 && encrypted === frames, `${encrypted} of ${frames}`);

console.log('');
for (const r of results) {
    console.log(`${r.ok ? 'PASS' : 'FAIL'}  ${r.id}  ${r.name}  (${r.detail})`);
}
process.exit(results.every(r => r.ok) ? 0 : 1);
