// Capture viewer: shows what the browser received, decrypts it with the keys it
// received, and plays both with the browser's own decoders (WebCodecs).
// No network access: the file stays in this tab.

import { compareCaptures } from './compare.js';
import { codecInfo, pack, splitByCodec, temporalUnits } from './containers.js';
import { createDecryptor, fingerprint, hasTrailer, toHex } from './frame-crypto.js';

const $ = id => document.getElementById(id);
const sleep = ms => new Promise(r => setTimeout(r, ms));
const status = text => {
    $('status').textContent = text;
};
const el = (tag, props = {}, ...children) => {
    const node = Object.assign(document.createElement(tag), props);

    node.append(...children.filter(c => c !== null && c !== undefined));

    return node;
};

function fromBase64(s) {
    const bin = atob(s);
    const out = new Uint8Array(bin.length);

    for (let i = 0; i < bin.length; i++) {
        out[i] = bin.charCodeAt(i);
    }

    return out;
}

function download(name, bytes) {
    const a = el('a', { href: URL.createObjectURL(new Blob([ bytes ])), download: name });

    a.click();
    setTimeout(() => URL.revokeObjectURL(a.href), 60000);
}

// ---------------------------------------------------------------- decoding

/** Draws one frame's bytes as grey pixels: what undecodable data "looks like". */
function drawBytes(canvas, bytes) {
    const w = 64;
    const h = Math.max(1, Math.ceil(bytes.length / w));
    const img = new ImageData(w, h);

    bytes.forEach((b, i) => img.data.set([ b, b, b, 255 ], i * 4));
    canvas.width = w;
    canvas.height = h;
    canvas.getContext('2d').putImageData(img, 0, 0);
    canvas.style.imageRendering = 'pixelated';
}

/**
 * Feeds frames to a VideoDecoder and paints each picture. With realtime, frames
 * are paced as they were received. Returns { shown, rejected }.
 */
async function playVideo(canvas, codec, captured, { realtime = true, onProgress } = {}) {
    const frames = temporalUnits(captured);
    const ctx = canvas.getContext('2d');
    const result = { shown: 0, rejected: 0 };
    let needKey = true;
    let decoder;
    const make = () => {
        decoder = new VideoDecoder({
            output: picture => {
                canvas.width = picture.displayWidth;
                canvas.height = picture.displayHeight;
                canvas.style.imageRendering = '';
                ctx.drawImage(picture, 0, 0);
                picture.close();
                result.shown++;
            },
            error: () => {
                result.rejected++;
                needKey = true;
            }
        });
        decoder.configure({ codec: codec.webcodecs, optimizeForLatency: true });
    };

    if (!codec.webcodecs || !(await VideoDecoder.isConfigSupported({ codec: codec.webcodecs })).supported) {
        drawBytes(canvas, frames[0].data);

        return { ...result, unsupported: true };
    }
    make();
    const t0 = frames[0].t;
    const start = performance.now();

    for (const f of frames) {
        if (realtime) {
            const wait = f.t - t0 - (performance.now() - start);

            if (wait > 0) {
                await sleep(wait);
            }
            onProgress?.(result);
        }
        if (decoder.state === 'closed') {
            make();
        }
        if (needKey && f.type !== 'key') {
            continue;
        }
        try {
            decoder.decode(new EncodedVideoChunk({ type: f.type === 'key' ? 'key' : 'delta',
                timestamp: (f.t - t0) * 1000, data: f.data }));
            needKey = false;
        } catch {
            result.rejected++;
            needKey = true;
        }
        // Back-pressure without flush(): after a flush the decoder demands a keyframe.
        while (!realtime && decoder.state === 'configured' && decoder.decodeQueueSize > 30) {
            await sleep(5);
        }
    }
    await decoder.flush().catch(() => {});
    if (!result.shown) {
        drawBytes(canvas, frames.find(f => f.type === 'key')?.data ?? frames[0].data);
    }
    onProgress?.(result);

    return result;
}

/** Decodes Opus frames to mono PCM at 48 kHz. Returns { pcm, rejected }. */
async function decodeAudio(frames) {
    const chunks = [];
    let rejected = 0;
    let decoder;
    const make = () => {
        decoder = new AudioDecoder({
            output: data => {
                const buf = new Float32Array(data.numberOfFrames);

                try {
                    data.copyTo(buf, { planeIndex: 0, format: 'f32-planar' });

                    // Ciphertext "decodes" to out-of-range values: clamp so playback
                    // is loud noise, not a speaker-damaging spike.
                    for (let i = 0; i < buf.length; i++) {
                        buf[i] = Math.max(-1, Math.min(1, buf[i] || 0));
                    }
                    chunks.push(buf);
                } catch {}
                data.close();
            },
            error: () => {
                rejected++;
            }
        });
        decoder.configure({ codec: 'opus', sampleRate: 48000, numberOfChannels: 2 });
    };

    make();
    for (let i = 0; i < frames.length; i++) {
        if (decoder.state === 'closed') {
            make();
        }
        try {
            decoder.decode(new EncodedAudioChunk({ type: 'key', timestamp: i * 20000, data: frames[i].data }));
        } catch {
            rejected++;
        }
        if (i % 50 === 49) {
            await decoder.flush().catch(() => {});
        }
    }
    await decoder.flush().catch(() => {});
    const pcm = new Float32Array(chunks.reduce((n, c) => n + c.length, 0));
    let o = 0;

    for (const c of chunks) {
        pcm.set(c, o);
        o += c.length;
    }

    return { pcm, rejected };
}

function drawWave(canvas, pcm) {
    const w = canvas.width = 800;
    const h = canvas.height = 200;
    const ctx = canvas.getContext('2d');
    const step = Math.max(1, Math.floor(pcm.length / w));

    ctx.fillStyle = '#000';
    ctx.fillRect(0, 0, w, h);
    ctx.strokeStyle = '#6fcf8d';
    ctx.beginPath();
    for (let x = 0; x < w; x++) {
        let lo = 0, hi = 0;

        for (let i = x * step; i < Math.min(pcm.length, (x + 1) * step); i++) {
            lo = Math.min(lo, pcm[i]);
            hi = Math.max(hi, pcm[i]);
        }
        ctx.moveTo(x, h / 2 - (hi * h) / 2);
        ctx.lineTo(x, h / 2 - (lo * h) / 2);
    }
    ctx.stroke();
}

let audioCtx;

function playPcm(pcm, volume) {
    audioCtx ??= new AudioContext({ sampleRate: 48000 });
    const buf = audioCtx.createBuffer(1, pcm.length, 48000);

    buf.copyToChannel(pcm, 0);
    const src = audioCtx.createBufferSource();
    const gain = audioCtx.createGain();

    gain.gain.value = volume;
    src.buffer = buf;
    src.connect(gain).connect(audioCtx.destination);
    src.start();

    return src;
}

// ---------------------------------------------------------------- rendering

const pct = (a, b) => (b ? `${Math.round((100 * a) / b)}%` : '—');

/** A player pane for one version (as received / decrypted) of a stream. */
async function pane(title, stream, frames, fileName, report) {
    const { codec, s } = stream;
    const canvas = el('canvas', { className: s.kind === 'audio' ? 'wave' : '' });
    const note = el('div', { className: 'note' });
    const play = el('button', { textContent: '▶ Play' });
    const save = el('button', { textContent: `Download .${codec.ext}` });

    save.onclick = () => download(fileName, pack(codec, frames));

    if (s.kind === 'audio') {
        const { pcm, rejected } = await decodeAudio(frames);
        let rms = 0;

        for (const v of pcm) {
            rms += v * v;
        }
        rms = Math.sqrt(rms / Math.max(1, pcm.length));
        drawWave(canvas, pcm);
        note.textContent = `${(pcm.length / 48000).toFixed(1)} s of sound; loudness ${rms.toFixed(3)} RMS`
            + `${rejected ? `; decoder rejected ${rejected} frames` : ''}.`;
        Object.assign(report, { seconds: pcm.length / 48000, rms, rejected });
        let src;

        play.onclick = () => {
            if (src) {
                src.stop();
                src = null;
                play.textContent = '▶ Play';

                return;
            }
            // Encrypted audio is full-scale noise: play it quietly.
            src = playPcm(pcm, rms > 0.1 ? 0.15 : 1);
            play.textContent = '■ Stop';
            src.onended = () => {
                src = null;
                play.textContent = '▶ Play';
            };
        };
    } else {
        const describe = r => {
            note.textContent = r.unsupported
                ? `This browser has no ${codec.name} decoder; showing raw bytes.`
                : r.shown
                    ? `${r.shown} pictures decoded${r.rejected ? `; decoder rejected the data ${r.rejected} times` : ''}.`
                    : 'Nothing decodable: the picture shows one frame\'s raw bytes as grey pixels.';
        };
        const preview = await playVideo(canvas, codec, frames, { realtime: false });

        describe(preview);
        Object.assign(report, preview);
        play.onclick = async () => {
            play.disabled = true;
            describe(await playVideo(canvas, codec, frames, { onProgress: describe }));
            play.disabled = false;
        };
    }

    return el('div', { className: 'pane' }, el('h4', { textContent: title }), canvas, play, save, note);
}

async function render(meta, streams) {
    const name = id => meta.participants?.[id] || id || 'unknown sender';
    const rel = t => `+${((t - meta.startedAt) / 1000).toFixed(1)} s`;
    const report = [];
    const box = $('streams');

    box.replaceChildren();
    for (const stream of streams) {
        const { s, frames, encrypted, decrypted, codec } = stream;
        const r = { stream: s.id, kind: s.kind, mode: s.mode, codec: codec.name, frames: frames.length,
            encrypted, decrypted: decrypted?.length ?? null, asReceived: {}, afterDecryption: {} };

        report.push(r);
        status(`Preparing stream ${s.id}…`);

        // The trailer test is a byte pattern, so a few plain frames match by chance.
        const isEncrypted = encrypted > frames.length / 2;
        const facts = el('div', { className: 'facts' },
            `${codec.name} · ${frames.length} frames · ${rel(frames[0].t)} to ${rel(frames.at(-1).t)}`,
            el('br'),
            el('span', { className: isEncrypted ? 'enc' : '' }, isEncrypted
                ? `${encrypted} of ${frames.length} frames encrypted (${pct(encrypted, frames.length)})`
                : 'Not end-to-end encrypted'));

        if (decrypted) {
            facts.append(el('br'), el('span', { className: decrypted.length ? 'ok' : 'enc' },
                `${decrypted.length} of ${encrypted} decrypted with the received keys`));
        }
        const left = el('div', {}, el('h3', { textContent: `${s.kind === 'audio' ? '🎤' : '🎥'} ${name(s.participantId)}` }),
            facts);
        const asReceived = await pane('As the server delivered it', stream, frames,
            `stream-${s.id}-as-received.${codec.ext}`, r.asReceived);
        let right;

        if (decrypted?.length) {
            right = await pane('Decrypted here with the received keys', stream, decrypted,
                `stream-${s.id}-decrypted.${codec.ext}`, r.afterDecryption);
        } else {
            right = el('div', { className: 'pane' }, el('h4', { textContent: 'Decrypted' }),
                el('div', { className: 'note', textContent: isEncrypted
                    ? 'No received key opens these frames.'
                    : 'Not encrypted: anyone relaying this stream, including the server, could see or hear it.' }));
        }
        box.append(el('div', { className: 'stream' }, left, asReceived, right));
    }

    window.__viewerSwitchover = renderSwitchover(meta, streams, rel);

    // Keys.
    const keyRows = await Promise.all(meta.keys.filter(k => k.key).map(async k => {
        const show = el('button', { textContent: 'Show key' });
        const cell = el('td', {}, show);

        show.onclick = () => cell.replaceChildren(el('code', { textContent: toHex(k.key) }));

        return el('tr', {}, el('td', { textContent: name(k.participantId) }), el('td', { textContent: k.keyIndex }),
            el('td', { textContent: rel(k.t) }), el('td', {}, el('code', { textContent: await fingerprint(k.key) })),
            el('td', { textContent: `${k.key.length * 8}-bit` }), cell);
    }));

    $('keys').replaceChildren(el('tr', {}, ...[ 'From', 'Index', 'Received', 'Fingerprint', 'Size', 'Key' ]
        .map(h => el('th', { textContent: h }))), ...keyRows);

    // Key exchange and meeting events, in order.
    const who = jid => (jid ? name(jid.split('/').pop()) : '');
    const EVENT = { 'joined': 'You joined the meeting', 'e2ee-on': 'End-to-end encryption switched ON',
        'e2ee-off': 'End-to-end encryption switched off', 'notice-sent': 'Inspector notice posted in chat' };
    const rows = [
        ...meta.events.map(e => ({ t: e.t, detail: '', what: e.event === 'sas-verified'
            ? `Emoji verification with ${name(e.participantId)} ${e.success ? 'succeeded' : 'FAILED'}`
            : e.event === 'identity-key-changed' ? `Identity key of ${name(e.participantId)} CHANGED`
                : EVENT[e.event] ?? e.event })),
        ...meta.keyExchange.map(m => ({ t: m.t,
            what: `Olm ${m.olmType} ${m.direction === 'sent' ? `sent to ${who(m.to)}` : `from ${who(m.from)}`}`,
            detail: `${m.ciphertextBytes} bytes, as the server relayed it: ${m.sample}…` })),
        ...meta.keys.map(k => ({ t: k.t, what: k.key ? `Media key of ${name(k.participantId)} handed to the decryptor`
            : `Key of ${name(k.participantId)} removed`, detail: '' }))
    ].sort((a, b) => a.t - b.t);

    $('timeline').replaceChildren(el('tr', {}, ...[ 'When', 'What', 'Content' ].map(h => el('th', { textContent: h }))),
        ...rows.map(r => el('tr', {}, el('td', { textContent: rel(r.t) }), el('td', { textContent: r.what }),
            el('td', {}, el('code', { textContent: r.detail })))));

    renderLeaks(meta, name, rel);
    renderRecipients(meta, name, rel);

    return report;
}

/**
 * How long unencrypted media kept arriving after E2EE was switched on. On first
 * enable lib-jitsi-meet reports E2EE as on at once, then sets up encrypted
 * channels with every participant, sends the keys and only then restarts the
 * media connection with encryption; until then media flows as before.
 */
function renderSwitchover(meta, streams, rel) {
    const on = meta.events.find(e => e.event === 'e2ee-on')?.t;
    const plain = streams.filter(s => s.encrypted <= s.frames.length / 2);
    const enc = streams.filter(s => s.encrypted > s.frames.length / 2);
    const box = $('switch');

    if (!on || !plain.length || !enc.length) {
        box.replaceChildren();

        return null;
    }
    const lastPlain = Math.max(...plain.map(s => s.frames.at(-1).t));
    const firstEnc = Math.min(...enc.map(s => s.frames[0].t));
    const gap = Math.max(0, lastPlain - on) / 1000;
    const result = { e2eeOn: on, lastUnencrypted: lastPlain, firstEncrypted: firstEnc, unencryptedAfterOnSeconds: gap };

    box.replaceChildren(el('div', { className: `verdict ${gap > 1 ? 'fail' : 'pass'}`, textContent: gap > 1
        ? `E2EE was switched on at ${rel(on)}, but unencrypted media kept arriving for another ${gap.toFixed(1)} s `
            + `(until ${rel(lastPlain)}) while the browsers set up encrypted channels with every participant and `
            + `exchanged keys. Encrypted media started at ${rel(firstEnc)}. During that time the server could see and `
            + 'hear the unencrypted media.'
        : `E2EE was switched on at ${rel(on)}; the last unencrypted frame arrived within ${gap.toFixed(1)} s, `
            + `and encrypted media started at ${rel(firstEnc)}.` }));

    return result;
}

function renderRecipients(meta, name, rel) {
    const c = meta.recipientCheck;

    if (!c) {
        $('recipients').replaceChildren(el('p', { textContent: 'This capture was made before this check existed.' }));

        return;
    }
    const verdict = c.notListed.length
        ? el('div', { className: 'verdict fail', textContent: `Your media key was sent to ${c.notListed.length} `
            + 'participant(s) who are not in the participant list.' })
        : el('div', { className: 'verdict pass', textContent: c.recipients.length
            ? `Your media key was sent to ${c.recipients.length} participant(s), all in the participant list.`
            : 'Your browser did not send its media key to anyone during the capture.' });
    const nodes = [ verdict ];

    if (c.recipients.length) {
        nodes.push(el('table', {}, el('tr', {}, ...[ 'First sent', 'Participant', 'In the participant list' ]
            .map(h => el('th', { textContent: h }))),
        ...c.recipients.map(r => el('tr', {}, el('td', { textContent: rel(r.t) }),
            el('td', { textContent: name(r.participantId) }),
            el('td', { className: r.listed === false ? 'fail' : '',
                textContent: r.listed === null ? 'unknown' : r.listed ? 'yes' : 'NO' })))));
    }
    $('recipients').replaceChildren(...nodes);
}

function renderLeaks(meta, name, rel) {
    const c = meta.leakCheck;

    if (!c) {
        $('leaks').replaceChildren(el('p', { textContent: 'This capture was made before the leak check existed.' }));

        return;
    }
    const total = c.scanned.websocket + c.scanned.datachannel + (c.scanned.http ?? 0);
    const verdict = c.findings.length
        ? el('div', { className: 'verdict fail',
            textContent: `A media key was found in ${c.findings.length} outgoing message(s). See below.` })
        : el('div', { className: 'verdict pass', textContent: `No media key was found in any of the ${total} outgoing `
            + `messages (${(c.bytes / 1048576).toFixed(1)} MB) checked against ${c.keysChecked} key(s).` });
    const watched = el('table', {}, el('tr', {}, el('th', { textContent: 'Watched' }), el('th', { textContent: 'Messages' })),
        ...[ [ 'WebSocket messages from the page (signalling, chat, other services)', c.scanned.websocket ],
            [ 'Data channel messages from the page (to the media bridge)', c.scanned.datachannel ],
            [ 'HTTP requests from the tab, including its workers and service worker', c.scanned.http ?? 'not watched' ] ]
            .map(([ w, n ]) => el('tr', {}, el('td', { textContent: w }), el('td', { textContent: n }))));
    const nodes = [ verdict, watched ];

    if (c.findings.length) {
        nodes.push(el('h3', { textContent: 'Where the keys went' }),
            el('table', {}, el('tr', {}, ...[ 'When', 'Channel', 'Destination', 'Key of', 'Written as' ]
                .map(h => el('th', { textContent: h }))),
            ...c.findings.map(f => el('tr', {}, el('td', { textContent: rel(f.t) }),
                el('td', { className: 'fail', textContent: f.channel }),
                el('td', {}, el('code', { textContent: f.destination ?? '' })),
                el('td', { textContent: `${name(f.participantId)} (index ${f.keyIndex})` }),
                el('td', { textContent: f.encoding })))));
    }
    $('leaks').replaceChildren(...nodes);
}

async function readMeta(file) {
    const reader = file.stream().pipeThrough(new TextDecoderStream()).getReader();
    let text = '';

    while (!text.includes('\n')) {
        const { value, done } = await reader.read();

        if (done) {
            break;
        }
        text += value;
    }
    reader.cancel().catch(() => {});

    return JSON.parse(text.split('\n')[0]);
}

function renderCompare(r) {
    const label = p => `${p.name || p.participantId} (${p.participantId})`;
    const cell = c => el('td', { className: c.status === 'pass' ? 'pass' : c.status === 'fail' ? 'fail' : '' },
        `${{ pass: '✓', fail: '✗', missing: '?', 'n/a': '–' }[c.status]} ${c.detail}`);
    const rows = [
        [ 'Identity key: what the owner\'s browser has vs what the other browser was given', 'identity' ],
        [ 'Identity key used to set up the encrypted channel (Olm session-init)', 'sessionInit' ],
        [ 'Media keys: received vs generated by the owner', 'mediaKeys' ]
    ];
    const verdicts = [];

    if (!r.sameMeeting) {
        verdicts.push(el('div', { className: 'verdict fail', textContent: 'These two captures are not from two different '
            + 'participants of the same meeting session (rejoining gives a new participant and new keys).' }));
    } else {
        verdicts.push(el('div', { className: `verdict ${r.noInterception ? 'pass' : 'fail'}`, textContent: r.noInterception
            ? 'No interception: each browser holds the other\'s genuine identity key, so the key exchange ran directly '
                + 'between the two browsers and the server could not read the media keys.'
            : 'The identity keys do not match: the key exchange between these browsers went through a third party.' }));
        verdicts.push(el('div', { className: `verdict ${r.keysIntact ? 'pass' : 'fail'}`, textContent: r.keysIntact
            ? 'Each browser received exactly the media keys the other one generated.'
            : 'The media keys received do not all match the keys that were generated.' }));
    }
    const leakText = n => (n === null ? 'not checked' : n ? `${n} leak finding(s)` : 'no key found');

    $('compare').replaceChildren(...verdicts,
        el('table', {}, el('tr', {}, el('th', { textContent: 'Check' }),
            el('th', { textContent: `Keys of ${label(r.a)} → seen by ${label(r.b)}` }),
            el('th', { textContent: `Keys of ${label(r.b)} → seen by ${label(r.a)}` })),
        ...rows.map(([ title, k ]) => el('tr', {}, el('td', { textContent: title }), cell(r.aToB[k]), cell(r.bToA[k]))),
        el('tr', {}, el('td', { textContent: 'Key leak check (outgoing traffic of each browser)' }),
            el('td', { textContent: `${label(r.a)}: ${leakText(r.leaks.a)}` }),
            el('td', { textContent: `${label(r.b)}: ${leakText(r.leaks.b)}` })),
        el('tr', {}, el('td', { textContent: 'Emoji verification done in the meeting' }),
            el('td', { colSpan: 2, textContent: r.emojiVerification.length
                ? r.emojiVerification.map(e => (e.success ? 'succeeded' : 'FAILED')).join(', ') : 'not done (optional)' }))));
}

let primaryMeta = null;

async function load(file) {
    status('Reading…');
    const lines = (await file.text()).split('\n').filter(Boolean);
    const meta = JSON.parse(lines[0]);

    if (meta.format !== 'e2ee-inspector/1') {
        throw new Error('this is not an E2EE Inspector capture');
    }
    const byStream = new Map(meta.streams.map(s => [ s.id, [] ]));

    for (let i = 1; i < lines.length; i++) {
        const f = JSON.parse(lines[i]);

        f.data = fromBase64(f.data);
        byStream.get(f.s)?.push(f);
    }

    status('Decrypting with the keys in the file…');
    const decrypt = createDecryptor(meta.keys);
    const streams = [];

    const parts = meta.streams.flatMap(s => (byStream.get(s.id)?.length ? splitByCodec(s, byStream.get(s.id)) : []));

    for (const { stream: s, frames } of parts) {
        let decrypted = null;

        if (s.mode === 'e2ee') {
            decrypted = [];
            for (const f of frames) {
                const data = await decrypt(s, f);

                if (data) {
                    decrypted.push({ ...f, data });
                }
            }
        }
        streams.push({ s, frames, codec: codecInfo(s.kind, s.mimeType), decrypted,
            encrypted: frames.filter(f => hasTrailer(f.data)).length });
    }
    streams.sort((a, b) => String(a.s.participantId).localeCompare(String(b.s.participantId))
        || a.s.kind.localeCompare(b.s.kind) || a.frames[0].t - b.frames[0].t);

    $('out').hidden = false;
    primaryMeta = meta;
    const report = await render(meta, streams);

    status(`${file.name}: ${streams.length} streams, ${meta.keys.filter(k => k.key).length} keys, `
        + `${meta.keyExchange.length} key-exchange messages.`);

    return report;
}

$('file').onchange = async e => {
    const file = e.target.files[0];

    if (!file) {
        return;
    }
    try {
        window.__viewerReport = await load(file);
    } catch (err) {
        status(`Could not open the file: ${err.message}`);
        window.__viewerReport = { error: err.message };
    }
};

$('file2').onchange = async e => {
    const file = e.target.files[0];

    if (!file || !primaryMeta) {
        return;
    }
    try {
        const other = await readMeta(file);

        if (other.format !== 'e2ee-inspector/1') {
            throw new Error('this is not an E2EE Inspector capture');
        }
        window.__compareReport = compareCaptures(primaryMeta, other);
        renderCompare(window.__compareReport);
    } catch (err) {
        $('compare').replaceChildren(el('p', { textContent: `Could not open the file: ${err.message}` }));
        window.__compareReport = { error: err.message };
    }
};
