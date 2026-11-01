// E2EE Inspector page hook. Must run in the page's own JS world before any page
// script (extension content script with world: 'MAIN', run_at: document_start,
// or Playwright's addInitScript).
//
// Records, in memory, for a TEST meeting:
//   - every encoded audio/video frame this browser RECEIVES, exactly as the
//     server delivered it and before lib-jitsi-meet decrypts it;
//   - every media key handed to the E2EE worker (setKey), i.e. the keys this
//     browser received over Olm;
//   - the Olm key-exchange messages relayed by the XMPP server.
//
// Frames pass through unchanged. Nothing leaves the browser except the file the
// user exports from the on-page panel (or window.__e2eeInspector.export*()).
// Everyone in the meeting is told in chat that the Inspector is on.
(() => {
    if (window.__e2eeInspector) {
        return;
    }

    const MAX_BYTES = 150 * 1024 * 1024;
    const state = {
        startedAt: Date.now(),
        recording: true,
        bytes: 0,
        dropped: 0,
        streams: [], // { id, kind, mode, participantId, mimeType, frames: [], encrypted }
        keys: [], // { t, participantId, keyIndex, key: number[] }
        keyExchange: [], // { t, direction, from, to, olmType, ciphertextBytes, sample }
        events: [], // { t, event, ... }: joins, E2EE on/off, notice sent
        participants: {}, // id -> display name
        identity: { self: null, seen: {} } // Olm identity keys: own, and as seen for others
    };
    const note = (event, extra) => state.events.push({ t: Date.now(), event, ...extra });

    // 1. Make lib-jitsi-meet use createEncodedStreams (frames visible on the main
    //    thread) instead of RTCRtpScriptTransform (frames only inside its worker).
    //    Its E2EE support check only needs createEncodedStreams.
    try {
        delete window.RTCRtpScriptTransform;
    } catch {
        window.RTCRtpScriptTransform = undefined;
    }

    const copyFrame = (stream, frame) => {
        if (!state.recording) {
            return;
        }
        const data = new Uint8Array(frame.data);

        if (state.bytes + data.length > MAX_BYTES) {
            state.dropped++;

            return;
        }
        let meta = {};

        try {
            meta = frame.getMetadata();
        } catch {}
        stream.mimeType ??= meta.mimeType;

        // A connection can change codec mid-stream (Jitsi moves to VP8 when E2EE starts).
        if (meta.payloadType !== undefined && meta.mimeType) {
            (stream.codecs ??= {})[meta.payloadType] ??= meta.mimeType;
        }
        state.bytes += data.length;
        if (data.length > 14 && data[data.length - 2] === 12) {
            stream.encrypted++;
        }
        stream.frames.push({
            t: Date.now(),
            type: frame.type, // 'key' | 'delta' for video, undefined for audio
            rtpTimestamp: frame.timestamp,
            ssrc: meta.synchronizationSource,
            payloadType: meta.payloadType,
            data: data.slice()
        });
    };

    const tap = (kind, mode) => {
        const stream = { id: state.streams.length, kind, mode, participantId: null, mimeType: undefined,
            frames: [], encrypted: 0 };

        state.streams.push(stream);

        return {
            stream,
            transform: new TransformStream({
                transform(frame, controller) {
                    copyFrame(stream, frame);
                    controller.enqueue(frame);
                }
            })
        };
    };

    // 2. Receivers on E2EE connections: lib-jitsi-meet calls createEncodedStreams
    //    and transfers the streams to its worker. Insert the tap in between.
    const tappedReadable = new WeakMap();
    const origRecv = RTCRtpReceiver.prototype.createEncodedStreams;

    RTCRtpReceiver.prototype.createEncodedStreams = function() {
        const streams = origRecv.call(this);

        if (this.__inspectorSelf) {
            return streams;
        }
        const { stream, transform } = tap(this.track?.kind, 'e2ee');
        const readable = streams.readable.pipeThrough(transform);

        tappedReadable.set(readable, stream);

        return { readable, writable: streams.writable };
    };

    // 3. Keys and the receiver -> participant mapping, from messages to the worker.
    const origPost = Worker.prototype.postMessage;

    Worker.prototype.postMessage = function(msg, ...rest) {
        try {
            if (msg?.operation === 'setKey' && msg.key) {
                const k = msg.key instanceof ArrayBuffer
                    ? new Uint8Array(msg.key)
                    : new Uint8Array(msg.key.buffer, msg.key.byteOffset, msg.key.byteLength);

                const entry = {
                    t: Date.now(),
                    participantId: msg.participantId,
                    keyIndex: msg.keyIndex,
                    key: Array.from(k),
                    cleared: false
                };

                state.keys.push(entry);
                addScanKey(entry);
            } else if (msg?.operation === 'setKey') {
                state.keys.push({ t: Date.now(), participantId: msg.participantId, keyIndex: msg.keyIndex,
                    key: null, cleared: true });
            } else if (msg?.operation === 'decode' && msg.readableStream) {
                const s = tappedReadable.get(msg.readableStream);

                if (s) {
                    s.participantId = msg.participantId;
                }
            }
        } catch {}

        return origPost.call(this, msg, ...rest);
    };

    // 4. Unencrypted connections: turn on encoded streams ourselves so the
    //    "before E2EE" frames can be recorded too, and pass everything through.
    const OrigPC = window.RTCPeerConnection;
    const plainTracks = new Map(); // stream -> MediaStreamTrack of its receiver

    function selfTapPeerConnection(pc) {
        const done = new WeakSet();
        const wire = (endpoint, kind, isReceiver) => {
            if (done.has(endpoint)) {
                return;
            }
            done.add(endpoint);
            endpoint.__inspectorSelf = true;
            try {
                const { readable, writable } = isReceiver
                    ? origRecv.call(endpoint) : endpoint.createEncodedStreams();

                if (isReceiver) {
                    const { stream, transform } = tap(kind, 'plain');

                    // Sender resolved later from the meeting's track list (watchMeeting).
                    plainTracks.set(stream, endpoint.track);
                    readable.pipeThrough(transform).pipeTo(writable);
                } else {
                    readable.pipeTo(writable);
                }
            } catch {}
        };
        const sweep = () => {
            for (const s of pc.getSenders()) {
                if (s.track || s.transport) {
                    wire(s, s.track?.kind, false);
                }
            }
        };

        pc.addEventListener('track', e => wire(e.receiver, e.track.kind, true));
        for (const m of [ 'addTrack', 'addTransceiver', 'setLocalDescription', 'setRemoteDescription' ]) {
            const orig = pc[m].bind(pc);

            pc[m] = (...args) => {
                const r = orig(...args);

                if (r?.then) {
                    r.then(sweep, () => {});
                } else {
                    sweep();
                }

                return r;
            };
        }
    }

    window.RTCPeerConnection = function(config = {}, ...rest) {
        const self = !config.encodedInsertableStreams;
        const pc = new OrigPC(self ? { ...config, encodedInsertableStreams: true } : config, ...rest);

        if (self) {
            selfTapPeerConnection(pc);
        }

        return pc;
    };
    window.RTCPeerConnection.prototype = OrigPC.prototype;
    Object.setPrototypeOf(window.RTCPeerConnection, OrigPC);

    // 5. Olm key-exchange messages as they cross the XMPP WebSocket.
    const OLM = /<json-message[^>]*>([\s\S]*?)<\/json-message>/;
    const noteStanza = (direction, text) => {
        if (typeof text !== 'string' || !text.includes('json-message') || !text.includes('olm')) {
            return;
        }
        const m = OLM.exec(text);

        try {
            const body = JSON.parse(m[1].replace(/&quot;/g, '"').replace(/&amp;/g, '&'));

            if (body.type !== 'olm') {
                return;
            }
            const ct = JSON.stringify(body.olm?.data ?? '');

            state.keyExchange.push({
                t: Date.now(),
                direction,
                from: /from=['"]([^'"]+)/.exec(text)?.[1] ?? null,
                to: /to=['"]([^'"]+)/.exec(text)?.[1] ?? null,
                olmType: body.olm?.type,
                ciphertextBytes: ct.length,
                sample: ct.slice(0, 160),

                // session-init carries the sender's public identity key in the clear.
                idKey: body.olm?.type === 'session-init' ? body.olm.data?.idKey ?? null : undefined
            });
        } catch {}
    };
    const origSend = WebSocket.prototype.send;

    WebSocket.prototype.send = function(data) {
        noteStanza('sent', data);
        scanOutgoing('websocket', urlWithoutQuery(this.url), data);

        return origSend.call(this, data);
    };
    const origAdd = WebSocket.prototype.addEventListener;

    WebSocket.prototype.addEventListener = function(type, fn, ...rest) {
        if (type === 'message') {
            origAdd.call(this, 'message', e => noteStanza('received', e.data));
        }

        return origAdd.call(this, type, fn, ...rest);
    };
    // Up the prototype chain: WebSocket may be a subclass (another extension or a
    // test harness wrapping it) that inherits the accessor.
    let onmessage;

    for (let p = WebSocket.prototype; p && !onmessage; p = Object.getPrototypeOf(p)) {
        onmessage = Object.getOwnPropertyDescriptor(p, 'onmessage');
    }

    onmessage?.set && Object.defineProperty(WebSocket.prototype, 'onmessage', {
        ...onmessage,
        set(fn) {
            onmessage.set.call(this, e => {
                noteStanza('received', e.data);

                return fn?.call(this, e);
            });
        }
    });

    // 6. Key leak check: every outgoing WebSocket and data-channel message from
    //    this page is searched for the media keys (leak-scan.js). HTTP requests,
    //    including those made by workers, are searched by the extension's
    //    background via webRequest; bridge.js relays keys there and results back.
    const LEAK_WINDOW_MS = 120000;
    const LEAK_BUFFER_BYTES = 20 * 1024 * 1024;
    const scanKeys = []; // every media key seen; kept even when the capture is discarded
    const recentOut = []; // recent outgoing messages, rescanned when a new key arrives
    let recentBytes = 0;
    const leak = { scanned: { websocket: 0, datachannel: 0 }, bytes: 0, findings: [], http: null };
    const sizeOf = p => (typeof p === 'string' ? p.length : p.byteLength);
    const reportLeaks = (hits, channel, destination, t) => {
        for (const h of hits) {
            leak.findings.push({ t, channel, destination, ...h });
        }
    };
    // Query strings can hold credentials (dev passes the JWT in the WebSocket URL).
    const urlWithoutQuery = url => {
        try {
            const u = new URL(url);

            return u.origin + u.pathname;
        } catch {
            return String(url).split('?')[0];
        }
    };
    const scanWith = (payload, keys) => globalThis.E2EELeakScan?.scan(payload, keys) ?? [];

    function scanOutgoing(channel, destination, payload) {
        try {
            if (payload instanceof Blob) {
                payload.arrayBuffer().then(b => scanOutgoing(channel, destination, b), () => {});

                return;
            }
            let copy;

            if (typeof payload === 'string') {
                copy = payload;
            } else if (payload instanceof ArrayBuffer) {
                copy = new Uint8Array(payload.slice(0));
            } else if (ArrayBuffer.isView(payload)) {
                copy = new Uint8Array(payload.buffer, payload.byteOffset, payload.byteLength).slice();
            } else {
                return;
            }
            const t = Date.now();

            leak.scanned[channel]++;
            leak.bytes += sizeOf(copy);
            reportLeaks(scanWith(copy, scanKeys), channel, destination, t);
            recentOut.push({ t, channel, destination, payload: copy });
            recentBytes += sizeOf(copy);
            while (recentOut.length && (recentOut[0].t < t - LEAK_WINDOW_MS || recentBytes > LEAK_BUFFER_BYTES)) {
                recentBytes -= sizeOf(recentOut.shift().payload);
            }
        } catch {}
    }

    function addScanKey({ participantId, keyIndex, key }) {
        const k = { participantId, keyIndex, key };

        scanKeys.push(k);
        for (const o of recentOut) {
            reportLeaks(scanWith(o.payload, [ k ]), o.channel, o.destination, o.t);
        }
    }

    const origDcSend = RTCDataChannel.prototype.send;

    RTCDataChannel.prototype.send = function(data) {
        scanOutgoing('datachannel', `data channel "${this.label}"`, data);

        return origDcSend.call(this, data);
    };

    // Extension background (HTTP scan): send the keys, receive its results.
    document.addEventListener('e2ee-inspector:http', e => {
        try {
            leak.http = JSON.parse(e.detail);
        } catch {}
    });
    const syncWithExtension = () => document.dispatchEvent(new CustomEvent('e2ee-inspector:keys', {
        detail: JSON.stringify(scanKeys.map(({ participantId, keyIndex, key }) => ({ participantId, keyIndex, key })))
    }));

    const leakCheck = () => ({
        keysChecked: scanKeys.length,
        watched: [ 'WebSocket messages from this page', 'data channel messages from this page',
            ...(leak.http ? [ `HTTP requests from this tab, including its workers, to ${leak.http.scope} (extension)` ] : []) ],
        scanned: { ...leak.scanned, http: leak.http?.scanned ?? null },
        bytes: leak.bytes + (leak.http?.bytes ?? 0),
        findings: [ ...leak.findings, ...(leak.http?.findings ?? []) ].sort((a, b) => a.t - b.t)
    });

    // 7. Meeting state: who is who, when E2EE switched, and the notice to everyone.
    const NOTICE = 'E2EE Inspector is ON for this participant: their browser is recording the media '
        + 'it receives (before decryption) and the media keys it receives, for an encryption test. '
        + 'It stays on this computer. If you do not agree, leave the meeting now.';
    let noticeRoom = null;
    let lastE2EE = null;

    const watchMeeting = () => {
        const room = window.APP?.conference?._room;

        if (!room?.isJoined?.()) {
            return;
        }
        try {
            const me = room.myUserId();

            if (!state.participants[me]) {
                note('joined', { participantId: me });
            }
            state.participants[me] = `${room.getLocalParticipantProperty?.('displayName')
                ?? window.APP.store?.getState()['features/base/settings']?.displayName ?? ''} (this browser)`;
            state.identity.self ??= { participantId: me };
            state.identity.self.curve25519 ??= room.getLocalParticipantProperty('e2ee.idKey.curve25519');
            state.identity.self.ed25519 ??= room.getLocalParticipantProperty('e2ee.idKey.ed25519');
            for (const p of room.getParticipants()) {
                state.participants[p.getId()] = p.getDisplayName() ?? '';
                const seen = { curve25519: p.getProperty('e2ee.idKey.curve25519'),
                    ed25519: p.getProperty('e2ee.idKey.ed25519') };
                const before = state.identity.seen[p.getId()];

                if (before?.curve25519 && (before.curve25519 !== seen.curve25519 || before.ed25519 !== seen.ed25519)) {
                    note('identity-key-changed', { participantId: p.getId() });
                }
                if (seen.curve25519 || !before) {
                    state.identity.seen[p.getId()] = seen;
                }
                for (const t of p.getTracks()) {
                    for (const [ stream, track ] of plainTracks) {
                        if (t.getTrack?.() === track) {
                            stream.participantId = p.getId();
                            plainTracks.delete(stream);
                        }
                    }
                }
            }
            const e2ee = room.isE2EEEnabled();

            if (e2ee !== lastE2EE) {
                note(e2ee ? 'e2ee-on' : 'e2ee-off');
                lastE2EE = e2ee;
            }
            if (noticeRoom !== room) {
                noticeRoom = room;
                room.sendTextMessage(NOTICE);
                note('notice-sent');
                room.on('conference.e2ee.verification.completed', (participantId, success) =>
                    note('sas-verified', { participantId, success }));
            }
        } catch {}
    };

    const toBase64 = bytes => {
        let s = '';

        for (let i = 0; i < bytes.length; i += 0x8000) {
            s += String.fromCharCode.apply(null, bytes.subarray(i, i + 0x8000));
        }

        return btoa(s);
    };

    const exportMeta = () => ({
        startedAt: state.startedAt,
        exportedAt: Date.now(),
        page: location.origin + location.pathname,
        participants: state.participants,
        identity: state.identity,
        leakCheck: leakCheck(),
        events: state.events,
        dropped: state.dropped,
        keys: state.keys,
        keyExchange: state.keyExchange,
        streams: state.streams.map(({ frames, encrypted, ...s }) => ({ ...s, frameCount: frames.length }))
    });

    // One file: the first line is the metadata, then one JSON line per frame.
    const exportCapture = () => {
        const parts = [ JSON.stringify({ format: 'e2ee-inspector/1', ...exportMeta() }), '\n' ];

        for (const s of state.streams) {
            for (const f of s.frames) {
                parts.push(JSON.stringify({ s: s.id, ...f, data: toBase64(f.data) }), '\n');
            }
        }

        return new Blob(parts, { type: 'application/x-ndjson' });
    };

    // 7. On-page panel: always visible while the hook is loaded.
    const mb = n => `${(n / 1048576).toFixed(1)} MB`;
    let panel;

    const renderPanel = () => {
        if (!panel) {
            if (!document.body) {
                return;
            }
            const host = document.createElement('div');

            host.id = 'e2ee-inspector-panel';
            host.style.cssText = 'position:fixed;left:12px;bottom:12px;z-index:2147483647';
            panel = host.attachShadow({ mode: 'open' });
            panel.innerHTML = `<style>
                .box{font:12px/1.4 system-ui,sans-serif;color:#f5f5f5;background:rgba(20,20,24,.92);
                  border:2px solid #e8a33c;border-radius:8px;padding:10px 12px;width:350px}
                h1{font-size:13px;margin:0 0 6px;color:#ffc56b}
                table{border-collapse:collapse;width:100%;margin:6px 0}
                td{padding:1px 4px 1px 0;white-space:nowrap}
                td.n{text-align:right}
                .warn{color:#ffc56b}
                .leak{color:#fff;background:#b3261e;border-radius:4px;padding:3px 6px;margin-top:4px;font-weight:600}
                .dim{color:#aaa}
                button{font:inherit;margin:4px 4px 0 0;padding:3px 8px;border-radius:4px;border:1px solid #888;
                  background:#2b2b31;color:#fff;cursor:pointer}
                button.primary{background:#e8a33c;color:#111;border-color:#e8a33c}
              </style>
              <div class="box" role="status" aria-live="off">
                <h1>● E2EE Inspector recording</h1>
                <div id="body"></div>
                <button class="primary" id="export">Export capture</button>
                <button id="pause"></button>
                <button id="discard">Discard</button>
              </div>`;
            panel.getElementById('export').onclick = () => {
                const a = document.createElement('a');

                a.href = URL.createObjectURL(exportCapture());
                a.download = `e2ee-capture-${new Date().toISOString().replace(/[:.]/g, '-')}.ndjson`;
                a.click();
                setTimeout(() => URL.revokeObjectURL(a.href), 60000);
            };
            panel.getElementById('pause').onclick = () => {
                state.recording = !state.recording;
            };
            panel.getElementById('discard').onclick = () => {
                for (const s of state.streams) {
                    s.frames = [];
                    s.encrypted = 0;
                }
                state.bytes = 0;
                state.dropped = 0;
                state.keys = [];
                state.keyExchange = [];
            };
            document.documentElement.appendChild(host);
        }
        const rows = state.streams.filter(s => s.frames.length).map(s => {
            const who = state.participants[s.participantId] || s.participantId || '?';

            return `<tr><td>${s.kind === 'audio' ? '🎤' : '🎥'} ${escape(who)}</td>`
                + `<td>${s.mode === 'e2ee' ? 'E2EE path' : 'plain path'}</td>`
                + `<td class="n">${s.frames.length}</td>`
                // A few plain frames match the trailer pattern by chance: judge the stream.
                + `<td class="n">${s.encrypted > s.frames.length / 2
                    ? `${Math.round(100 * s.encrypted / s.frames.length)}% encrypted` : 'not encrypted'}</td></tr>`;
        }).join('');

        panel.getElementById('body').innerHTML = `
            <div>E2EE in this meeting: <b>${lastE2EE === null ? '—' : lastE2EE ? 'ON' : 'off'}</b></div>
            <div>Media keys received: <b>${state.keys.filter(k => k.key).length}</b> ·
                 Olm messages: <b>${state.keyExchange.length}</b></div>
            <table><tr><td>Received</td><td></td><td class="n">frames</td><td></td></tr>${rows}</table>
            <div>${mb(state.bytes)} of ${mb(MAX_BYTES)}${state.dropped
                ? ` · <span class="warn">full, ${state.dropped} frames not kept</span>` : ''}
                ${state.recording ? '' : ' · <span class="warn">paused</span>'}</div>
            <div>Everyone was told in chat: <b>${noticeRoom ? 'yes' : 'not yet'}</b></div>
            ${leakLine()}`;
        panel.getElementById('pause').textContent = state.recording ? 'Pause' : 'Resume';
    };
    const leakLine = () => {
        const c = leakCheck();
        const n = c.scanned.websocket + c.scanned.datachannel + (c.scanned.http ?? 0);
        const where = `WebSocket ${c.scanned.websocket}, data channel ${c.scanned.datachannel}, HTTP ${
            c.scanned.http === null ? 'not watched' : `${c.scanned.http} (to ${leak.http.scope})`}`;

        return c.findings.length
            ? `<div class="leak">⚠ Media key found in ${c.findings.length} outgoing message(s): ${
                escape([ ...new Set(c.findings.map(f => f.channel)) ].join(', '))}</div>`
            : `<div>Key leak check: <b>no key</b> in ${n} outgoing messages <span class="dim">(${where})</span></div>`;
    };
    const escape = s => String(s).replace(/[&<>"']/g, c => `&#${c.charCodeAt(0)};`);

    setInterval(() => {
        watchMeeting();
        syncWithExtension();
        renderPanel();
    }, 1000);

    // Read-out API (also used by capture.mjs).
    window.__e2eeInspector = {
        summary: () => ({
            startedAt: state.startedAt,
            bytes: state.bytes,
            dropped: state.dropped,
            keys: state.keys.length,
            keyExchange: state.keyExchange.length,
            streams: state.streams.map(s => ({ id: s.id, kind: s.kind, mode: s.mode,
                participantId: s.participantId, mimeType: s.mimeType, frames: s.frames.length,
                ssrcs: [ ...new Set(s.frames.map(f => f.ssrc)) ] }))
        }),
        exportMeta,
        exportCapture,
        leakCheck,

        // Frames of one stream, [from, to), data as base64.
        exportFrames: (id, from, to) => state.streams[id].frames.slice(from, to).map(f => ({
            ...f,
            data: toBase64(f.data)
        }))
    };
})();
