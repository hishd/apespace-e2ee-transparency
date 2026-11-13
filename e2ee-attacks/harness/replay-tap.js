// Injected into a receiving browser by checks/frame-counter-replay.mjs.
//
// Sits where a malicious media server sits: on the encrypted frames between the
// network and the receiver's decryption. It
//   - records the IV of every encrypted frame received (SSRC, RTP timestamp,
//     frame counter), for the IV checks;
//   - on request, replaces the payload of later audio frames with the payload of
//     earlier ones (a replay), and notes which frames it replaced;
//   - records the RTP timestamp of every frame that comes out of decryption, so
//     the check can see whether a replayed frame was let through to be played.
//
// lib-jitsi-meet uses RTCRtpScriptTransform when the browser has it; frames are
// then only visible in its worker. Removing it makes the library use
// createEncodedStreams, with the frames on this thread. Its E2EE support check
// only needs createEncodedStreams.

(() => {
    if (window.top !== window) {
        return;
    }
    try {
        delete window.RTCRtpScriptTransform;
    } catch (e) {
        window.RTCRtpScriptTransform = undefined;
    }

    const state = {
        ivs: [], // { kind, ssrc, timestamp, counter } per received encrypted frame
        history: [], // { t, data } recent encrypted audio payloads
        plan: null, // { count, ageMs } replays still to make
        replaced: [], // { rtpTimestamp, ageMs } frames whose payload was replaced
        inboundAudio: [], // RTP timestamps of audio frames received unaltered
        decrypted: new Set() // `${kind}:${rtpTimestamp}` of frames out of decryption
    };

    window.__replayTap = {
        // Replace the payload of the next `count` audio frames with ones received ~ageMs earlier.
        replay(count, ageMs) {
            state.plan = { count, ageMs };
        },
        pending: () => state.plan?.count ?? 0,

        // Start a fresh IV record (call once encryption is on).
        resetIvs() {
            state.ivs = [];
            state.inboundAudio = [];
        },
        report() {
            const replays = state.replaced.map(r => ({ ...r, played: state.decrypted.has(`audio:${r.rtpTimestamp}`) }));

            const genuine = state.inboundAudio.filter(t => !state.replaced.some(r => r.rtpTimestamp === t));

            return {
                ivs: state.ivs,
                replays,
                genuineAudio: genuine.length,
                genuinePlayed: genuine.filter(t => state.decrypted.has(`audio:${t}`)).length
            };
        }
    };

    const IV_LENGTH = 12;
    const ivOf = data => {
        if (data.byteLength < IV_LENGTH + 2 || new Uint8Array(data)[data.byteLength - 2] !== IV_LENGTH) {
            return null;
        }
        const v = new DataView(data, data.byteLength - 2 - IV_LENGTH, IV_LENGTH);

        return { ssrc: v.getUint32(0), timestamp: v.getUint32(4), counter: v.getUint32(8) };
    };

    const origRecv = RTCRtpReceiver.prototype.createEncodedStreams;

    RTCRtpReceiver.prototype.createEncodedStreams = function() {
        const streams = origRecv.call(this);
        const kind = this.track?.kind;

        // Before decryption: record IVs, and replay on request.
        const inbound = new TransformStream({
            transform(frame, controller) {
                const iv = ivOf(frame.data);

                if (iv) {
                    state.ivs.push({ kind, ...iv });
                }
                if (kind === 'audio' && iv) {
                    const now = performance.now();

                    state.history.push({ t: now, data: frame.data.slice(0) });
                    while (state.history.length && now - state.history[0].t > 60000) {
                        state.history.shift();
                    }

                    const plan = state.plan;

                    if (plan && plan.count > 0) {
                        // The newest recorded payload at least ageMs old, not used before.
                        const old = [ ...state.history ].reverse()
                            .find(h => now - h.t >= plan.ageMs && !h.used);

                        if (old) {
                            old.used = true;
                            state.replaced.push({ rtpTimestamp: frame.timestamp, ageMs: Math.round(now - old.t) });
                            frame.data = old.data.slice(0);
                            plan.count--;
                        }
                    }
                    if (frame.data.byteLength && !state.replaced.some(r => r.rtpTimestamp === frame.timestamp)) {
                        state.inboundAudio.push(frame.timestamp);
                    }
                }
                controller.enqueue(frame);
            }
        });

        // After decryption: note what the decryptor let through.
        const outbound = new TransformStream({
            transform(frame, controller) {
                state.decrypted.add(`${kind}:${frame.timestamp}`);
                controller.enqueue(frame);
            }
        });

        outbound.readable.pipeTo(streams.writable);

        return { readable: streams.readable.pipeThrough(inbound), writable: outbound.writable };
    };
})();
