// Finds media keys inside outgoing data. Classic script (no modules) so it can be
// loaded both into the meeting page (before hook.js) and into the extension's
// service worker (importScripts). Exposes globalThis.E2EELeakScan.
//
// A key is looked for as: raw bytes, hex, base64 / base64url at any byte
// alignment (so a key inside a larger encoded blob is still found), and as a
// JSON/CSV list of byte values. Encrypted or deliberately disguised copies cannot
// be found this way; that is what code verification is for.
(() => {
    if (globalThis.E2EELeakScan) {
        return;
    }
    const B64 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';

    const base64 = bytes => {
        let s = '';

        for (let i = 0; i < bytes.length; i += 3) {
            const n = (bytes[i] << 16) | ((bytes[i + 1] ?? 0) << 8) | (bytes[i + 2] ?? 0);

            s += B64[(n >> 18) & 63] + B64[(n >> 12) & 63] + B64[(n >> 6) & 63] + B64[n & 63];
        }

        return s;
    };
    const hex = bytes => Array.from(bytes, b => b.toString(16).padStart(2, '0')).join('');

    /** Text patterns and a raw-byte prefix that identify one key. */
    function needles(keyBytes) {
        const key = Uint8Array.from(keyBytes);
        const text = [
            { encoding: 'hex', value: hex(key) },
            { encoding: 'byte list', value: Array.from(key).join(',') },
            { encoding: 'byte list', value: Array.from(key).join(', ') }
        ];

        for (let shift = 0; shift < 3; shift++) {
            const padded = new Uint8Array(shift + key.length);

            padded.set(key, shift);

            // Drop the first and last 4-character groups: they mix in neighbouring bytes.
            const core = base64(padded).slice(4, -4);

            text.push({ encoding: 'base64', value: core });
            text.push({ encoding: 'base64url', value: core.replace(/\+/g, '-').replace(/\//g, '_') });
        }

        return { text, raw: key.subarray(0, 16) };
    }

    const indexOfBytes = (hay, needle) => {
        outer: for (let i = 0; i + needle.length <= hay.length; i++) {
            for (let j = 0; j < needle.length; j++) {
                if (hay[i + j] !== needle[j]) {
                    continue outer;
                }
            }

            return i;
        }

        return -1;
    };

    /**
     * payload: string | ArrayBuffer | ArrayBufferView. keys: [{ participantId, keyIndex, key }].
     * Returns the keys found: [{ participantId, keyIndex, encoding }].
     */
    function scan(payload, keys) {
        const found = [];
        let text = null, bytes = null;

        if (typeof payload === 'string') {
            text = payload;
            text = text.toLowerCase() === text ? text : `${text}\n${text.toLowerCase()}`;
        } else if (payload instanceof ArrayBuffer) {
            bytes = new Uint8Array(payload);
        } else if (ArrayBuffer.isView(payload)) {
            bytes = new Uint8Array(payload.buffer, payload.byteOffset, payload.byteLength);
        } else {
            return found;
        }
        for (const k of keys) {
            k.needles ??= needles(k.key);
            if (bytes) {
                if (indexOfBytes(bytes, k.needles.raw) >= 0) {
                    found.push({ participantId: k.participantId, keyIndex: k.keyIndex, encoding: 'raw bytes' });
                }

                // Binary frames can still carry text.
                if (bytes.length < 4 * 1024 * 1024) {
                    const asText = new TextDecoder('latin1').decode(bytes);
                    const hit = k.needles.text.find(n => asText.includes(n.value));

                    hit && found.push({ participantId: k.participantId, keyIndex: k.keyIndex, encoding: hit.encoding });
                }
            } else {
                const hit = k.needles.text.find(n => text.includes(n.value));

                hit && found.push({ participantId: k.participantId, keyIndex: k.keyIndex, encoding: hit.encoding });
            }
        }

        return found;
    }

    globalThis.E2EELeakScan = { scan, needles };
})();
