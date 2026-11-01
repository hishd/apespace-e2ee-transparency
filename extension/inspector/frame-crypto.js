// Decrypts Jitsi E2EE media frames with the keys a browser received over Olm.
// Shared by the viewer page (browser) and decrypt.mjs (Node); uses WebCrypto only.
//
// Mirrors lib-jitsi-meet modules/e2ee/crypto-utils.js and Context.js:
//   key      = HKDF-SHA-256(material, salt "JFrameEncryptionKey") -> AES-GCM-128
//   ratchet  = HKDF-SHA-256(material, salt "JFrameRatchetKey") -> next material
//   frame    = header | ciphertext | IV(12) | IV_LENGTH | KEY_INDEX
//   header   = first 10 bytes of a video keyframe, 3 of a delta frame, 1 of audio
//              (left readable for the bridge; authenticated as AES-GCM extra data)

export const IV_LENGTH = 12;
export const RATCHET_WINDOW = 8;

const enc = new TextEncoder();
const subtle = () => globalThis.crypto.subtle;

export const headerLength = type => (type === 'key' ? 10 : type === 'delta' ? 3 : 1);

export const hasTrailer = data => data.length > IV_LENGTH + 2 && data[data.length - 2] === IV_LENGTH;

export const toHex = bytes => Array.from(bytes, b => b.toString(16).padStart(2, '0')).join('');

/** First 8 bytes of SHA-256(key), hex: lets two people compare a key without revealing it. */
export async function fingerprint(keyBytes) {
    return toHex(new Uint8Array(await subtle().digest('SHA-256', new Uint8Array(keyBytes))).subarray(0, 8));
}

const importMaterial = bytes => subtle().importKey('raw', bytes, 'HKDF', false, [ 'deriveBits', 'deriveKey' ]);
const deriveAesKey = material => subtle().deriveKey(
    { name: 'HKDF', hash: 'SHA-256', salt: enc.encode('JFrameEncryptionKey'), info: new ArrayBuffer(0) },
    material, { name: 'AES-GCM', length: 128 }, false, [ 'decrypt' ]);
const ratchet = async material => importMaterial(await subtle().deriveBits(
    { name: 'HKDF', hash: 'SHA-256', salt: enc.encode('JFrameRatchetKey'), info: new ArrayBuffer(0) },
    material, 256));

async function tryDecrypt(aesKey, data, hdr) {
    const ivLen = data[data.length - 2];
    const iv = data.subarray(data.length - 2 - ivLen, data.length - 2);
    const ct = data.subarray(hdr, data.length - 2 - ivLen);
    const plain = new Uint8Array(await subtle().decrypt(
        { name: 'AES-GCM', iv, additionalData: data.subarray(0, hdr) }, aesKey, ct));
    const out = new Uint8Array(hdr + plain.length);

    out.set(data.subarray(0, hdr));
    out.set(plain, hdr);

    return out;
}

/**
 * keys: [{ t, participantId, keyIndex, key: number[] | null }] as recorded by hook.js.
 * Returns decrypt(stream, frame) -> Uint8Array | null. A frame decrypts only if
 * AES-GCM authentication succeeds, so a wrong key can never yield "plausible" media.
 */
export function createDecryptor(keys) {
    // Per (participant, keyIndex): the key that last worked, advanced by ratcheting
    // when the sender ratchets (on joins) without distributing a new key.
    const state = new Map();

    const candidates = (participantId, keyIndex, t) => {
        const usable = keys.filter(k => k.key && k.keyIndex === keyIndex && k.t <= t + 5000)
            .sort((a, b) => b.t - a.t);

        // The sender's own keys first; then any other (receivers can be remapped
        // between participants by the bridge).
        return [ ...usable.filter(k => k.participantId === participantId),
            ...usable.filter(k => k.participantId !== participantId) ];
    };

    return async (stream, frame) => {
        const data = frame.data;

        if (!hasTrailer(data)) {
            return null;
        }
        const keyIndex = data[data.length - 1];
        const hdr = headerLength(frame.type);
        const slot = `${stream.participantId}:${keyIndex}`;
        const cached = state.get(slot);

        if (cached) {
            let { material, aes } = cached;

            for (let r = 0; r <= RATCHET_WINDOW; r++) {
                try {
                    const out = await tryDecrypt(aes, data, hdr);

                    state.set(slot, { material, aes });

                    return out;
                } catch {
                    material = await ratchet(material);
                    aes = await deriveAesKey(material);
                }
            }
        }
        for (const k of candidates(stream.participantId, keyIndex, frame.t)) {
            let material = await importMaterial(new Uint8Array(k.key));

            for (let r = 0; r <= RATCHET_WINDOW; r++) {
                const aes = await deriveAesKey(material);

                try {
                    const out = await tryDecrypt(aes, data, hdr);

                    state.set(slot, { material, aes });

                    return out;
                } catch {
                    material = await ratchet(material);
                }
            }
        }

        return null;
    };
}
