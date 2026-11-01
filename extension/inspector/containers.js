// Packs captured encoded frames into files ordinary players open (VLC, ffplay):
// Opus -> .ogg, VP8/VP9/AV1 -> .ivf, H.264 -> raw Annex B .h264.
// Shared by the viewer page and decrypt.mjs; returns Uint8Array, no Node APIs.

export function codecInfo(kind, mimeType) {
    const mime = (mimeType ?? '').toLowerCase();

    if (kind === 'audio') {
        return { name: 'Opus', ext: 'ogg', webcodecs: 'opus' };
    }
    if (mime.endsWith('/av1')) {
        return { name: 'AV1', ext: 'ivf', fourcc: 'AV01', webcodecs: 'av01.0.08M.08' };
    }
    if (mime.endsWith('/vp9')) {
        return { name: 'VP9', ext: 'ivf', fourcc: 'VP90', webcodecs: 'vp09.00.41.08' };
    }
    if (mime.endsWith('/h264')) {
        return { name: 'H.264', ext: 'h264', webcodecs: 'avc1.42E033' };
    }

    // Chrome versions without metadata.mimeType: Jitsi's default video codec.
    return { name: 'VP8', ext: 'ivf', fourcc: 'VP80', webcodecs: 'vp8' };
}

/**
 * Splits a captured stream where its codec changes (by RTP payload type), so each
 * part is played and packed with the right codec. Returns [{ stream, frames }].
 */
export function splitByCodec(stream, frames) {
    const codecs = stream.codecs ?? {};

    if (new Set(Object.values(codecs)).size < 2) {
        return [ { stream, frames } ];
    }
    const parts = [];

    for (const f of frames) {
        const mimeType = codecs[f.payloadType] ?? stream.mimeType;
        const last = parts.at(-1);

        if (last?.stream.mimeType === mimeType) {
            last.frames.push(f);
        } else {
            parts.push({ stream: { ...stream, id: `${stream.id}${String.fromCharCode(97 + parts.length)}`, mimeType },
                frames: [ f ] });
        }
    }

    return parts;
}

const CRC = Array.from({ length: 256 }, (_, i) => {
    let r = i << 24;

    for (let j = 0; j < 8; j++) {
        r = r & 0x80000000 ? (r << 1) ^ 0x04c11db7 : r << 1;
    }

    return r >>> 0;
});

const ascii = s => Uint8Array.from(s, c => c.charCodeAt(0));

function concat(parts) {
    const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
    let o = 0;

    for (const p of parts) {
        out.set(p, o);
        o += p.length;
    }

    return out;
}

function oggPage(payload, granule, seq, flags) {
    const lacing = [ ...Array(Math.floor(payload.length / 255)).fill(255), payload.length % 255 ];
    const page = new Uint8Array(27 + lacing.length + payload.length);
    const v = new DataView(page.buffer);

    page.set(ascii('OggS'), 0);
    page[5] = flags;
    v.setBigInt64(6, BigInt(granule), true);
    v.setUint32(14, 0x494e5350, true);
    v.setUint32(18, seq, true);
    page[26] = lacing.length;
    page.set(lacing, 27);
    page.set(payload, 27 + lacing.length);
    let crc = 0;

    for (const b of page) {
        crc = ((crc << 8) ^ CRC[((crc >>> 24) ^ b) & 0xff]) >>> 0;
    }
    v.setUint32(22, crc, true);

    return page;
}

/** Samples (at 48 kHz) in one Opus packet, from its TOC byte (RFC 6716 3.1). */
export function opusSamples(p) {
    const toc = p[0] ?? 0;
    const cfg = toc >> 3;
    const size = cfg < 12 ? [ 480, 960, 1920, 2880 ][cfg % 4] : cfg < 16 ? [ 480, 960 ][cfg % 2]
        : [ 120, 240, 480, 960 ][cfg % 4];
    const c = toc & 3;
    const n = c === 0 ? 1 : c < 3 ? 2 : Math.max(1, Math.min(48, (p[1] ?? 1) & 0x3f));

    return size * n;
}

export function oggOpus(frames) {
    const head = concat([ ascii('OpusHead'), Uint8Array.of(1, 2, 0x38, 0x01, 0x80, 0xbb, 0, 0, 0, 0, 0) ]);
    const tags = concat([ ascii('OpusTags'), Uint8Array.of(9, 0, 0, 0), ascii('inspector'), Uint8Array.of(0, 0, 0, 0) ]);
    const pages = [ oggPage(head, 0, 0, 2), oggPage(tags, 0, 1, 0) ];
    let granule = 0;

    frames.forEach((f, i) => {
        granule += opusSamples(f);
        pages.push(oggPage(f, granule, i + 2, i === frames.length - 1 ? 4 : 0));
    });

    return concat(pages);
}

export function ivf(frames, fourcc) {
    let w = 0, h = 0;

    for (const f of frames) {
        if (fourcc === 'VP80' && f.length >= 10 && !(f[0] & 1) && f[3] === 0x9d && f[4] === 0x01 && f[5] === 0x2a) {
            w = (f[6] | (f[7] << 8)) & 0x3fff;
            h = (f[8] | (f[9] << 8)) & 0x3fff;
            break;
        }
    }
    const hdr = new Uint8Array(32);
    const v = new DataView(hdr.buffer);

    hdr.set(ascii('DKIF'), 0);
    v.setUint16(6, 32, true);
    hdr.set(ascii(fourcc), 8);
    v.setUint16(12, w, true);
    v.setUint16(14, h, true);
    v.setUint32(16, 30, true);
    v.setUint32(20, 1, true);
    v.setUint32(24, frames.length, true);
    const parts = [ hdr ];

    frames.forEach((f, i) => {
        const fh = new Uint8Array(12);
        const fv = new DataView(fh.buffer);

        fv.setUint32(0, f.length, true);
        fv.setBigUint64(4, BigInt(i), true);
        parts.push(fh, f);
    });

    return concat(parts);
}

/**
 * Joins video frames that share an RTP timestamp into one temporal unit. With
 * scalable AV1/VP9 the bridge forwards each spatial layer as its own frame, but
 * decoders (WebCodecs, IVF readers) expect one unit per picture time.
 */
export function temporalUnits(frames) {
    const units = [];

    for (const f of frames) {
        const last = units.at(-1);

        if (last && f.rtpTimestamp !== undefined && last.rtpTimestamp === f.rtpTimestamp) {
            last.parts.push(f.data);
        } else {
            units.push({ ...f, parts: [ f.data ] });
        }
    }

    return units.map(({ parts, ...u }) => ({ ...u, data: parts.length === 1 ? parts[0] : concat(parts) }));
}

/** File bytes for captured frames ({ data, rtpTimestamp }) of the given codec (see codecInfo). */
export function pack(codec, frames) {
    if (codec.ext === 'ogg') {
        return oggOpus(frames.map(f => f.data));
    }
    if (codec.ext === 'ivf') {
        return ivf(temporalUnits(frames).map(f => f.data), codec.fourcc);
    }

    return concat(frames.map(f => f.data));
}
