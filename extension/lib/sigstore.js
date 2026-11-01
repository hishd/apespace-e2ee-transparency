// Verifies a Sigstore bundle (cosign sign-blob --bundle) for a file, using only
// WebCrypto, so the same code runs in the browser and in Node.
//
// Checks, against the trust anchors in config.json:
//  1. the signature over the file is valid for the certificate's key
//  2. the certificate was issued by Sigstore's certificate authority (Fulcio)
//  3. the certificate names the expected signer (the build workflow)
//  4. the signature is recorded in Sigstore's public log (Rekor): the log entry
//     matches, it is included in the log (Merkle proof), and the log head is
//     signed by Rekor, while the short-lived certificate was valid

const subtle = globalThis.crypto.subtle;
const enc = new TextEncoder();

export const b64 = s => Uint8Array.from(atob(s), c => c.charCodeAt(0));
export const hex = bytes => [ ...new Uint8Array(bytes) ].map(b => b.toString(16).padStart(2, '0')).join('');
const fromHex = s => Uint8Array.from(s.match(/../g), h => parseInt(h, 16));
const concat = (...parts) => {
    const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
    let i = 0;

    for (const p of parts) {
        out.set(p, i);
        i += p.length;
    }

    return out;
};
const sha256 = async data => new Uint8Array(await subtle.digest('SHA-256', data));
const equal = (a, b) => a.length === b.length && a.every((x, i) => x === b[i]);

// --- Minimal DER reader (enough for X.509 certificates) ---

function readTlv(buf, pos = 0) {
    const tag = buf[pos];
    let len = buf[pos + 1];
    let start = pos + 2;

    if (len & 0x80) {
        const n = len & 0x7f;

        len = 0;
        for (let i = 0; i < n; i++) {
            len = (len * 256) + buf[start + i];
        }
        start += n;
    }

    return { tag, start, end: start + len, all: buf.subarray(pos, start + len), value: buf.subarray(start, start + len) };
}

function children(buf) {
    const out = [];

    for (let pos = 0; pos < buf.length;) {
        const t = readTlv(buf, pos);

        out.push(t);
        pos = t.end;
    }

    return out;
}

function oid(bytes) {
    const parts = [ Math.floor(bytes[0] / 40), bytes[0] % 40 ];
    let n = 0;

    for (const b of bytes.subarray(1)) {
        n = (n * 128) + (b & 0x7f);
        if (!(b & 0x80)) {
            parts.push(n);
            n = 0;
        }
    }

    return parts.join('.');
}

function time(t) {
    const s = new TextDecoder().decode(t.value);
    const full = t.tag === 0x17 ? (Number(s.slice(0, 2)) < 50 ? '20' : '19') + s : s;

    return Date.UTC(full.slice(0, 4), full.slice(4, 6) - 1, full.slice(6, 8), full.slice(8, 10),
        full.slice(10, 12), full.slice(12, 14));
}

/**
 * Parses the parts of an X.509 certificate needed for verification.
 */
export function parseCertificate(der) {
    const [ tbs, sigAlg, sigValue ] = children(readTlv(der).value);
    const fields = children(tbs.value);
    const i = fields[0].tag === 0xa0 ? 1 : 0; // explicit version
    const validity = children(fields[i + 3].value);
    const extensions = {};
    const extField = fields.find(f => f.tag === 0xa3);

    for (const ext of extField ? children(children(extField.value)[0].value) : []) {
        const parts = children(ext.value);

        extensions[oid(parts[0].value)] = parts[parts.length - 1].value;
    }

    // Subject alternative names: URIs are [6].
    const san = extensions['2.5.29.17']
        ? children(readTlv(extensions['2.5.29.17']).value).filter(n => n.tag === 0x86)
            .map(n => new TextDecoder().decode(n.value))
        : [];

    // Fulcio's OIDC issuer extension: 1.3.6.1.4.1.57264.1.8 (DER string) or .1.1 (raw).
    const issuerExt = extensions['1.3.6.1.4.1.57264.1.8'] ?? extensions['1.3.6.1.4.1.57264.1.1'];
    const issuer = issuerExt && new TextDecoder().decode(
        extensions['1.3.6.1.4.1.57264.1.8'] ? readTlv(issuerExt).value : issuerExt);

    return {
        tbs: tbs.all,
        signatureAlgorithm: oid(children(sigAlg.value)[0].value),
        signature: sigValue.value.subarray(1), // skip the unused-bits byte
        spki: fields[i + 5].all,
        notBefore: time(validity[0]),
        notAfter: time(validity[1]),
        san,
        oidcIssuer: issuer
    };
}

// ECDSA signatures are DER sequences; WebCrypto wants r || s.
function ecdsaRaw(der, size) {
    const [ r, s ] = children(readTlv(der).value).map(x => {
        const v = x.value[0] === 0 ? x.value.subarray(1) : x.value;

        return concat(new Uint8Array(size - v.length), v);
    });

    return concat(r, s);
}

const CURVES = { 'P-256': [ 32, 'SHA-256' ], 'P-384': [ 48, 'SHA-384' ] };
const HASH_OF = { '1.2.840.10045.4.3.2': 'SHA-256', '1.2.840.10045.4.3.3': 'SHA-384' };

// The curve of an EC public key (SubjectPublicKeyInfo).
function curveOf(spki) {
    const curve = oid(children(children(readTlv(spki).value)[0].value)[1].value);

    return { '1.2.840.10045.3.1.7': 'P-256', '1.3.132.0.34': 'P-384' }[curve];
}

async function ecdsaVerify(spki, derSignature, data, hash) {
    const curve = curveOf(spki);
    const key = await subtle.importKey('spki', spki, { name: 'ECDSA', namedCurve: curve }, false, [ 'verify' ]);

    return subtle.verify({ name: 'ECDSA', hash: hash ?? CURVES[curve][1] }, key,
        ecdsaRaw(derSignature, CURVES[curve][0]), data);
}

// --- Log inclusion (RFC 9162, section 2.1.3.2) ---

async function verifyInclusion(index, treeSize, leafHash, proof, root) {
    let fn = index;
    let sn = treeSize - 1;
    let r = leafHash;

    for (const p of proof) {
        if (sn === 0) {
            return false;
        }
        if (fn % 2 === 1 || fn === sn) {
            r = await sha256(concat([ 1 ], p, r));
            while (fn % 2 === 0 && fn !== 0) {
                fn = Math.floor(fn / 2);
                sn = Math.floor(sn / 2);
            }
        } else {
            r = await sha256(concat([ 1 ], r, p));
        }
        fn = Math.floor(fn / 2);
        sn = Math.floor(sn / 2);
    }

    return sn === 0 && equal(r, root);
}

/**
 * Verifies a bundle for a file. Returns the signer details, or throws with the
 * reason it does not verify.
 *
 * @param {Uint8Array} file - The signed file.
 * @param {Object} bundle - The parsed .sigstore.json bundle.
 * @param {Object} trust - config.json's trust section.
 * @param {RegExp} identity - The expected certificate identity (SAN URI).
 */
export async function verifyBundle(file, bundle, trust, identity) {
    const fail = msg => {
        throw new Error(msg);
    };
    const certDer = b64(bundle.verificationMaterial.certificate.rawBytes);
    const cert = parseCertificate(certDer);
    const signature = b64(bundle.messageSignature.signature);

    // 1. Signature over the file.
    hex(await sha256(file)) === hex(b64(bundle.messageSignature.messageDigest.digest))
        || fail('the file does not match the signed digest');
    await ecdsaVerify(cert.spki, signature, file) || fail('invalid signature');

    // 2. Certificate chain up to Sigstore's root.
    const chain = [ certDer, ...trust.fulcioChain.map(b64) ].map(parseCertificate);

    for (let i = 0; i < chain.length - 1; i++) {
        await ecdsaVerify(chain[i + 1].spki, chain[i].signature, chain[i].tbs, HASH_OF[chain[i].signatureAlgorithm])
            || fail('certificate not issued by Sigstore');
    }

    // 3. Signer identity.
    cert.oidcIssuer === trust.oidcIssuer || fail(`unexpected identity provider ${cert.oidcIssuer}`);
    cert.san.some(u => identity.test(u)) || fail(`signed by ${cert.san.join(', ')}, not the official build`);

    // 4. Public log entry.
    const entry = bundle.verificationMaterial.tlogEntries[0];
    const body = JSON.parse(atob(entry.canonicalizedBody));
    const integrated = Number(entry.integratedTime) * 1000;

    entry.logId.keyId === trust.rekor.keyId || fail('logged in an unknown log');
    body.spec.data.hash.value === hex(await sha256(file)) || fail('log entry is for another file');
    body.spec.signature.content === bundle.messageSignature.signature || fail('log entry has another signature');
    atob(body.spec.signature.publicKey.content).replace(/-----[^-]+-----|\s/g, '')
        === bundle.verificationMaterial.certificate.rawBytes || fail('log entry has another certificate');
    integrated >= cert.notBefore && integrated <= cert.notAfter || fail('logged outside the certificate validity');

    const proof = entry.inclusionProof;
    const leaf = await sha256(concat([ 0 ], b64(entry.canonicalizedBody)));

    await verifyInclusion(Number(proof.logIndex), Number(proof.treeSize), leaf, proof.hashes.map(b64),
        b64(proof.rootHash)) || fail('not included in the log');

    // The checkpoint (signed log head) must cover that root and be signed by Rekor.
    const [ note, sigLines ] = proof.checkpoint.envelope.split('\n\n');
    const [ , size, root ] = note.split('\n');

    size === String(proof.treeSize) && root === btoa(String.fromCharCode(...b64(proof.rootHash)))
        || fail('log checkpoint does not match the proof');
    const sig = b64(sigLines.trim().split(' ').pop()).subarray(4); // 4-byte key hint

    await ecdsaVerify(b64(trust.rekor.publicKey), sig, enc.encode(`${note}\n`), 'SHA-256')
        || fail('log checkpoint not signed by Rekor');

    return {
        signer: cert.san[0],
        loggedAt: new Date(integrated).toISOString(),
        logIndex: entry.logIndex
    };
}

export { fromHex, sha256 };
