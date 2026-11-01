// Compares two participants' captures of the same meeting (metadata lines only).
//
// What it can show:
//  - Identity keys. Each browser publishes its Olm identity keys and every other
//    browser builds its encrypted channel to it from what the server relays. If the
//    server had put itself in the middle, at least one browser would hold an
//    identity key the other never had. Same keys on both sides = no interception.
//  - Media keys. Each media key one browser received is byte-for-byte a key the
//    other browser generated. (On its own this would not rule out interception, as
//    an interceptor could pass the key on unchanged; the identity check does that.)

const ownName = c => c.participants?.[c.identity?.self?.participantId]?.replace(/ \(this browser\)$/, '');
const resource = jid => (jid ? jid.split('/').pop() : null);
const sameBytes = (a, b) => a.length === b.length && a.every((v, i) => v === b[i]);

function identityCheck(owner, receiver) {
    const own = owner.identity?.self;
    const seen = receiver.identity?.seen?.[own?.participantId];

    if (!own?.curve25519 || !seen?.curve25519) {
        return { status: 'missing', detail: 'Identity keys not in one of the captures.' };
    }
    const ok = own.curve25519 === seen.curve25519 && own.ed25519 === seen.ed25519;

    return {
        status: ok ? 'pass' : 'fail',
        owner: own.curve25519,
        received: seen.curve25519,
        detail: ok ? 'Identical on both computers.' : 'Different: the key exchange did not run directly between these two browsers.'
    };
}

function sessionInitCheck(owner, receiver) {
    const id = owner.identity?.self?.participantId;
    const inits = receiver.keyExchange.filter(m => m.direction === 'received' && m.olmType === 'session-init'
        && resource(m.from) === id && m.idKey);

    if (!inits.length) {
        return { status: 'n/a', detail: 'The other side started this Olm session.' };
    }
    const ok = inits.every(m => m.idKey === owner.identity.self.curve25519);

    return { status: ok ? 'pass' : 'fail',
        detail: ok ? 'The session was set up with the genuine identity key.'
            : 'The session was set up with an identity key this participant never had.' };
}

function mediaKeyCheck(owner, receiver) {
    const id = owner.identity?.self?.participantId;
    const used = owner.keys.filter(k => k.key && k.participantId === id);
    const got = receiver.keys.filter(k => k.key && k.participantId === id);

    if (!got.length || !used.length) {
        return { status: 'missing', detail: 'No media key of this participant in one of the captures.' };
    }
    const match = (a, b) => a.keyIndex === b.keyIndex && sameBytes(a.key, b.key);

    // A conflict is a key slot holding different bytes on the two sides: what a
    // substituted key would look like. A received key the owner never put to use
    // is harmless: lib-jitsi-meet replaces a key it is still distributing when
    // someone leaves at that moment.
    const conflicts = got.filter(g => !used.some(u => match(u, g)) && used.some(u => u.keyIndex === g.keyIndex));
    const unused = got.filter(g => !used.some(u => u.keyIndex === g.keyIndex));
    const undelivered = used.filter(u => !got.some(g => match(u, g)));
    const delivered = used.length - undelivered.length;
    const notes = [];

    unused.length && notes.push(`${unused.length} other key(s) received that this participant replaced before using`);
    undelivered.length && notes.push(`${undelivered.length} key(s) used by this participant not in the other capture `
        + '(exported before it arrived?)');

    return {
        status: conflicts.length ? 'fail' : delivered ? 'pass' : 'missing',
        detail: conflicts.length
            ? `${conflicts.length} received key(s) differ from the key this participant used in the same slot.`
            : `${delivered} key(s) this participant encrypted with were received byte-for-byte identical${
                notes.length ? `; ${notes.join('; ')}` : ''}.`
    };
}

/** a, b: capture metadata objects. */
export function compareCaptures(a, b) {
    const idA = a.identity?.self?.participantId;
    const idB = b.identity?.self?.participantId;
    const sameMeeting = a.page === b.page && Boolean(idA && idB) && idA !== idB
        && idB in (a.participants ?? {}) && idA in (b.participants ?? {});
    const direction = (owner, receiver) => ({
        identity: identityCheck(owner, receiver),
        sessionInit: sessionInitCheck(owner, receiver),
        mediaKeys: mediaKeyCheck(owner, receiver)
    });
    const aToB = direction(a, b);
    const bToA = direction(b, a);
    const all = [ aToB, bToA ].flatMap(d => Object.values(d));
    const sas = [ a, b ].flatMap(c => c.events.filter(e => e.event === 'sas-verified'));

    return {
        sameMeeting,
        a: { participantId: idA, name: ownName(a) },
        b: { participantId: idB, name: ownName(b) },
        aToB,
        bToA,
        noInterception: sameMeeting && [ aToB, bToA ].every(d => d.identity.status === 'pass')
            && [ aToB.sessionInit, bToA.sessionInit ].every(c => c.status !== 'fail'),
        keysIntact: sameMeeting && [ aToB, bToA ].every(d => d.mediaKeys.status === 'pass'),
        anyFailure: all.some(c => c.status === 'fail'),
        leaks: { a: a.leakCheck?.findings?.length ?? null, b: b.leakCheck?.findings?.length ?? null },
        emojiVerification: sas
    };
}
