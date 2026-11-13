# Cryptographic libraries and roadmap

_Status: draft for APE Space approval · 13 November 2026. Answers checklist rows KEY-07 (key exchange library) and KEY-08 (post-quantum)._

## What APE Space uses

| Part | Library and version | Pinned by | Algorithms |
|---|---|---|---|
| Key exchange and emoji check | `@matrix-org/olm` 3.2.15 (libolm, compiled to WebAssembly) | npm lockfile integrity hash; the served `olm.js` and `olm.wasm` hashes in `extension/config.json` | Curve25519 key agreement, Ed25519 signatures, AES-256-CBC with HMAC-SHA-256 |
| Media frame encryption, key ratchet | lib-jitsi-meet v2118.0.0 + eight public patches, using the browser's Web Crypto | the vendored package's hash; the served files' hashes in `extension/config.json`; rebuilt by `e2ee-module/build.sh` | AES-128-GCM, HKDF-SHA-256 |
| Group safety number | `group-safety-number.patch`, Web Crypto | as above | SHA-256 |

## KEY-07: the Olm library

**Status of libolm.** The Matrix.org Foundation deprecated libolm in August 2024 in favour of vodozemac, its Rust implementation of the same protocols ([announcement](https://matrix.org/blog/2024/08/libolm-deprecation/)). Two things go with that:
- **Maintenance:** libolm gets no further maintenance.
- **Side channels:** third-party reports in 2024 described timing side channels in it. The maintainers said that, to their knowledge, these aren't exploitable in practice, but they strongly encourage moving to vodozemac. RustSec lists the Rust wrapper as unmaintained and potentially vulnerable (RUSTSEC-2024-0368).

**Jitsi still uses it.** Upstream lib-jitsi-meet still pins `@matrix-org/olm` 3.2.15 (master `fb7890da`, 12 November 2026). Its E2EE protocol is built on Olm's one-to-one sessions.

**Why APE Space keeps it for now.**
- **Narrow use.** Only Olm's one-to-one sessions are used, to carry media keys and verification messages. Media itself is encrypted by the browser's Web Crypto, not by Olm, and Megolm isn't used.
- **No remote way to time it.** The reported issues are timing side channels in local computation. Olm runs in the participant's browser, inside the sandboxed key vault, which runs no other code and makes no network requests. An attacker would need precise timing of computations inside that frame, from the same device.
- **The protocol is checked independently.** The attack scripts in `e2ee-attacks/` test what the Olm exchange must guarantee (no key to a server in the middle, no key to a hidden participant), whatever the implementation.
- **A switch alone has its own risk.** Moving to vodozemac without Jitsi would leave APE Space alone with a key-exchange implementation its upstream doesn't run.

**Plan.**
1. **Track** advisories for `@matrix-org/olm` and lib-jitsi-meet, and every upstream change to lib-jitsi-meet's `modules/e2ee/`, weekly and automatically (`.github/workflows/upstream-watch.yml`). Each change found is reviewed and recorded in `e2ee-module/UPSTREAM-REVIEWED`.
2. **Act on an advisory** that affects how APE Space uses Olm (session set-up, signatures, message decryption) as an incident: assess it within 5 working days, and ship a fix or a mitigation.
3. **Migrate to vodozemac** (WebAssembly build) when either of these comes first:
   - Jitsi moves to it, in which case APE Space follows upstream;
   - a libolm issue that is exploitable in APE Space's use is published.
   Either way the migration is a change to the key-exchange code, and goes through the re-review policy (`docs/re-review-policy.md`).

## KEY-08: quantum computers

**The risk.** Key agreement uses Curve25519, which a large enough quantum computer could break. Someone who records a meeting today could decrypt it later: the Olm messages that carry the media keys and the encrypted media, both of which pass through the servers. This is "harvest now, decrypt later". Media keys change whenever someone joins or leaves, but every key reaches participants through Olm, so breaking Curve25519 exposes all of them.

The symmetric parts are not the weak point. AES-GCM and HKDF-SHA-256 lose at most half their strength to a quantum computer. That leaves AES-128 with a margin that is still considered acceptable today; AES-256 would restore the full margin.

**Position.** APE Space doesn't currently protect recorded meetings against a future quantum computer, and says so in its customer-facing limits. No standard post-quantum Olm exists, and browsers' Web Crypto offers no post-quantum key agreement that APE Space could rely on everywhere.

**Plan (proposed).**
1. **Hybrid key agreement for the media key exchange.** Each participant also publishes an ML-KEM-768 public key, signed with its Ed25519 identity key like its other keys. A media key is then sent under a secret derived (HKDF) from both the Olm session and an ML-KEM encapsulation to the recipient. Recorded traffic stays safe unless both Curve25519 and ML-KEM are broken. This needs an audited ML-KEM implementation in the browser (WebAssembly), or Web Crypto support where available.
2. **AES-256-GCM for frames.** Derive a 256-bit frame key instead of 128 bits. Every client must change at once, so this ships as one coordinated release.
3. **Follow upstream.** If Matrix (vodozemac) or Jitsi adopt a post-quantum design, prefer it over an APE Space-only one.

Milestones for these, to be confirmed by APE Space:
- a design document for step 1 by the end of Q2 2027;
- an implementation and independent review after that.

Any change here goes through the re-review policy.
