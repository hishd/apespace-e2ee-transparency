# APESpace encryption code

APESpace meetings are end-to-end encrypted by **lib-jitsi-meet**, Jitsi's open-source WebRTC library, and the keys are held by Olm. This folder lets you rebuild every file of the encryption code APESpace serves, from public source, and check each is byte-for-byte the same.

Source: [jitsi/lib-jitsi-meet](https://github.com/jitsi/lib-jitsi-meet) v2118.0.0 (`67fd2c84`) + `olm-key-auth.patch` + `hidden-key-recipients.patch` + `group-safety-number.patch` + `e2ee-key-vault.patch` + `newcomer-key-ratchet.patch` + `dtx-empty-frames.patch` + `frame-counter-replay.patch` + `vp8-on-reenable.patch`, and [@matrix-org/olm](https://www.npmjs.com/package/@matrix-org/olm) 3.2.15 from the npm registry.

| Served as | What it is | SHA-256 |
|---|---|---|
| `/libs/lib-jitsi-meet.min.js` | The library | `686d5d759c1a7173736de95cf83fd61ca9fc2abcaedd39ba36e1bd8c8ee0a20c` |
| `/libs/lib-jitsi-meet.e2ee-worker.js` | Encrypts and decrypts media frames | `61ae549c1f20e0ff1134114b351dd5c7333c7ca68e811a7f0a5806090b2b220e` |
| `/libs/lib-jitsi-meet.e2ee-vault.html` | The key vault page (sandboxed frame) | `e5e9a55757ff0c2f9131032a41503bdfd4f3cd01a3f20b3a0923f8ffcac6c157` |
| `/libs/lib-jitsi-meet.e2ee-vault.js` | The key vault's code (unminified) | `3998dee7c80ca1a00dd754b5ea8ab57730e5e9e83dc3023a9e5364120e645ab6` |
| `/libs/olm.js` | Olm, from @matrix-org/olm | `cf9a793bcbad919967d79e7f2bf52e0492b646332d36ee7e1c2d1b0ff47b3c40` |
| `/libs/olm.wasm` | Olm, from @matrix-org/olm | `3fc8dbfe8f44d550b1c9165e6c2af33323aaeba0a5ec223cef74959dd434642b` |

## What the patches are

`olm-key-auth.patch` is Jitsi's own security fix, upstream commit [`4a958bc1`](https://github.com/jitsi/lib-jitsi-meet/commit/4a958bc1651f96c20fbdcabdfe5e5e35a7de4600) ("feat(e2ee): authenticate Olm curve25519 keys and bind them to SAS"), applied to v2118. It changes only `modules/e2ee/OlmAdapter.js` and `modules/e2ee/E2EEErrors.ts`, exactly as upstream did.

Without it, a malicious server could swap the keys used to set up encryption between participants and read every meeting key, while the emoji verification still showed a match. With it:

- each participant's key-exchange key is signed with their identity key, and a swapped key is rejected;
- emoji verification also confirms the key-exchange key, not only the identity key.

`hidden-key-recipients.patch` is APESpace's own change. Recorders and transcribers join a meeting as hidden participants, which the participant list doesn't show. With the patch:

- the library never opens a key-exchange channel with a hidden participant, in either direction, so a hidden participant never receives a media key: everyone who can decrypt your audio and video is in the participant list;
- the library reports the participants who hold your media key (`E2EE_KEY_RECIPIENTS_CHANGED`), and the APESpace app shows them on the end-to-end encryption label.

It changes `modules/e2ee/OlmAdapter.js`, `modules/e2ee/E2EEErrors.ts`, `modules/e2ee/ManagedKeyHandler.js` and `JitsiConferenceEvents.ts`.

`group-safety-number.patch` is APESpace's own too: one safety number for the whole meeting, compared aloud once, instead of comparing emoji pair by pair. The protocol is in the new file `modules/e2ee/GroupVerification.js`:

- each participant draws a random value and first sends only a commitment to it, bound to its identity keys; it reveals the value only once it holds every other participant's commitment, and each revealed value is checked against its commitment with the keys we hold for that participant;
- the number is 12 digits (40 bits of SHA-256) over the round and every participant's keys and value;
- a server that showed participants different keys must fix the keys and values it substitutes before it learns the real ones, so it can't make the numbers match (1 chance in 10^12), and a participant shown to only some participants changes their number.

`e2ee-key-vault.patch` is APESpace's own too: every key lives in the **key vault**, out of reach of the meeting page.

- The vault is `lib-jitsi-meet.e2ee-vault.html`, loaded in an iframe with `sandbox="allow-scripts"`. It has its own opaque origin, so the page (including the closed-source APESpace app) can't reach into it. Its code is built unminified from `modules/e2ee/vault/`, and it loads Olm from `olm.js`. Olm's WebAssembly (the same `olm.wasm` from @matrix-org/olm 3.2.15) is built into the vault's script, so the vault fetches nothing and its policy allows no connections; in a sandboxed frame, Safari refuses a fetch of `olm.wasm`.
- The vault holds the Olm account and sessions, generates and ratchets our media key, and runs emoji verification and the group safety number. This is the library's unchanged `OlmAdapter` and `ManagedKeyHandler`, running on a stand-in conference (`VaultConference`).
- The page only relays: participants and their E2EE properties into the vault; Olm messages (already encrypted), our public identity keys and E2EE events out of it.
- Media keys go from the vault straight to the encryption worker, over a `MessageChannel` whose two ends the page hands over without keeping. Once the worker has that channel, it ignores keys from the page.

What it doesn't do: the page still shows the decrypted video and plays the audio, and the code that runs the page can still hook browser functions. So the vault keeps keys out of the app's reach, but it can't stop a deliberately malicious build of the page. That is what the signed releases and an independent audit are for.

`newcomer-key-ratchet.patch` is APESpace's own too: a participant who joins can't decrypt media sent before they joined.

- When a participant joins, every participant is meant to move its media key one step forward with HKDF, which can't be reversed. But that step ran 5 seconds after the join, and each participant sent the newcomer its current key as soon as their encrypted channel was set up. The newcomer received the key in use before they joined and could decrypt everything sent since it last changed: since the last departure, or the whole meeting. Upstream lib-jitsi-meet still behaves this way.
- With the patch, our key moves one step forward, and our own media switches to the new key, before our current key first goes to a participant (`OlmAdapter._keyInfoFor`). The others follow by stepping forward when a frame fails to decrypt, as they already do.
- `e2ee-attacks/checks/key-lifecycle.mjs` checks it: a late joiner's keys opened 300 of 300 frames sent before they joined without the patch, and 0 of 300 with it.

It changes `modules/e2ee/OlmAdapter.js` and `modules/e2ee/ManagedKeyHandler.js`.

`dtx-empty-frames.patch` is upstream commit [`8b4d9371`](https://github.com/jitsi/lib-jitsi-meet/commit/8b4d9371cb9723df6b057524aeb93d8fbf833536), applied unchanged with its tests. With Opus DTX the encoder emits empty frames during silence; the encryption transform read a header that wasn't there and stopped, so the sender's audio never recovered. A frame shorter than its readable header now passes through untouched: it carries no payload.

`frame-counter-replay.patch` is APESpace's own: each frame's IV is unique under one key, and receivers drop replayed frames.

- Each frame's 96-bit AES-GCM IV is the stream's SSRC, the RTP timestamp and a per-stream frame counter. The counter started at `Math.random()` and was cut to 16 bits although its IV field has 32, so it wrapped after about 36 minutes of video. It now starts at a random 32-bit value from `crypto.getRandomValues` and uses all 32 bits: it doesn't repeat for 2^32 frames of one stream (over two years at 50 frames per second), and it keeps counting across key changes. Receivers read the IV from the frame, so older receivers are unaffected.
- Receivers accepted any frame that decrypted, so a media server could replay an earlier frame and it would be played again. Now, once AES-GCM has authenticated a frame (IV included, so the counter can't be forged), its counter is checked against a window of 1024 per stream: a counter seen before, or more than 1024 frames behind the newest, is dropped (`Context._isReplay`).
- A sender on an older build is followed across its 16-bit wrap, so mixed versions keep working during an upgrade; for such a sender a frame replayed more than 32767 frames later can still pass.
- On the receiving side, only frames with no data at all skip decryption (`dtx-empty-frames.patch` allowed anything shorter than the readable header), so no frame with content reaches the decoder undecrypted.
- Tested by new unit tests in `Context.spec.ts` (the library's suite: 400 pass), and in a real meeting by `e2ee-attacks/checks/frame-counter-replay.mjs`: without the patch, 20 of 20 replayed frames were played; with it, 0 of 20.

It changes `modules/e2ee/Context.ts` and its tests.

`vp8-on-reenable.patch` is APESpace's own: encrypted video is VP8 every time E2EE is switched on.

- E2EE media only works with VP8, and the published frame layout is VP8's, so the library chooses VP8 while E2EE is on. It restarted the media sessions, which applies that choice, only the first time E2EE was switched on.
- After E2EE was switched off, a join or leave (which chooses the codec again without that rule, e.g. AV1) and E2EE back on, the existing participants kept sending AV1. It was still encrypted, but couldn't be played, so their video froze for everyone.
- The patch restarts the media sessions on every switch-on, as on the first (`KeyHandler.setEnabled`).
- `e2ee-attacks/checks/codecs.mjs` checks it: without the patch, the existing participants sent AV1 and none of their video was decoded; with it, VP8 and all of it.

It changes `modules/e2ee/KeyHandler.js`.

## Rebuild it

Needs git and Docker:

```sh
./build.sh
```

It clones Jitsi's repository, checks out v2118.0.0, applies the eight patches, builds in the `node:20` image, downloads @matrix-org/olm 3.2.15 from the npm registry, and prints the SHA-256 of each file above. They must equal the table, which is also what the [verification page](../) checks the servers serve.

## Read it

The encryption itself (key exchange, emoji verification, frame encryption, the key vault) is in `modules/e2ee/` of lib-jitsi-meet. With these patches applied, everything in the library is public source.
