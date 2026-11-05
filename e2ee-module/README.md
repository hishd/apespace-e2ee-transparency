# APESpace encryption code

APESpace meetings are end-to-end encrypted by **lib-jitsi-meet**, Jitsi's open-source WebRTC library, and the keys are held by Olm. This folder lets you rebuild every file of the encryption code APESpace serves, from public source, and check each is byte-for-byte the same.

Source: [jitsi/lib-jitsi-meet](https://github.com/jitsi/lib-jitsi-meet) v2118.0.0 (`67fd2c84`) + `olm-key-auth.patch` + `hidden-key-recipients.patch` + `group-safety-number.patch` + `e2ee-key-vault.patch`, and [@matrix-org/olm](https://www.npmjs.com/package/@matrix-org/olm) 3.2.15 from the npm registry.

| Served as | What it is | SHA-256 |
|---|---|---|
| `/libs/lib-jitsi-meet.min.js` | The library | `7e5dde66ab7a7f0cc041b18c2bfe53b5765e4b7fb9615d691eafbacfecd885be` |
| `/libs/lib-jitsi-meet.e2ee-worker.js` | Encrypts and decrypts media frames | `f0a0e95a6eb4d915b8c12f772c6d1b293a91a9fa11e2dce7d4e7b144a8edb86e` |
| `/libs/lib-jitsi-meet.e2ee-vault.html` | The key vault page (sandboxed frame) | `7ef57ec59fd0d307b4cddb3dd67a1d71bb6e4dd16696c636ea76f7c5a7a60cf5` |
| `/libs/lib-jitsi-meet.e2ee-vault.js` | The key vault's code (unminified) | `ab3cfa60869dc007310e60aab63795280117559dfafd7b09292e6d490bb2f3e4` |
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

- The vault is `lib-jitsi-meet.e2ee-vault.html`, loaded in an iframe with `sandbox="allow-scripts"`. It has its own opaque origin, so the page (including the closed-source APESpace app) can't reach into it. Its code is built unminified from `modules/e2ee/vault/`, and it loads Olm from `olm.js`.
- The vault holds the Olm account and sessions, generates and ratchets our media key, and runs emoji verification and the group safety number. This is the library's unchanged `OlmAdapter` and `ManagedKeyHandler`, running on a stand-in conference (`VaultConference`).
- The page only relays: participants and their E2EE properties into the vault; Olm messages (already encrypted), our public identity keys and E2EE events out of it.
- Media keys go from the vault straight to the encryption worker, over a `MessageChannel` whose two ends the page hands over without keeping. Once the worker has that channel, it ignores keys from the page.

What it doesn't do: the page still shows the decrypted video and plays the audio, and the code that runs the page can still hook browser functions. So the vault keeps keys out of the app's reach, but it can't stop a deliberately malicious build of the page. That is what the signed releases and an independent audit are for.

## Rebuild it

Needs git and Docker:

```sh
./build.sh
```

It clones Jitsi's repository, checks out v2118.0.0, applies the four patches, builds in the `node:20` image, downloads @matrix-org/olm 3.2.15 from the npm registry, and prints the SHA-256 of each file above. They must equal the table, which is also what the [verification page](../) checks the servers serve.

## Read it

The encryption itself (key exchange, emoji verification, frame encryption, the key vault) is in `modules/e2ee/` of lib-jitsi-meet. With these patches applied, everything in the library is public source.
