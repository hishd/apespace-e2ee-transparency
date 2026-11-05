# APESpace encryption library

APESpace meetings are end-to-end encrypted by **lib-jitsi-meet**, Jitsi's open-source WebRTC library. This folder lets you rebuild the exact library APESpace serves, from public source, and check it is byte-for-byte the same.

| | |
|---|---|
| Served as | `/libs/lib-jitsi-meet.min.js` |
| SHA-256 | `0133cb8aededd3595bcb538fb5030540337012906c2f6d2a3855f6a30039e0ed` |
| Source | [jitsi/lib-jitsi-meet](https://github.com/jitsi/lib-jitsi-meet) v2118.0.0 (`67fd2c84`) + `olm-key-auth.patch` + `hidden-key-recipients.patch` |

## What the patches are

`olm-key-auth.patch` is Jitsi's own security fix, upstream commit [`4a958bc1`](https://github.com/jitsi/lib-jitsi-meet/commit/4a958bc1651f96c20fbdcabdfe5e5e35a7de4600) ("feat(e2ee): authenticate Olm curve25519 keys and bind them to SAS"), applied to v2118. It changes only `modules/e2ee/OlmAdapter.js` and `modules/e2ee/E2EEErrors.ts`, exactly as upstream did.

Without it, a malicious server could swap the keys used to set up encryption between participants and read every meeting key, while the emoji verification still showed a match. With it:

- each participant's key-exchange key is signed with their identity key, and a swapped key is rejected;
- emoji verification also confirms the key-exchange key, not only the identity key.

`hidden-key-recipients.patch` is APESpace's own change. Recorders and transcribers join a meeting as hidden participants, which the participant list doesn't show. With the patch:

- the library never opens a key-exchange channel with a hidden participant, in either direction, so a hidden participant never receives a media key: everyone who can decrypt your audio and video is in the participant list;
- the library reports the participants who hold your media key (`E2EE_KEY_RECIPIENTS_CHANGED`), and the APESpace app shows them on the end-to-end encryption label.

It changes `modules/e2ee/OlmAdapter.js`, `modules/e2ee/E2EEErrors.ts`, `modules/e2ee/ManagedKeyHandler.js` and `JitsiConferenceEvents.ts`.

## Rebuild it

Needs git and Docker:

```sh
./build.sh
```

It clones Jitsi's repository, checks out v2118.0.0, applies both patches, builds in the `node:20` image, and prints the SHA-256 of `lib-jitsi-meet.min.js`. It must equal the one above, which is also what the [verification page](../) checks the servers serve.

## Read it

The encryption itself (key exchange, emoji verification, frame encryption) is in `modules/e2ee/` of lib-jitsi-meet. With these patches applied, everything in the library is public source.
