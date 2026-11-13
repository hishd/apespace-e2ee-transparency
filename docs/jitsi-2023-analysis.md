# The 2023 analysis of Jitsi Meet, assessed against APE Space

_Status: draft for APE Space approval · 13 November 2026_

**The analysis.** Robertas Maleckas, Kenneth G. Paterson and Martin R. Albrecht, "Practically-exploitable Vulnerabilities in the Jitsi Video Conferencing System", [IACR ePrint 2023/1118](https://eprint.iacr.org/2023/1118) (July 2023). It grew out of Maleckas's 2022 ETH Zürich master's thesis. The authors studied jitsi-meet 2.0.6865 with lib-jitsi-meet `4baeb98964c6` (early 2022). They reported six issues to Jitsi on 9 August 2022.

**The APE Space version assessed.** The web app is a fork of 2025–2026 jitsi-meet. The encryption library is lib-jitsi-meet v2118.0.0 plus the eight public patches in [`e2ee-module/`](../e2ee-module). The test scripts named below are in [`e2ee-attacks/`](../e2ee-attacks).

**Result.** Four of the six issues are fixed in APE Space. Each is fixed by Jitsi's own fix, by an APE Space change, or by both, and each has a test.
- §4.3 (what end-to-end encryption covers) is unchanged and disclosed.
- §4.6 (peer-to-peer mode) doesn't arise in encrypted meetings, which never run peer to peer.

## Summary

| § | Issue | Fixed upstream | APE Space status |
|---|---|---|---|
| 4.1 | A malicious server sits in the middle of the Olm key exchange | Partly (emoji check, `751b3630`, 2022). The rest only in `4a958bc1` (2026). | Fixed: `4a958bc1` applied, hidden key recipients refused, group safety number. Detection depends on participants comparing. |
| 4.2 | Frames that fail to decrypt are played (fail open) | Yes, `c29de010` (2022) | Fixed. Stricter than upstream: only frames with no data skip decryption. |
| 4.3 | Chat, polls, names and avatars aren't end-to-end encrypted | Documentation only | Unchanged, disclosed (checklist ENC-01, ENC-02) |
| 4.4 | Poll author and votes can be faked | Yes (jitsi-meet stable-8044, 2022) | Fixed: identities come from the server. The server itself can still alter polls (§4.3). |
| 4.5 | Fake "E2EE on/off" signals | Partly (GHSA-8f5r-2qpr-4g34, 2022) | Fixed further: only a moderator's "off" is followed, always with a warning, and clients that can't encrypt leave |
| 4.6 | Peer-to-peer mode: the server can sit in the middle | Documentation only | Doesn't arise: encrypted meetings never run peer to peer |

## Each issue

### 4.1 Olm key exchange: man in the middle

**The paper.** A malicious signalling (XMPP) server rewrites the Olm session setup, so it holds one Olm session with Alice and another with Bob. It then decrypts and re-encrypts every media key it relays. A second step hides the attacker from the participant list while the bridge still sends it media.

**Upstream.**
- Jitsi added an optional emoji (SAS) check in `751b3630` (2022). That check covered only the Ed25519 key. The Curve25519 keys that build the Olm sessions weren't bound to it, so a server could still sit in the middle while the emoji matched.
- Jitsi closed that gap in `4a958bc1` (September 2026). The Curve25519 keys are signed with Ed25519 and checked before a session is created, and the emoji check covers them.

**APE Space.**
- `olm-key-auth.patch` is upstream `4a958bc1`.
- `hidden-key-recipients.patch` refuses Olm sessions with participants the app doesn't list. That closes the hiding step: a hidden participant gets no key.
- `group-safety-number.patch` adds one number for the whole meeting, so a swap shows up without comparing every pair.

**Tested.** `attacks/olm-mitm.mjs` plays the malicious server against the deployed build:
- every swap that keeps the real identity keys is rejected, and the server gets no key;
- the swap that gets keys (forging every identity key) makes the emoji check fail for both users;
- `attacks/group-safety-number.mjs`: under the same swap, participants get different numbers;
- `attacks/hidden-recipient.mjs`: a hidden participant receives 0 keys.

**What remains, as the paper says.** Olm proves who you are talking to only if participants compare the emoji or the safety number. APE Space creates new identity keys for every meeting, so nothing remembers a participant's key between meetings (checklist KEY-02).

### 4.2 Fail-open decryption

**The paper.** A malicious video bridge sends ordinary unencrypted frames. Decryption fails, the frame is passed on anyway, and it is shown as if it came from a participant.

**Upstream.** Fixed in `c29de010` (2022): frames that fail to decrypt are dropped (advisory GHSA-hg53-vwvc-h58x).

**APE Space.**
- v2118 includes that fix.
- Upstream `8b4d9371` (2026, applied as `dtx-empty-frames.patch`) lets frames shorter than their readable header skip decryption. APE Space narrows that on the receiving side to frames with no data at all (`frame-counter-replay.patch`), so no frame with content skips decryption.
- Receivers also drop replayed frames, which the paper didn't cover.

**Tested.**
- `checks/key-lifecycle.mjs`: one flipped bit in the header, payload, IV or tag is rejected, 60 of 60 at each.
- `checks/unsupported-participant.mjs`: unencrypted video from a participant who can't encrypt is never played (0 frames decoded).
- `checks/frame-counter-replay.mjs`: replayed frames are dropped, 0 of 20.
- Unit tests in `Context.spec.ts`.

### 4.3 What end-to-end encryption covers

**The paper.** Chat, private messages, polls, display names and avatars aren't end-to-end encrypted, so the server reads them.

**Upstream.** Jitsi documents it: E2EE "doesn't cover chat, polls, etc."

**APE Space.** The same: audio, video and screen sharing are end-to-end encrypted, and nothing else is. This is a product decision. APE Space's customer explainer states it, and it is listed under checklist ENC-01 and ENC-02. File sharing also goes through APE Space's file service unencrypted.

### 4.4 Poll manipulation

**The paper.** Any participant, or the server, can fake a poll's author or votes, because clients trusted sender fields written by other clients.

**Upstream.** Fixed in jitsi-meet stable-8044, November 2022 (GHSA-rj5g-9fmh-p5fj).

**APE Space.** The fork is based on a much later jitsi-meet. Polls are handled by the server's polls component, and the sender of a poll or vote is the identity the server assigns, not a field a client writes. The server itself can still alter polls, because they aren't end-to-end encrypted (§4.3).

### 4.5 Fake E2EE signals

**The paper.**
- Clients that couldn't encrypt still played the "E2EE on" announcement.
- A participant or the server could trigger E2EE cues through presence.
- With mixed clients, the server could tell capable clients that E2EE is off.

**Upstream.** Clients that can't encrypt no longer show E2EE cues (GHSA-8f5r-2qpr-4g34, 2022). The on/off signal itself is still unauthenticated presence.

**APE Space.**
- **"Off".** Only a moderator's "E2EE off" is followed. Every participant then gets a warning that stays on screen. An "off" from anyone else is ignored. The server assigns roles, so it could still forge a moderator's "off", but that is never silent.
- **Turning it on.** Local media is held (black frames and silence) until outgoing media is actually encrypted.
- **Clients that can't encrypt.** A client that can't encrypt leaves an encrypted meeting at once and says why, so its unencrypted media never enters the meeting.

**Tested.**
- `test-e2ee-remote-off.mjs` (the evidence for checklist SRV-04).
- `checks/unsupported-participant.mjs`: without the change, the client stayed and sent unencrypted media; with it, it left and 0 of its frames reached anyone.

### 4.6 Peer-to-peer mode

**The paper.** In peer-to-peer mode the server can sit in the middle of the DTLS-SRTP fingerprints exchanged over signalling. It can also make calls fall back to the bridge.

**Upstream.** Documentation only.

**APE Space.** lib-jitsi-meet never starts or keeps a peer-to-peer session while E2EE is on (`JitsiConference._maybeStartOrStopP2P`), and switching E2EE on restarts the media sessions through the bridge. So in encrypted meetings, media always goes through the bridge and is protected end to end, whatever the server does to peer-to-peer signalling. Unencrypted meetings are outside the E2EE guarantee.

**Tested.** `checks/codecs.mjs` reports for every participant whether media runs peer to peer. In every encrypted meeting tested, media went via the bridge.

## Observations the paper makes in passing

| Observation | APE Space |
|---|---|
| Self-ratcheting also runs when authentication fails | Unchanged. The ratchet is limited to 8 steps per frame, and a frame that doesn't authenticate is dropped. |
| An IV collision would leak the XOR of two frames and the GCM authentication key | The IV's frame counter now uses 32 bits from a cryptographic random start, and the full IV (stream, timestamp, counter) is tested unique (`checks/frame-counter-replay.mjs`) |
| The IV-length field in the frame is unused | It is always 12. A frame that decrypts with any other IV length is dropped by the replay check. |

## Sources

- The paper: https://eprint.iacr.org/2023/1118
- The thesis: https://ethz.ch/content/dam/ethz/special-interest/infk/inst-infsec/appliedcrypto/education/theses/Robertas_Maleckas_thesis.pdf
- Advisories:
  - GHSA-hg53-vwvc-h58x: https://github.com/jitsi/lib-jitsi-meet/security/advisories/GHSA-hg53-vwvc-h58x
  - GHSA-8f5r-2qpr-4g34: https://github.com/jitsi/jitsi-meet/security/advisories/GHSA-8f5r-2qpr-4g34
  - GHSA-rj5g-9fmh-p5fj: https://github.com/jitsi/jitsi-meet/security/advisories/GHSA-rj5g-9fmh-p5fj
- Upstream changes:
  - lib-jitsi-meet PR 2113 (`c29de010`): https://github.com/jitsi/lib-jitsi-meet/pull/2113
  - PR 2146 (`751b3630`): https://github.com/jitsi/lib-jitsi-meet/pull/2146
  - PR 3104 (`8b4d9371`): https://github.com/jitsi/lib-jitsi-meet/pull/3104
  - PR 3110 (`4a958bc1`): https://github.com/jitsi/lib-jitsi-meet/pull/3110
- Jitsi's security page: https://jitsi.org/security/
