# Design note: remembered identity keys

_Status: design note for later work, not built · 13 November 2026. For checklist rows KEY-02 (persistent identity keys with a warning on change) and IDN-04 (an account reset is visible to other participants)._

## The gap

Every participant gets a new Olm identity key pair (Ed25519 and Curve25519) in every meeting. Within a meeting the keys are strongly protected:
- they are signed;
- they are bound to the emoji check and to the group safety number;
- they never leave the key vault.

But nothing connects one meeting's keys to the next. So:

- **A server swapping keys (KEY-02)** is caught only if participants compare the emoji or the safety number in that meeting.
- **An insider resetting a user's account and joining as them (IDN-04)** looks exactly like the real user joining from a new browser. Nothing tells the others that the key changed, because there is no earlier key to compare with.

The fix in other secure messengers is to remember each contact's long-term identity key, and warn when it changes. In Signal this is the safety number change; in Matrix, cross-signing and device verification.

## Constraints

1. **The key vault has no storage.** It is a sandboxed frame with an opaque origin, which keeps the page from reaching into it. Because of that, the browser gives it no localStorage or IndexedDB, so a long-term private key can't be kept there as the vault is built today.
2. **The page can't be the keeper.** The app page could store data, but private keys there would undo the key vault. The record of known keys must also resist tampering by the page's code, which the server delivers (checklist REL-05).
3. **The server can't be the source of truth.** IDN-04 is about an insider with backend access. An identity key that the backend vouches for can be replaced by that insider, so server attestations can only add to a check made on the device, never replace it.
4. **Many devices, guests, cleared data.**
   - A user may join from a laptop, a phone and a browser profile, each with its own key.
   - Guests have no account to attach a key to.
   - Clearing browser data loses a device key.
   Each of these must be handled without warnings so frequent that people learn to ignore them.

## Proposed design

### 1. A long-term device key, kept by a vault with its own origin

- **Its own origin.** The vault frame moves to its own origin (for example `vault.<deployment domain>`), served as static, signed files like the meeting page, with `sandbox="allow-scripts allow-same-origin"`. A different origin keeps the page out just as the opaque origin does today, and gives the vault storage of its own.
- **The device key.** The vault creates the device's Olm account once. It stores the account encrypted under a non-extractable AES-GCM key generated with Web Crypto and kept in the vault origin's IndexedDB. The raw key can't be read out, even by the vault's own code.
- **Per meeting.** In each meeting the vault uses that long-term account. Signed session keys, the emoji check and the safety number all work as now.
- **Partitioning.** Browsers partition a frame's storage by the top-level site. The meeting site is always the top level, so the vault's storage is stable for that site.

### 2. Known keys, remembered on the device (trust on first use)

- **The record.** The vault keeps, in its own storage, a record per account: the account ID the participant joined with, and the identity key fingerprints seen for it. Each fingerprint has a first-seen date and whether it was verified (emoji or safety number).
- **Unknown key.** When a participant joins with a key not on record for that account, the vault reports one of two things:
  - **new device** (the account has other known keys), which is informational;
  - **key changed** (the only previously known key is gone, or the user had verified the old one), which is a warning.
- **Showing it.** The warning appears in the participant list and in the E2EE label, in the same style as a failed verification. It offers to compare the safety number, which marks the new key as verified.
- **Guests** are shown as unverified guests, with no history.

### 3. Optional: account-level attestation

- **Signing new devices.** A user's verified device can sign each new device key of the same account (cross-signing). Others then see "new device, confirmed by their known device" instead of a warning.
- **Why it helps against insiders.** A backend insider can't produce that signature without one of the user's devices. That is what turns an account reset (IDN-04) into a visible warning for everyone who has met the user before.

## What it would take

| Part | Change |
|---|---|
| Hosting | A vault origin with its own static, signed files, and its CSP and fingerprints in the transparency checks |
| Library | Persist and reload the Olm account in the vault; key record and change events (a new patch) |
| App | New device and key-changed indicators; a "verify again" flow; the copy for guests |
| Tests | Two meetings in a row with a forged identity in the second (`attacks/olm-mitm.mjs`), and an account reset simulated by joining from a fresh profile. Both must show the warning to the others. |
| Review | Level A under the re-review policy (key exchange and the key vault boundary) |

## Open questions for APE Space

- Is moving the vault to its own subdomain acceptable for every deployment, including the mobile WebViews?
- Should "new device" ever be silent, for example inside one organisation?
- What should happen when a user clears their browser? It is indistinguishable from an account reset unless cross-signing (part 3) exists.

Until this is built, the control is in-meeting verification, and APE Space's customer statements say so.
