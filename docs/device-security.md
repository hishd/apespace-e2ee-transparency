# Keeping your meetings private on your own device

_Status: draft for APE Space approval · 13 November 2026. The customer-facing statement for checklist row CLI-01._

## What end-to-end encryption protects, and what it can't

When end-to-end encryption is on, your audio, video and screen sharing are encrypted on your device and decrypted only on the devices of the people in the meeting. APE Space's servers relay the encrypted media, but can't read it.

Encryption can't protect what happens on a device itself. Before encrypting and after decrypting, the meeting is plain sound and picture on each participant's device. Anything that controls a device can see or record it there:
- malware;
- a malicious browser extension;
- screen-recording software;
- someone with access to an unlocked device.

**Each participant's device is outside APE Space's guarantee.**

## What you can do

- **Keep your system and browser up to date.** Use a current version of Chrome, Edge, Firefox or Safari, or the latest APE Space app. Updates fix the flaws malware uses.
- **Be careful with browser extensions.** An extension that may "read and change data on all websites" can read the meeting page. Keep only extensions you trust. For sensitive meetings, use a browser profile with no other extensions than APE Space Verify (below).
- **Install software only from sources you trust,** and keep your device's own protection (for example Windows Security or XProtect) on.
- **Lock your device** with a PIN, password or biometrics, and don't join sensitive meetings from shared or public computers.
- **For sensitive meetings, verify the meeting code.** Install the APE Space Verify browser extension ([instructions](../extension/README.md)). It checks that every file your meeting loads is APE Space's published, signed release, so it would notice code altered for you alone.
- **Check who is in the meeting.** For sensitive meetings, compare the safety number aloud with everyone. A matching number means no one is intercepting the encryption between you.
- **Mind your surroundings.** Others in the room, or a window behind you, aren't protected by encryption.
- **Remember the other participants.** Their devices see what you share. Only invite people you trust with the conversation.

## What isn't end-to-end encrypted

Chat, polls, reactions, shared files, participant names and meeting details go through APE Space's servers without end-to-end encryption. Don't put anything sensitive in them.
