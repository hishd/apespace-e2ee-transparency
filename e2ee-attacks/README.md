# Attacking APESpace's end-to-end encryption

This kit lets you **become the meeting server** and try to read an end-to-end-encrypted APESpace meeting. It answers the question reviewers ask:

> Can whoever runs the server read the meeting, or silently sit in the middle of the key exchange, without anyone noticing?

You run it yourself, against a real APESpace meeting (development, production, or a server you built from source), and watch the attacks fail.

## The claim, and its one condition

A meeting server relays every message, so it can always *try* to swap keys — that is not in question. What this kit shows is that it **cannot both read the meeting and stay hidden**:

| What the server does | Result | Needs people to act? |
|---|---|---|
| Swaps keys in the exchange but leaves the published identity keys alone | Rejected automatically — the browsers refuse the unsigned keys and E2EE fails to turn on. The server reads nothing. | No |
| Forges **every** key, including the identity keys, so each browser sees a consistent fake | The server does get the media keys — but the safety number / emoji verification fails, with a red "Verification failed" warning on both sides. | Yes: someone must compare the safety number |

The second row is the limit of *every* end-to-end-encrypted system without an outside identity source (Signal and WhatsApp included): only a human check can catch a server that forges all identities. So the honest promise is:

> **APESpace cannot read your meeting, provided the verified release is running and participants confirm the safety number.**

This kit demonstrates every part of that sentence.

## How a script can be the server

Each script opens its own browsers (with [Playwright](https://playwright.dev/)) and intercepts the signalling connection between those browsers and the real server. On that connection it can read and rewrite every message — exactly the power the operator of the meeting server has. It does **not** sit on your own browser's connection: it can only attack the browsers it launches itself, which is why it is safe to run against a live deployment. It plays a malicious server named "Mallory".

## Requirements

- **Node.js 20+**.
- **Google Chrome** installed (the scripts drive your system Chrome).
- A meeting URL, and a token if your deployment needs one.
- **Docker + git** only if you want to build the pre-fix library for the "detects a break" demo (below).

## Install

```sh
cd e2ee-attacks
npm install
```

## Run it

Open a meeting and copy its URL. Keep the room empty apart from the browsers the kit opens. Then:

```sh
node run-all.mjs --url "https://<your meeting URL>"
```

If your deployment needs a JWT, give it in any of these ways:
- in the URL: `--url "https://…/room?jwt=<token>"`
- as a flag: `--token "<token>"`
- as an environment variable: `MEET_JWT=<token>`
- in a file `token.txt` next to this README

The token is bound to one room, is never printed, and is scrubbed from any error output.

`run-all.mjs` runs the whole suite and prints a summary. Every run also prints its own `VERDICT:` line. Against a current build, **every run should say "secure"**.

### Watch it happen (visible browsers)

By default the browsers are headless. To watch them — the E2EE toggle, the emoji dialog, the red "Verification failed" warning — add `--headed`, and `--slowmo <ms>` to slow each action down:

```sh
node attacks/olm-mitm.mjs --url "https://<meeting URL>" --attack swap-all --headed --slowmo 500
```

Each run opens one window per participant (two for most attacks, three for the group number). The camera and microphone are simulated (a test pattern and a tone), so no real devices are used. `--headed` and `--slowmo` work on `run-all.mjs` too, and every other flag.

## The attacks, and what "secure" looks like

### Key-exchange man-in-the-middle — `attacks/olm-mitm.mjs`

Mallory tries to put herself in the middle of the key exchange. Four variants, from least to most aggressive:

| `--attack` | What Mallory forges | Secure result on the current build |
|---|---|---|
| `none` | nothing (honest server) | Media keys stolen: 0; both verified; the honest call keeps decoding video |
| `swap` | the keys inside the key-exchange messages | **0 keys stolen** — rejected with "Invalid key signature" |
| `swap-presence` | also one published Curve25519 key | **0 keys stolen** — rejected |
| `swap-full` | also every published Curve25519 key | **0 keys stolen** — rejected |
| `swap-all` | also every published Ed25519 (signing) key, re-signed | keys stolen, **but verification fails** (MAC mismatch) and both users get a red "Verification failed" warning |

```sh
node attacks/olm-mitm.mjs --url "https://<meeting URL>" --attack swap
node attacks/olm-mitm.mjs --url "https://<meeting URL>" --attack swap-all
```

The report shows, per run: how many media keys Mallory read, whether the emoji matched, whether verification passed, how many video frames the honest call kept decoding, and how many frames Mallory's stolen keys could open.

### Group safety number — `attacks/group-safety-number.mjs`

One number for the whole meeting, compared aloud once. Mallory forges every identity (as in `swap-all`) and does her best to make the numbers match anyway — replacing each participant's commitment and revealed value.

| `--attack` | Secure result |
|---|---|
| `none` (3 participants) | all participants read the **same** number |
| `swap-all` (2 participants + Mallory) | the two numbers **differ**, so the attack is visible to everyone |

```sh
node attacks/group-safety-number.mjs --url "https://<meeting URL>" --attack none --participants 3
node attacks/group-safety-number.mjs --url "https://<meeting URL>" --attack swap-all
```

She cannot steer the numbers to match, because she must commit to her forged values before she learns the real ones (the chance of a match is 1 in 10¹²).

### Hidden key recipient — `attacks/hidden-recipient.mjs`

Can the server get the media keys by adding a participant nobody sees (like a silent recorder)? Mallory announces a "ghost" on the deployment's hidden domain and asks each browser for the key.

```sh
node attacks/hidden-recipient.mjs --url "https://<meeting URL>"
```

On the current build the ghost is refused (`e2ee.session.hidden-participant`) and the Inspector lists every real key recipient. With `--visible` the same participant, shown in the list, does receive keys — and appears in everyone's participant list, so it can be seen and removed.

## Key lifecycle and tampering — `checks/key-lifecycle.mjs`

Three checks that need no malicious server. Alice and Bob start an encrypted meeting; Carol joins later and then leaves. Every browser records, with the published Inspector, the media keys it holds and the encrypted frames it receives, and the script then tries the keys against real captured frames. Keys are tried at every key index and every allowed ratchet step, so a check passes only because the key material differs.

| Check | Passes when |
|---|---|
| A late joiner can't read earlier content | Carol's keys open none of the frames Alice sent before Carol joined |
| A participant who left can't keep decrypting | Carol's keys open none of the frames Alice sent once the key changed after Carol left. The run also reports how long her old key kept working. |
| Tampering is rejected | One flipped bit in the readable header, the encrypted payload, the IV or the authentication tag makes decryption fail |

```sh
node checks/key-lifecycle.mjs --url "https://<meeting URL>"
```

## Proving the test is meaningful: run it against pre-fix code

A test that always passes proves nothing. To see the attacks **succeed** — and the suite report `INSECURE` — run them against the library APESpace forked *before* the fix:

```sh
./build-old-lib.sh                 # builds plain lib-jitsi-meet v2118 into ./old-lib (needs Docker)
node attacks/olm-mitm.mjs --url "https://<your own pre-fix build>" --attack swap --client old --lib ./old-lib
```

Against the pre-fix library, `swap` reads every media key while both users still see "verified" — the exact hole the current build closes. (Serve the pre-fix library against a server you built from the pre-fix source; mixing it into a current deployment, which also ships the key vault, will not reflect a real pre-fix client.)

## Running against a build you compiled yourself

The strongest check is to point the kit at a server **you** built from APESpace's public source, so you trust the code the browsers load. Rebuild the encryption library with [`../e2ee-module/build.sh`](../e2ee-module/) and confirm its fingerprints match what the [verification page](https://hishd.github.io/apespace-e2ee-transparency/) reports the live servers serve, then run this suite against that server.

## A note on the key vault and the Inspector

APESpace holds the E2EE keys in a sandboxed "key vault" frame that the app cannot reach into. These scripts load the published [Inspector](../extension/inspector/) (the same code as the APESpace Verify extension), which is a debugging tool injected into the page; it instruments the vault to *observe* keys for these checks. That observation is the measurement tool, not a hole in the vault: the point of the vault is that the shipped app code cannot reach the keys, and an audit of the signed release can confirm that.

## What this does and does not prove

- It **does** show that the specific attacks here — the ones a meeting server can actually mount — fail against the current build, and that the same attacks succeed against the pre-fix code, so the checks are meaningful.
- It does **not** prove the absence of every possible attack. That is what the public source, the reproducible build, and an independent audit are for.
