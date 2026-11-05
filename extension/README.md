# APESpace Verify (browser extension)

Checks, inside your own meeting, that APESpace runs exactly the published, signed code, and lets you inspect its end-to-end encryption yourself.

## Install (Chrome, Edge, Brave)

1. Download this repository: **Code → Download ZIP** on GitHub, and unzip it (or `git clone` it).
2. Open `chrome://extensions` and turn on **Developer mode** (top right).
3. Click **Load unpacked** and choose this `extension` folder.
4. Pin **APESpace Verify** to the toolbar.

You are loading the code in this folder, so you can read every line of what you install.

## 1. Code check (always on)

When you open an APESpace meeting, the extension fingerprints (SHA-256) every script, WebAssembly module and stylesheet the meeting loads, including those of embedded meetings and of the meeting's workers. It compares them with the release whose app the meeting loaded, and checks that release is signed by APESpace's official build. The checks are the same as on the [verification page](https://hishd.github.io/apespace-e2ee-transparency/): Sigstore signature, certificate issued to the build workflow, entry in Sigstore's public log.

The toolbar icon shows:

| Badge | Meaning |
|---|---|
| ✓ | Every file this meeting loaded matches a signed release |
| ! | A file differs from the release, is not part of it, or the app is not in any published release. Click the icon to see which file. |
| … | Still checking |

Unlike the verification page, this checks the meeting **you** are in, so it would also notice code served to you alone.

The meeting page itself, in the tab or in an embedding site's frame, is checked too when the release's pages are static files (releases that include `static/load-config.js`). Such a page carries a Content Security Policy that lets only the release's own scripts run, and reads `config.js` and `interface_config.js` as data, without running them in the page. In earlier releases each server assembled the page, so it is not compared.

Not compared: `config.js` and `interface_config.js`, which each server generates for its own deployment (addresses, settings).

How it reads the files: Chrome does not let extensions read what a page downloaded, so the extension downloads each file again and fingerprints it. To deceive the check, a server would have to recognise the extension's download and answer it differently from the page's.

## 2. E2EE Inspector (off by default, test meetings)

Switch on **Inspector mode** in the popup, then join or reload a meeting. While it is on, the meeting shows an orange **E2EE Inspector recording** panel, and everyone in the meeting is told in chat. It records what your browser receives before decryption, and the media keys your browser receives, so you can see that what the server delivered is unreadable without those keys. The capture viewer (**Open capture viewer…**) shows:

- what you received, before and after E2EE was switched on, and the same media decrypted with the received keys;
- the media keys your browser received, and every key-exchange message the server relayed;
- whether a media key left your browser: every outgoing WebSocket message, data-channel message and HTTP request is searched for the keys;
- who received your media key: every participant your browser sent it to, checked against the participant list you see (a recorder or other hidden participant receiving it would be flagged);
- with another participant's capture: that each of you holds the other's genuine identity key (no one sat in the middle of the key exchange) and the same media keys.

By default the HTTP part of the leak check covers requests to the meeting site. Tick **Check requests to all sites for leaked keys** to cover every site: Chrome then asks for access to all sites, which the extension gives back when Inspector mode is switched off.

With the key vault, the media keys never pass through the meeting page: the Inspector also runs inside the vault frame and reports each key sent to the encryption worker to the page's Inspector. Inspector mode therefore makes the keys visible to the page, on purpose, for the test meeting.

Inspector mode turns itself off when Chrome restarts. A capture file contains that meeting's media keys: anyone with the file can play back the recorded part. Use test meetings, and delete captures when done.

While Inspector mode is on, the meeting uses Chrome's older frame-processing API so the extension can see frames before decryption. Media is not altered.

## Privacy

Nothing is sent anywhere. The extension downloads the meeting's own files from the meeting site and the signed records from this GitHub repository; captures stay in your browser until you export them to your own computer.

## Permissions

| Permission | Why |
|---|---|
| Access to the APESpace meeting sites | To see which files a meeting loads, download them for fingerprinting, and (Inspector mode only) run the Inspector in the meeting |
| `webRequest`, `webNavigation` | To see the files a meeting loads, and when a tab moves to a new page |
| `scripting` | To add the Inspector to meeting pages, only while Inspector mode is on |
| `storage` | To keep each tab's results while the tab is open |
| Access to all sites (optional, asked for) | Only for the Inspector's leak check across every site |

## The meeting sites

The extension works on the sites listed under `host_permissions` in `manifest.json`. The trust anchors (Sigstore's certificate authority and log key) and the expected signer are in `config.json`.
