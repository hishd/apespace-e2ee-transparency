// Where a test meeting runs, given with --url <meeting URL>. If your deployment
// needs a JWT, put it in the URL (…?jwt=…), pass --token <jwt>, set MEET_JWT, or
// put it in token.txt next to this kit. The token is bound to one room, so every
// run uses that room; it is never printed, and errors are scrubbed of it.
//
// With no --url, a fresh room on a local server at https://localhost:8443 is used
// (for running against your own locally built, open server).

import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const HERE = path.dirname(fileURLToPath(import.meta.url));

function readToken(fromUrl, argv) {
    if (fromUrl) {
        return fromUrl;
    }
    if (argv.includes('--token')) {
        return argv[argv.indexOf('--token') + 1];
    }
    if (process.env.MEET_JWT) {
        return process.env.MEET_JWT.trim();
    }
    const file = path.join(HERE, '..', 'token.txt');

    return fs.existsSync(file) ? fs.readFileSync(file, 'utf8').trim() : null;
}

export function meetingTarget(argv, prefix) {
    const raw = argv.includes('--url') ? argv[argv.indexOf('--url') + 1] : null;
    const url = raw ? raw.replace(/[?#].*$/, '') : null;
    const tokenInUrl = raw?.match(/[?&]jwt=([^&#]+)/)?.[1] ?? null;
    const token = url ? readToken(tokenInUrl, argv) : null;
    const roomUrl = url ?? `https://localhost:8443/${prefix}${Date.now()}`;
    const redact = s => (token ? String(s).split(token).join('<jwt>') : String(s));

    // Playwright errors echo the page URL, which carries the token.
    for (const event of [ 'uncaughtException', 'unhandledRejection' ]) {
        process.removeAllListeners(event);
        process.on(event, err => {
            console.error(redact(err?.stack ?? err));
            process.exit(1);
        });
    }

    return {
        deployment: Boolean(url),
        redact,
        room: roomUrl.split('/').pop(),
        url: hash => `${roomUrl}${token ? `?jwt=${token}` : ''}#${Object.entries(hash)
            .map(([ k, v ]) => `${k}=${encodeURIComponent(JSON.stringify(v))}`).join('&')}`
    };
}

/**
 * Opens the meeting, gets past a pre-join screen if the deployment shows one,
 * and turns the camera on (some deployments start with it off).
 */
/**
 * Polls a check in the page until it is true. Unlike page.waitForFunction, it
 * doesn't compile the check with eval, which a page's Content Security Policy
 * may forbid.
 */
export async function waitInPage(page, fn, arg, timeout = 30000) {
    const until = Date.now() + timeout;

    while (!await page.evaluate(fn, arg).catch(() => false)) {
        if (Date.now() > until) {
            throw new Error(`timed out after ${timeout} ms waiting for ${String(fn).slice(0, 80)}`);
        }
        await new Promise(r => setTimeout(r, 250));
    }
}

export async function joinMeeting(page, url, name, timeout = 90000) {
    await page.goto(url, { waitUntil: 'domcontentloaded', timeout: 60000 });
    const joinBtn = page.locator('[data-testid="prejoin.joinMeeting"]');
    const nameBox = page.getByPlaceholder('Enter your name');
    const isJoined = () => page.evaluate(() => window.APP?.conference?._room?.isJoined?.()).catch(() => false);

    // One resilient loop instead of "wait for the button once, then click once".
    // On this deployment the pre-join screen can take well over 20 s to render
    // (it gates on a device check), and a JWT pre-join re-renders the name field
    // when its value changes, so a single early click lands on a button that
    // isn't there yet or gets replaced. Each pass: stop if we are in; otherwise,
    // when the pre-join button is visible, set the name and click it. Deployments
    // that drop straight into the room never show the button and just become
    // joined. Don't throw mid-loop: clicks race with re-renders, so tolerate
    // transient action errors and retry on the next pass.
    const until = Date.now() + timeout;
    let typedName = false;

    while (Date.now() < until) {
        if (await isJoined()) {
            break;
        }
        if (await joinBtn.isVisible().catch(() => false)) {
            // Set the name once; retyping every pass fights the re-render.
            if (!typedName && await nameBox.isVisible().catch(() => false)) {
                await nameBox.click().catch(() => {});
                await nameBox.fill('').catch(() => {});
                // The name field ignores values set without key events.
                await nameBox.pressSequentially(name, { delay: 30 }).catch(() => {});
                typedName = true;
            }
            await joinBtn.click({ timeout: 4000 }).catch(() => {});
        }
        await new Promise(r => setTimeout(r, 1000));
    }
    if (!await isJoined()) {
        throw new Error(`joinMeeting: not joined within ${timeout} ms`);
    }
    await page.evaluate(() => APP.conference.muteVideo(false)).catch(() => {});
}

/**
 * Leaves the meeting properly, so the participant does not linger in the room
 * (a lingering participant stalls E2EE key setup in the next run).
 */
export async function leaveMeeting(page) {
    await page.evaluate(() => APP.conference._room?.leave()).catch(() => {});
}
