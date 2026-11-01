// Checks that each environment serves exactly a release signed by the official
// build, and whether they all serve the same one. Runs in the browser (index.html)
// and in Node (cli.mjs).
//
// 1. Read the published releases from this repository and verify their signed
//    build records (extension/lib).
// 2. For each environment, find the release whose app bundle it serves, then
//    download every file of that release that a browser runs or that styles the
//    page, exactly as a meeting would load it, and compare its SHA-256 with the
//    signed manifest.
//
// Pages (HTML) and interface_config.js are assembled by each server for its own
// deployment, so they are not compared. Images, fonts and sounds are skipped.

import { get, releaseLoader, sha256Hex } from '../extension/lib/releases.js';

const COMPARED = /\.(css|js|json|mjs|svg|wasm)$/;
const GENERATED = [ '/interface_config.js' ];

/**
 * Checks one environment against the releases.
 *
 * @param {Object} env - { name, origin }.
 * @param {Object} config - extension/config.json.
 * @param {Object} loader - From releaseLoader().
 * @param {Function} [progress] - Called with (done, total).
 */
export async function checkEnvironment(env, config, loader, progress = () => {}) {
    const origin = env.origin.replace(/\/+$/, '');
    const bundleHash = await sha256Hex(await get(`${origin}/libs/app.bundle.min.js`, 'bytes'));
    const result = { ...env, release: null, identical: 0, mismatches: [], unreadable: [], compared: 0 };

    // Which published release has this app bundle?
    result.release = await loader.find('/libs/app.bundle.min.js', bundleHash);
    if (!result.release) {
        return result;
    }

    const queue = Object.entries(result.release.files).filter(([ p ]) => COMPARED.test(p) && !GENERATED.includes(p));

    result.compared = queue.length;
    await Promise.all(Array.from({ length: 6 }, async () => {
        while (queue.length) {
            const [ path, expected ] = queue.shift();
            let res;

            try {
                res = await fetch(origin + encodeURI(path), { cache: 'no-store' });
            } catch {
                // In a browser, a server that does not allow other sites to read a
                // file (no CORS header) makes the request fail: not a mismatch.
                result.unreadable.push(path);
            }
            if (res) {
                const actual = res.ok && await sha256Hex(await res.arrayBuffer());

                actual === expected.sha256 ? result.identical++ : result.mismatches.push(path);
            }
            progress(result.identical + result.mismatches.length + result.unreadable.length, result.compared);
        }
    }));
    result.mismatches.sort();
    result.unreadable.sort();

    const lib = config.encryptionLibrary;

    result.encryptionLibrary = result.release.files[lib.path]?.sha256 === lib.sha256
        && !result.mismatches.includes(lib.path);

    return result;
}

/**
 * Checks every environment. Returns the per-environment results and a verdict.
 */
export async function checkAll(config, progress = () => {}) {
    const loader = releaseLoader(config);
    const results = [];

    for (const env of config.environments) {
        results.push(await checkEnvironment(env, config, loader,
            (done, total) => progress(env, done, total)));
    }

    const ok = r => r.release?.signed && r.mismatches.length === 0 && r.encryptionLibrary;

    return {
        results,
        allVerified: results.every(ok),
        sameRelease: results.every(ok) && new Set(results.map(r => r.release.id)).size === 1
    };
}
