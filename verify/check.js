// Checks that each environment serves exactly a release signed by the official
// build, and whether they all serve the same one. Runs in the browser (index.html)
// and in Node (cli.mjs).
//
// 1. Read the published releases from this repository and verify their signed
//    build records (sigstore.js).
// 2. For each environment, find the release whose app bundle it serves, then
//    download every file of that release that a browser runs or that styles the
//    page, exactly as a meeting would load it, and compare its SHA-256 with the
//    signed manifest.
//
// Pages (HTML) and interface_config.js are assembled by each server for its own
// deployment, so they are not compared. Images, fonts and sounds are skipped.

import { hex, sha256, verifyBundle } from './sigstore.js';

const COMPARED = /\.(css|js|json|mjs|svg|wasm)$/;
const GENERATED = [ '/interface_config.js' ];

const sha256Hex = async buf => hex(await sha256(new Uint8Array(buf)));

async function get(url, as = 'json') {
    const res = await fetch(url, { cache: 'no-store' });

    if (!res.ok) {
        throw new Error(`${url}: HTTP ${res.status}`);
    }

    return as === 'json' ? res.json() : new Uint8Array(await res.arrayBuffer());
}

/**
 * Lists the published releases and their build records.
 */
export async function listReleases(config) {
    const tree = await get(`https://api.github.com/repos/${config.repository}/git/trees/main?recursive=1`);
    const releases = {};

    for (const { path } of tree.tree) {
        const m = path.match(/^releases\/([0-9a-f]{64})\/(manifest\.json|builds\/([^/]+)(?<!\.sigstore)\.json)$/);

        if (m) {
            const r = releases[m[1]] ??= { id: m[1], builds: [] };

            m[3] && r.builds.push(path);
        }
    }

    return Object.values(releases);
}

/**
 * Loads a release and verifies it: the manifest must hash to the release id, and
 * at least one build record for it must carry a valid signature from the
 * official build workflow.
 */
export async function loadRelease(config, release) {
    const raw = `https://raw.githubusercontent.com/${config.repository}/main`;
    const manifestBytes = await get(`${raw}/releases/${release.id}/manifest.json`, 'bytes');
    const builds = [];

    if (await sha256Hex(manifestBytes) !== release.id) {
        throw new Error(`release ${release.id}: manifest does not match its id`);
    }
    for (const path of release.builds) {
        const recordBytes = await get(`${raw}/${path}`, 'bytes');
        const record = JSON.parse(new TextDecoder().decode(recordBytes));

        try {
            const bundle = await get(`${raw}/${path}.sigstore.json`);
            const signed = await verifyBundle(recordBytes, bundle, config.trust, new RegExp(config.signer));

            if (record.release !== release.id) {
                throw new Error('record is for another release');
            }
            builds.push({ ...record, ...signed, verified: true });
        } catch (e) {
            builds.push({ ...record, verified: false, error: e.message });
        }
    }

    return {
        id: release.id,
        files: JSON.parse(new TextDecoder().decode(manifestBytes)).files,
        builds,
        signed: builds.some(b => b.verified)
    };
}

/**
 * Checks one environment against the releases.
 *
 * @param {Object} env - { name, origin }.
 * @param {Object} config - config.json.
 * @param {Function} load - Loads (and verifies) a release by id, cached.
 * @param {Array} releases - From listReleases().
 * @param {Function} [progress] - Called with (done, total).
 */
export async function checkEnvironment(env, config, load, releases, progress = () => {}) {
    const origin = env.origin.replace(/\/+$/, '');
    const bundleHash = await sha256Hex(await get(`${origin}/libs/app.bundle.min.js`, 'bytes'));
    const result = { ...env, release: null, identical: 0, mismatches: [], unreadable: [], compared: 0 };

    // Which published release has this app bundle?
    for (const r of releases) {
        const release = await load(r.id);

        if (release.files['/libs/app.bundle.min.js']?.sha256 === bundleHash) {
            result.release = release;
            break;
        }
    }
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
    const releases = await listReleases(config);
    const cache = {};
    const load = id => (cache[id] ??= loadRelease(config, releases.find(r => r.id === id)));

    // Newest first, so the current release is found quickly.
    releases.reverse();
    const results = [];

    for (const env of config.environments) {
        results.push(await checkEnvironment(env, config, load, releases,
            (done, total) => progress(env, done, total)));
    }

    const ok = r => r.release?.signed && r.mismatches.length === 0 && r.encryptionLibrary;

    return {
        results,
        allVerified: results.every(ok),
        sameRelease: results.every(ok) && new Set(results.map(r => r.release.id)).size === 1
    };
}
