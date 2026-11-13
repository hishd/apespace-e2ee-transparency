// Reads the signed releases published in the transparency repository and
// verifies them. Shared by the browser extension, the verification page and the
// command-line check.

import { hex, sha256, verifyBundle } from './sigstore.js';

export const sha256Hex = async buf => hex(await sha256(new Uint8Array(buf)));

export async function get(url, as = 'json') {
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
        // Build records are builds/<name>.json; their signature bundles (.json.sigstore.json) and
        // software bills of materials (.sbom.cdx.json, covered by the record's "sbom" hash) are not.
        const m = path.match(/^releases\/([0-9a-f]{64})\/(manifest\.json|builds\/([^/]+)(?<!\.sigstore)(?<!\.sbom\.cdx)\.json)$/);

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
 * Lists the releases once and loads (and verifies) each one at most once.
 * Newest first, so the current release is found quickly.
 */
export function releaseLoader(config) {
    let list;
    const cache = {};
    const load = async id => {
        const releases = await (list ??= listReleases(config).then(r => r.reverse()));

        return cache[id] ??= loadRelease(config, releases.find(r => r.id === id));
    };

    return {
        load,
        releases: () => (list ??= listReleases(config).then(r => r.reverse())),

        // The published release whose manifest has this file with this hash.
        async find(path, sha256) {
            for (const { id } of await this.releases()) {
                const release = await load(id);

                if (release.files[path]?.sha256 === sha256) {
                    return release;
                }
            }

            return null;
        }
    };
}
