// Command-line version of the verification page (Node 20 or later):
//
//   git clone https://github.com/hishd/apespace-e2ee-transparency.git
//   cd apespace-e2ee-transparency
//   node verify/cli.mjs
//
// Exits with 0 only if every environment serves exactly the same signed release.

import fs from 'node:fs';

import { checkAll } from './check.js';

const config = JSON.parse(fs.readFileSync(new URL('../extension/config.json', import.meta.url), 'utf8'));
const short = id => id.slice(0, 16);
let last = '';

const { results, allVerified, sameRelease } = await checkAll(config, (env, done, total) => {
    const line = `  ${env.name}: comparing files ${done}/${total}`;

    if (process.stdout.isTTY && line !== last) {
        process.stdout.write(`\r${line}`);
        last = line;
    }
});

process.stdout.isTTY && process.stdout.write('\r\x1b[K');

for (const r of results) {
    console.log(`\n${r.name}  ${r.origin}`);
    if (!r.release) {
        console.log('  ✗ serves an app that is not in any published release');
        continue;
    }
    console.log(`  release ${r.release.id}`);
    for (const b of r.release.builds) {
        console.log(b.verified
            ? `  ✓ signed build: ${b.source.branch} @ ${b.source.commit.slice(0, 7)}, ${b.builtAt} (Rekor #${b.logIndex})`
            : `  ✗ build record ${b.source?.branch ?? ''} does not verify: ${b.error}`);
    }
    console.log(r.mismatches.length
        ? `  ✗ ${r.mismatches.length} of ${r.compared} files differ: ${r.mismatches.slice(0, 5).join(', ')}`
        : `  ✓ all ${r.compared} files identical to the signed release`);
    r.unreadable.length && console.log(`  · ${r.unreadable.length} files could not be downloaded: ${r.unreadable.join(', ')}`);
    console.log(r.encryptionLibrary
        ? `  ✓ encryption library is the published build (${short(config.encryptionLibrary.sha256)}…)`
        : '  ✗ encryption library differs from the published build');
}

console.log(`\n${sameRelease
    ? `✓ All environments serve the same signed release (${short(results[0].release.id)}…)`
    : allVerified ? '✗ Environments serve different releases' : '✗ Verification failed'}`);
process.exit(sameRelease ? 0 : 1);
