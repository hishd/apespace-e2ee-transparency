// Runs the whole attack suite against one meeting and prints a PASS/FAIL summary.
//
//   node run-all.mjs --url <meeting URL>            # the deployed/served build
//   node run-all.mjs --url <URL> --client old --lib <dir>   # a rebuilt pre-fix build
//
// Pass the JWT, if your deployment needs one, the same way the individual
// scripts do: in the --url, with --token <jwt>, via MEET_JWT, or in token.txt.
// Keep the room empty apart from the two or three browsers each run opens.
//
// Each run's own VERDICT line says "secure" or "INSECURE". Against the current
// build every run should be secure; against a pre-fix build (--client old), the
// key-swap runs turn INSECURE, which shows the suite detects a real break.

import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const passthrough = process.argv.slice(2); // --url / --token / --client / --lib
const runs = [
    [ 'olm-mitm.mjs', '--attack', 'none' ],
    [ 'olm-mitm.mjs', '--attack', 'swap' ],
    [ 'olm-mitm.mjs', '--attack', 'swap-presence' ],
    [ 'olm-mitm.mjs', '--attack', 'swap-full' ],
    [ 'olm-mitm.mjs', '--attack', 'swap-all' ],
    [ 'group-safety-number.mjs', '--attack', 'none', '--participants', '3' ],
    [ 'group-safety-number.mjs', '--attack', 'swap-all' ]
];
const results = [];

for (const [ script, ...args ] of runs) {
    const label = `${script.replace('.mjs', '')} ${args.join(' ')}`;

    console.log(`\n\n========== ${label} ==========`);
    const r = spawnSync('node', [ path.join(HERE, 'attacks', script), ...args, ...passthrough ],
        { stdio: 'inherit' });

    results.push({ label, ok: r.status === 0 });
}

console.log('\n\n========== summary ==========');
for (const r of results) {
    console.log(`${r.ok ? 'PASS (secure)' : 'FAIL (insecure)'}  ${r.label}`);
}
const allOk = results.every(r => r.ok);

console.log(allOk
    ? '\nAll runs secure: the server could not read the meeting without being caught.'
    : '\nSome runs are INSECURE (expected only against a pre-fix build with --client old).');
process.exit(allOk ? 0 : 1);
