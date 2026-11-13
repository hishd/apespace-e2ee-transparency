# Re-review policy for encryption-relevant changes

_Status: draft for APE Space approval · 13 November 2026. Answers checklist row REL-09._

An audit covers one release. Releases are reproducible and signed (`releases/`), so an audit report names the exact release ID it covers, and anyone can check whether an environment runs it (`verify/`). This policy says which later changes need a new review before they reach production.

## What counts as an encryption-relevant change

Any change to:

1. **The encryption library:**
   - `vendor/lib-jitsi-meet/` in the application (its patches, its package, its build script);
   - `e2ee-module/` here.
   This changes the published encryption fingerprints in `extension/config.json`, so the change is visible to anyone.
2. **The app's E2EE code:**
   - `react/features/e2ee/`;
   - the E2EE handling in `react/features/base/participants/middleware.ts`;
   - the settings that decide how media keys are managed (`e2ee.*` in `configWhitelist.ts` and `config.js`).
3. **What can run in the meeting page:** the static signed page, its Content Security Policy, and the scripts it loads.
4. **The release pipeline:** `.github/` in the application (build, manifest, SBOM, signing, publishing), and `verify/` and `extension/` here.
5. **The dependency that carries the key exchange:** `@matrix-org/olm`, or replacing it (`docs/crypto-roadmap.md`).

## What each such change needs

| Level | Applies to | Before production |
|---|---|---|
| **A. Independent re-review** | Changes to key exchange, verification (emoji, safety number), frame encryption or its format, the key vault boundary, what may run in the page, a new library patch, or replacing Olm | Review by an independent reviewer with cryptographic expertise, reported with the release ID it covers |
| **B. Internal security review** | Every other change in the list above | Review by a second engineer who didn't write it, plus the full test run below |
| **None** | Comments, translations and UI wording that don't change what is shown about encryption state | The normal review rule (REL-08) |

**The full test run** for levels A and B covers the deployed development build:
- the attack kit and checks: `node e2ee-attacks/run-all.mjs` and each script in `e2ee-attacks/checks/`;
- the switch-off test;
- a `verify/` run.

Results are kept with the change.

## The record

- **Every release:** a signed build record in `releases/<release ID>/` (commit, branch, image, SBOM hash), logged in Rekor.
- **Every change to the encryption library:** this repository's history of `e2ee-module/` and `extension/config.json`, with the reason in the patch description.
- **Upstream changes reviewed:** `e2ee-module/UPSTREAM-REVIEWED`, kept current by the weekly watch.
- **The change history since an audit** is therefore the git history of these paths between the audited release and the current one, plus the release records in between.
