# How APE Space builds, signs and publishes a release

_Status: draft for APE Space approval · 13 November 2026. Answers checklist rows REL-02, REL-06, REL-07 and REL-08. Sections marked **To complete** need details only APE Space can give._

## The pipeline

One GitHub Actions workflow in the application repository (`.github/workflows/build-docker-image.yml`) runs on every push to `develop`, `main`, `master` or `release`. It:

1. **Builds** the web app image from the `Dockerfile`:
   - base images pinned by digest (`node:22.23.4@sha256:18a6…`, `jitsi/web@sha256:2183…`);
   - npm packages installed exactly as in `package-lock.json` (`npm ci`);
   - the encryption library from the vendored package, checked by hash.
   The build is reproducible: the same commit gives the same files.
2. **Pushes** the image to the GitHub container registry, by digest.
3. **Fingerprints** every file the image serves into a release manifest. The manifest's SHA-256 is the release ID.
4. **Writes an SBOM** (CycloneDX 1.5, `.github/release/make-sbom.mjs`): every npm package in the lockfile and the pinned base images.
5. **Writes a build record**: release ID, number of files, image digest, the SBOM's SHA-256, repository, branch, commit, time and the workflow run.
6. **Signs** the build record with Sigstore keyless signing. The certificate names the workflow, repository and commit, and the signature is logged in the public Rekor log.
7. **Publishes** the manifest, the record, its signature bundle and the SBOM to `releases/<release ID>/` in this repository.

## Build inputs and provenance (REL-07)

| Input | How it is fixed | Where it is recorded |
|---|---|---|
| Source | the commit being built | build record (`source.commit`), signing certificate |
| Workflow | the workflow file at that commit | signing certificate (workflow path and ref) |
| Base images | pinned by digest in the `Dockerfile` | SBOM (`container` components) |
| npm packages | `package-lock.json` with integrity hashes, `npm ci` | SBOM (`library` components with SHA-512) |
| Encryption library | vendored package, rebuilt from public source by `e2ee-module/build.sh` | `extension/config.json` (served file hashes), SBOM |
| Third-party actions | pinned by commit | the workflow file |
| Runner | GitHub-hosted `ubuntu-latest` | the workflow run |

**Permissions.** The job's token can only:
- read the repository;
- write packages, which is needed to push the image;
- request a signing identity (`id-token: write`), which Sigstore needs.

**Secrets.** There are two:
- the job's own token;
- `TRANSPARENCY_DEPLOY_KEY`: an SSH deploy key that can push to this repository only. Its `main` branch allows no force pushes or deletions, so the key can add release records but can't rewrite them.

**Tampering is visible.** A tampered build would differ from an independent rebuild of the same commit. The encryption code can be rebuilt by anyone (`e2ee-module/build.sh`); the full app can be rebuilt by an auditor with access to the application source.

**Deployment.**
- The development and production servers are APE Space's own (self-hosted), and only authorised staff have access to them.
- Each server runs Watchtower, which pulls a new image from the GitHub container registry when the image tag it follows changes, and restarts the web container with it.
- So whatever reaches that tag is deployed without a person in between. That is either the pipeline above, or anyone who can push to the registry package.
- Anyone can check what a server serves against the signed releases (`verify/`). A build that isn't a signed release shows as one.

**To complete:**
- who has admin and write access to the application repository, the organisation and the registry package;
- whether two-factor authentication is required for them;
- who can change Actions settings and secrets.

## Signing (REL-02)

- **No signing key to hold.** There is no long-lived signing key, so there is no hardware key inventory. Each signature uses a certificate valid for minutes, issued by Sigstore to the workflow's identity after GitHub vouches for the run.
- **Releases can't be signed outside the pipeline.** No person can produce a valid release record outside it. Every signing event is public in Rekor, and is listed in `releases/` with its Rekor entry.
- **The two-person gap.** One person with write access to the application repository can change what the workflow builds and signs (the workflow is in the same repository), because second-person review isn't enforced (REL-08). Until it is, a single insider could ship a release that passes the checks. That release would still be public, signed and logged with its commit, and so attributable and reviewable after the fact.

## Dependencies (REL-06)

- **Pinned:**
  - npm packages: lockfile with integrity hashes, installed with `npm ci`;
  - base images: by digest;
  - the encryption library: vendored, rebuilt from public source, checked by hash.
- **Software bill of materials:** published for every build, next to its signed record, and covered by the signature through its hash.
- **Updates:** a dependency update is a change like any other. It goes through a pull request and review (REL-08), and through the re-review policy when it touches the encryption library or Olm (`docs/re-review-policy.md`).
- **Advisories:** the weekly watch (`.github/workflows/upstream-watch.yml`) covers the encryption libraries. **To complete:** enable GitHub Dependabot alerts on the application repository for the other dependencies.
- **Known inconsistency:** the lockfile resolves `@jitsi/logger` 2.0.2 while the vendored lib-jitsi-meet declares 2.1.1, so `npm sbom` refuses to run (hence the SBOM script). It has no effect on what is served: the library is shipped as a prebuilt bundle with its own copy.

## Review before release (REL-08)

- **Team rule.** Changes reach `develop` and `main` through pull requests, and the team requires one approving review from someone other than the author.
- **Not enforced by GitHub.** On the organisation's current plan, branch protection isn't available for the private application repository, so the rule isn't enforced.
- **What would close it:**
  - branch protection or a ruleset on `develop` and `main` requiring one approving review;
  - dismissing stale approvals, and including administrators;
  - the same for changes to `.github/`.
- **Evidence an auditor can have:** the merged pull requests and their reviews, from the repository, under the confidentiality agreement.
