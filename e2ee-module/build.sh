#!/bin/sh
# Rebuilds APESpace's encryption code from public source, and prints the SHA-256
# of every file of it that APESpace serves:
#
#   lib-jitsi-meet v2118.0.0 plus olm-key-auth.patch (upstream commit 4a958bc1),
#   hidden-key-recipients.patch, group-safety-number.patch, e2ee-key-vault.patch,
#   newcomer-key-ratchet.patch, dtx-empty-frames.patch (upstream commit 8b4d9371) and
#   frame-counter-replay.patch:
#     /libs/lib-jitsi-meet.min.js            the library
#     /libs/lib-jitsi-meet.e2ee-worker.js    encrypts and decrypts media frames
#     /libs/lib-jitsi-meet.e2ee-vault.html   the key vault (sandboxed frame)
#     /libs/lib-jitsi-meet.e2ee-vault.js
#   @matrix-org/olm 3.2.15 from the npm registry, used by the key vault:
#     /libs/olm.js
#     /libs/olm.wasm
#
#   ./build.sh [workdir]
#
# Needs git and Docker. The output must match "encryptionLibrary" in
# ../extension/config.json, which the verification page checks the servers serve.

set -eu

BASE=67fd2c84  # upstream v2118.0.0
FIX=4a958bc1   # feat(e2ee): authenticate Olm curve25519 keys and bind them to SAS
OLM=3.2.15
HERE=$(cd "$(dirname "$0")" && pwd)
WORK=${1:-$(mktemp -d)}

git clone -q --filter=blob:none https://github.com/jitsi/lib-jitsi-meet.git "$WORK/src"
git -C "$WORK/src" checkout -q "$BASE"
git -C "$WORK/src" apply "$HERE/olm-key-auth.patch"
git -C "$WORK/src" apply "$HERE/hidden-key-recipients.patch"
git -C "$WORK/src" apply "$HERE/group-safety-number.patch"
git -C "$WORK/src" apply "$HERE/e2ee-key-vault.patch"
git -C "$WORK/src" apply "$HERE/newcomer-key-ratchet.patch"
git -C "$WORK/src" apply "$HERE/dtx-empty-frames.patch"
git -C "$WORK/src" apply "$HERE/frame-counter-replay.patch"

docker run --rm -v "$WORK/src":/src -w /src -e LIB_JITSI_MEET_COMMIT_HASH="$BASE+$FIX+apespace" node:20 \
    sh -c "npm ci --no-audit --no-fund >/dev/null && npm pack >/dev/null && npm pack @matrix-org/olm@$OLM >/dev/null"

for f in lib-jitsi-meet.min.js lib-jitsi-meet.e2ee-worker.js lib-jitsi-meet.e2ee-vault.html lib-jitsi-meet.e2ee-vault.js; do
    printf '%s  /libs/%s\n' "$(tar xzOf "$WORK/src/lib-jitsi-meet-0.0.0.tgz" "package/dist/umd/$f" | shasum -a 256 | cut -c1-64)" "$f"
done
for f in olm.js olm.wasm; do
    printf '%s  /libs/%s\n' "$(tar xzOf "$WORK/src/matrix-org-olm-$OLM.tgz" "package/$f" | shasum -a 256 | cut -c1-64)" "$f"
done
