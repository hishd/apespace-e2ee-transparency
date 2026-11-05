#!/bin/sh
# Rebuilds APESpace's encryption library from Jitsi's public source:
# lib-jitsi-meet v2118.0.0 plus olm-key-auth.patch (upstream commit 4a958bc1)
# and hidden-key-recipients.patch.
#
#   ./build.sh [workdir]
#
# Needs git and Docker. Prints the SHA-256 of the built lib-jitsi-meet.min.js,
# the file APESpace serves. It must be
#   0133cb8aededd3595bcb538fb5030540337012906c2f6d2a3855f6a30039e0ed

set -eu

BASE=67fd2c84  # upstream v2118.0.0
FIX=4a958bc1   # feat(e2ee): authenticate Olm curve25519 keys and bind them to SAS
HERE=$(cd "$(dirname "$0")" && pwd)
WORK=${1:-$(mktemp -d)}

git clone -q --filter=blob:none https://github.com/jitsi/lib-jitsi-meet.git "$WORK/src"
git -C "$WORK/src" checkout -q "$BASE"
git -C "$WORK/src" apply "$HERE/olm-key-auth.patch"
git -C "$WORK/src" apply "$HERE/hidden-key-recipients.patch"

docker run --rm -v "$WORK/src":/src -w /src -e LIB_JITSI_MEET_COMMIT_HASH="$BASE+$FIX+apespace" node:20 \
    sh -c 'npm ci --no-audit --no-fund >/dev/null && npm pack >/dev/null'

tar xzOf "$WORK/src/lib-jitsi-meet-0.0.0.tgz" package/dist/umd/lib-jitsi-meet.min.js | shasum -a 256
