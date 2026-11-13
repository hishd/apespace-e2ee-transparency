#!/bin/sh
# Builds the pre-fix encryption library (plain lib-jitsi-meet v2118.0.0, with
# none of APESpace's patches) into a directory you can pass to the attacks with
# --client old --lib <dir>. Against this library the key-swap and hidden-recipient
# attacks succeed, which shows the suite detects a real break.
#
#   ./build-old-lib.sh [outdir]      # default outdir: ./old-lib
#
# Needs git and Docker. It writes:
#   <outdir>/lib-jitsi-meet.min.js
#   <outdir>/lib-jitsi-meet.e2ee-worker.js
#
# This is the public, unmodified Jitsi v2118 release, the version APESpace forked
# before adding the key-authentication fix. The current build adds that fix (see
# ../e2ee-module/olm-key-auth.patch and hidden-key-recipients.patch).

set -eu

BASE=67fd2c84  # upstream lib-jitsi-meet v2118.0.0
HERE=$(cd "$(dirname "$0")" && pwd)
OUT=${1:-"$HERE/old-lib"}
WORK=$(mktemp -d)

git clone -q --filter=blob:none https://github.com/jitsi/lib-jitsi-meet.git "$WORK/src"
git -C "$WORK/src" checkout -q "$BASE"

docker run --rm -v "$WORK/src":/src -w /src -e LIB_JITSI_MEET_COMMIT_HASH="$BASE" node:20 \
    sh -c "npm ci --no-audit --no-fund >/dev/null && npm pack >/dev/null"

mkdir -p "$OUT"
for f in lib-jitsi-meet.min.js lib-jitsi-meet.e2ee-worker.js; do
    tar xzOf "$WORK/src/lib-jitsi-meet-0.0.0.tgz" "package/dist/umd/$f" > "$OUT/$f"
    printf '%s  %s\n' "$(shasum -a 256 "$OUT/$f" | cut -c1-64)" "$f"
done
rm -rf "$WORK"
echo "pre-fix library written to $OUT"
