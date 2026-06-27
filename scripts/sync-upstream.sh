#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
UPSTREAM_URL="${UPSTREAM_URL:-https://github.com/iBotPeaches/Apktool.git}"
UPSTREAM_BRANCH="${UPSTREAM_BRANCH:-main}"
WORKDIR="${1:-$ROOT_DIR/work/Apktool}"

rm -rf "$WORKDIR"
mkdir -p "$(dirname "$WORKDIR")"

git clone --depth 1 --branch "$UPSTREAM_BRANCH" "$UPSTREAM_URL" "$WORKDIR"
python3 "$ROOT_DIR/scripts/apply-local-mods.py" "$WORKDIR"

cd "$WORKDIR"
chmod +x ./gradlew
./gradlew --no-daemon build shadowJar

printf '\nBuilt jars:\n'
find brut.apktool/apktool-cli/build/libs -maxdepth 1 -type f -name '*.jar' -print
