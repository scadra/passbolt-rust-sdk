#!/usr/bin/env bash
# Give the workspace crates the version a release tag names: the packages, the CLI's --version
# and the crates.io upload then carry it. Run in CI, on a checkout of the tagged commit.
# Usage: scripts/set-version.sh <X.Y.Z>
set -euo pipefail
cd "$(dirname "$0")/.."

version="${1:-}"
if [[ ! "$version" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
  echo "usage: $0 <X.Y.Z>, not '$version'" >&2
  exit 1
fi
# Perl rather than `sed -i`, which differs on macOS.
for crate in passbolt-sdk passbolt-cli passbolt-ffi passbolt-wasm; do
  VERSION="$version" perl -0pi -e 's/^version = "[^"]*"/version = "$ENV{VERSION}"/m' \
    "crates/$crate/Cargo.toml"
  VERSION="$version" CRATE="$crate" perl -0pi -e \
    's/(name = "\Q$ENV{CRATE}\E"\r?\nversion = )"[^"]*"/$1"$ENV{VERSION}"/' Cargo.lock
done
