#!/usr/bin/env bash
# Publish the SDK and the CLI on crates.io as `<prefix>-passbolt-sdk` and `<prefix>-passbolt-cli`;
# the code keeps `passbolt_sdk` and the binary stays `passbolt`.
# Usage: scripts/publish-crates.sh <prefix> [cargo publish option...], e.g. --dry-run.
# It rewrites the manifests of the checkout: run it in CI or in a throwaway copy.
set -euo pipefail
cd "$(dirname "$0")/.."

if (( $# < 1 )); then
  echo "usage: $0 <prefix> [cargo publish option...]" >&2
  exit 1
fi
prefix="$1"
shift
sdk="$prefix-passbolt-sdk"
cli="$prefix-passbolt-cli"
version=$(sed -n 's/^version = "\(.*\)"$/\1/p' crates/passbolt-sdk/Cargo.toml | head -n 1)

# The repository of the workflow, if any: crates.io links to it.
repository="${GITHUB_SERVER_URL:-https://github.com}/${GITHUB_REPOSITORY:-}"
for crate in sdk cli; do
  name="$prefix-passbolt-$crate"
  line="name = \"$name\""
  [[ -n "${GITHUB_REPOSITORY:-}" ]] && line="$line\nrepository = \"$repository\""
  sed -i "s|^name = \"passbolt-$crate\"$|$line|" "crates/passbolt-$crate/Cargo.toml"
done
printf '\n[lib]\nname = "passbolt_sdk"\n' >> crates/passbolt-sdk/Cargo.toml
# The dependents keep their `passbolt-sdk` key, now naming the published package and version.
for manifest in crates/*/Cargo.toml; do
  sed -i "s|^passbolt-sdk = { path = |passbolt-sdk = { package = \"$sdk\", version = \"=$version\", path = |" \
    "$manifest"
done

# Both at once: the CLI is checked against the SDK about to be published.
cargo publish --allow-dirty -p "$sdk" -p "$cli" "$@"
