#!/usr/bin/env bash
# Run the CLI end-to-end tests against a real Passbolt server.
# Settings: PASSBOLT_E2E_* from the environment or .env.e2e (see .env.e2e.example).
set -euo pipefail
cd "$(dirname "$0")/.."
if [[ -f .env.e2e ]]; then
  set -a
  source .env.e2e
  set +a
fi
# Tests run from the crate directory: make the key paths absolute.
for key_file in PASSBOLT_E2E_USER_PRIVATE_KEY_FILE PASSBOLT_E2E_ADMIN_USER_PRIVATE_KEY_FILE; do
  if [[ -n "${!key_file:-}" ]]; then
    export "$key_file=$(realpath "${!key_file}")"
  fi
done
# What the CLI stores is checked with OpenPGP.js, as the browser extension reads it.
npm ci --prefix tests/interop --no-audit --no-fund --silent
# Release: OpenPGP is much faster optimized. Tests create uniquely named data, so they run in parallel.
cargo test --release -p passbolt-cli --features e2e --test e2e "$@" -- --test-threads="${E2E_THREADS:-4}"
# migrate-metadata upgrades every v4 resource of the server: alone, after the other tests.
cargo test --release -p passbolt-cli --features e2e --test e2e_migration "$@" -- --test-threads=1
