#!/usr/bin/env bash
# Generate the SDK bindings of passbolt-ffi from its compiled library.
# Usage: scripts/sdk-bindings.sh <libpassbolt_ffi.so|.dylib> <out-dir> [language...]
# Languages: python kotlin swift ruby (UniFFI), go csharp java (generators on PATH).
# Package names come from crates/passbolt-ffi/uniffi.toml.
set -euo pipefail
cd "$(dirname "$0")/.."

if (( $# < 2 )); then
  echo "usage: $0 <library> <out-dir> [language...]" >&2
  exit 1
fi
lib="$1"
out="$2"
shift 2
languages=("$@")
(( ${#languages[@]} > 0 )) || languages=(python kotlin swift ruby go csharp java)

# The UniFFI version of Cargo.lock: the bindings must match the library's scaffolding.
# Debug build: only reads the library's metadata, no need to wait for LTO.
cargo build --locked -p passbolt-ffi --bin uniffi-bindgen
bindgen="${CARGO_TARGET_DIR:-target}/debug/uniffi-bindgen"

for language in "${languages[@]}"; do
  dir="$out/$language"
  mkdir -p "$dir"
  case "$language" in
    python | kotlin | swift | ruby)
      "$bindgen" generate --no-format --library "$lib" --language "$language" --out-dir "$dir" ;;
    go) uniffi-bindgen-go --no-format --library --out-dir "$dir" "$lib" ;;
    csharp) uniffi-bindgen-cs --library --out-dir "$dir" "$lib" ;;
    java) uniffi-bindgen-java generate --no-format --library --out-dir "$dir" "$lib" ;;
    *)
      echo "unknown language: $language" >&2
      exit 1 ;;
  esac
  # A stripped library has no UniFFI metadata: the generators then write nothing, silently.
  if [[ -z "$(ls -A "$dir")" ]]; then
    echo "$language: nothing generated, is $lib stripped?" >&2
    exit 1
  fi
  echo "$language: $dir"
done
