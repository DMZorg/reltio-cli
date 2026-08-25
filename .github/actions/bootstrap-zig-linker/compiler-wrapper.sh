#!/usr/bin/env bash
set -euo pipefail

: "${NEXUS_ZIG:?}"
: "${NEXUS_NATIVE_LIB:?}"

case "${0##*/}" in
  zig-cxx)
    compiler=c++
    ;;
  zig-cc)
    compiler=cc
    ;;
  *)
    printf 'unsupported Zig compiler wrapper name: %s\n' "${0##*/}" >&2
    exit 1
    ;;
esac

arguments=()
for argument in "$@"; do
  case "$argument" in
    --target=x86_64-unknown-linux-gnu)
      arguments+=(--target=x86_64-linux-gnu)
      ;;
    *)
      arguments+=("$argument")
      ;;
  esac
done

exec "$NEXUS_ZIG" "$compiler" "-L$NEXUS_NATIVE_LIB" "${arguments[@]}"
