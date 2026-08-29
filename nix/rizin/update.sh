#!/usr/bin/env bash

set -euo pipefail

usage() {
    echo "Usage: $0 [RIZIN_COMMIT]" >&2
}

if (( $# > 1 )); then
    usage
    exit 2
fi

if [[ ${1:-} == "-h" || ${1:-} == "--help" ]]; then
    usage
    exit 0
fi

repo_root=$(git rev-parse --show-toplevel)
checksum_file="$repo_root/nix/rizin/checksum.json"

if [[ ! -f "$checksum_file" ]]; then
    echo "Could not find $checksum_file; run this updater from the rizin-rs checkout." >&2
    exit 1
fi
if (( $# == 1 )); then
    rev=$1
else
    remote_ref=$(git ls-remote https://github.com/rizinorg/rizin.git refs/heads/dev)
    rev=${remote_ref%%[[:space:]]*}
fi

if [[ ! $rev =~ ^[0-9a-f]{40}$ ]]; then
    echo "Expected a full 40-character Rizin commit SHA, got: $rev" >&2
    exit 1
fi

source_url="https://github.com/rizinorg/rizin/archive/$rev.tar.gz"
echo "Prefetching Rizin source at $rev"
prefetch_json=$(nix store prefetch-file --json --unpack "$source_url")
src_hash=$(printf '%s\n' "$prefetch_json" | sed -n 's/.*"hash"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p')
source_path=$(printf '%s\n' "$prefetch_json" | sed -n 's/.*"storePath"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p')

if [[ $src_hash != sha256-* ]]; then
    echo "Could not extract the Rizin source hash from: $prefetch_json" >&2
    exit 1
fi
if [[ ! -d $source_path ]]; then
    echo "Could not extract the unpacked Rizin source path from: $prefetch_json" >&2
    exit 1
fi

upstream_version=$(sed -n "s/^[[:space:]]*version: 'v\([^']*\)',/\1/p" "$source_path/meson.build" | head -n 1)
if [[ ! $upstream_version =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
    echo "Could not extract a three-part Rizin version from $source_path/meson.build" >&2
    exit 1
fi

backup=$(mktemp)
cp -- "$checksum_file" "$backup"
restore_on_error() {
    status=$?
    if (( status != 0 )); then
        cp -- "$backup" "$checksum_file"
        echo "Update failed; restored $checksum_file" >&2
    fi
    rm -f -- "$backup"
    return "$status"
}
trap restore_on_error EXIT

write_checksums() {
    target_version=$1
    target_rev=$2
    target_src_hash=$3
    target_deps_hash=$4
    tmp=$(mktemp "${checksum_file}.tmp.XXXXXX")
    printf '{\n  "version": "%s",\n  "rev": "%s",\n  "srcHash": "%s",\n  "mesonDepsHash": "%s"\n}\n' \
        "$target_version" "$target_rev" "$target_src_hash" "$target_deps_hash" >"$tmp"
    mv -- "$tmp" "$checksum_file"
}

fake_hash="sha256-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
write_checksums "$upstream_version" "$rev" "$src_hash" "$fake_hash"

echo "Calculating the Meson dependency hash"
set +e
deps_log=$(nix build '.#rizin.mesonDeps' --no-link --print-build-logs 2>&1)
deps_status=$?
set -e
if (( deps_status == 0 )); then
    echo "The fake Meson dependency hash unexpectedly succeeded." >&2
    exit 1
fi

meson_deps_hash=$(printf '%s\n' "$deps_log" | sed -n 's/.*got:[[:space:]]*\(sha256-[A-Za-z0-9+\/=]*\).*/\1/p' | tail -n 1)

if [[ $meson_deps_hash != sha256-* ]]; then
    printf '%s\n' "$deps_log" >&2
    echo "Could not extract the Meson dependency hash from the Nix build." >&2
    exit 1
fi

write_checksums "$upstream_version" "$rev" "$src_hash" "$meson_deps_hash"
echo "Validating Rizin and rizin-rs"
nix build .#rizin --no-link --print-build-logs
nix build .#rizin-rs --no-link --print-build-logs

echo "Updated nix/rizin/checksum.json"
echo "  version: $upstream_version"
echo "  rev: $rev"
echo "  srcHash: $src_hash"
echo "  mesonDepsHash: $meson_deps_hash"
