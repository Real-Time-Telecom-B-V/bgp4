#!/usr/bin/env bash
# Seed the fuzz corpora from the captured FRR and BIRD messages, so the fuzzer
# starts from real traffic instead of from nothing.
#
#   scripts/fuzz-corpus.sh
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
vectors="$root/tests/vectors"
corpus="$root/fuzz/corpus"
mkdir -p "$corpus/message" "$corpus/open" "$corpus/update"

for file in "$vectors"/*.hex; do
    name="$(basename "$file" .hex)"
    hex="$(tr -d '\n' <"$file")"
    # `message` and `update` take a context octet first: 4-octet AS numbers
    # on an external session, except in the 2-octet scenario.
    selector="05"
    case "$name" in two-octet-session-*) selector="04" ;; esac
    printf '%s%s' "$selector" "$hex" | xxd -r -p >"$corpus/message/$name"
    # The header is 19 octets, 38 hex digits.
    case "$name" in
    *-open-*) printf '%s' "${hex:38}" | xxd -r -p >"$corpus/open/$name" ;;
    *-update-*) printf '%s%s' "$selector" "${hex:38}" | xxd -r -p >"$corpus/update/$name" ;;
    esac
done
