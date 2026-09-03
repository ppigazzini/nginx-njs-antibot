#!/usr/bin/env bash
#
# Build src/pow_solver.c natively and check it against OpenSSL's SHA-256
# under AddressSanitizer, UndefinedBehaviorSanitizer, libFuzzer and valgrind.
#
# include/wasm_simd128.h stands in for clang's wasm header, so the solver
# source is compiled unmodified.
#
# Usage:
#   ./test/native/check.sh              fuzz for 60 seconds
#   ./test/native/check.sh 300          fuzz for 300 seconds
#   ./test/native/check.sh 300 corpus   keep the corpus in ./corpus, so
#                                       coverage carries over between runs
#
set -euo pipefail

# Resolve the corpus against the caller's directory before changing into this
# one, or a relative path would be taken relative to test/native.
case ${2:-} in
    "")  corpus_arg="" ;;
    /*)  corpus_arg=$2 ;;
    *)   corpus_arg="$PWD/$2" ;;
esac
readonly CORPUS=$corpus_arg

cd "$(dirname "$0")" && cd "$(pwd -P)"

readonly FUZZ_SECONDS=${1:-60}
readonly SRC=fuzz_pow.c
readonly FLAGS=(-std=c11 -O1 -g -Iinclude -D__wasm_simd128__=1
                -Wno-unknown-attributes)
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

command -v clang >/dev/null || { echo "clang not found" >&2; exit 1; }

echo "== sanitizers =="
clang "${FLAGS[@]}" -fsanitize=address,undefined -fno-sanitize-recover=all \
    -fno-omit-frame-pointer -o "$tmp/sanitized" "$SRC" -lcrypto
"$tmp/sanitized" 2000 1

echo "== libFuzzer, ${FUZZ_SECONDS}s =="
clang "${FLAGS[@]}" -fsanitize=fuzzer,address,undefined -fno-sanitize-recover=all \
    -DPOW_LIBFUZZER -o "$tmp/fuzzer" "$SRC" -lcrypto
corpus=${CORPUS:-$tmp/corpus}
mkdir -p "$corpus"
[ -n "$(ls -A "$corpus")" ] || head -c 75 /dev/urandom > "$corpus/seed"
printf '  corpus %s, %s input(s) on entry\n' "$corpus" "$(find "$corpus" -type f | wc -l)"
"$tmp/fuzzer" "$corpus" -max_total_time="$FUZZ_SECONDS" -print_final_stats=1 \
    2>&1 | grep -E "^Done|stat::number_of_executed_units|ERROR|SUMMARY"
# Keep only the inputs that still add coverage, so the corpus does not grow
# without bound across runs.
mkdir -p "$tmp/merged"
"$tmp/fuzzer" -merge=1 "$tmp/merged" "$corpus" > /dev/null 2>&1 || true
if [ -n "$(ls -A "$tmp/merged")" ]; then
    rm -rf "${corpus:?}"
    mkdir -p "$corpus"
    cp "$tmp/merged"/* "$corpus"/
fi
printf '  corpus %s input(s) on exit, after merge\n' "$(find "$corpus" -type f | wc -l)"

if command -v valgrind >/dev/null; then
    echo "== valgrind =="
    clang "${FLAGS[@]}" -o "$tmp/plain" "$SRC" -lcrypto
    valgrind --error-exitcode=1 --leak-check=full --errors-for-leak-kinds=all \
        -q "$tmp/plain" 200 2
else
    echo "== valgrind: not installed, skipped =="
fi

echo "all native checks passed"
