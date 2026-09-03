#!/usr/bin/env bash
#
# Build the proof-of-work solver and assemble the deployable njs module.
#
# src/pow_solver.c compiles to dist/pow_solver.wasm with -msimd128. A module
# containing SIMD instructions fails validation as a whole on an engine
# without SIMD, so it cannot double as its own fallback: engines without SIMD
# run the pure-JS solver in src/antibot.js.
#
# src/antibot.js carries an empty POW_WASM_SIMD_B64. This script fills it with
# the compiled solver and writes the result to dist/antibot.js. Nothing in the
# source tree is modified, and no binary is committed.
#
# Deploy dist/antibot.js. CI publishes it as a build artifact.
#
# Usage:
#   ./build.sh              compile, assemble, test
#   ./build.sh --no-test    compile and assemble only
#   ./build.sh --strict     treat warnings as errors
#
# Warnings are not errors by default. A compiler newer or older than the one
# a change was written against can warn about untouched code, and that must
# not stop the deliverable from building. CI runs --strict as its own step so
# a warning fails visibly instead of silently.
#
set -euo pipefail

# Portable: readlink -f is GNU only.
cd "$(dirname "$0")" && cd "$(pwd -P)"

readonly SOURCE=src/pow_solver.c
readonly MODULE_SRC=src/antibot.js
readonly DIST=dist
readonly WASM=$DIST/pow_solver.wasm
readonly MODULE=$DIST/antibot.js
readonly PAYLOAD=POW_WASM_SIMD_B64
# Constant in the module, and the file written into it. Each of these is a
# program in its own right and is parsed on its own before it goes in.
readonly EMBEDS=(
    "POW_JS_SOLVER:src/solver.js"
    "WORKER_TEMPLATE:src/worker.js"
    "PAGE_TEMPLATE:src/page.html"
)
readonly VERSION_CONST=ANTIBOT_VERSION

# Hand-written crypto in a security path: every warning that can catch a
# narrowing or a shadowed variable is on, and warnings are errors.
readonly WARNINGS=(
    -Wall -Wextra -Wpedantic -Wconversion -Wshadow
    -Wstrict-prototypes -Wcast-qual -Wmissing-prototypes -Wdouble-promotion
)
# Freestanding: no libc, no imports, no start function. Two pages of memory
# hold the challenge, the midstate and the message schedule.
readonly CFLAGS=(--target=wasm32 -O3 -std=c11 -msimd128 -nostdlib -ffreestanding)
# shellcheck disable=SC2054  # linker flags carry their own commas
readonly LDFLAGS=(-Wl,--no-entry -Wl,--strip-all -Wl,--initial-memory=131072)

test=1 strict=0
for arg in "$@"; do
    case "$arg" in
        --no-test) test=0 ;;
        --strict)  strict=1 ;;
        -h|--help) awk 'NR>2 && /^#/ {sub(/^# ?/, ""); print; next} NR>2 {exit}' "$0"; exit 0 ;;
        *) printf 'unknown option: %s (try --help)\n' "$arg" >&2; exit 2 ;;
    esac
done

die() { printf '%s: %s\n' "${0##*/}" "$*" >&2; exit 1; }

command -v clang   >/dev/null || die "clang not found"
command -v wasm-ld >/dev/null || die "wasm-ld not found (install lld)"
clang --print-targets 2>/dev/null | grep -q wasm32 || die "clang has no wasm32 target"
[ -f "$SOURCE" ]     || die "$SOURCE not found"
[ -f "$MODULE_SRC" ] || die "$MODULE_SRC not found"
grep -q "^const $PAYLOAD = \"\";" "$MODULE_SRC" \
    || die "$MODULE_SRC does not declare an empty $PAYLOAD"
for embed in "${EMBEDS[@]}"; do
    [ -f "${embed#*:}" ] || die "${embed#*:} not found"
    grep -q "^const ${embed%%:*} = \"\";" "$MODULE_SRC" \
        || die "$MODULE_SRC does not declare an empty ${embed%%:*}"
done

mkdir -p "$DIST"

printf 'compiling %s\n' "$SOURCE"
werror=()
[ "$strict" -eq 1 ] && werror=(-Werror)
clang "${CFLAGS[@]}" "${WARNINGS[@]}" "${werror[@]}" "${LDFLAGS[@]}" -o "$WASM" "$SOURCE"
b64=$DIST/.wasm.b64
# base64 -w0 is GNU only; fold the newlines instead.
base64 < "$WASM" | tr -d '\n' > "$b64"
printf '  %-24s %6s bytes  (%s base64 chars)\n' \
    "$WASM" "$(wc -c < "$WASM" | tr -d ' ')" "$(wc -c < "$b64" | tr -d ' ')"

# The page, the worker and the JS solver are parsed before they are written
# in. A syntax error in any of them stops the build here rather than reaching
# a browser, which a string literal inside the module never allowed.
if command -v node >/dev/null; then
    node --check src/solver.js || die "src/solver.js does not parse"
    node --check src/worker.js || die "src/worker.js does not parse"
    script=$DIST/.page-script.js
    sed -n '/<script>/,/<\/script>/p' src/page.html \
        | sed -e 's|.*<script>||' -e 's|</script>.*||' > "$script"
    node --check "$script" || die "the script block in src/page.html does not parse"
    rm -f "$script"
fi

# Replace the empty payload with the compiled solver, and each empty program
# constant with the file beside it, as a JavaScript string.
embed_text() {
    awk -v name="$1" -v file="$2" '
        $0 == "const " name " = \"\";" {
            out = ""
            while ((getline line < file) > 0) {
                gsub(/\\/, "\\\\", line)
                gsub(/"/, "\\\"", line)
                gsub(/\t/, "\\t", line)
                gsub(/\r/, "\\r", line)
                out = out line "\\n"
            }
            close(file)
            printf "const %s = \"%s\";\n", name, out
            next
        }
        { print }
    '
}

cp "$MODULE_SRC" "$MODULE.tmp"
awk -v name="$PAYLOAD" -v b64file="$b64" '
    $0 == "const " name " = \"\";" {
        getline value < b64file
        print "const " name " ="
        print "    \"" value "\";"
        next
    }
    { print }
' "$MODULE.tmp" > "$MODULE"
rm -f "$b64"

for embed in "${EMBEDS[@]}"; do
    file=${embed#*:}
    printf '  %-24s %6s bytes\n' "$file" "$(wc -c < "$file" | tr -d ' ')"
    embed_text "${embed%%:*}" "$file" < "$MODULE" > "$MODULE.tmp"
    mv "$MODULE.tmp" "$MODULE"
done
rm -f "$MODULE.tmp"

# One version, taken from package.json, so the module, the package and the
# release tag cannot drift apart.
# Parsed where node is available, so the value does not depend on how
# package.json is indented. The fallback is anchored to the top-level key.
if command -v node >/dev/null; then
    version=$(node -e 'const v = require("./package.json").version;
        if (typeof v !== "string" || !v) { process.exit(1); }
        process.stdout.write(v);') || die "no version in package.json"
else
    version=$(sed -n 's/^  "version": *"\([^"]*\)".*/\1/p' package.json)
    [ "$(printf '%s\n' "$version" | wc -l)" -eq 1 ] \
        || die "package.json has more than one top-level version"
fi
[ -n "$version" ] || die "no version in package.json"
sed "s/^const $VERSION_CONST = \".*\";\$/const $VERSION_CONST = \"$version\";/" \
    "$MODULE" > "$DIST/.versioned.js"
grep -q "^const $VERSION_CONST = \"$version\";\$" "$DIST/.versioned.js" \
    || die "could not stamp $VERSION_CONST"
cat "$DIST/.versioned.js" > "$MODULE"
rm -f "$DIST/.versioned.js"

command -v node >/dev/null && { node --check "$MODULE" || die "$MODULE does not parse"; }
printf 'assembled %s, version %s\n' "$MODULE" "$version"

if [ "$test" -eq 1 ]; then
    command -v node >/dev/null || die "node not found (use --no-test to skip)"
    printf '\n--- test/solver.test.mjs ---\n'
    node test/solver.test.mjs
    printf '\n--- test/module.test.mjs ---\n'
    node test/module.test.mjs
    printf '\n--- test/module-fuzz.mjs ---\n'
    node test/module-fuzz.mjs
fi

printf '\ndone\n'
