#!/usr/bin/env bash
#
# Exercise the release guards. They run once per release and refused the first
# one, so they are checked here rather than at the next release.
set -euo pipefail
cd "$(dirname "$0")"
# shellcheck source=test/release/guards.sh
. ./guards.sh

failures=0
readonly SHA=1111111111111111111111111111111111111111
readonly OTHER=2222222222222222222222222222222222222222

expect() {
    # Scoped: these functions are sourced into this shell, and a guard that
    # assigned a bare `want` would otherwise decide its own result.
    local want=$1
    shift
    local label=$1
    shift
    local got
    if "$@" >/dev/null 2>&1; then
        got=pass
    else
        got=refuse
    fi
    if [ "$got" = "$want" ]; then
        echo "  ok: $label"
    else
        echo "  FAIL: $label: expected $want, got $got"
        failures=$((failures + 1))
    fi
}

echo "== the tag is v and the version =="
expect pass   "v0.1.0"          release_check_tag_shape v0.1.0
expect pass   "v10.2.3-rc.1"    release_check_tag_shape v10.2.3-rc.1
expect refuse "0.1.0"           release_check_tag_shape 0.1.0
expect refuse "release-1"       release_check_tag_shape release-1
expect refuse "empty"           release_check_tag_shape ""

echo "== the tag does not already point elsewhere =="
# The first release: the tag does not exist. This is the case that refused.
expect pass   "tag absent"      release_check_tag_target v0.1.0 "" "$SHA"
expect pass   "tag on this sha" release_check_tag_target v0.1.0 "$SHA" "$SHA"
expect refuse "tag on another"  release_check_tag_target v0.1.0 "$OTHER" "$SHA"

echo "== the tag names the built version =="
expect pass   "v0.1.0 / 0.1.0"  release_check_version v0.1.0 0.1.0
expect refuse "v0.1.0 / 0.2.0"  release_check_version v0.1.0 0.2.0
expect refuse "v0.1.0 / v0.1.0" release_check_version v0.1.0 v0.1.0
expect refuse "nothing stamped" release_check_version v0.1.0 ""
expect refuse "unbuilt module"  release_check_version v0.1.0 0.0.0-unbuilt
echo
if [ "$failures" -eq 0 ]; then
    echo "all release guards behave"
else
    echo "$failures FAILURE(S)"
    exit 1
fi
