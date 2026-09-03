# shellcheck shell=bash
#
# Guards the release workflow applies before it publishes. Kept here as
# functions over values so they can be exercised without publishing anything:
# the workflow reads GitHub, these decide.
#
# Each prints why it refused and returns non-zero.

# The tag is v and the version. SemVer 2.0.0 states that "v1.2.3" is not a
# semantic version and illustrates its tag as `git tag v1.2.3`, so the version
# in package.json is 1.2.3 and the tag for it is v1.2.3.
release_check_tag_shape() {
    local tag=$1
    case "$tag" in
        v[0-9]*)
            return 0
            ;;
        [0-9]*)
            echo "refusing to release '$tag': the tag is v$tag"
            return 1
            ;;
        *)
            echo "refusing to release '$tag': expected a tag such as v0.1.0"
            return 1
            ;;
    esac
}

# gh release create --target only applies when the tag is new, so a tag that
# already points elsewhere would publish this build against the old commit.
# An empty second argument means the tag does not exist yet.
release_check_tag_target() {
    local tag=$1
    local existing=$2
    local current=$3
    if [ -z "$existing" ]; then
        return 0
    fi
    if [ "$existing" != "$current" ]; then
        echo "tag $tag already points at $existing, not $current"
        return 1
    fi
    return 0
}

# The tag names the version stamped into the artifact, which build.sh took
# from package.json.
release_check_version() {
    local tag=$1
    local built=$2
    if [ -z "$built" ]; then
        echo "no version is stamped in the artifact"
        return 1
    fi
    # package.json holds the version; the tag is v and the version.
    if [ "$tag" != "v$built" ]; then
        echo "tag $tag does not match the built version $built"
        echo "set package.json to ${tag#v} and rebuild"
        return 1
    fi
    return 0
}
