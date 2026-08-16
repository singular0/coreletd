#!/bin/sh
# Build the coreletd Debian package.
#
#   tools/build-deb.sh                 native build (run this on the uConsole)
#   tools/build-deb.sh deps            install the build dependencies, then stop
#   tools/build-deb.sh --docker        build for arm64 in a debian:trixie container
#   tools/build-deb.sh --docker amd64  ... or for some other architecture
#
# The .deb lands in dist/, named after `git describe`: an untagged checkout
# builds as 0.0.0+g<hash>, a release tag as the version it names.
#
# Every build happens in a temporary staged tree. That is where the Git-derived
# manifest and the matching changelog stanza are injected, so dpkg can use them
# without anything being written into the working copy.
set -eu

repo=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
image=debian:trixie
stage_root=

cleanup() {
    if [ -n "$stage_root" ] && [ -d "$stage_root" ]; then
        rm -rf "$stage_root"
    fi
}

die() {
    echo "build-deb: $*" >&2
    exit 1
}

manifest_value() {
    sed -n "s/^set($1 \"\\(.*\\)\")\$/\\1/p" "$2"
}

# Everything that turns a stock Debian machine into one that can build the
# package. debian/control's Build-Depends is the only list: apt-get reads it
# out of there rather than having it repeated here, in the container recipe
# below, and again in CI.
install_deps() {
    command -v apt-get >/dev/null 2>&1 || die "deps needs a Debian system"
    sudo=
    [ "$(id -u)" -eq 0 ] || sudo=sudo
    DEBIAN_FRONTEND=noninteractive
    export DEBIAN_FRONTEND
    $sudo apt-get update -qq
    $sudo apt-get install -y --no-install-recommends build-essential dpkg-dev debhelper
    $sudo apt-get build-dep -y "$repo"
}

native_build() {
    command -v dpkg-buildpackage >/dev/null 2>&1 || {
        echo "dpkg-buildpackage not found. On a Debian system run" >&2
        echo "'tools/build-deb.sh deps' first; anywhere else, use --docker." >&2
        exit 1
    }

    stage_root=$(mktemp -d)
    [ -n "$stage_root" ] && [ -d "$stage_root" ] \
        || die "cannot create a temporary build tree"
    trap cleanup EXIT
    source=$stage_root/coreletd
    manifest=$stage_root/version.cmake

    # A container build resolves the version against the read-only mount of the
    # real checkout and passes the answer in, because the tree this one is
    # about to build has no .git.
    if [ -n "${CORELETD_VERSION_MANIFEST-}" ]; then
        [ -f "$CORELETD_VERSION_MANIFEST" ] \
            || die "version manifest not found: $CORELETD_VERSION_MANIFEST"
        cp "$CORELETD_VERSION_MANIFEST" "$manifest"
    else
        cmake -DSOURCE_DIR="$repo" -DOUTPUT_MANIFEST="$manifest" \
            -P "$repo/cmake/version.cmake"
    fi

    version=$(manifest_value CORELETD_VERSION_DEBIAN "$manifest")
    display=$(manifest_value CORELETD_VERSION "$manifest")
    date=$(manifest_value CORELETD_VERSION_DATE "$manifest")
    [ -n "$version" ] && [ -n "$display" ] && [ -n "$date" ] \
        || die "the version resolver produced an incomplete manifest"
    arch=$(dpkg --print-architecture)

    mkdir -p "$source"
    tar -C "$repo" --exclude=./build --exclude=./dist --exclude=./.git -cf - . |
        tar -C "$source" -xf -
    cp "$manifest" "$source/.coreletd-version.cmake"

    # debhelper takes the binary package's version from the first changelog
    # stanza. The stanzas in the tree are release history; a generated one is
    # prepended only when the frozen Git version is not already what the first
    # one says, which is every build that is not exactly on a release tag.
    current=$(sed -n '1s/^coreletd (\([^)]*\)).*/\1/p' "$source/debian/changelog")
    if [ "$current" != "$version" ]; then
        maintainer=$(sed -n 's/^Maintainer:[[:space:]]*//p' "$source/debian/control" | head -1)
        [ -n "$maintainer" ] || die "cannot read the package maintainer"
        {
            printf 'coreletd (%s) unstable; urgency=medium\n\n' "$version"
            printf '  * Build from Git version %s.\n\n' "$display"
            printf ' -- %s  %s\n\n' "$maintainer" "$date"
            cat "$source/debian/changelog"
        } >"$source/debian/changelog.generated"
        mv "$source/debian/changelog.generated" "$source/debian/changelog"
    fi

    # dpkg-buildpackage compiles serially unless told otherwise, which on a
    # four-core CM4 leaves three cores idle for the whole build.
    DEB_BUILD_OPTIONS="${DEB_BUILD_OPTIONS:-parallel=$(getconf _NPROCESSORS_ONLN 2>/dev/null || echo 2)}"
    export DEB_BUILD_OPTIONS
    ( cd "$source" && dpkg-buildpackage -us -uc -b )

    mkdir -p "$repo/dist"
    # dpkg-buildpackage writes to the parent of the source tree, and leaves a
    # .changes and a .buildinfo there describing an upload nobody is making.
    mv "$stage_root"/coreletd*_"$version"_"$arch".*deb "$repo/dist/"

    # The manifest, the changelog stanza and the filename are three separate
    # steps away from one Git observation; ask dpkg what it actually built.
    actual=$(dpkg-deb -f "$repo/dist/coreletd_${version}_${arch}.deb" Version)
    [ "$actual" = "$version" ] \
        || die "package says $actual, version manifest says $version"
}

docker_build() {
    arch=$1
    command -v docker >/dev/null 2>&1 || die "docker is required to build for $arch"
    mkdir -p "$repo/dist"

    # The source tree is mounted read-only and copied inside: dpkg-buildpackage
    # writes into it and drops its output in the parent directory, and neither
    # belongs in the working copy. Git is resolved from that read-only mount
    # once the dependencies are in place, and the manifest follows the source
    # into the staged native build, so a container package identifies itself
    # exactly as a native one would.
    docker run --rm --platform "linux/$arch" \
        -v "$repo:/src:ro" -v "$repo/dist:/out" \
        -e DEBIAN_FRONTEND=noninteractive \
        "$image" sh -eux -c '
            mkdir -p /build/coreletd
            tar -C /src --exclude=./build --exclude=./dist --exclude=./.git -cf - . |
                tar -C /build/coreletd -xf -
            /build/coreletd/tools/build-deb.sh deps
            cmake -DSOURCE_DIR=/src -DOUTPUT_MANIFEST=/tmp/coreletd-version.cmake \
                -P /src/cmake/version.cmake
            CORELETD_VERSION_MANIFEST=/tmp/coreletd-version.cmake \
                /build/coreletd/tools/build-deb.sh
            cp /build/coreletd/dist/*.deb /out/
        '
}

case "${1-}" in
    --docker) docker_build "${2-arm64}" ;;
    deps)     install_deps; exit 0 ;;
    "")       native_build ;;
    *)        echo "usage: $0 [deps | --docker [arch]]" >&2; exit 2 ;;
esac

echo
echo "Built:"
ls -1 "$repo"/dist/*.deb
