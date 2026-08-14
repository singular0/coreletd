#!/bin/sh
# Build the coreletd Debian package.
#
#   tools/build-deb.sh                 native build (run this on the uConsole)
#   tools/build-deb.sh --docker        build for arm64 in a debian:trixie container
#   tools/build-deb.sh --docker amd64  ... or for some other architecture
#
# The .deb lands in dist/. Native builds need the build dependencies installed:
#   sudo apt install build-essential debhelper cmake pkgconf \
#                    libsodium-dev libssl-dev libgpiod-dev
set -eu

repo=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
image=debian:trixie

# The build dependencies, kept in one place so the container installs exactly
# what debian/control asks for.
build_deps='build-essential debhelper cmake pkgconf libsodium-dev libssl-dev libgpiod-dev'

docker_build() {
    arch=$1
    mkdir -p "$repo/dist"

    # The source tree is mounted read-only and copied inside: dpkg-buildpackage
    # writes into it and drops its output in the parent directory, and neither
    # belongs in the working copy.
    docker run --rm --platform "linux/$arch" \
        -v "$repo:/src:ro" -v "$repo/dist:/out" \
        -e DEBIAN_FRONTEND=noninteractive \
        -e DEB_BUILD_OPTIONS="parallel=$(getconf _NPROCESSORS_ONLN 2>/dev/null || echo 2)" \
        "$image" sh -eux -c "
            apt-get update -qq
            apt-get install -y --no-install-recommends $build_deps
            mkdir -p /build/coreletd
            tar -C /src --exclude=./build --exclude=./dist --exclude=./.git -cf - . |
                tar -C /build/coreletd -xf -
            cd /build/coreletd
            dpkg-buildpackage -us -uc -b
            cp ../coreletd_*.deb ../coreletd-dbgsym_*.d*b /out/ 2>/dev/null ||
                cp ../coreletd_*.deb /out/
        "
}

native_build() {
    command -v dpkg-buildpackage >/dev/null 2>&1 || {
        echo "dpkg-buildpackage not found -- this is not a Debian system." >&2
        echo "Use 'tools/build-deb.sh --docker' instead." >&2
        exit 1
    }

    mkdir -p "$repo/dist"
    ( cd "$repo" && dpkg-buildpackage -us -uc -b )
    # dpkg-buildpackage writes to the parent of the source tree.
    mv "$repo"/../coreletd_*.deb "$repo/dist/"
    mv "$repo"/../coreletd-dbgsym_*.d*b "$repo/dist/" 2>/dev/null || true
}

case "${1-}" in
    --docker) docker_build "${2-arm64}" ;;
    "")       native_build ;;
    *)        echo "usage: $0 [--docker [arch]]" >&2; exit 2 ;;
esac

echo
echo "Built:"
ls -1 "$repo"/dist/*.deb
