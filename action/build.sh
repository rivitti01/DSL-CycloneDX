#!/usr/bin/env bash
# Builds sbom-dsl for the GitHub Action (see action.yml).
#
#   build.sh prepare   computes the cache key and install directory (step outputs)
#   build.sh build     configures, builds and installs sbom-dsl into SBOM_DSL_INSTALL_DIR
#
# The cache key covers the sources, the runner image and the compiler version, so a binary
# is never restored on a runner whose C++ runtime could be incompatible with it.
set -euo pipefail

root="${GITHUB_ACTION_PATH:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"
temp_dir="${RUNNER_TEMP:-${TMPDIR:-/tmp}}"
output_file="${GITHUB_OUTPUT:-/dev/stdout}"

fail() {
    echo "::error title=sbom-dsl setup::$1"
    exit 2
}

require() {
    command -v "$1" >/dev/null 2>&1 || fail "'$1' was not found on PATH. $2"
}

short_hash() {
    if command -v sha256sum >/dev/null 2>&1; then
        sha256sum | cut -c1-16
    else
        shasum -a 256 | cut -c1-16
    fi
}

prepare() {
    if [ "${RUNNER_OS:-}" = "Windows" ]; then
        fail "Windows runners are not supported yet. Use ubuntu-* or macos-* runners."
    fi
    require cmake "Install CMake 3.20 or newer (it is preinstalled on GitHub-hosted runners)."
    local cxx="${CXX:-c++}"
    require "$cxx" "Install a C++20 compiler (GCC 11+, Clang 13+ or AppleClang 15+)."

    local src_hash cxx_hash image install_dir
    src_hash="$(cd "$root" && find CMakeLists.txt src include -type f | LC_ALL=C sort |
        while IFS= read -r f; do printf '%s\n' "$f"; cat "$f"; done | short_hash)"
    cxx_hash="$("$cxx" --version 2>/dev/null | head -n 1 | short_hash)"
    image="${ImageOS:-$(uname -sm | tr ' ' '-')}"
    install_dir="$temp_dir/sbom-dsl/$src_hash-$cxx_hash"

    {
        echo "cache-key=sbom-dsl-${RUNNER_OS:-local}-${RUNNER_ARCH:-$(uname -m)}-$image-$cxx_hash-$src_hash"
        echo "install-dir=$install_dir"
        echo "binary=$install_dir/bin/sbom-dsl"
        # A previous use of the action in the same job already built it.
        if [ -x "$install_dir/bin/sbom-dsl" ]; then echo "installed=true"; else echo "installed=false"; fi
    } >> "$output_file"
}

build() {
    : "${SBOM_DSL_INSTALL_DIR:?SBOM_DSL_INSTALL_DIR is not set}"
    local build_dir="$temp_dir/sbom-dsl-build"
    local jobs
    jobs="$(getconf _NPROCESSORS_ONLN 2>/dev/null || echo 2)"

    echo "::group::Build sbom-dsl"
    cmake -S "$root" -B "$build_dir" -DCMAKE_BUILD_TYPE=Release -DSBOM_DSL_BUILD_TESTS=OFF
    cmake --build "$build_dir" --target sbom-dsl --parallel "$jobs"
    cmake --install "$build_dir" --prefix "$SBOM_DSL_INSTALL_DIR"
    echo "::endgroup::"
    "$SBOM_DSL_INSTALL_DIR/bin/sbom-dsl" --version
}

case "${1:-}" in
    prepare) prepare ;;
    build) build ;;
    *) echo "usage: $0 prepare|build" >&2; exit 2 ;;
esac
