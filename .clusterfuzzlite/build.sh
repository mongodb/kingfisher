#!/bin/bash -eu

# Install build dependencies required by vendored vectorscan (C/C++).
#
# OSS-Fuzz's Ubuntu 20.04 mirrors are intermittently flaky from the
# ClusterFuzzLite runners — a single connection-failed on archive.ubuntu.com
# while fetching e.g. libxml2 used to fail the entire build. Retry the
# update + install up to 5 times with `--fix-missing` so a transient hiccup
# doesn't block a PR.
APT_PACKAGES=(cmake pkg-config libboost-dev patch ragel)
apt_install_with_retry() {
    local attempt
    for attempt in 1 2 3 4 5; do
        if apt-get update -qq \
            && apt-get install -y --no-install-recommends --fix-missing \
                "${APT_PACKAGES[@]}"; then
            return 0
        fi
        echo "apt-get attempt ${attempt} failed; retrying after backoff..." >&2
        sleep $((attempt * 5))
    done
    echo "apt-get failed after 5 attempts" >&2
    return 1
}
apt_install_with_retry

cd "$SRC/kingfisher"

# OSS-Fuzz's clang/libc++ toolchain builds vendored Vectorscan against Ubuntu
# 20.04's Boost headers. Re-enable the removed unary_function/binary_function
# compatibility shims so Boost 1.71 still compiles in C++17 mode.
export CXXFLAGS="${CXXFLAGS:-} -D_LIBCPP_ENABLE_CXX17_REMOVED_UNARY_BINARY_FUNCTION"

# ClusterFuzzLite's base Rust image can lag behind our MSRV, so install an
# explicit nightly that satisfies the workspace's rust-version before building.
rustup toolchain install "${RUST_FUZZ_TOOLCHAIN}" --profile minimal
export RUSTUP_TOOLCHAIN="${RUST_FUZZ_TOOLCHAIN}"
rustc --version

# Build all fuzz targets in release mode with debug assertions
cargo fuzz build -O --debug-assertions

# Copy built fuzz binaries to the output directory
FUZZ_TARGET_OUTPUT_DIR=fuzz/target/x86_64-unknown-linux-gnu/release
for f in fuzz/fuzz_targets/*.rs; do
    FUZZ_TARGET_NAME=$(basename "${f%.*}")
    if [ -f "$FUZZ_TARGET_OUTPUT_DIR/$FUZZ_TARGET_NAME" ]; then
        cp "$FUZZ_TARGET_OUTPUT_DIR/$FUZZ_TARGET_NAME" "$OUT/"
    fi
done
