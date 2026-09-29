#!/usr/bin/env bash
# Builds the Reth guest from a zkVM static library, as Ere publishes them
# (`staticlib-<zkvm>.tar.gz`): `libzkvm.a` (the zkVM's runtime and accelerators as fat LTO objects),
# `zkvm.ld`, and optionally `zkvm.features` and `zkvm-lto-plugin.so`. The guest
# (`bin/stateless-validator-reth/zkvm`) is compiled to bitcode and optimized together with the
# static library at link time.
#
# Requires `ld.lld` (LD_LLD) from LLVM 22, the LLVM of the static library's bitcode and of Rust
# 1.95.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(git -C "$SCRIPT_DIR" rev-parse --show-toplevel)"
# shellcheck source=config.sh
source "$SCRIPT_DIR/config.sh"

if [[ $# -lt 2 || $# -gt 3 ]]; then
    echo "usage: $0 <openvm|sp1|zisk> <staticlib-directory> [output-directory]" >&2
    exit 2
fi

guest_config "$1"
LIB="$(cd "$2" && pwd)"
OUTPUT_DIR="${3:-$REPO_ROOT/output}"
mkdir -p "$OUTPUT_DIR"
OUTPUT_DIR="$(cd "$OUTPUT_DIR" && pwd)"
GUEST_DIR="$REPO_ROOT/bin/stateless-validator-reth/zkvm"
TARGET_DIR="$REPO_ROOT/target/zkvm-staticlib/$ZKVM"

rustflags=(-C linker-plugin-lto -C passes=lower-atomic)
if [[ -s "$LIB/zkvm.features" ]]; then
    rustflags+=(-C "target-feature=$(tr -d '[:space:]' <"$LIB/zkvm.features")")
fi
CARGO_ENCODED_RUSTFLAGS="$(IFS=$'\x1f' && echo "${rustflags[*]}")" RUSTC_BOOTSTRAP=1 \
    cargo +1.95.0 build --locked --release \
    --manifest-path "$GUEST_DIR/Cargo.toml" \
    --target "$REPO_ROOT/targets/riscv64im-unknown-none-elf.json" \
    --target-dir "$TARGET_DIR" \
    -Zbuild-std=core,alloc -Zbuild-std-features=compiler-builtins-mem -Zjson-target-spec

link_options=()
if [[ -f "$LIB/zkvm-lto-plugin.so" ]]; then
    link_options+=("--load-pass-plugin=$LIB/zkvm-lto-plugin.so")
fi
if [[ "$ZKVM" == sp1 ]]; then
    # `cargo prove build` compiles every SP1 guest with this scheduling direction.
    link_options+=(-mllvm -misched-prera-direction=bottomup -mllvm -misched-postra-direction=bottomup)
fi
"${LD_LLD:-ld.lld}" -T "$LIB/zkvm.ld" -L "$LIB" --gc-sections --fat-lto-objects --lto-O3 \
    "${link_options[@]}" \
    -o "$OUTPUT_DIR/$ARTIFACT_NAME.elf" \
    "$TARGET_DIR/riscv64im-unknown-none-elf/release/libstateless_validator_reth_zkvm.a"

docker run --rm \
    -e RUST_LOG=info \
    --mount "type=bind,src=$OUTPUT_DIR,dst=/output" \
    "$SERVER_IMAGE" \
    --elf-path "/output/$ARTIFACT_NAME.elf" \
    keygen \
    --program-vk-path "/output/$ARTIFACT_NAME.vk"

echo "Built $ARTIFACT_NAME"
