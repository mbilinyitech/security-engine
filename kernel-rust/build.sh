#!/bin/sh
# Build the bare-metal kernel image.
set -eu
cd "$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
cargo build --release --target x86_64-unknown-none
echo "image: target/x86_64-unknown-none/release/sovereign-kernel"
