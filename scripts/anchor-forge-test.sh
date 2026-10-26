#!/usr/bin/env bash
# Run the anchor contract's tests without vendoring forge-std: assemble a throwaway
# tree, borrow forge-std from a discovered lib, run the pinned forge, report.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
FORGE="${HAZMAT_FORGE:-$HOME/.foundry/bin/forge}"
STD="${HAZMAT_FORGE_STD:-$HOME/code/claus-network-specimen/contracts/lib/forge-std}"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
mkdir -p "$WORK/src" "$WORK/lib"
cp "$ROOT/anchors/HazMatAnchor.sol" "$ROOT/anchors/HazMatAnchor.t.sol" "$WORK/src/"
cp -R "$STD" "$WORK/lib/forge-std"
cat > "$WORK/foundry.toml" <<'TOML'
[profile.default]
src = "src"
test = "src"
libs = ["lib"]
auto_detect_remappings = false
remappings = ["forge-std/=lib/forge-std/src/"]
solc_version = "0.8.24"
evm_version = "cancun"
optimizer = true
optimizer_runs = 200
TOML
cd "$WORK"
"$FORGE" test -vv
