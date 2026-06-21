#!/usr/bin/env bash
#
# two-device-demo.sh — a local, two-"device" CE Notes sync demo.
#
# Simulates two devices on one machine by running two CE nodes with separate data dirs (and thus
# separate identities), then creating a space on device A, sharing it to device B by capability, and
# editing on both — converging over the mesh.
#
# Prereqs:
#   * a `ce` binary on PATH (the CE node), built from ~/ce-net/ce
#   * this crate built: `cargo build` in ~/ce-net/ce-notes  (produces target/debug/ce-notes)
#
# This is a demonstration harness, not a CI test (it starts real nodes and uses the live mesh). The
# pure-logic paths are covered by `cargo test`.

set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/.." && pwd)"
NOTES="${CE_NOTES_BIN:-$ROOT/target/debug/ce-notes}"
CE_BIN="${CE_BIN:-ce}"

WORK="$(mktemp -d -t ce-notes-demo.XXXXXX)"
A_DATA="$WORK/deviceA"
B_DATA="$WORK/deviceB"
mkdir -p "$A_DATA" "$B_DATA"

# Two nodes need distinct ports.
A_API=8844
B_API=8855
A_P2P=4101
B_P2P=4102

cleanup() {
  echo ">> stopping nodes"
  [[ -n "${A_PID:-}" ]] && kill "$A_PID" 2>/dev/null || true
  [[ -n "${B_PID:-}" ]] && kill "$B_PID" 2>/dev/null || true
  echo ">> work dir left at: $WORK (remove when done)"
}
trap cleanup EXIT

if [[ ! -x "$NOTES" ]]; then
  echo "!! ce-notes binary not found at $NOTES — run 'cargo build' first" >&2
  exit 1
fi

echo ">> starting device A node (api :$A_API, p2p :$A_P2P)"
"$CE_BIN" start --data-dir "$A_DATA" --api-port "$A_API" --p2p-port "$A_P2P" --no-mine \
  >"$WORK/nodeA.log" 2>&1 &
A_PID=$!

echo ">> starting device B node (api :$B_API, p2p :$B_P2P)"
"$CE_BIN" start --data-dir "$B_DATA" --api-port "$B_API" --p2p-port "$B_P2P" --no-mine \
  >"$WORK/nodeB.log" 2>&1 &
B_PID=$!

echo ">> waiting for both nodes to answer /health"
for url in "http://127.0.0.1:$A_API/health" "http://127.0.0.1:$B_API/health"; do
  for _ in $(seq 1 30); do
    if curl -fsS "$url" >/dev/null 2>&1; then break; fi
    sleep 1
  done
done

a() { "$NOTES" --node-url "http://127.0.0.1:$A_API" --data-dir "$A_DATA" --identity-dir "$A_DATA/identity" "$@"; }
b() { "$NOTES" --node-url "http://127.0.0.1:$B_API" --data-dir "$B_DATA" --identity-dir "$B_DATA/identity" "$@"; }

echo ">> device A id: $(a whoami)"
echo ">> device B id: $(b whoami)"
B_ID="$(b whoami)"

echo ">> A creates a space"
A_SPACE_LINE="$(a space new "Shared Work")"
echo "   $A_SPACE_LINE"
A_SPACE="$(echo "$A_SPACE_LINE" | awk '{print $3}')"

echo ">> A creates a note and writes a body"
NOTE="$(a new --space "$A_SPACE" "Roadmap")"
a set --space "$A_SPACE" "$NOTE" "# Roadmap"$'\n\n'"- ship notes"$'\n' >/dev/null
echo "   note id: $NOTE"

echo ">> A invites B as a writer"
a invite --space "$A_SPACE" --to "$B_ID" --role writer --out "$WORK/invite.bin" >/dev/null
echo ">> B imports the invite"
b import "$WORK/invite.bin"

echo ">> giving the mesh a moment to converge"
sleep 3
b sync --space "$A_SPACE" || true

echo ">> B reads the note A wrote:"
b cat --space "$A_SPACE" "$NOTE" || echo "   (not converged yet — check nodeA/B logs)"

echo ">> B appends a concurrent edit"
b set --space "$A_SPACE" "$NOTE" "# Roadmap"$'\n\n'"- ship notes"$'\n'"- review from B"$'\n' >/dev/null
sleep 3
a sync --space "$A_SPACE" || true

echo ">> A reads back the merged note:"
a cat --space "$A_SPACE" "$NOTE" || true

echo ">> done. Both devices should show the same merged body once converged."
