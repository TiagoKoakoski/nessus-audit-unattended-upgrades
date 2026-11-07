#!/usr/bin/env bash
# Lints every .nasl file in the repo root using the locally-built
# openvas-scanner (AUR package "openvas-scanner"). Not installed as a
# system package here (the AUR install stopped before the final sudo
# step) — this script runs the binaries straight from the yay build
# cache instead.
#
# Uses tools/nasl_lint_stubs/ as a stand-in for the real compat.inc
# from the Greenbone NVT feed, which isn't available standalone. It
# only defines the handful of legacy script_*/ssh_*/security_report_v4
# symbols our plugins actually call — good enough to catch real syntax
# and undefined-symbol bugs, not a substitute for a real Tenable test.
set -euo pipefail

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BUILD_DIR="$HOME/.cache/yay/openvas-scanner/src/build"
LINT_BIN="$BUILD_DIR/nasl/openvas-nasl-lint"
INC_DIR="$REPO_DIR/tools/nasl_lint_stubs"

if [ ! -x "$LINT_BIN" ]; then
  echo "openvas-nasl-lint not found at $LINT_BIN" >&2
  echo "Build it with: yay -S openvas-scanner (needs your own sudo password in a real terminal)" >&2
  exit 1
fi

export LD_LIBRARY_PATH="$BUILD_DIR/nasl:$BUILD_DIR/misc:$BUILD_DIR/base"

status=0
for f in "$REPO_DIR"/*.nasl; do
  [ -e "$f" ] || continue
  echo "=== $(basename "$f") ==="
  if ! "$LINT_BIN" -i "$INC_DIR" "$f"; then
    status=1
  fi
  echo
done

exit $status
