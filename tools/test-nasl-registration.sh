#!/usr/bin/env bash
# Goes one step further than lint-nasl.sh: actually registers the NASL
# plugin(s) into a local redis-backed NVT cache using the real
# openvas-scanner engine (`openvas -u`), the same mechanism Tenable
# uses internally when you upload a custom plugin package. Catches
# things plain syntax lint can't, like a missing script_oid()/
# script_name()/script_family() that silently drops the plugin from
# the cache with 0 registered — exactly the "0 total Plugins found"
# symptom seen on Tenable.
#
# Starts its own throwaway redis-server (no sudo, no system service,
# unix socket in the scratch dir below) and stops it on exit.
set -euo pipefail

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BUILD_DIR="$HOME/.cache/yay/openvas-scanner/src/build"
OPENVAS_BIN="$BUILD_DIR/src/openvas"
WORK_DIR="$(mktemp -d)"
PLUGINS_DIR="$WORK_DIR/plugins"
REDIS_DIR="$WORK_DIR/redis"
SOCK="$REDIS_DIR/redis.sock"

if [ ! -x "$OPENVAS_BIN" ]; then
  echo "openvas binary not found at $OPENVAS_BIN" >&2
  echo "Build it with: yay -S openvas-scanner" >&2
  exit 1
fi

mkdir -p "$PLUGINS_DIR" "$REDIS_DIR"
cp "$REPO_DIR"/*.nasl "$PLUGINS_DIR/" 2>/dev/null || true
cp "$REPO_DIR"/tools/nasl_lint_stubs/*.inc "$PLUGINS_DIR/"

TS="$(date +%Y%m%d%H%M)"
cat > "$PLUGINS_DIR/plugin_feed_info.inc" <<EOF
PLUGIN_SET = "$TS";
PLUGIN_FEED = "Local Test";
FEED_VENDOR = "local";
FEED_HOME = "local";
FEED_NAME = "local-test";
EOF

cat > "$WORK_DIR/redis.conf" <<EOF
port 0
unixsocket $SOCK
unixsocketperm 700
daemonize no
dir $REDIS_DIR
logfile $REDIS_DIR/redis.log
EOF

cat > "$WORK_DIR/openvas.conf" <<EOF
plugins_folder = $PLUGINS_DIR
include_folders = $PLUGINS_DIR
db_address = $SOCK
EOF

redis-server "$WORK_DIR/redis.conf" &
REDIS_PID=$!
cleanup() {
  kill "$REDIS_PID" 2>/dev/null || true
  rm -rf "$WORK_DIR"
}
trap cleanup EXIT

sleep 1
redis-cli -s "$SOCK" PING >/dev/null

export LD_LIBRARY_PATH="$BUILD_DIR/nasl:$BUILD_DIR/misc:$BUILD_DIR/base"
echo "=== openvas -u (register VTs) ==="
"$OPENVAS_BIN" -c "$WORK_DIR/openvas.conf" -u
echo ""
echo "=== registered NVTs (redis db 1) ==="
redis-cli -s "$SOCK" -n 1 KEYS 'nvt:*'
