#!/bin/sh
d=$(cd "$(dirname "$0")/.." 2>/dev/null && pwd); [ -f "$d/sentinel/runtime.py" ] || d=${FLEET_SENTINEL_PLUGIN_DIR:-${HERMES_HOME:-$HOME/.hermes}/plugins/fleet-sentinel}
exec "${FLEET_SENTINEL_PYTHON:-python3}" "$d/scripts/tick.py" "$@"
