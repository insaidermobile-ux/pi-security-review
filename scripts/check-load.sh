#!/usr/bin/env bash
# Loads the package into pi in RPC mode with discovery disabled and prints the registered commands.
# Fails if pi reports extension errors or /security-review is missing.
set -euo pipefail
cd "$(dirname "$0")/.."
out=$( (printf '%s\n' '{"id":"c1","type":"get_commands"}'; sleep 5) | pi --mode rpc -ne -ns -np -e ./ --no-session --offline 2>&1 )
echo "$out"
if echo "$out" | grep -qi "extension error\|failed to load"; then
	echo "extension errors reported" >&2
	exit 1
fi
echo "$out" | grep -q '"name":"security-review"' || { echo "/security-review not registered" >&2; exit 1; }
