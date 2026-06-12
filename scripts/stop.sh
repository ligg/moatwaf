#!/bin/bash
# scripts/stop.sh
set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"

cd "$PROJECT_DIR"
nginx -c conf/nginx.conf -s stop
echo "Moat WAF stopped."
