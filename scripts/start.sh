#!/bin/bash
# scripts/start.sh
set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"

cd "$PROJECT_DIR"

# Validate config
nginx -t -c conf/nginx.conf

# Start
nginx -c conf/nginx.conf
echo "Moat WAF started."
echo "Admin UI: http://127.0.0.1/admin/"
echo "Health:   http://127.0.0.1/waf-health"
