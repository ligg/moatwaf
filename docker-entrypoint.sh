#!/bin/sh
set -e

# Substitute environment variables in nginx.conf
# WAF_BACKEND: upstream backend address (default: 127.0.0.1:8080)
# WAF_ADMIN_TOKEN: admin API token (validated by init_by_lua_block)

WAF_BACKEND="${WAF_BACKEND:-127.0.0.1:80}"
WAF_MAX_UPLOAD_SIZE="${WAF_MAX_UPLOAD_SIZE:-500m}"
WAF_UPLOAD_SCAN_LIMIT="${WAF_UPLOAD_SCAN_LIMIT:-20m}"
WAF_MODE="${WAF_MODE:-block}"
WAF_ADMIN_PATH="${WAF_ADMIN_PATH:-/admin/}"
WAF_HEALTH_PATH="${WAF_HEALTH_PATH:-/waf-health}"

# Substitute placeholders in nginx.conf when present.
# NOTE: each sed -i is guarded so it only runs when the placeholder actually
# exists. sed -i works by rename(2), which fails on bind-mounted config files
# ("Resource busy"), so skipping it for configs without placeholders keeps the
# container working when /opt/moat/conf/nginx.conf is bind-mounted from the host.
if grep -q 'server 127.0.0.1:80;' /opt/moat/conf/nginx.conf; then
    sed -i "s|server 127.0.0.1:80;|server ${WAF_BACKEND};|" /opt/moat/conf/nginx.conf
fi

if grep -q '\${WAF_MAX_UPLOAD_SIZE}' /opt/moat/conf/nginx.conf; then
    sed -i "s|\${WAF_MAX_UPLOAD_SIZE}|${WAF_MAX_UPLOAD_SIZE}|" /opt/moat/conf/nginx.conf
fi

if grep -q '\${WAF_ADMIN_PATH}' /opt/moat/conf/nginx.conf; then
    sed -i "s|\${WAF_ADMIN_PATH}|${WAF_ADMIN_PATH}|g" /opt/moat/conf/nginx.conf
fi

if grep -q '\${WAF_HEALTH_PATH}' /opt/moat/conf/nginx.conf; then
    sed -i "s|\${WAF_HEALTH_PATH}|${WAF_HEALTH_PATH}|g" /opt/moat/conf/nginx.conf
fi

# Update rules version to force cache reload on container start
date +%s > /opt/moat/conf/rules/.version

# Validate nginx configuration
/usr/local/openresty/bin/openresty -p /opt/moat/ -t

# Background watcher: reload nginx when trigger file appears
( while true; do
    if [ -f /tmp/.nginx-reload ]; then
        rm -f /tmp/.nginx-reload
        /usr/local/openresty/bin/openresty -p /opt/moat/ -s reload 2>&1 | head -c 2048 > /tmp/.nginx-reload-result
    fi
    sleep 1
done ) &

# Start openresty in foreground
exec /usr/local/openresty/bin/openresty -p /opt/moat/ -g "daemon off;"
