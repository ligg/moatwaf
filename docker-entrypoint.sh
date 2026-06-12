#!/bin/sh
set -e

# Substitute environment variables in nginx.conf
# WAF_BACKEND: upstream backend address (default: 127.0.0.1:8080)
# WAF_ADMIN_TOKEN: admin API token (validated by init_by_lua_block)

WAF_BACKEND="${WAF_BACKEND:-127.0.0.1:80}"
WAF_MAX_UPLOAD_SIZE="${WAF_MAX_UPLOAD_SIZE:-10m}"
WAF_ADMIN_PATH="${WAF_ADMIN_PATH:-/admin/}"
WAF_HEALTH_PATH="${WAF_HEALTH_PATH:-/waf-health}"

# Replace backend server address in nginx.conf
sed -i "s|server 127.0.0.1:80;|server ${WAF_BACKEND};|" /opt/moat/conf/nginx.conf

# Replace max upload size in nginx.conf
sed -i "s|\${WAF_MAX_UPLOAD_SIZE}|${WAF_MAX_UPLOAD_SIZE}|" /opt/moat/conf/nginx.conf

# Replace admin path and health path in nginx.conf
sed -i "s|\${WAF_ADMIN_PATH}|${WAF_ADMIN_PATH}|g" /opt/moat/conf/nginx.conf
sed -i "s|\${WAF_HEALTH_PATH}|${WAF_HEALTH_PATH}|g" /opt/moat/conf/nginx.conf

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
