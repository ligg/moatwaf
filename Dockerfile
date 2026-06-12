FROM openresty/openresty:1.25.3.2-0-alpine

LABEL maintainer="moat-waf"
LABEL description="Moat WAF - nginx-based Web Application Firewall"

# No additional dependencies needed - WAF uses only cjson and re (built into OpenResty)

# Create application directory structure
RUN mkdir -p /opt/moat/conf/rules \
             /opt/moat/lib \
             /opt/moat/logs \
             /opt/moat/scripts

# Copy nginx configuration
COPY conf/nginx.conf /opt/moat/conf/nginx.conf
COPY conf/mime.types /opt/moat/conf/mime.types

# Copy WAF rule files
COPY conf/rules/ /opt/moat/conf/rules/

# Copy IP control lists
COPY conf/ip_blacklist.txt /opt/moat/conf/ip_blacklist.txt
COPY conf/ip_whitelist.txt /opt/moat/conf/ip_whitelist.txt
COPY conf/geo_block.txt /opt/moat/conf/geo_block.txt

# Copy Lua libraries
COPY lib/ /opt/moat/lib/
COPY static/ /opt/moat/static/

# Copy scripts
COPY scripts/ /opt/moat/scripts/

# Fix lua_package_path to use absolute path
RUN sed -i 's|lua_package_path "lib/?.lua;;";|lua_package_path "/opt/moat/?.lua;;";|' \
    /opt/moat/conf/nginx.conf

# Initialize rules version file
RUN date +%s > /opt/moat/conf/rules/.version

# Make conf and logs writable by nginx worker (nobody)
RUN chmod -R 777 /opt/moat/conf /opt/moat/logs

# Copy and configure entrypoint
COPY docker-entrypoint.sh /docker-entrypoint.sh
RUN chmod +x /docker-entrypoint.sh

# Expose HTTP port
EXPOSE 80

# Health check
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD wget -qO- http://127.0.0.1${WAF_HEALTH_PATH} || exit 1

# Environment variables:
#   WAF_BACKEND       - upstream backend address (default: 127.0.0.1:80)
#   WAF_ADMIN_TOKEN   - admin API token (min 32 characters, validated at startup)
#   WAF_ADMIN_PATH    - admin API path prefix (default: /admin/)
#   WAF_HEALTH_PATH   - health check endpoint path (default: /waf-health)
ENV WAF_BACKEND=127.0.0.1:80
ENV WAF_ADMIN_PATH=/admin/
ENV WAF_HEALTH_PATH=/waf-health

ENTRYPOINT ["/docker-entrypoint.sh"]
