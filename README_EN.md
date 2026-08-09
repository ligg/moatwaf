# Moat WAF

<div align="center">

<img src="static/logo-shield.svg" alt="Moat WAF" width="260">

**A lightweight, modern, self-hosted Web Application Firewall**

English | [中文](README.md)

</div>

---

## Overview

Moat WAF is a Web Application Firewall built on OpenResty (nginx + Lua), providing HTTP/HTTPS traffic inspection, threat detection, and request filtering for web applications.

### Key Features

- **Multi-layer detection engine** — PCRE regex + YAML rule definitions, covering SQL injection, XSS, path traversal, command injection, SSRF, and 9 attack categories
- **CC protection** — Per-IP QPS limiting, connection limits, JS Challenge mode
- **IP control** — Blacklist/whitelist with TTL auto-expiry, geo-blocking
- **Visual dashboard** — Neon Cyberpunk UI with Chart.js data visualization, real-time log streaming
- **Rule editor** — Web-based custom rule management with search, testing, and hit statistics
- **Nginx config management** — Online editing, syntax checking, hot reload
- **Multi-language** — 简体中文 / 繁体中文 / English with auto-detection
- **Zero external dependencies** — No database, no external services, single container, minimal resource usage

---

## Quick Start

### Docker One-liner

```bash
docker run -d --name moat-waf \
  -p 8080:80 \
  -e WAF_BACKEND=your-backend-ip:80 \
  -e WAF_ADMIN_TOKEN=your-secure-token-min-32-chars \
  angelababa/moat-waf:latest
```

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `WAF_BACKEND` | Backend server address | `127.0.0.1:80` |
| `WAF_ADMIN_TOKEN` | Admin panel access token (min 32 chars) | Required |
| `WAF_ADMIN_PATH` | Admin panel URL path | `/admin/` |
| `WAF_HEALTH_PATH` | Health check endpoint path | `/waf-health` |
| `WAF_MAX_UPLOAD_SIZE` | Maximum upload file size | `500m` |
| `WAF_UPLOAD_SCAN_LIMIT` | Full-content scan threshold; uploads larger than this only get extension + magic-number prefix checks | `20m` |
| `WAF_MODE` | Run mode: `block` (reject) or `log_only` (record only) | `block` |
| `WAF_LOG_DIR` | Log directory path | `/opt/moat/logs` |

### Access Admin Panel

1. Open `http://your-server:8080/admin/` in browser
2. Enter `WAF_ADMIN_TOKEN` to login
3. View real-time stats, manage rules, and inspect logs from the dashboard

> The panel can edit `nginx.conf` online (syntax check + hot reload) and switch the run mode
> (block / log_only). Panel edits live inside the container and are lost on recreate; mount
> `/opt/moat/conf/nginx.conf` to the host with `-v` in production.

### Host Allowlist (waf_allowed_hosts)

Every request's `Host` header is validated against an allowlist - hosts not listed get a 403
(prevents DNS rebinding / Host-header injection / other domains pointed at your server).
This check always applies, regardless of run mode.

- Configure it per server block: `set $waf_allowed_hosts "example.com,foo.com";`
- **Suffix matching** is supported: `example.com` allows `example.com` and every `*.example.com`
  subdomain. Explicit wildcards (`*.example.com`, subdomains only) and exact names
  (`www.example.com`) also work.
- Separate multiple domains with commas; matching is case-insensitive.

Example (reverse-proxying multiple domains):

```nginx
server {
    listen 443 ssl http2;
    server_name *.example.com;
    set $waf_allowed_hosts "example.com";   # allow all *.example.com

    location / {
        rewrite_by_lua_block { local waf = require("lib.waf"); waf.rewrite_phase() }
        access_by_lua_block  { local waf = require("lib.waf"); waf.access_phase() }
        proxy_pass http://127.0.0.1:8080;
    }
}
```

### Upload Inspection

- `WAF_MAX_UPLOAD_SIZE` is the hard upload limit (default `500m`); larger requests are rejected
  with 403 (**not bypassed by log_only**). Keep nginx `client_max_body_size` at least this large.
- To avoid loading large bodies into worker memory, multipart uploads larger than
  `WAF_UPLOAD_SCAN_LIMIT` (default `20m`) only get **extension + magic-number prefix** checks
  (dangerous extensions / executables), skipping the full-content (shell-code) scan. Uploads
  within `20m` still get the full validation.

### Security Response Headers

Moat WAF sits in front of arbitrary applications as a reverse proxy, so strict global headers
(CSP / HSTS / X-Frame-Options) are **not applied by default** - they can break applications
(inline scripts, CDN assets, iframes, subdomain-wide HSTS). Add them per server / location when
needed:

```nginx
add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
add_header Content-Security-Policy "default-src 'self'" always;
```

### Build from Source

```bash
git clone https://github.com/ligg/moatwaf.git
cd moat-waf
docker build -t angelababa/moat-waf:latest .
docker run -d --name moat-waf \
  -p 8080:80 \
  -e WAF_BACKEND=192.168.1.100:80 \
  -e WAF_ADMIN_TOKEN=your-secure-token-here \
  angelababa/moat-waf:latest
```

---

## Project Structure

```
├── conf/                    # nginx config and rule files
│   ├── nginx.conf           # Main config (env var placeholders)
│   ├── rules/               # WAF rule sets (YAML format)
│   │   ├── sql_injection.yaml
│   │   ├── xss.yaml
│   │   ├── path_traversal.yaml
│   │   └── custom.yaml      # Custom rules
│   ├── ip_blacklist.txt     # IP blacklist
│   ├── ip_whitelist.txt     # IP whitelist
│   └── geo_block.txt        # Geo-blocking
├── lib/                     # Core Lua modules
│   ├── waf.lua              # WAF processing pipeline
│   ├── rule_engine.lua      # Rule engine
│   ├── cc_protect.lua       # CC protection
│   ├── ip_control.lua       # IP control
│   ├── logger.lua           # Logging module
│   ├── upload_check.lua     # Upload inspection
│   └── admin/               # Admin panel modules
│       ├── html.lua         # Frontend templates
│       ├── dashboard.lua    # Dashboard API
│       ├── logs.lua         # Log viewing API
│       ├── rules.lua        # Rule management API
│       ├── nginx.lua        # Nginx config API
│       └── challenge.lua    # JS Challenge page
├── static/                  # Static assets (logo, Chart.js, fonts)
├── scripts/                 # Helper scripts
├── docs/                    # Documentation
├── Dockerfile
├── docker-entrypoint.sh
└── README.md
```

---

## License

This project is open source under the MIT License.
