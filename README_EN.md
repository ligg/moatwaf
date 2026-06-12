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
| `WAF_MAX_UPLOAD_SIZE` | Maximum upload file size | `10m` |
| `WAF_LOG_DIR` | Log directory path | `/opt/moat/logs` |

### Access Admin Panel

1. Open `http://your-server:8080/admin/` in browser
2. Enter `WAF_ADMIN_TOKEN` to login
3. View real-time stats, manage rules, and inspect logs from the dashboard

### Build from Source

```bash
git clone <repository-url>
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
