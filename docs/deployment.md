# Moat WAF 部署指南

本文档涵盖 Moat WAF 的完整部署流程，适用于云环境下的反向代理模式部署。

## 部署架构

```
客户端  --> Moat (nginx + Lua) --> 后端服务器
```

Moat 作为独立的 WAF 层提供 5 阶段请求处理管道：

1. **IP 管控** — 白名单/黑名单检查（rewrite 阶段）
2. **CC 防护** — 速率限制、连接限制、路径扫描检测（access 阶段）
3. **规则引擎** — SQLi/XSS/命令注入等规则匹配（access 阶段）
4. **上传检测** — 文件类型、大小、恶意内容检查（access 阶段）
5. **日志/监控** — 审计日志、统计数据记录（log 阶段）

## 1. 环境准备

### 1.1 系统要求

| 项目 | 最低要求 | 推荐配置 |
|------|---------|---------|
| 操作系统 | Ubuntu 20.04 / CentOS 7+ | Ubuntu 22.04 LTS |
| CPU | 2 核 | 4 核 |
| 内存 | 2 GB | 4 GB |
| 磁盘 | 20 GB | 50 GB（日志存储） |
| 网络 | 100 Mbps | 1 Gbps |

### 1.2 安装 OpenResty

Moat 基于 OpenResty 运行，需要 nginx 1.25+ 和 LuaJIT 2.1。

**Ubuntu/Debian：**

```bash
# 安装依赖
apt-get update
apt-get install -y wget gnupg ca-certificates lsb-release

# 添加 OpenResty APT 源
wget -O - https://openresty.org/package/pubkey.gpg | apt-key add -
echo "deb http://openresty.org/package/ubuntu $(lsb_release -sc) main" \
    | tee /etc/apt/sources.list.d/openresty.list
apt-get update

# 安装 OpenResty
apt-get install -y openresty
```

**CentOS/RHEL：**

```bash
yum install -y yum-utils
yum-config-manager --add-repo https://openresty.org/package/centos/openresty.repo
yum install -y openresty
```

**验证安装：**

```bash
# 检查 OpenResty 版本（需要 1.25+）
openresty -v

# 检查 LuaJIT 版本（需要 2.1+）
openresty -V 2>&1 | grep -i luajit
```

### 1.3 创建目录结构

```bash
# 假设安装到 /opt/moat
mkdir -p /opt/moat/{conf,lib,rules,logs,scripts}

# 复制项目文件
cp -r conf/* /opt/moat/conf/
cp -r lib/*  /opt/moat/lib/
cp -r rules/* /opt/moat/rules/
cp -r scripts/* /opt/moat/scripts/
```

最终目录结构：

```
/opt/moat/
├── conf/
│   ├── nginx.conf          # 主配置文件
│   ├── mime.types           # MIME 类型定义
│   ├── ip_blacklist.txt     # 静态 IP 黑名单
│   ├── ip_whitelist.txt     # 静态 IP 白名单
│   ├── geo_block.txt        # 地域封锁列表
│   └── rules/               # CC/上传相关规则
├── lib/
│   ├── init.lua             # 模块加载器
│   ├── waf.lua              # WAF 主入口（各阶段调度）
│   ├── ip_control.lua       # IP 管控模块
│   ├── cc_protect.lua       # CC 防护模块
│   ├── rule_engine.lua      # 规则引擎
│   ├── upload_check.lua     # 上传检测模块
│   ├── logger.lua           # 日志模块
│   ├── admin.lua            # Admin REST API
│   └── utils.lua            # 工具函数
├── rules/                   # 检测规则集（YAML 格式）
│   ├── sql_injection.yaml
│   ├── xss.yaml
│   ├── path_traversal.yaml
│   ├── cmd_injection.yaml
│   ├── sensitive_files.yaml
│   ├── scanner_detection.yaml
│   ├── ssrf.yaml
│   ├── proto.yaml
│   └── custom.yaml
├── logs/                    # 日志目录
└── scripts/
    ├── install.sh
    ├── start.sh
    └── stop.sh
```

## 2. nginx.conf 配置与调优

### 2.1 核心配置

nginx.conf 位于 `conf/nginx.conf`，以下是关键配置项说明：

```nginx
worker_processes auto;       # 自动检测 CPU 核数，建议等于 CPU 核数
error_log logs/error.log info;
pid logs/nginx.pid;

events {
    worker_connections 4096;  # 每个 worker 的最大连接数
    use epoll;                # Linux 高性能事件模型
    multi_accept on;          # 一次接受多个连接
}
```

**调优建议：**

| 场景 | worker_processes | worker_connections | 说明 |
|------|-----------------|-------------------|------|
| 低流量（<1000 QPS） | 2 | 2048 | 2 核 2G 机器 |
| 中流量（1000-5000 QPS） | 4 | 4096 | 4 核 4G 机器 |
| 高流量（>5000 QPS） | CPU 核数 | 8192 | 需同步调大共享字典 |

### 2.2 上游后端配置

```nginx
upstream backend {
    server 127.0.0.1:8080;   # 替换为实际地址
    keepalive 32;             # 长连接池大小
}
```

部署前必须将 `server` 指令替换为实际的后端地址。如果后端有多个节点：

```nginx
upstream backend {
    server 10.0.1.10:8080 weight=3;
    server 10.0.1.11:8080 weight=3;
    server 10.0.1.12:8080 backup;   # 备用节点
    keepalive 64;
}
```

### 2.3 日志格式

```nginx
log_format waf '$remote_addr - $remote_user [$time_local] '
               '"$request" $status $body_bytes_sent '
               '"$http_referer" "$http_user_agent" '
               'rt=$request_time '
               'waf_action=$waf_action waf_rule=$waf_rule';
```

日志字段说明：
- `rt` — 请求处理时间（秒）
- `waf_action` — WAF 决策（pass/block）
- `waf_rule` — 命中的规则 ID

### 2.4 lua_package_path

```nginx
lua_package_path "lib/?.lua;;";
```

确保所有 Lua 模块可以被正确加载。如果 Moat 安装在非标准路径，需要使用绝对路径：

```nginx
lua_package_path "/opt/moat/lib/?.lua;;";
```

### 2.5 模块预加载

```nginx
init_by_lua_block {
    require("lib.init")
}
```

在 nginx 启动时预加载 WAF 模块，避免首次请求时的加载延迟。

## 3. 共享字典内存分配

Moat 使用 7 个 `lua_shared_dict` 存储运行时状态：

```nginx
lua_shared_dict ip_blacklist  10m;   # 动态 IP 黑名单
lua_shared_dict ip_whitelist   5m;   # 动态 IP 白名单
lua_shared_dict rate_limit    50m;   # CC 防护速率限制计数器
lua_shared_dict block_rules   20m;   # 规则缓存
lua_shared_dict session_track 30m;   # 会话跟踪（连接计数、路径扫描）
lua_shared_dict upload_cache  10m;   # 上传检测缓存
lua_shared_dict waf_stats      5m;   # WAF 统计数据
```

### 3.1 字典用途详解

| 字典名 | 用途 | 存储内容 | TTL |
|--------|------|---------|-----|
| `ip_blacklist` | 动态 IP 黑名单 | IP -> "admin_added"/"cc_auto" | 动态（默认 300s） |
| `ip_whitelist` | 动态 IP 白名单 | IP -> "admin_added" | 永久（0） |
| `rate_limit` | CC 防护计数器 | QPS 计数、连接数 | 1-300s |
| `block_rules` | 规则缓存 | 编译后的规则对象 | 60s |
| `session_track` | 会话跟踪 | 连接计数、扫描计数、CC 配置覆盖 | 5-300s |
| `upload_cache` | 上传检测 | 临时缓存 | 短期 |
| `waf_stats` | 统计数据 | 请求计数、拦截计数 | 3600s |

### 3.2 内存调优

根据实际流量调整字典大小：

```nginx
# 高流量场景（>5000 QPS，大量 IP）
lua_shared_dict ip_blacklist  20m;
lua_shared_dict rate_limit   100m;
lua_shared_dict session_track 50m;

# 低流量场景（<500 QPS）
lua_shared_dict ip_blacklist   5m;
lua_shared_dict rate_limit    20m;
lua_shared_dict session_track 15m;
```

**注意：** `lua_shared_dict` 的内存是在 nginx 启动时分配的，所有 worker 进程共享同一块内存。修改后需要重启 nginx（`nginx -s reload` 不会重新分配共享内存）。

### 3.3 CC 防护默认参数

CC 防护模块的默认参数定义在 `lib/cc_protect.lua` 中：

| 参数 | 默认值 | 说明 |
|------|-------|------|
| `ip_qps_limit` | 100 | 单 IP 每秒请求数上限 |
| `ip_conn_limit` | 50 | 单 IP 并发连接数上限 |
| `global_qps_limit` | 5000 | 全局每秒请求数上限 |
| `window_size` | 60 | 固定窗口大小（秒） |

这些参数可通过 Admin API 动态调整，无需重启。

## 4. TLS/SSL 配置

### 4.1 Moat 终止 TLS

如需 Moat 直接处理 HTTPS：

```nginx
server {
    listen 80;
    server_name your-domain.com;
    return 301 https://$host$request_uri;
}

server {
    listen 443 ssl;
    server_name your-domain.com;

    ssl_certificate     /etc/ssl/certs/your-domain.crt;
    ssl_certificate_key /etc/ssl/private/your-domain.key;
    ssl_protocols       TLSv1.2 TLSv1.3;
    ssl_ciphers         HIGH:!aNULL:!MD5;
    ssl_prefer_server_ciphers on;
    ssl_session_cache   shared:SSL:10m;
    ssl_session_timeout 10m;

    # HSTS
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;

    # WAF 配置与 HTTP server 块相同
    location / {
        rewrite_by_lua_block { ... }
        access_by_lua_block { ... }
        proxy_pass http://backend;
        # ...
    }
}
```

### 4.2 证书管理

```bash
# Let's Encrypt 自动续期（如使用方案 B）
apt-get install -y certbot
certbot certonly --webroot -w /opt/moat -d your-domain.com

# 设置自动续期
echo "0 3 * * * certbot renew --quiet --post-hook 'openresty -s reload'" | crontab -
```

## 5. systemd 服务配置

### 5.1 创建服务文件

创建 `/etc/systemd/system/moat.service`：

```ini
[Unit]
Description=Moat WAF (OpenResty)
After=network.target
Wants=network-online.target

[Service]
Type=forking
PIDFile=/opt/moat/logs/nginx.pid
ExecStartPre=/usr/local/openresty/bin/openresty -t -c /opt/moat/conf/nginx.conf
ExecStart=/usr/local/openresty/bin/openresty -c /opt/moat/conf/nginx.conf
ExecStop=/bin/kill -s QUIT $MAINPID
ExecReload=/bin/kill -s HUP $MAINPID
Restart=always
RestartSec=5
LimitNOFILE=65535
LimitNPROC=65535

# 安全加固
PrivateTmp=true
ProtectSystem=full
ProtectHome=true
NoNewPrivileges=true

[Install]
WantedBy=multi-user.target
```

### 5.2 启用与管理

```bash
# 重载 systemd 配置
systemctl daemon-reload

# 启用开机自启
systemctl enable moat

# 启动服务
systemctl start moat

# 查看状态
systemctl status moat

# 重载配置（不停服）
systemctl reload moat

# 查看日志
journalctl -u moat -f
```

### 5.3 文件描述符限制

WAF 需要处理大量并发连接，建议调高系统限制：

```bash
# /etc/security/limits.conf
*    soft    nofile    65535
*    hard    nofile    65535
root soft    nofile    65535
root hard    nofile    65535
```

## 6. 健康检查端点

### 6.1 内置健康检查

Moat 提供内置健康检查端点供使用：

```nginx
location /waf-health {
    access_log off;
    default_type text/plain;
    return 200 "OK";
}
```

### 6.2 Admin API 状态检查

通过 Admin API 获取更详细的 WAF 状态：

```bash
# 健康状态
curl -H "Authorization: Bearer YOUR_TOKEN" http://127.0.0.1/admin/stats
```

返回示例：

```json
{
    "total_requests": 12345,
    "passed_total": 12000,
    "blocked_total": 345,
    "blocked_sqli": 120,
    "blocked_xss": 80,
    "blocked_cc": 100,
    "blocked_ip": 30,
    "blocked_other": 15
}
```

### 6.3 自定义健康检查脚本

更全面的健康检查脚本：

```bash
#!/bin/bash
# scripts/health_check.sh

HEALTH_URL="http://127.0.0.1/waf-health"
ADMIN_URL="http://127.0.0.1/admin/status"
ADMIN_TOKEN="${WAF_ADMIN_TOKEN}"

# 1. 检查基础健康端点
HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" "$HEALTH_URL")
if [ "$HTTP_CODE" != "200" ]; then
    echo "CRITICAL: Health endpoint returned $HTTP_CODE"
    exit 2
fi

# 2. 检查 Admin API
if [ -n "$ADMIN_TOKEN" ]; then
    ADMIN_CODE=$(curl -s -o /dev/null -w "%{http_code}" \
        -H "Authorization: Bearer $ADMIN_TOKEN" "$ADMIN_URL")
    if [ "$ADMIN_CODE" != "200" ]; then
        echo "WARNING: Admin API returned $ADMIN_CODE"
        exit 1
    fi
fi

# 3. 检查 nginx 进程
if ! pgrep -f "nginx: master" > /dev/null; then
    echo "CRITICAL: nginx master process not running"
    exit 2
fi

echo "OK: Moat WAF is healthy"
exit 0
```

## 7. 日志轮转

### 7.1 logrotate 配置

创建 `/etc/logrotate.d/moat`：

```
/opt/moat/logs/*.log {
    daily
    rotate 30
    compress
    delaycompress
    missingok
    notifempty
    create 0640 nginx nginx
    sharedscripts
    postrotate
        [ -f /opt/moat/logs/nginx.pid ] && kill -USR1 $(cat /opt/moat/logs/nginx.pid)
    endscript
}
```

### 7.2 日志标签与过滤

Moat 使用以下日志标签，便于 grep 过滤：

| 标签 | 用途 | 过滤命令 |
|------|------|---------|
| `WAF_AUDIT` | 被拦截请求的审计日志 | `grep WAF_AUDIT logs/error.log` |
| `WAF_ATTACK` | 高严重度攻击事件 | `grep WAF_ATTACK logs/error.log` |
| `WAF_OPERATIONAL` | WAF 内部运行状态 | `grep WAF_OPERATIONAL logs/error.log` |
| `WAF_SECURITY` | WAF 自身安全事件 | `grep WAF_SECURITY logs/error.log` |

### 7.3 日志格式示例

**WAF_AUDIT 日志（被拦截请求）：**

```json
{
    "timestamp": 1718000000.123,
    "source_ip": "203.0.113.50",
    "method": "GET",
    "uri": "/search",
    "rule_id": "SQLI_001",
    "severity": "critical",
    "action": "block",
    "reason": "SQL Injection - UNION SELECT",
    "user_agent": "Mozilla/5.0 ...",
    "host": "example.com"
}
```

### 7.4 日志发送到远程收集

建议将 WAF 日志发送到集中式日志系统：

```bash
# 使用 rsyslog 转发
# /etc/rsyslog.d/moat.conf
if $programname == 'nginx' and $msg contains 'WAF_' then {
    @log-server:514
    stop
}
```

或使用 Filebeat 采集：

```yaml
# filebeat.yml
filebeat.inputs:
  - type: log
    paths:
      - /opt/moat/logs/error.log
    include_lines: ['WAF_AUDIT', 'WAF_ATTACK', 'WAF_SECURITY']
    json.keys_under_root: true

output.elasticsearch:
  hosts: ["elastic-server:9200"]
```

## 8. 部署验证

### 8.1 启动前检查

```bash
# 验证配置语法
nginx -t -c /opt/moat/conf/nginx.conf

# 检查规则文件是否可读
ls -la /opt/moat/rules/*.yaml

# 检查 IP 列表文件
ls -la /opt/moat/conf/ip_*.txt /opt/moat/conf/geo_block.txt
```

### 8.2 启动与验证

```bash
# 启动
systemctl start moat

# 验证进程
ps aux | grep nginx

# 测试健康检查
curl http://127.0.0.1/waf-health
# 预期输出: OK

# 测试规则引擎（应被拦截）
curl "http://127.0.0.1/search?id=1' UNION SELECT * FROM users--"
# 预期输出: {"error":"Forbidden","message":"SQL Injection - UNION SELECT","code":403}

# 测试正常请求（应放行）
curl http://127.0.0.1/
# 预期输出: 后端响应
```

### 8.3 性能基线测试

```bash
# 安装压测工具
apt-get install -y wrk

# 基线测试（100 并发，30 秒）
wrk -t4 -c100 -d30s http://127.0.0.1/waf-health

# 记录结果作为基线
# 后续对比使用
```

## 9. Docker 部署

### 9.1 构建镜像

在项目根目录下执行构建：

```bash
docker build -t angelababa/moat-waf:latest .
```

构建完成后，镜像大小约为 106MB（基于 `openresty/openresty:1.25.3.2-0-alpine`）。

### 9.2 环境变量

| 变量 | 说明 | 默认值 | 必填 |
|------|------|--------|------|
| `WAF_BACKEND` | 后端服务器地址（host:port） | `127.0.0.1:80` | 否 |
| `WAF_ADMIN_TOKEN` | 管理面板访问 Token（最少 32 字符） | — | 是 |
| `WAF_LOG_DIR` | WAF 日志文件存储目录 | `/opt/moat/logs` | 否 |
| `WAF_MAX_UPLOAD_SIZE` | 最大上传文件大小（支持 k/m 后缀） | `10m` | 否 |

### 9.3 快速启动

```bash
docker run -d \
  --name moat-waf \
  -p 8080:80 \
  -e WAF_BACKEND="172.20.0.4:80" \
  -e WAF_ADMIN_TOKEN="your-secure-token-at-least-32-chars" \
  -e WAF_LOG_DIR="/opt/moat/logs" \
  -e WAF_MAX_UPLOAD_SIZE="10m" \
  --network money_default \
  angelababa/moat-waf:latest
```

### 9.4 挂载自定义 nginx.conf

如需自定义 nginx 配置，将本地 `nginx.conf` 挂载到容器中：

```bash
docker run -d \
  --name moat-waf \
  -p 8080:80 \
  -v /path/to/your/nginx.conf:/usr/local/openresty/nginx/conf/nginx.conf:ro \
  -e WAF_BACKEND="172.20.0.4:80" \
  -e WAF_ADMIN_TOKEN="your-secure-token-at-least-32-chars" \
  -e WAF_LOG_DIR="/opt/moat/logs" \
  -e WAF_MAX_UPLOAD_SIZE="10m" \
  --network money_default \
  angelababa/moat-waf:latest
```

> **注意**: 挂载自定义 `nginx.conf` 后，`docker-entrypoint.sh` 中的 `WAF_BACKEND` 环境变量替换仍然生效（通过 `envsubst` 实现）。请确保配置文件中使用 `${WAF_BACKEND}` 占位符。

### 9.5 挂载规则目录

如需动态更新 WAF 规则而不重新构建镜像：

```bash
docker run -d \
  --name moat-waf \
  -p 8080:80 \
  -v /path/to/nginx.conf:/usr/local/openresty/nginx/conf/nginx.conf:ro \
  -v /path/to/rules:/opt/moat/conf/rules:ro \
  -e WAF_BACKEND="172.20.0.4:80" \
  -e WAF_ADMIN_TOKEN="your-secure-token-at-least-32-chars" \
  -e WAF_LOG_DIR="/opt/moat/logs" \
  -e WAF_MAX_UPLOAD_SIZE="10m" \
  --network money_default \
  angelababa/moat-waf:latest
```

更新规则后重载 nginx：

```bash
docker exec moat-waf openresty -s reload
```

### 9.6 Docker Compose 示例

```yaml
version: "3.8"

services:
  moat-waf:
    image: angelababa/moat-waf:latest
    container_name: moat-waf
    ports:
      - "8080:80"
    environment:
      WAF_BACKEND: "money-api-1:80"
      WAF_ADMIN_TOKEN: "your-secure-token-at-least-32-chars"
      WAF_LOG_DIR: "/opt/moat/logs"
      WAF_MAX_UPLOAD_SIZE: "10m"
    volumes:
      - ./conf/nginx.conf:/usr/local/openresty/nginx/conf/nginx.conf:ro
      - ./conf/rules:/opt/moat/conf/rules:ro
    networks:
      - money_default
    healthcheck:
      test: ["CMD", "curl", "-sf", "http://127.0.0.1/waf-health"]
      interval: 30s
      timeout: 5s
      retries: 3
    restart: unless-stopped

networks:
  money_default:
    external: true
```

### 9.7 网络配置

Moat WAF 容器需要与后端服务容器处于同一 Docker 网络中。常见场景：

| 场景 | 配置方式 |
|------|----------|
| 后端使用 docker-compose 部署 | 使用 `external: true` 引入已有网络（如 `money_default`） |
| 后端使用独立容器部署 | 使用 `--network <backend-network>` 加入同一网络 |
| 后端在宿主机上运行 | 使用 `--add-host=host.docker.internal:host-gateway`，`WAF_BACKEND` 设为 `host.docker.internal:port` |

### 9.8 常用运维命令

```bash
# 查看容器状态
docker ps --filter name=moat-waf

# 查看实时日志（access log 输出到 stdout）
docker logs -f moat-waf

# 进入容器调试
docker exec -it moat-waf sh

# 验证 nginx 配置
docker exec moat-waf openresty -t

# 重载 nginx 配置（不中断服务）
docker exec moat-waf openresty -s reload

# 查看 WAF 健康状态
curl http://localhost:8080/waf-health

# 查看容器资源使用
docker stats moat-waf --no-stream
```

### 9.9 故障排查

**容器启动失败**

```bash
# 查看启动日志
docker logs moat-waf

# 常见原因：
# - WAF_ADMIN_TOKEN 少于 32 字符
# - WAF_BACKEND 指向的后端不可达（不影响启动，但请求会 502）
# - nginx.conf 语法错误
```

**请求返回 502 Bad Gateway**

```bash
# 检查后端是否可达
docker exec moat-waf sh -c 'curl -s http://$WAF_BACKEND/ -o /dev/null -w "%{http_code}"'

# 检查容器网络
docker network inspect money_default
```

**健康检查显示 unhealthy**

```bash
# 手动测试健康检查端点
docker exec moat-waf curl -sf http://127.0.0.1/waf-health

# 检查 nginx 进程
docker exec moat-waf ps aux | grep nginx
```
