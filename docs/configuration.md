# Moat WAF 配置参考

本文档是 Moat WAF 所有配置项的完整参考手册。

## 1. nginx.conf 配置项参考

### 1.1 全局配置

```nginx
worker_processes auto;
error_log logs/error.log info;
pid logs/nginx.pid;
```

| 指令 | 默认值 | 说明 |
|------|-------|------|
| `worker_processes` | `auto` | nginx worker 进程数。`auto` 自动检测 CPU 核数 |
| `error_log` | `logs/error.log info` | 错误日志路径及级别。WAF 审计日志也写入此文件 |
| `pid` | `logs/nginx.pid` | PID 文件路径 |

### 1.2 events 配置

```nginx
events {
    worker_connections 4096;
    use epoll;
    multi_accept on;
}
```

| 指令 | 默认值 | 说明 |
|------|-------|------|
| `worker_connections` | `4096` | 每个 worker 进程的最大并发连接数 |
| `use` | `epoll` | I/O 复用模型。Linux 推荐 `epoll`，macOS 用 `kqueue` |
| `multi_accept` | `on` | 一次 accept 多个连接，提高吞吐 |

### 1.3 HTTP 配置

```nginx
http {
    include       mime.types;
    default_type  application/octet-stream;
    sendfile      on;
    keepalive_timeout 65;
    lua_package_path "lib/?.lua;;";
}
```

| 指令 | 默认值 | 说明 |
|------|-------|------|
| `lua_package_path` | `"lib/?.lua;;"` | Lua 模块搜索路径。部署时改为绝对路径如 `"/opt/moat/lib/?.lua;;"` |
| `keepalive_timeout` | `65` | 长连接超时（秒） |
| `sendfile` | `on` | 零拷贝文件传输 |

### 1.4 共享字典配置

所有 `lua_shared_dict` 在 `http` 块中定义，nginx 启动时分配内存，所有 worker 进程共享。

```nginx
lua_shared_dict ip_blacklist  10m;
lua_shared_dict ip_whitelist   5m;
lua_shared_dict rate_limit    50m;
lua_shared_dict block_rules   20m;
lua_shared_dict session_track 30m;
lua_shared_dict upload_cache  10m;
lua_shared_dict waf_stats      5m;
```

| 字典名 | 默认大小 | 用途 | 存储格式 | TTL |
|--------|---------|------|---------|-----|
| `ip_blacklist` | 10m | 动态 IP 黑名单 | `IP -> "admin_added"/"cc_auto"` | 默认 300s（CC 自动拉黑）；管理员手动添加的用指定 TTL |
| `ip_whitelist` | 5m | 动态 IP 白名单 | `IP -> "admin_added"` | 0（永久，手动删除） |
| `rate_limit` | 50m | CC 防护速率计数 | `"rl:" + IP + ":" + window -> count` | window_size（默认 60s） |
| `block_rules` | 20m | 编译后的规则缓存 | `rule_id -> compiled_rule` | 60s |
| `session_track` | 30m | 会话跟踪 + CC 配置覆盖 | 连接计数、扫描计数、`cc_config:*` | 5-300s |
| `upload_cache` | 10m | 上传检测临时缓存 | 临时数据 | 短期 |
| `waf_stats` | 5m | WAF 统计数据 | 各类计数器 | 3600s |

**内存调优公式：** 每个 IP 黑名单条目约占 100 字节。10m 可存储约 10 万个 IP。根据实际独立 IP 数量调整。

### 1.5 上游后端

```nginx
upstream backend {
    server 127.0.0.1:8080;
    keepalive 32;
}
```

| 指令 | 说明 |
|------|------|
| `server` | 后端服务器地址。支持 `weight`、`backup`、`max_fails`、`fail_timeout` 参数 |
| `keepalive` | 到后端的长连接池大小 |

### 1.6 日志格式

```nginx
log_format waf '$remote_addr - $remote_user [$time_local] '
               '"$request" $status $body_bytes_sent '
               '"$http_referer" "$http_user_agent" '
               'rt=$request_time '
               'waf_action=$waf_action waf_rule=$waf_rule';
```

| 变量 | 说明 |
|------|------|
| `$waf_action` | WAF 决策：`pass` 或 `block` |
| `$waf_rule` | 命中的规则 ID（如 `SQLI_001`） |
| `$request_time` | 请求处理总时间（秒） |

### 1.7 server 配置

```nginx
server {
    listen 80;
    server_name _;

    # 健康检查端点
    location /waf-health {
        access_log off;
        default_type text/plain;
        return 200 "OK";
    }

    # Admin API
    location /admin {
        allow 127.0.0.1;
        deny all;
        set $waf_admin_token "YOUR_ADMIN_TOKEN";
        content_by_lua_block {
            require("lib.admin").handle()
        }
    }

    # 默认处理
    location / {
        rewrite_by_lua_block  { require("lib.waf").rewrite_phase() }
        access_by_lua_block   { require("lib.waf").access_phase() }
        body_filter_by_lua_block { require("lib.waf").body_filter_phase() }
        log_by_lua_block      { require("lib.waf").log_phase() }

        proxy_pass http://backend;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

| 位置 | 说明 |
|------|------|
| `/waf-health` | 健康检查端点，返回 200 "OK" |
| `/admin/*` | Admin API，受 IP 限制和 Bearer Token 保护 |
| `/` | WAF 处理入口，4 个 Lua 阶段依次执行 |

**注意：** `content_by_lua_block` 中调用的是 `require("lib.admin").handle()`。如果 nginx.conf 中写的是 `admin.handle_request()` 会导致 500 错误。

### 1.8 模块预加载

```nginx
init_by_lua_block {
    require("lib.init")
}
```

在 nginx master 进程启动时执行，预加载 WAF 模块。不在此处处理请求相关逻辑。

## 2. 环境变量

Moat 支持通过 nginx `set` 指令配置环境变量：

| 变量 | 设置位置 | 说明 | 示例 |
|------|---------|------|------|
| `$waf_admin_token` | `location /admin` 中的 `set` | Admin API 的 Bearer Token | `set $waf_admin_token "strong-random-token";` |

**安全建议：** 生成强随机 Token：

```bash
openssl rand -base32 32
```

## 3. 规则配置格式

### 3.1 规则文件

规则文件位于 `rules/` 目录，YAML 格式。每个文件包含同一类别的多条规则，以 `---` 分隔：

| 文件名 | 规则类别 | 规则 ID 前缀 |
|--------|---------|-------------|
| `sql_injection.yaml` | SQL 注入 | `SQLI_` |
| `xss.yaml` | 跨站脚本 | `XSS_` |
| `path_traversal.yaml` | 路径穿越 | `PATH_` |
| `cmd_injection.yaml` | 命令注入 | `CMDI_` |
| `sensitive_files.yaml` | 敏感文件访问 | `FILE_` |
| `scanner_detection.yaml` | 扫描器检测 | `SCAN_` |
| `ssrf.yaml` | 服务端请求伪造 | `SSRF_` |
| `proto.yaml` | 协议攻击 | `PROTO_` |
| `custom.yaml` | 自定义规则 | 自定义 |

### 3.2 规则格式

```yaml
id: "SQLI_001"
description: "SQL Injection - UNION SELECT"
target: "ARGS"
pattern: "(?i)(?:union\\s+(?:all\\s+)?select)"
action: "block"
severity: "critical"
---
id: "SQLI_002"
description: "SQL Injection - OR/AND condition"
target: "URI"
pattern: "(?i)(?:or|and)\\s+\\d+\\s*=\\s*\\d+"
action: "block"
severity: "high"
```

| 字段 | 类型 | 必填 | 说明 |
|------|------|------|------|
| `id` | string | 是 | 规则唯一标识，建议使用 `类别_编号` 格式 |
| `description` | string | 是 | 规则描述，用于日志 |
| `target` | string | 是 | 匹配目标：`URI`、`ARGS`、`BODY`、`HEADERS`、`COOKIE` |
| `pattern` | string | 是 | PCRE 正则表达式（支持 `(?i)` 等标志），或 Lua 模式 |
| `action` | string | 是 | 匹配后动作：`block`（拦截）或 `log`（仅记录） |
| `severity` | string | 是 | 严重级别：`critical`、`high`、`medium`、`low` |

### 3.3 规则匹配目标

| 目标 | 说明 | 获取方式 |
|------|------|---------|
| `URI` | 请求路径 | `ngx.var.uri` |
| `ARGS` | 查询参数 | `ngx.var.args` |
| `BODY` | 请求体 | `ngx.req.get_body_data()` |
| `HEADERS` | 请求头 | `ngx.req.get_headers()` |
| `COOKIE` | Cookie | `ngx.var.http_cookie` |

### 3.4 模式语法

规则引擎优先使用 PCRE（通过 `lua-resty-core` 的 `re` 模块），不支持时回退到 Lua 模式。

**PCRE 常用语法：**

```
(?i)                 # 不区分大小写
\\b                  # 单词边界
(?:...)              # 非捕获组
\\s+                 # 一个或多个空白
\\d+                 # 一个或多个数字
[a-z]                # 字符类
x|y                  # 或
```

**Lua 模式语法（回退）：**

```
%a   字母       %d   数字       %s   空白
%w   字母数字   %p   标点       .    任意字符
+    一次或多次  *    零次或多次  -    非贪婪匹配
```

### 3.5 规则加载优先级

规则按以下文件顺序加载，每条规则按文件内顺序评估：

1. `sql_injection.yaml`
2. `xss.yaml`
3. `path_traversal.yaml`
4. `cmd_injection.yaml`
5. `sensitive_files.yaml`
6. `scanner_detection.yaml`
7. `ssrf.yaml`
8. `proto.yaml`
9. `custom.yaml`

**命中第一条匹配规则后立即返回，不再继续评估。** 将更精确、高优先级的规则放在文件顶部。

### 3.6 多层输入规范化

在匹配规则前，引擎对输入进行多层规范化处理以检测绕过尝试：

1. URL 解码（`%xx` -> 字符）
2. HTML 实体解码（`&lt;` -> `<`，`&#xxx;` -> 字符）
3. 再次 URL 解码（检测双重编码绕过）

每层解码后的结果都会与规则进行匹配。

### 3.7 自定义规则示例

```yaml
# rules/custom.yaml

# 拦截包含特定关键词的请求
id: "CUSTOM_001"
description: "Block requests with internal IP in SSRF attempt"
target: "ARGS"
pattern: "(?i)(?:127\\.0\\.0\\.1|192\\.168\\.\\d+\\.\\d+|10\\.\\d+\\.\\d+\\.\\d+)"
action: "block"
severity: "high"
---
# 仅记录可疑的 User-Agent
id: "CUSTOM_002"
description: "Log suspicious user agent - curl"
target: "HEADERS"
pattern: "(?i)curl/"
action: "log"
severity: "low"
```

## 4. CC 防护参数

### 4.1 默认参数

定义在 `lib/cc_protect.lua` 的 `DEFAULTS` 表中：

| 参数 | 默认值 | 说明 |
|------|-------|------|
| `ip_qps_limit` | 100 | 单 IP 每秒请求数上限。超过此值触发拦截 |
| `ip_conn_limit` | 50 | 单 IP 并发连接数上限 |
| `global_qps_limit` | 5000 | 全局每秒请求数上限。所有 IP 共享 |
| `window_size` | 60 | 固定窗口大小（秒）。计数器每 window_size 秒重置 |

### 4.2 动态调整

通过 Admin API 动态调整，无需重启：

```bash
# 查看当前配置
curl -H "Authorization: Bearer TOKEN" http://127.0.0.1/admin/cc/config

# 调整参数
curl -X POST \
    -H "Authorization: Bearer TOKEN" \
    -H "Content-Type: application/json" \
    -d '{"ip_qps_limit": 200, "global_qps_limit": 10000}' \
    http://127.0.0.1/admin/cc/config
```

配置覆盖存储在 `session_track` 共享字典中，key 前缀为 `cc_config:`。nginx 重启后丢失覆盖值，恢复为代码中的默认值。

### 4.3 CC 防护行为

当 IP 超过 `ip_qps_limit` 时：
1. 请求被拦截，返回 HTTP 429
2. 响应头包含 `Retry-After: 300`
3. 该 IP 被自动加入动态黑名单，持续 300 秒
4. 日志记录 `WAF_AUDIT` 标签，rule_id 为 `CC-001`

### 4.4 路径扫描检测

CC 防护模块同时检测路径扫描行为：
- 阈值：60 秒内同一 IP 产生 20 个 404 响应
- 触发后该 IP 被自动拉黑
- 存储在 `session_track` 字典中

### 4.5 白名单 IP 跳过 CC 防护

在白名单中的 IP 会跳过 CC 防护的连接计数和速率限制检查，但仍受规则引擎约束。

## 5. IP 管控配置

### 5.1 静态 IP 列表文件

| 文件 | 格式 | 说明 |
|------|------|------|
| `conf/ip_blacklist.txt` | 每行一个 IP 或 CIDR | 静态 IP 黑名单 |
| `conf/ip_whitelist.txt` | 每行一个 IP 或 CIDR | 静态 IP 白名单 |
| `conf/geo_block.txt` | 每行一个 IP 段或 CIDR | 地域封锁列表 |

示例：

```
# conf/ip_blacklist.txt
# 已知恶意 IP
203.0.113.50
198.51.100.0/24
```

```
# conf/ip_whitelist.txt
# 内部管理 IP
10.0.0.0/8
172.16.0.0/12
```

### 5.2 IP 检查顺序

1. **白名单检查** — 静态白名单 + 动态白名单。命中则直接放行，跳过所有后续检查
2. **静态黑名单** — 来自 `conf/ip_blacklist.txt` 和 `conf/geo_block.txt`
3. **动态黑名单** — 来自 `ip_blacklist` 共享字典（管理员手动添加或 CC 防护自动拉黑）

### 5.3 动态 IP 管理

通过 Admin API 管理：

```bash
# 查看动态黑名单
curl -H "Authorization: Bearer TOKEN" http://127.0.0.1/admin/ip/blacklist

# 添加 IP 到黑名单（TTL 300 秒）
curl -X POST \
    -H "Authorization: Bearer TOKEN" \
    -H "Content-Type: application/json" \
    -d '{"ip": "203.0.113.50", "ttl": 300}' \
    http://127.0.0.1/admin/ip/blacklist

# 从黑名单移除 IP
curl -X DELETE \
    -H "Authorization: Bearer TOKEN" \
    http://127.0.0.1/admin/ip/blacklist/203.0.113.50

# 添加 IP 到白名单（永久，需手动删除）
curl -X POST \
    -H "Authorization: Bearer TOKEN" \
    -H "Content-Type: application/json" \
    -d '{"ip": "10.0.1.100"}' \
    http://127.0.0.1/admin/ip/whitelist
```

### 5.4 客户端 IP 解析

Moat 通过 `lib/utils.lua` 中的 `get_client_ip()` 函数解析真实客户端 IP：

1. 检查 `X-Forwarded-For` 头（仅信任来自内部网络 IP 的请求）
2. 回退到 `$remote_addr`

内部网络 IP 范围：`10.0.0.0/8`、`172.16.0.0/12`、`192.168.0.0/16`、`127.0.0.0/8`

## 6. 上传检测配置

### 6.1 参数

| 参数 | 默认值 | 说明 |
|------|-------|------|
| 最大文件大小 | 10 MB | 超过此大小的上传被拒绝 |
| Shell 代码检测范围 | 前 8 KB | 检查文件前 8KB 内容 |

### 6.2 危险扩展名黑名单

以下扩展名的文件上传会被直接拦截：

**PHP 系列：** php, php3, php4, php5, php7, phtml, pht
**ASP 系列：** asp, aspx, asa, asax, ascx, ashx, asmx
**Java 系列：** jsp, jspx, jsw, jsv, jspf, war, ear, jar
**脚本/Shell：** cgi, pl, py, rb, sh, bash, csh
**Windows 可执行文件：** exe, bat, cmd, com, msi, scr
**配置文件：** htaccess, htpasswd, config, ini, env

### 6.3 允许扩展名白名单

仅以下扩展名的文件允许上传：

jpg, jpeg, png, gif, webp, pdf, doc, docx, xls, xlsx, ppt, pptx, txt, csv, zip, rar, 7z

### 6.4 Magic Number 检测

通过文件头部字节识别真实文件类型：

| 十六进制前缀 | 文件类型 |
|-------------|---------|
| `FFD8FF` | JPEG |
| `89504E47` | PNG |
| `47494638` | GIF |
| `52494646` | WebP |
| `25504446` | PDF |
| `D0CF11E0` | MS Office 文档 |
| `504B0304` | ZIP |
| `1F8B08` | GZIP |
| `4D5A` | Windows 可执行文件（阻断） |
| `7F454C46` | ELF 可执行文件（阻断） |

### 6.5 检查流程

上传检测按以下顺序执行，任一步骤失败即拦截：

1. 危险扩展名检查（黑名单）
2. 文件大小检查（10 MB 限制）
3. Magic number 检测（识别可执行文件）
4. Content-Type 一致性检查（声明类型 vs 实际类型）
5. Shell 代码检测（前 8KB 内容）
6. 扩展名白名单检查

### 6.6 拦截规则 ID

| 规则 ID | 含义 |
|---------|------|
| `UPLOAD-001` | 危险扩展名或不在白名单中的扩展名 |
| `UPLOAD-002` | 文件大小超过限制 |
| `UPLOAD-003` | Content-Type 与实际文件类型不匹配 |
| `UPLOAD-004` | 文件内容包含 Shell 代码 |

## 7. Admin API 参考

### 7.1 认证

所有 Admin API 请求需要在 `Authorization` 头中携带 Bearer Token：

```
Authorization: Bearer YOUR_ADMIN_TOKEN
```

Token 在 nginx.conf 的 `location /admin` 块中通过 `set $waf_admin_token` 配置。

### 7.2 IP 访问限制

默认仅允许 `127.0.0.1` 访问。如需远程访问，在 nginx.conf 中添加：

```nginx
location /admin {
    allow 10.0.0.0/8;       # 内网
    allow 127.0.0.1;        # 本地
    deny all;
    # ...
}
```

### 7.3 API 端点

#### GET /admin/status

获取 WAF 基本状态。

**响应：**

```json
{
    "status": "ok",
    "version": "1.0.0",
    "uptime": 1718000000.123,
    "modules": {
        "rule_engine": true,
        "cc_protect": true,
        "logger": true
    }
}
```

#### GET /admin/stats

获取 WAF 统计数据。

**响应：**

```json
{
    "total_requests": 12345,
    "passed_total": 12000,
    "blocked_total": 345,
    "blocked_sqli": 120,
    "blocked_xss": 80,
    "blocked_cmdi": 50,
    "blocked_cc": 100,
    "blocked_other": 15,
    "blocked_ip": 30,
    "last_request_time": 1718000000
}
```

#### POST /admin/rules/reload

热重载规则文件，无需重启。

**响应：**

```json
{"status": "ok", "message": "Rules reloaded"}
```

#### GET /admin/ip/blacklist

获取动态 IP 黑名单。

**响应：**

```json
{
    "entries": {
        "203.0.113.50": "cc_auto",
        "198.51.100.1": "admin_added"
    }
}
```

#### POST /admin/ip/blacklist

添加 IP 到动态黑名单。

**请求体：**

```json
{"ip": "203.0.113.50", "ttl": 300}
```

| 字段 | 类型 | 必填 | 说明 |
|------|------|------|------|
| `ip` | string | 是 | IPv4 地址 |
| `ttl` | number | 否 | 过期时间（秒），默认 300 |

#### DELETE /admin/ip/blacklist/{ip}

从动态黑名单移除 IP。

#### GET /admin/ip/whitelist

获取动态 IP 白名单。

#### POST /admin/ip/whitelist

添加 IP 到动态白名单（永久，需手动删除）。

**请求体：**

```json
{"ip": "10.0.1.100"}
```

#### DELETE /admin/ip/whitelist/{ip}

从动态白名单移除 IP。

#### GET /admin/cc/config

获取当前 CC 防护配置（包含动态覆盖）。

**响应：**

```json
{
    "ip_qps_limit": 100,
    "ip_conn_limit": 50,
    "global_qps_limit": 5000,
    "window_size": 60
}
```

#### POST /admin/cc/config

动态调整 CC 防护参数。

**请求体：**

```json
{"ip_qps_limit": 200, "global_qps_limit": 10000}
```

可调整的 key 与 `cc_protect.DEFAULTS` 中的 key 一致，值必须为正数。未指定的 key 保持原值。

### 7.4 Admin API 错误码

| HTTP 状态码 | 说明 |
|------------|------|
| 200 | 成功 |
| 400 | 请求参数错误（无效 IP、无效 JSON、未知配置 key） |
| 401 | 认证失败（缺少 Authorization 头、格式错误、Token 无效） |
| 403 | Admin API 未配置（`$waf_admin_token` 为空） |
| 404 | 未知路由 |
| 500 | 服务端错误（共享字典不可用等） |

## 8. 日志配置

### 8.1 日志标签

所有 WAF 日志写入 nginx error log，通过前缀标签区分：

| 标签 | 函数 | 用途 |
|------|------|------|
| `WAF_AUDIT` | `logger.audit()` | 被拦截请求的审计日志 |
| `WAF_ATTACK` | `logger.attack()` | 高严重度攻击事件 |
| `WAF_OPERATIONAL` | `logger.operational()` | WAF 内部运行状态 |
| `WAF_SECURITY` | `logger.security()` | WAF 自身安全事件 |

### 8.2 日志级别

WAF_OPERATIONAL 支持日志级别过滤：

| 级别 | 值 | 说明 |
|------|---|------|
| DEBUG | 1 | 调试信息 |
| INFO | 2 | 一般信息（默认） |
| WARN | 3 | 警告 |
| ERROR | 4 | 错误 |
| CRITICAL | 5 | 严重错误 |

### 8.3 审计日志字段

WAF_AUDIT 日志包含以下字段：

| 字段 | 说明 |
|------|------|
| `timestamp` | 请求时间戳（`ngx.now()`） |
| `source_ip` | 客户端 IP |
| `method` | HTTP 方法 |
| `uri` | 请求路径 |
| `rule_id` | 命中规则 ID |
| `severity` | 严重级别 |
| `action` | WAF 动作（block/pass） |
| `reason` | 拦截原因描述 |
| `user_agent` | User-Agent |
| `host` | 请求 Host |

### 8.4 统计数据键

`waf_stats` 共享字典中的键：

| 键 | 说明 |
|----|------|
| `total_requests` | 总请求数 |
| `passed_total` | 放行请求数 |
| `blocked_total` | 拦截总数 |
| `blocked_sqli` | SQL 注入拦截数 |
| `blocked_xss` | XSS 拦截数 |
| `blocked_cmdi` | 命令注入拦截数 |
| `blocked_cc` | CC 防护拦截数 |
| `blocked_other` | 其他规则拦截数 |
| `blocked_ip` | IP 黑名单拦截数 |
| `last_request_time` | 最后请求时间戳 |

## 9. 请求处理管道

### 9.1 阶段总览

```
请求进入
    |
    v
[rewrite 阶段] waf.rewrite_phase()
    |-- 解析客户端 IP
    |-- 检查 IP 白名单 -> 命中则放行
    |-- 检查静态 IP 黑名单 -> 命中则拦截 (403)
    |-- 检查动态 IP 黑名单 -> 命中则拦截 (403)
    |-- 开始 CC 连接计数（白名单 IP 跳过）
    |
    v
[access 阶段] waf.access_phase()
    |-- CC 防护检查
    |   |-- 速率限制 -> 超限则拦截 (429) + 自动拉黑 300s
    |   |-- 连接限制 -> 超限则拦截 (429)
    |   |-- 全局限制 -> 超限则拦截 (429)
    |   +-- 路径扫描检测 -> 超限则拦截
    |
    |-- 规则引擎检查
    |   |-- 加载规则（缓存 60s）
    |   |-- 规范化输入（URL解码 -> HTML解码 -> URL解码）
    |   |-- 按优先级匹配规则
    |   +-- 命中则拦截 (403)
    |
    |-- 上传检测（仅 multipart/form-data 请求）
    |   |-- 扩展名检查
    |   |-- 文件大小检查
    |   |-- Magic number 检测
    |   |-- Content-Type 一致性
    |   +-- Shell 代码检测
    |
    +-- 记录放行统计
    |
    v
[body_filter 阶段] waf.body_filter_phase()
    |-- 当前为空操作（上传检测已移至 access 阶段）
    |
    v
[log 阶段] waf.log_phase()
    |-- 结束 CC 连接计数
    +-- 被拦截请求写入 WAF_AUDIT 日志
    |
    v
响应返回客户端
```

### 9.2 拦截响应格式

**IP 黑名单拦截（403）：**

```json
{"error": "Forbidden", "message": "Your IP has been blocked", "code": 403}
```

**CC 防护拦截（429）：**

```json
{"error": "Too Many Requests", "message": "Rate limit exceeded", "code": 429}
```

响应头包含 `Retry-After: 300`。

**规则引擎拦截（403）：**

```json
{"error": "Forbidden", "message": "SQL Injection - UNION SELECT", "code": 403}
```

注意：响应中不暴露 rule_id，防止攻击者针对性绕过。

**上传拦截（403）：**

```json
{"error": "Forbidden", "message": "File size exceeds upload limit", "code": 403}
```

## 10. IP 黑名单/白名单管理

### 10.1 静态列表管理

编辑配置文件后重新加载：

```bash
# 编辑黑名单
vim /opt/moat/conf/ip_blacklist.txt

# 重新加载配置（不停服）
systemctl reload moat
```

IP 列表缓存 60 秒后自动刷新（`IP_LISTS_TTL = 60`）。

### 10.2 动态列表管理

通过 Admin API 管理，立即生效：

```bash
TOKEN="your-admin-token"

# 拉黑恶意 IP（300 秒后自动解除）
curl -X POST -H "Authorization: Bearer $TOKEN" \
    -H "Content-Type: application/json" \
    -d '{"ip": "1.2.3.4", "ttl": 300}' \
    http://127.0.0.1/admin/ip/blacklist

# 紧急白名单（防止误拦截）
curl -X POST -H "Authorization: Bearer $TOKEN" \
    -H "Content-Type: application/json" \
    -d '{"ip": "10.0.1.100"}' \
    http://127.0.0.1/admin/ip/whitelist

# 查看当前状态
curl -H "Authorization: Bearer $TOKEN" http://127.0.0.1/admin/ip/blacklist
curl -H "Authorization: Bearer $TOKEN" http://127.0.0.1/admin/ip/whitelist
```

### 10.3 CIDR 支持

静态 IP 列表文件支持 CIDR 格式：

```
10.0.0.0/8
172.16.0.0/12
192.168.1.0/24
```

动态列表（Admin API）仅支持单个 IPv4 地址。
