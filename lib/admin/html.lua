-- lib/admin/html.lua
-- HTML/CSS/JS template constants for admin panel
local _M = {}

-- Configurable admin path prefix (from env var, default /admin/)
local ADMIN_PATH = os.getenv("WAF_ADMIN_PATH") or "/admin/"
if ADMIN_PATH:sub(-1) ~= "/" then ADMIN_PATH = ADMIN_PATH .. "/" end

local LOGIN_HTML = [=[
<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Moat WAF - 管理面板</title>
<link href="/__waf_static__/fonts.css" rel="stylesheet">
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:'Rajdhani',sans-serif;background:#0d0221;color:#e0d7ff;min-height:100vh;display:flex;align-items:center;justify-content:center;overflow:hidden}
body::before{content:'';position:fixed;inset:0;background:linear-gradient(rgba(138,43,226,0.06) 1px,transparent 1px),linear-gradient(90deg,rgba(138,43,226,0.06) 1px,transparent 1px);background-size:40px 40px;pointer-events:none}
body::after{content:'';position:fixed;top:-50%;left:-50%;width:200%;height:200%;background:radial-gradient(ellipse at 30% 20%,rgba(138,43,226,0.15) 0%,transparent 50%),radial-gradient(ellipse at 70% 80%,rgba(0,180,255,0.1) 0%,transparent 50%);pointer-events:none}
.login-card{background:rgba(13,2,33,0.8);backdrop-filter:blur(20px);border:1px solid rgba(138,43,226,0.2);border-radius:16px;padding:40px;width:100%;max-width:420px;position:relative;z-index:1;animation:slideUp .5s ease-out}
@keyframes slideUp{from{opacity:0;transform:translateY(20px)}to{opacity:1;transform:translateY(0)}}
.login-card::before{content:'';position:absolute;top:0;left:0;right:0;height:2px;background:linear-gradient(90deg,transparent,#8a2be2,#00b4ff,transparent);border-radius:16px 16px 0 0}
.logo{text-align:center;margin-bottom:32px}
.logo h1{font-family:'Orbitron',sans-serif;font-size:22px;font-weight:700;background:linear-gradient(135deg,#8a2be2,#00b4ff);-webkit-background-clip:text;-webkit-text-fill-color:transparent;letter-spacing:3px;margin-bottom:6px}
.logo p{font-size:14px;color:#a78bfa;font-weight:400;letter-spacing:1px}
.form-group{margin-bottom:20px}
.form-group label{display:block;font-size:13px;font-weight:500;color:#a78bfa;margin-bottom:8px;letter-spacing:0.5px}
.form-group input{width:100%;padding:12px 16px;background:rgba(13,2,33,0.6);border:1px solid rgba(138,43,226,0.2);border-radius:8px;color:#e0d7ff;font-size:14px;font-family:'Segoe UI','SF Pro Display','Helvetica Neue',Arial,'PingFang SC','Microsoft YaHei',sans-serif;outline:none;transition:all .3s}
.form-group input:focus{border-color:rgba(138,43,226,0.6);box-shadow:0 0 15px rgba(138,43,226,0.2)}
.form-group input::placeholder{color:#6b5b8a}
.btn{width:100%;padding:12px;background:linear-gradient(135deg,rgba(138,43,226,0.3),rgba(0,180,255,0.2));border:1px solid rgba(138,43,226,0.4);color:#e0d7ff;border-radius:8px;font-size:14px;font-family:'Orbitron',sans-serif;font-weight:600;cursor:pointer;transition:all .3s;letter-spacing:2px;text-transform:uppercase}
.btn:hover{background:linear-gradient(135deg,rgba(138,43,226,0.5),rgba(0,180,255,0.3));box-shadow:0 0 20px rgba(138,43,226,0.3);transform:translateY(-1px)}
.btn:disabled{background:rgba(138,43,226,0.1);color:#6b5b8a;cursor:not-allowed;transform:none;box-shadow:none}
.error{background:rgba(255,0,110,0.1);border:1px solid rgba(255,0,110,0.3);border-radius:8px;padding:12px;margin-bottom:16px;color:#ff006e;font-size:13px;display:none}
.footer{text-align:center;margin-top:24px;font-size:11px;color:#6b5b8a;font-family:'Orbitron',sans-serif;letter-spacing:1px}
</style>
</head>
<body>
<div class="login-card">
<div class="logo">
<img src="/__waf_static__/logo-v3-hex-minimal.svg" alt="Moat WAF" style="width:320px;height:auto;margin-bottom:12px">
<p style="font-size:18px;color:#a78bfa;letter-spacing:2px">WAF 安全管理平台</p>
</div>
<div id="error" class="error"></div>
<form id="loginForm">
<div class="form-group">
<label for="token">访问令牌</label>
<input type="password" id="token" name="token" placeholder="请输入访问令牌" autocomplete="off" autofocus>
</div>
<button type="submit" class="btn" id="submitBtn">验证身份</button>
</form>
<div class="footer">MOAT WAF v2.0</div>
</div>
<script>
(function(){
var form=document.getElementById('loginForm');
var errDiv=document.getElementById('error');
var btn=document.getElementById('submitBtn');
form.addEventListener('submit',function(e){
e.preventDefault();
var token=document.getElementById('token').value.trim();
if(!token){showError('请输入访问令牌');return;}
btn.disabled=true;btn.textContent='验证中...';errDiv.style.display='none';
fetch('__SG_ADMIN__status',{headers:{'Authorization':'Bearer '+token}})
.then(function(r){
if(r.ok){document.cookie='waf_token='+token+';path=/;SameSite=Strict';window.location.href='__SG_ADMIN__dashboard';}
else if(r.status===401||r.status===429){showError('令牌无效或访问被拒绝');btn.disabled=false;btn.textContent='验证身份';}
else if(r.status===503){showError('管理面板未配置');btn.disabled=false;btn.textContent='验证身份';}
else{showError('服务器错误 ('+r.status+')');btn.disabled=false;btn.textContent='验证身份';}
})
.catch(function(){showError('网络连接失败');btn.disabled=false;btn.textContent='验证身份';});
});
function showError(msg){errDiv.textContent=msg;errDiv.style.display='block';}
})();
</script>
</body>
</html>
]=]

local DASHBOARD_HTML = [=[
<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Moat WAF - 仪表盘</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
select,option{font-family:'Segoe UI','SF Pro Display','Helvetica Neue',Arial,'PingFang SC','Microsoft YaHei',sans-serif}
select{color:#e0d7ff}
option{background:#0d0221;color:#e0d7ff;padding:4px 8px}
body{font-family:'Segoe UI','SF Pro Display','Helvetica Neue',Arial,'PingFang SC','Microsoft YaHei',sans-serif;background:#0d0221;color:#e0d7ff;min-height:100vh}
body::before{content:'';position:fixed;inset:0;background:linear-gradient(rgba(138,43,226,0.06) 1px,transparent 1px),linear-gradient(90deg,rgba(138,43,226,0.06) 1px,transparent 1px);background-size:40px 40px;pointer-events:none;z-index:0}
body::after{content:'';position:fixed;top:-50%;left:-50%;width:200%;height:200%;background:radial-gradient(ellipse at 30% 20%,rgba(138,43,226,0.15) 0%,transparent 50%),radial-gradient(ellipse at 70% 80%,rgba(0,180,255,0.1) 0%,transparent 50%);pointer-events:none;z-index:0}
.header{background:rgba(13,2,33,0.8);backdrop-filter:blur(20px);padding:16px 24px;display:flex;justify-content:space-between;align-items:center;border-bottom:1px solid rgba(138,43,226,0.15);position:relative;z-index:1}
.header::after{content:'';position:absolute;bottom:0;left:0;right:0;height:1px;background:linear-gradient(90deg,transparent,#8a2be2,#00b4ff,transparent)}
.header h1{font-family:'Orbitron',sans-serif;font-size:18px;font-weight:700;background:linear-gradient(135deg,#8a2be2,#00b4ff);-webkit-background-clip:text;-webkit-text-fill-color:transparent;letter-spacing:3px}
.header .logout{background:rgba(138,43,226,0.15);border:1px solid rgba(138,43,226,0.3);color:#a78bfa;padding:8px 16px;border-radius:8px;cursor:pointer;font-size:13px;font-family:'Rajdhani',sans-serif;transition:all .3s}
.header .logout:hover{background:rgba(138,43,226,0.3);box-shadow:0 0 15px rgba(138,43,226,0.2)}
.container{max-width:1200px;margin:0 auto;padding:24px;position:relative;z-index:1}
.stats-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:16px;margin-bottom:24px}
.stat-card{background:rgba(138,43,226,0.06);backdrop-filter:blur(20px);border-radius:16px;padding:20px;border:1px solid rgba(138,43,226,0.15);position:relative;overflow:hidden;transition:transform .3s,box-shadow .3s}
.stat-card::before{content:'';position:absolute;top:0;left:0;right:0;height:2px;background:linear-gradient(90deg,transparent,#8a2be2,#00b4ff,transparent)}
.stat-card:hover{transform:translateY(-2px);box-shadow:0 8px 30px rgba(138,43,226,0.2)}
.stat-card .label{font-size:13px;color:#a78bfa;margin-bottom:4px;font-weight:500;letter-spacing:0.5px}
.stat-card .value{font-size:28px;font-weight:700;font-family:'Orbitron',sans-serif;color:#e0d7ff}
.stat-card .value.red{color:#ff006e}
.stat-card .value.green{color:#00ff88}
.section{background:rgba(138,43,226,0.06);backdrop-filter:blur(20px);border-radius:16px;padding:20px;border:1px solid rgba(138,43,226,0.15);margin-bottom:20px;position:relative;overflow:hidden}
.section::before{content:'';position:absolute;top:0;left:0;right:0;height:2px;background:linear-gradient(90deg,transparent,#8a2be2,#00b4ff,transparent)}
.section h2{font-family:'Orbitron',sans-serif;font-size:16px;margin-bottom:16px;color:#e0d7ff;font-weight:600;letter-spacing:1px}
.table-wrap{overflow-x:auto}
table{width:100%;border-collapse:collapse}
th,td{text-align:left;padding:10px 12px;border-bottom:1px solid rgba(138,43,226,0.1);font-size:13px}
th{color:#a78bfa;font-weight:500;font-family:'Rajdhani',sans-serif;letter-spacing:0.5px}
td{color:#e0d7ff}
.badge{display:inline-block;padding:2px 10px;border-radius:20px;font-size:11px;font-weight:600}
.badge.block{background:rgba(255,0,110,0.2);color:#ff006e;border:1px solid rgba(255,0,110,0.3)}
.badge.pass{background:rgba(0,255,136,0.15);color:#00ff88;border:1px solid rgba(0,255,136,0.3)}
.empty{text-align:center;color:#6b5b8a;padding:40px;font-size:14px}
.actions{display:flex;gap:8px;flex-wrap:wrap;margin-bottom:16px}
button{background:rgba(138,43,226,0.08);border:1px solid rgba(138,43,226,0.2);color:#a78bfa;padding:8px 16px;border-radius:8px;cursor:pointer;font-family:'Rajdhani',sans-serif;font-size:13px;font-weight:500;transition:all .2s;letter-spacing:0.5px}
button:hover{background:rgba(138,43,226,0.15);border-color:rgba(138,43,226,0.4);color:#e0d7ff}
button.primary{background:linear-gradient(135deg,rgba(138,43,226,0.25),rgba(0,180,255,0.15));border-color:rgba(138,43,226,0.4);color:#e0d7ff}
button.primary:hover{background:linear-gradient(135deg,rgba(138,43,226,0.4),rgba(0,180,255,0.25));box-shadow:0 0 12px rgba(138,43,226,0.2)}
button.danger{border-color:rgba(255,0,110,0.3);color:#ff006e;background:rgba(255,0,110,0.06)}
button.danger:hover{background:rgba(255,0,110,0.15);box-shadow:0 0 12px rgba(255,0,110,0.15)}
#toast{position:fixed;top:20px;right:20px;background:rgba(13,2,33,0.9);backdrop-filter:blur(20px);border:1px solid rgba(138,43,226,0.3);padding:12px 20px;border-radius:12px;font-size:13px;display:none;z-index:999}
#toast.success{border-color:rgba(0,255,136,0.4);color:#00ff88}
#toast.error{border-color:rgba(255,0,110,0.4);color:#ff006e}
.tabs{display:flex;gap:4px;margin-bottom:20px;border-bottom:none;padding-bottom:0;background:rgba(138,43,226,0.06);border-radius:40px;padding:4px;width:fit-content}
.tabs button{background:none;border:none;color:#6b5b8a;padding:10px 20px;cursor:pointer;font-size:14px;font-family:'Rajdhani',sans-serif;font-weight:500;border-radius:40px;transition:all .3s}
.tabs button:hover{color:#a78bfa}
.tabs button.active{color:#e0d7ff;background:linear-gradient(135deg,rgba(138,43,226,0.4),rgba(0,180,255,0.3));box-shadow:0 0 15px rgba(138,43,226,0.2)}
.filter-bar{display:flex;gap:8px;flex-wrap:wrap;margin-bottom:16px;align-items:center}
.filter-bar input,.filter-bar select{padding:8px 12px;background:rgba(13,2,33,0.6);border:1px solid rgba(138,43,226,0.15);border-radius:8px;color:#e0d7ff;font-size:13px;outline:none;transition:all .3s}
.filter-bar select{font-family:'Segoe UI','SF Pro Display','Helvetica Neue',Arial,'PingFang SC','Microsoft YaHei',sans-serif}
.filter-bar input:focus,.filter-bar select:focus{border-color:rgba(138,43,226,0.5);box-shadow:0 0 10px rgba(138,43,226,0.15)}
.filter-bar input{width:140px}
.filter-bar select{min-width:120px}
.log-table{width:100%;border-collapse:collapse}
.log-table th,.log-table td{padding:8px 10px;border-bottom:1px solid rgba(138,43,226,0.1);font-size:12px;text-align:left}
.log-table th{color:#a78bfa;font-weight:500;position:sticky;top:0;background:rgba(13,2,33,0.9);backdrop-filter:blur(20px)}
.log-table td{color:#e0d7ff;max-width:200px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.log-table tr:hover{background:rgba(138,43,226,0.08)}
.severity-badge{display:inline-block;padding:2px 10px;border-radius:20px;font-size:11px;font-weight:600}
.severity-badge.critical{background:rgba(255,0,110,0.2);color:#ff006e;border:1px solid rgba(255,0,110,0.3)}
.severity-badge.high{background:rgba(255,102,0,0.2);color:#ff6600;border:1px solid rgba(255,102,0,0.3)}
.severity-badge.medium{background:rgba(138,43,226,0.2);color:#a78bfa;border:1px solid rgba(138,43,226,0.3)}
.severity-badge.low{background:rgba(0,255,136,0.15);color:#00ff88;border:1px solid rgba(0,255,136,0.3)}
.pagination{display:flex;gap:4px;justify-content:center;margin-top:16px;align-items:center}
.pagination button{background:rgba(138,43,226,0.15);border:1px solid rgba(138,43,226,0.2);color:#a78bfa;padding:6px 12px;border-radius:8px;cursor:pointer;font-size:12px;transition:all .3s}
.pagination button:hover{background:rgba(138,43,226,0.25);box-shadow:0 0 10px rgba(138,43,226,0.15)}
.pagination button.active{background:linear-gradient(135deg,rgba(138,43,226,0.4),rgba(0,180,255,0.3));color:#e0d7ff;border-color:transparent}
.pagination button:disabled{opacity:.3;cursor:not-allowed}
.pagination .page-info{color:#6b5b8a;font-size:12px;margin:0 8px}
.log-detail-grid{display:grid;grid-template-columns:120px 1fr;gap:8px;font-size:13px}
.log-detail-grid .label{color:#a78bfa;text-align:right;padding-right:8px;font-weight:500}
.log-detail-grid .value{color:#e0d7ff;word-break:break-all}
.refresh-bar{display:flex;justify-content:space-between;align-items:center;margin-bottom:12px}
.refresh-bar .status{font-size:12px;color:#6b5b8a}
.tab-content{display:none}
.tab-content.active{display:block}
.rule-form{background:rgba(13,2,33,0.6);border:1px solid rgba(138,43,226,0.15);border-radius:16px;padding:16px;margin-bottom:16px;display:none}
.rule-form.active{display:block}
.rule-form h3{margin-bottom:12px;font-size:14px;font-family:'Orbitron',sans-serif;color:#a78bfa;letter-spacing:1px}
.rule-form .form-row{display:flex;gap:8px;margin-bottom:10px;flex-wrap:wrap}
.rule-form .form-row label{display:block;font-size:11px;color:#6b5b8a;margin-bottom:4px;font-weight:500}
.rule-form .form-row>div{flex:1;min-width:140px}
.rule-form input,.rule-form select{width:100%;padding:8px 10px;background:rgba(138,43,226,0.06);border:1px solid rgba(138,43,226,0.15);border-radius:8px;color:#e0d7ff;font-size:13px;outline:none;box-sizing:border-box;transition:all .3s}
.rule-form select{font-family:'Segoe UI','SF Pro Display','Helvetica Neue',Arial,'PingFang SC','Microsoft YaHei',sans-serif}
.rule-form input:focus,.rule-form select:focus{border-color:rgba(138,43,226,0.5);box-shadow:0 0 10px rgba(138,43,226,0.15)}
.rule-table{width:100%;border-collapse:collapse}
.rule-table th,.rule-table td{padding:8px 10px;border-bottom:1px solid rgba(138,43,226,0.1);font-size:12px;text-align:left}
.rule-table th{color:#a78bfa;font-weight:500}
.rule-table td{color:#e0d7ff}
.rule-table tr:hover{background:rgba(138,43,226,0.08)}
.modal-overlay{display:none;position:fixed;inset:0;background:rgba(0,0,0,0.7);backdrop-filter:blur(8px);z-index:100;align-items:center;justify-content:center}
.modal-overlay.active{display:flex}
.modal{background:rgba(13,2,33,0.9);backdrop-filter:blur(20px);border-radius:16px;padding:24px;width:90%;max-width:400px;border:1px solid rgba(138,43,226,0.2);position:relative;overflow:hidden;animation:modalSlideUp .3s ease-out}
.modal::before{content:'';position:absolute;top:0;left:0;right:0;height:2px;background:linear-gradient(90deg,transparent,#8a2be2,#00b4ff,transparent)}
@keyframes modalSlideUp{from{opacity:0;transform:translateY(20px)}to{opacity:1;transform:translateY(0)}}
.modal h3{margin-bottom:16px;font-size:16px;font-family:'Orbitron',sans-serif;color:#e0d7ff;letter-spacing:1px}
.modal input{width:100%;padding:10px 12px;background:rgba(138,43,226,0.06);border:1px solid rgba(138,43,226,0.15);border-radius:8px;color:#e0d7ff;font-size:14px;margin-bottom:12px;outline:none;font-family:'Segoe UI','SF Pro Display','Helvetica Neue',Arial,'PingFang SC','Microsoft YaHei',sans-serif;transition:all .3s}
.modal input:focus{border-color:rgba(138,43,226,0.5);box-shadow:0 0 10px rgba(138,43,226,0.15)}
.modal .modal-actions{display:flex;gap:8px;justify-content:flex-end}
.modal .modal-actions button{padding:8px 16px;border-radius:8px;cursor:pointer;font-size:13px}
.confirm-overlay{position:fixed;inset:0;background:rgba(0,0,0,0.6);backdrop-filter:blur(4px);display:flex;align-items:center;justify-content:center;z-index:10000;opacity:0;pointer-events:none;transition:opacity .2s}
.confirm-overlay.active{opacity:1;pointer-events:auto}
.confirm-box{background:rgba(13,2,33,0.95);backdrop-filter:blur(20px);border:1px solid rgba(138,43,226,0.3);border-radius:16px;padding:28px 32px;max-width:420px;width:90%;transform:translateY(20px);transition:transform .25s;position:relative;overflow:hidden}
.confirm-overlay.active .confirm-box{transform:translateY(0)}
.confirm-box::before{content:'';position:absolute;top:0;left:0;right:0;height:2px;background:linear-gradient(90deg,transparent,#8a2be2,#00b4ff,transparent)}
.confirm-box h3{font-family:'Orbitron',sans-serif;font-size:14px;color:#e0d7ff;margin-bottom:12px;letter-spacing:1px}
.confirm-box p{color:#a78bfa;font-size:13px;line-height:1.6;margin-bottom:20px;white-space:pre-line}
.confirm-box .confirm-actions{display:flex;gap:10px;justify-content:flex-end}
.confirm-box .confirm-actions button{padding:8px 20px;border-radius:8px;cursor:pointer;font-size:13px;font-weight:500}
.mode-toggle{display:flex;align-items:center;gap:10px}
.mode-label{font-size:13px;color:#a78bfa}
.mode-btn{display:flex;align-items:center;gap:8px;padding:8px 16px;border-radius:40px;border:2px solid;cursor:pointer;font-size:13px;font-weight:600;transition:all .3s;font-family:'Rajdhani',sans-serif}
.mode-btn.block{background:rgba(255,0,110,0.1);border-color:rgba(255,0,110,0.4);color:#ff006e}
.mode-btn.block:hover{background:rgba(255,0,110,0.2);box-shadow:0 0 15px rgba(255,0,110,0.15)}
.mode-btn.log_only{background:rgba(138,43,226,0.15);border-color:rgba(138,43,226,0.4);color:#a78bfa}
.mode-btn.log_only:hover{background:rgba(138,43,226,0.25);box-shadow:0 0 15px rgba(138,43,226,0.15)}
.mode-dot{width:10px;height:10px;border-radius:50%;display:inline-block}
.mode-btn.block .mode-dot{background:#ff006e;box-shadow:0 0 8px #ff006e}
.mode-btn.log_only .mode-dot{background:#a78bfa;box-shadow:0 0 8px rgba(138,43,226,0.6)}
.nginx-editor{width:100%;min-height:480px;background:rgba(13,2,33,0.6);border:1px solid rgba(138,43,226,0.15);border-radius:16px;color:#e0d7ff;font-family:"Cascadia Code","Fira Code","JetBrains Mono",Consolas,monospace;font-size:13px;line-height:1.6;padding:16px;resize:vertical;outline:none;tab-size:4;white-space:pre;overflow:auto;transition:border-color .3s}
.nginx-editor:focus{border-color:rgba(138,43,226,0.5);box-shadow:0 0 15px rgba(138,43,226,0.1)}
.output-area{background:rgba(13,2,33,0.6);border:1px solid rgba(138,43,226,0.15);border-radius:16px;padding:12px 16px;margin-top:12px;font-family:monospace;font-size:12px;line-height:1.5;color:#6b5b8a;white-space:pre-wrap;word-break:break-all;max-height:300px;overflow-y:auto;display:none}
.output-area.show{display:block}
.output-area.success{border-color:rgba(0,255,136,0.3);color:#00ff88}
.output-area.error{border-color:rgba(255,0,110,0.3);color:#ff006e}
.editor-status{font-size:12px;color:#6b5b8a;margin-bottom:8px}
.log-filter{display:flex;gap:8px;flex-wrap:wrap;margin-bottom:14px;align-items:center}
.log-filter input,.log-filter select{padding:8px 12px;background:rgba(13,2,33,0.6);border:1px solid rgba(138,43,226,0.15);border-radius:8px;color:#e0d7ff;font-size:13px;outline:none}
.log-filter select{font-family:'Segoe UI','SF Pro Display','Helvetica Neue',Arial,'PingFang SC','Microsoft YaHei',sans-serif}
.log-filter input:focus,.log-filter select:focus{border-color:rgba(138,43,226,0.5);box-shadow:0 0 10px rgba(138,43,226,0.2)}
.range-btn{background:transparent;border:1px solid rgba(138,43,226,0.2);color:#6b5b8a;padding:6px 12px;border-radius:20px;cursor:pointer;font-family:'Orbitron',sans-serif;font-size:9px;letter-spacing:1px;transition:all .3s}
.range-btn.active{background:rgba(138,43,226,0.2);color:#e0d7ff;border-color:rgba(138,43,226,0.5)}
.ban-btn{background:rgba(255,0,110,0.1);border:1px solid rgba(255,0,110,0.3);color:#ff006e;padding:3px 10px;border-radius:20px;cursor:pointer;font-size:10px;font-family:'Orbitron',sans-serif;transition:all .3s}
.ban-btn:hover{background:rgba(255,0,110,0.2);box-shadow:0 0 10px rgba(255,0,110,0.2)}
.log-detail{background:rgba(138,43,226,0.04);border:1px solid rgba(138,43,226,0.1);border-radius:8px;padding:14px;margin:8px 0}
.detail-grid{display:grid;grid-template-columns:120px 1fr;gap:6px;font-size:12px}
.detail-grid .dlabel{color:#6b5b8a;text-align:right;font-family:'JetBrains Mono',monospace}
.detail-grid .dvalue{color:#c4b5fd;font-family:'JetBrains Mono',monospace;word-break:break-all}
.hit-badge{font-family:'JetBrains Mono',monospace;font-size:10px;padding:2px 8px;border-radius:12px}
.hit-badge.active{background:rgba(0,255,136,0.1);color:#00ff88}
.hit-badge.zero{color:#6b5b8a}
.rule-search{padding:8px 12px;background:rgba(13,2,33,0.6);border:1px solid rgba(138,43,226,0.15);border-radius:8px;color:#e0d7ff;width:200px;font-size:13px;margin-bottom:12px}
.realtime-toggle{display:flex;align-items:center;gap:6px;cursor:pointer;font-size:12px;color:#a78bfa}
.realtime-toggle input{appearance:none;width:36px;height:20px;background:rgba(138,43,226,0.2);border-radius:10px;position:relative;cursor:pointer;transition:all .3s;border:none;outline:none}
.realtime-toggle input:checked{background:rgba(0,255,136,0.3)}
.realtime-toggle input::after{content:'';position:absolute;top:2px;left:2px;width:16px;height:16px;background:#6b5b8a;border-radius:50%;transition:all .3s}
.realtime-toggle input:checked::after{left:18px;background:#00ff88;box-shadow:0 0 6px rgba(0,255,136,0.5)}
.test-btn{background:rgba(0,180,255,0.1);border:1px solid rgba(0,180,255,0.3);color:#00b4ff;padding:3px 10px;border-radius:20px;cursor:pointer;font-size:10px;font-family:'Orbitron',sans-serif;transition:all .3s;margin-right:4px}
.test-btn:hover{background:rgba(0,180,255,0.2);box-shadow:0 0 10px rgba(0,180,255,0.2)}
</style>
<script src="/__waf_static__/chart.umd.min.js"></script>
<link href="/__waf_static__/fonts.css" rel="stylesheet">
</head>
<body>
<div class="header">
<img src="/__waf_static__/logo-v3-hex-minimal.svg" alt="Moat WAF" style="height:50px;width:auto">
<div class="mode-toggle">
<span class="mode-label" data-i18n="header.mode">运行模式:</span>
<button id="mode-btn" class="mode-btn block" onclick="toggleMode()">
<span class="mode-dot"></span>
<span id="mode-text">拦截模式</span>
</button>
<span id="status-info" style="font-size:12px;color:#6b5b8a;font-family:'JetBrains Mono',monospace;margin-left:12px">加载中...</span>
<div style="display:flex;gap:6px;margin-left:12px">
<button class="primary" style="padding:5px 12px;font-size:11px" onclick="loadStats()" data-i18n="header.refresh">刷新</button>
<button style="padding:5px 12px;font-size:11px" onclick="reloadRules()" data-i18n="header.reload_rules">重载规则</button>
</div>
<select id="lang-select" onchange="setLang(this.value)" style="margin-left:12px;background:rgba(138,43,226,0.08);border:1px solid rgba(138,43,226,0.2);color:#a78bfa;padding:6px 10px;border-radius:8px;font-size:12px;cursor:pointer;outline:none"><option value="zh-CN">简体中文</option><option value="zh-TW">繁體中文</option><option value="en">English</option></select>
</div>
<button class="logout" onclick="document.cookie='waf_token=;path=/;max-age=0';location.reload()" data-i18n="header.logout">退出登录</button>
</div>
<div class="container">
<div class="tabs">
<button class="active" onclick="switchTab('dashboard')" data-i18n="tab.dashboard">仪表盘</button>
<button onclick="switchTab('logs')" data-i18n="tab.logs">拦截日志</button>
<button onclick="switchTab('rules')" data-i18n="tab.rules">自定义规则</button>
<button onclick="switchTab('nginx')" data-i18n="tab.nginx">Nginx配置</button>
</div>
<div class="tab-content active" id="tab-dashboard">
<div class="stats-grid">
<div class="stat-card"><div class="label" data-i18n="stats.total">总请求数</div><div class="value" id="stat-total">-</div></div>
<div class="stat-card"><div class="label" data-i18n="stats.blocked">已拦截</div><div class="value red" id="stat-blocked">-</div></div>
<div class="stat-card"><div class="label" data-i18n="stats.passed">已放行</div><div class="value green" id="stat-passed">-</div></div>
<div class="stat-card"><div class="label" data-i18n="stats.rate">拦截率</div><div class="value" id="stat-rate">-</div></div>
</div>
<div class="charts-grid" style="display:grid;grid-template-columns:2fr 1fr;gap:14px;margin-bottom:20px">
<div style="background:rgba(138,43,226,0.06);backdrop-filter:blur(20px);border:1px solid rgba(138,43,226,0.15);border-radius:16px;padding:20px;position:relative;overflow:hidden">
<div style="position:absolute;top:0;left:0;right:0;height:2px;background:linear-gradient(90deg,transparent,#8a2be2,#00b4ff,transparent)"></div>
<div style="font-family:'Orbitron',sans-serif;font-size:11px;color:#a78bfa;text-transform:uppercase;letter-spacing:2px;margin-bottom:12px" data-i18n="chart.trend">攻击趋势</div>
<div style="display:flex;gap:4px;margin-bottom:12px">
<button class="range-btn active" onclick="loadTrend('24h')">24H</button>
<button class="range-btn" onclick="loadTrend('7d')">7D</button>
</div>
<canvas id="trendChart" height="200"></canvas>
</div>
<div style="background:rgba(138,43,226,0.06);backdrop-filter:blur(20px);border:1px solid rgba(138,43,226,0.15);border-radius:16px;padding:20px;position:relative;overflow:hidden">
<div style="position:absolute;top:0;left:0;right:0;height:2px;background:linear-gradient(90deg,transparent,#8a2be2,#00b4ff,transparent)"></div>
<div style="font-family:'Orbitron',sans-serif;font-size:11px;color:#a78bfa;text-transform:uppercase;letter-spacing:2px;margin-bottom:12px" data-i18n="chart.category">攻击类型分布</div>
<canvas id="categoryChart" height="200"></canvas>
</div>
</div>
<div style="background:rgba(138,43,226,0.06);backdrop-filter:blur(20px);border:1px solid rgba(138,43,226,0.15);border-radius:16px;padding:20px;margin-bottom:20px;position:relative;overflow:hidden">
<div style="position:absolute;top:0;left:0;right:0;height:2px;background:linear-gradient(90deg,transparent,#8a2be2,#00b4ff,transparent)"></div>
<div style="font-family:'Orbitron',sans-serif;font-size:11px;color:#a78bfa;text-transform:uppercase;letter-spacing:2px;margin-bottom:12px" data-i18n="chart.top_ip">TOP 10 攻击源 IP</div>
<canvas id="topIpChart" height="150"></canvas>
</div>
<div class="section">
<h2 data-i18n="ip.blacklist">IP 黑名单</h2>
<div class="actions">
<button class="danger" onclick="showAddModal('blacklist')" data-i18n="ip.add">添加 IP</button>
</div>
<div class="table-wrap"><table id="blacklist-table"><thead><tr><th data-i18n="ip.address">IP 地址</th><th data-i18n="ip.ttl_col">TTL</th><th data-i18n="common.operation">操作</th></tr></thead><tbody></tbody></table></div>
<div class="empty" id="blacklist-empty" data-i18n="ip.empty_blacklist">暂无黑名单条目</div>
</div>
<div class="section">
<h2 data-i18n="ip.whitelist">IP 白名单</h2>
<div class="actions">
<button class="primary" onclick="showAddModal('whitelist')" data-i18n="ip.add">添加 IP</button>
</div>
<div class="table-wrap"><table id="whitelist-table"><thead><tr><th data-i18n="ip.address">IP 地址</th><th data-i18n="common.operation">操作</th></tr></thead><tbody></tbody></table></div>
<div class="empty" id="whitelist-empty" data-i18n="ip.empty_whitelist">暂无白名单条目</div>
</div>
</div>
<div class="tab-content" id="tab-logs">
<div class="refresh-bar">
<div class="status" id="logs-status" data-i18n="logs.status">就绪</div>
<button class="primary" onclick="loadLogs()" data-i18n="logs.refresh">刷新日志</button>
</div>
<div class="log-filter">
<button class="range-btn" onclick="setRange('1h')">1H</button>
<button class="range-btn" onclick="setRange('6h')">6H</button>
<button class="range-btn active" onclick="setRange('24h')">24H</button>
<button class="range-btn" onclick="setRange('7d')">7D</button>
<input type="text" id="filter-rule-id" data-i18n-placeholder="logs.rule_id" placeholder="规则 ID" style="width:100px">
<select id="filter-severity">
<option value="" data-i18n="logs.severity_all">全部级别</option>
<option value="critical">Critical</option>
<option value="high">High</option>
<option value="medium">Medium</option>
<option value="low">Low</option>
</select>
<input type="text" id="filter-ip" data-i18n-placeholder="logs.source_ip" placeholder="源 IP">
<select id="filter-action">
<option value="" data-i18n="logs.action_all">全部动作</option>
<option value="BLOCK">BLOCK</option>
<option value="LOG">LOG</option>
</select>
<button onclick="loadLogs()" data-i18n="logs.query">查询</button>
<button onclick="clearFilters()" data-i18n="logs.reset">重置</button>
<label class="realtime-toggle"><input type="checkbox" id="realtime-toggle" onchange="toggleRealtime()"> <span data-i18n="logs.realtime">实时</span></label>
</div>
<div style="overflow-x:auto"><table class="log-table" id="logs-table"><thead><tr><th data-i18n="logs.time">时间</th><th>IP</th><th data-i18n="logs.method">方法</th><th>URI</th><th data-i18n="logs.rule_id">规则ID</th><th data-i18n="logs.severity_col">级别</th><th data-i18n="common.operation">操作</th></tr></thead><tbody></tbody></table></div>
<div class="empty" id="logs-empty" data-i18n="logs.empty">暂无拦截日志</div>
<div class="pagination" id="logs-pagination"></div>
</div>
<div class="tab-content" id="tab-rules">
<div class="actions">
<button class="primary" onclick="loadRuleFiles()" data-i18n="rules.refresh">刷新列表</button>
<button onclick="toggleRuleForm()" data-i18n="rules.add">添加新规则</button>
<button class="danger" onclick="restoreDefaultRules()" data-i18n="rules.restore">恢复默认规则</button>
</div>
<div class="rule-form" id="rule-form">
<h3 id="rule-form-title" data-i18n="rules.form_title_add">添加自定义规则</h3>
<div class="form-row">
<div><label data-i18n="rules.rule_id">规则 ID</label><input type="text" id="rf-id" placeholder="CUSTOM-01"></div>
<div><label data-i18n="rules.desc">描述</label><input type="text" id="rf-desc" data-i18n-placeholder="rules.desc_placeholder" placeholder="规则描述"></div>
</div>
<div class="form-row">
<div><label data-i18n="rules.severity">严重级别</label><select id="rf-severity"><option value="critical">Critical</option><option value="high">High</option><option value="medium" selected>Medium</option><option value="low">Low</option></select></div>
<div><label data-i18n="rules.target">匹配目标</label><select id="rf-target"><option value="URI">URI</option><option value="ARGS">ARGS</option><option value="BODY">BODY</option><option value="HEADERS">HEADERS</option><option value="COOKIE">COOKIE</option></select></div>
<div><label data-i18n="rules.action">动作</label><select id="rf-action"><option value="BLOCK">BLOCK</option><option value="LOG">LOG</option></select></div>
</div>
<div class="form-row">
<div style="flex:3"><label data-i18n="rules.pattern_label">匹配模式 (PCRE)</label><input type="text" id="rf-pattern" data-i18n-placeholder="rules.pattern_placeholder" placeholder="正则表达式"></div>
</div>
<div class="form-row">
<button class="primary" onclick="saveRule()" data-i18n="rules.save">保存</button>
<button onclick="toggleRuleForm()" data-i18n="rules.cancel">取消</button>
<span id="rule-form-msg" style="font-size:12px;color:#94a3b8;margin-left:8px"></span>
</div>
</div>
<input class="rule-search" id="rule-search" data-i18n-placeholder="rules.search_placeholder" placeholder="搜索规则 ID 或描述..." oninput="filterRules()">
<div style="overflow-x:auto"><table class="rule-table" id="custom-rules-table"><thead><tr><th>ID</th><th data-i18n="rules.hit">命中</th><th data-i18n="rules.desc_col">描述</th><th data-i18n="rules.severity_col">级别</th><th data-i18n="rules.target">目标</th><th data-i18n="rules.pattern">模式</th><th data-i18n="rules.action_col">动作</th><th data-i18n="common.operation">操作</th></tr></thead><tbody></tbody></table></div>
<div class="empty" id="custom-rules-empty" data-i18n="rules.empty">暂无自定义规则</div>
<div class="section" style="margin-top:20px">
<h2 data-i18n="rules.file_overview">规则文件概览</h2>
<div id="rule-files-list" style="font-size:13px;color:#94a3b8;">加载中...</div>
</div>
</div>
<div class="tab-content" id="tab-nginx">
<div class="actions">
<button class="primary" onclick="saveNginxConfig()" data-i18n="nginx.save">保存配置</button>
<button onclick="testNginxConfig()" data-i18n="nginx.test">检查语法</button>
<button onclick="reloadNginx()" data-i18n="nginx.reload">热重载</button>
<button onclick="restoreNginxBackup()" data-i18n="nginx.restore">恢复备份</button>
<button onclick="loadNginxConfig()" data-i18n="nginx.refresh">刷新</button>
</div>
<div class="editor-status" id="nginx-status">就绪</div>
<textarea class="nginx-editor" id="nginx-editor" spellcheck="false" placeholder="加载中..."></textarea>
<div class="output-area" id="nginx-output"></div>
</div>
</div>
</div>
<div id="toast"></div>
<div class="modal-overlay" id="modal-overlay">
<div class="modal">
<h3 id="modal-title">添加 IP</h3>
<input type="text" id="modal-ip" placeholder="输入 IP 地址 (如 192.168.1.100)">
<div style="display:flex;align-items:center;gap:8px"><input type="number" id="modal-ttl" placeholder="0" value="0" style="width:120px"><span style="font-size:12px;color:#94a3b8">单位：秒，默认0即为永久生效</span></div>
<div class="modal-actions">
<button onclick="closeModal()" data-i18n="ip.cancel">取消</button>
<button class="primary" onclick="confirmAdd()" data-i18n="ip.confirm_add">确认添加</button>
</div>
</div>
</div>
<div class="modal-overlay" id="log-detail-modal">
<div class="modal" style="max-width:600px">
<h3>日志详情</h3>
<div id="log-detail-content" class="log-detail-grid"></div>
<div class="modal-actions">
<button onclick="closeLogDetail()" data-i18n="common.close">关闭</button>
</div>
</div>
</div>
<div class="confirm-overlay" id="confirm-overlay">
<div class="confirm-box">
<h3 id="confirm-title"></h3>
<p id="confirm-message"></p>
<div class="confirm-actions">
<button id="confirm-cancel" onclick="closeConfirm(false)">取消</button>
<button class="danger" id="confirm-ok" onclick="closeConfirm(true)">确认</button>
</div>
</div>
</div>
<script>
var ADMIN_PREFIX=']= ADMIN_PATH ..[=[';
var LANGS={'zh-CN':{'login.title':'WAF 安全管理平台','login.token_label':'访问令牌','login.token_placeholder':'请输入访问令牌','login.submit':'验证身份','login.invalid':'令牌无效或访问被拒绝','login.unconfigured':'管理面板未配置','login.server_error':'服务器错误','login.network_error':'网络连接失败','header.mode':'运行模式:','header.intercept':'拦截模式','header.log_only':'仅记录模式','header.refresh':'刷新','header.reload_rules':'重载规则','header.logout':'退出登录','tab.dashboard':'仪表盘','tab.logs':'拦截日志','tab.rules':'自定义规则','tab.nginx':'Nginx配置','stats.total':'总请求数','stats.blocked':'已拦截','stats.passed':'已放行','stats.rate':'拦截率','chart.trend':'攻击趋势','chart.category':'攻击类型分布','chart.top_ip':'TOP 10 攻击源 IP','chart.blocked':'拦截','chart.passed':'放行','chart.attacks':'攻击次数','ip.blacklist':'IP 黑名单','ip.whitelist':'IP 白名单','ip.add':'添加 IP','ip.ttl':'TTL','ip.ttl_hint':'单位：秒，默认0即为永久生效','ip.permanent':'永久','ip.confirm_add':'确认添加','ip.cancel':'取消','ip.empty_blacklist':'暂无黑名单条目','ip.empty_whitelist':'暂无白名单条目','ip.added':'已添加','ip.deleted':'已删除','ip.add_failed':'添加失败','ip.delete_failed':'删除失败','ip.delete_confirm':'确定要删除吗？','logs.status':'就绪','logs.refresh':'刷新日志','logs.severity_all':'全部级别','logs.action_all':'全部动作','logs.query':'查询','logs.reset':'重置','logs.empty':'暂无拦截日志','logs.ban':'封禁','logs.ban_confirm':'确定要封禁此 IP 吗？','logs.banned':'已封禁','logs.ban_failed':'封禁失败','logs.loading':'刷新中...','logs.query_failed':'查询失败','rules.refresh':'刷新列表','rules.add':'添加新规则','rules.restore':'恢复默认规则','rules.empty':'暂无自定义规则','rules.form_title_add':'添加自定义规则','rules.form_title_edit':'编辑规则','rules.save':'保存','rules.cancel':'取消','rules.search_placeholder':'搜索规则...','rules.added':'规则已添加','rules.updated':'规则已更新','rules.deleted':'规则已删除','rules.delete_confirm':'确定要删除规则吗？','rules.restore_confirm':'确定要恢复默认规则吗？','rules.restored':'已恢复默认规则','rules.restore_failed':'恢复失败','nginx.save':'保存配置','nginx.test':'检查语法','nginx.reload':'热重载','nginx.restore':'恢复备份','nginx.refresh':'刷新','nginx.save_confirm':'保存配置将自动备份\n\n确定要保存吗？','nginx.reload_confirm':'将检查语法后热重载\n\n确定要继续吗？','nginx.saved':'配置已保存','nginx.syntax_ok':'语法检查通过','nginx.reloaded':'已重载','nginx.restored':'已恢复备份','mode.confirm':'确定要切换到{mode}吗？','mode.switched':'已切换到','common.delete':'删除','common.edit':'编辑','common.detail':'详情','common.close':'关闭','common.cancel':'取消','common.success':'成功','common.error':'失败','common.loading':'加载中...','common.permanent':'永久','common.operation':'操作','common.address':'地址',
'logs.rule_id':'规则 ID','logs.source_ip':'源 IP','logs.realtime':'实时','logs.time':'时间','logs.method':'方法','logs.severity_col':'级别','logs.action_col':'操作',
'rules.hit':'命中','rules.desc_col':'描述','rules.severity_col':'级别','rules.target':'目标','rules.pattern':'模式','rules.action_col':'动作','rules.file_overview':'规则文件概览','rules.file_count':'条规则',
'ip.address':'IP 地址','ip.ttl_col':'TTL','rules.desc':'描述','rules.severity':'严重级别','rules.action':'动作','rules.pattern_label':'匹配模式 (PCRE)','rules.desc_placeholder':'规则描述','rules.pattern_placeholder':'正则表达式','rules.rule_id':'规则 ID'},'zh-TW':{'login.title':'WAF 安全管理平台','login.token_label':'訪問令牌','login.token_placeholder':'請輸入訪問令牌','login.submit':'驗證身份','login.invalid':'令牌無效或訪問被拒絕','login.unconfigured':'管理面板未配置','login.server_error':'伺服器錯誤','login.network_error':'網路連線失敗','header.mode':'運行模式:','header.intercept':'攔截模式','header.log_only':'僅記錄模式','header.refresh':'重新整理','header.reload_rules':'重載規則','header.logout':'登出','tab.dashboard':'儀錶板','tab.logs':'攔截日誌','tab.rules':'自訂規則','tab.nginx':'Nginx設定','stats.total':'總請求數','stats.blocked':'已攔截','stats.passed':'已放行','stats.rate':'攔截率','chart.trend':'攻擊趨勢','chart.category':'攻擊類型分佈','chart.top_ip':'TOP 10 攻擊來源 IP','chart.blocked':'攔截','chart.passed':'放行','chart.attacks':'攻擊次數','ip.blacklist':'IP 黑名單','ip.whitelist':'IP 白名單','ip.add':'新增 IP','ip.ttl':'TTL','ip.ttl_hint':'單位：秒，預設0即為永久生效','ip.permanent':'永久','ip.confirm_add':'確認新增','ip.cancel':'取消','ip.empty_blacklist':'暫無黑名單條目','ip.empty_whitelist':'暫無白名單條目','ip.added':'已新增','ip.deleted':'已刪除','ip.add_failed':'新增失敗','ip.delete_failed':'刪除失敗','ip.delete_confirm':'確定要刪除嗎？','logs.status':'就緒','logs.refresh':'重新整理日誌','logs.severity_all':'全部級別','logs.action_all':'全部動作','logs.query':'查詢','logs.reset':'重置','logs.empty':'暫無攔截日誌','logs.ban':'封禁','logs.ban_confirm':'確定要封禁此 IP 嗎？','logs.banned':'已封禁','logs.ban_failed':'封禁失敗','logs.loading':'重新整理中...','logs.query_failed':'查詢失敗','rules.refresh':'重新整理列表','rules.add':'新增自訂規則','rules.restore':'恢復預設規則','rules.empty':'暫無自訂規則','rules.form_title_add':'新增自訂規則','rules.form_title_edit':'編輯規則','rules.save':'儲存','rules.cancel':'取消','rules.search_placeholder':'搜尋規則...','rules.added':'規則已新增','rules.updated':'規則已更新','rules.deleted':'規則已刪除','rules.delete_confirm':'確定要刪除規則嗎？','rules.restore_confirm':'確定要恢復預設規則嗎？','rules.restored':'已恢復預設規則','rules.restore_failed':'恢復失敗','nginx.save':'儲存設定','nginx.test':'檢查語法','nginx.reload':'熱重載','nginx.restore':'恢復備份','nginx.refresh':'重新整理','nginx.save_confirm':'儲存設定將自動備份\n\n確定要儲存嗎？','nginx.reload_confirm':'將檢查語法後熱重載\n\n確定要繼續嗎？','nginx.saved':'設定已儲存','nginx.syntax_ok':'語法檢查通過','nginx.reloaded':'已重載','nginx.restored':'已恢復備份','mode.confirm':'確定要切換到{mode}嗎？','mode.switched':'已切換到','common.delete':'刪除','common.edit':'編輯','common.detail':'詳情','common.close':'關閉','common.cancel':'取消','common.success':'成功','common.error':'失敗','common.loading':'載入中...','common.permanent':'永久','common.operation':'操作','common.address':'地址','logs.rule_id':'規則 ID','logs.source_ip':'來源 IP','logs.realtime':'即時','logs.time':'時間','logs.method':'方法','logs.severity_col':'級別','logs.action_col':'操作','rules.hit':'命中','rules.desc_col':'描述','rules.severity_col':'級別','rules.target':'目標','rules.pattern':'模式','rules.action_col':'動作','rules.file_overview':'規則檔案概覽','rules.file_count':'條規則','ip.address':'IP 位址','ip.ttl_col':'TTL','rules.desc':'描述','rules.severity':'嚴重級別','rules.action':'動作','rules.pattern_label':'匹配模式 (PCRE)','rules.desc_placeholder':'規則描述','rules.pattern_placeholder':'正規表達式','rules.rule_id':'規則 ID'},'en':{'login.title':'WAF Security Console','login.token_label':'Access Token','login.token_placeholder':'Enter your access token','login.submit':'Authenticate','login.invalid':'Invalid token or access denied','login.unconfigured':'Admin panel not configured','login.server_error':'Server error','login.network_error':'Network connection failed','header.mode':'Mode:','header.intercept':'INTERCEPT','header.log_only':' LOG ONLY','header.refresh':'Refresh','header.reload_rules':'Reload Rules','header.logout':'Logout','tab.dashboard':'Dashboard','tab.logs':'Logs','tab.rules':'Rules','tab.nginx':'Nginx Config','stats.total':'Total Requests','stats.blocked':'Blocked','stats.passed':'Passed','stats.rate':'Block Rate','chart.trend':'Attack Trend','chart.category':'Attack Categories','chart.top_ip':'Top 10 Source IPs','chart.blocked':'Blocked','chart.passed':'Passed','chart.attacks':'Attacks','ip.blacklist':'IP Blacklist','ip.whitelist':'IP Whitelist','ip.add':'Add IP','ip.ttl':'TTL','ip.ttl_hint':'Unit: seconds, 0 = permanent','ip.permanent':'Permanent','ip.confirm_add':'Confirm','ip.cancel':'Cancel','ip.empty_blacklist':'No blacklist entries','ip.empty_whitelist':'No whitelist entries','ip.added':'Added','ip.deleted':'Deleted','ip.add_failed':'Add failed','ip.delete_failed':'Delete failed','ip.delete_confirm':'Are you sure?','logs.status':'Ready','logs.refresh':'Refresh Logs','logs.severity_all':'All Severities','logs.action_all':'All Actions','logs.query':'Query','logs.reset':'Reset','logs.empty':'No blocked logs','logs.ban':'Ban','logs.ban_confirm':'Ban this IP?','logs.banned':'Banned','logs.ban_failed':'Ban failed','logs.loading':'Refreshing...','logs.query_failed':'Query failed','rules.refresh':'Refresh','rules.add':'Add Rule','rules.restore':'Restore Defaults','rules.empty':'No custom rules','rules.form_title_add':'Add Custom Rule','rules.form_title_edit':'Edit Rule','rules.save':'Save','rules.cancel':'Cancel','rules.search_placeholder':'Search rules...','rules.added':'Rule added','rules.updated':'Rule updated','rules.deleted':'Rule deleted','rules.delete_confirm':'Delete this rule?','rules.restore_confirm':'Restore default rules?','rules.restored':'Defaults restored','rules.restore_failed':'Restore failed','nginx.save':'Save Config','nginx.test':'Test Syntax','nginx.reload':'Hot Reload','nginx.restore':'Restore Backup','nginx.refresh':'Refresh','nginx.save_confirm':'Saving will backup current version.\n\nContinue?','nginx.reload_confirm':'Will test syntax then reload.\n\nContinue?','nginx.saved':'Config saved','nginx.syntax_ok':'Syntax OK','nginx.reloaded':'Reloaded','nginx.restored':'Backup restored','mode.confirm':'Switch to {mode}?','mode.switched':'Switched to','common.delete':'Delete','common.edit':'Edit','common.detail':'Detail','common.close':'Close','common.cancel':'Cancel','common.success':'Success','common.error':'Error','common.loading':'Loading...','common.permanent':'Permanent','common.operation':'Action','common.address':'Address','logs.rule_id':'Rule ID','logs.source_ip':'Source IP','logs.realtime':'Realtime','logs.time':'Time','logs.method':'Method','logs.severity_col':'Severity','logs.action_col':'Action','rules.hit':'Hits','rules.desc_col':'Description','rules.severity_col':'Severity','rules.target':'Target','rules.pattern':'Pattern','rules.action_col':'Action','rules.file_overview':'Rule Files Overview','rules.file_count':'rules','ip.address':'IP Address','ip.ttl_col':'TTL','rules.desc':'Description','rules.severity':'Severity','rules.action':'Action','rules.pattern_label':'Pattern (PCRE)','rules.desc_placeholder':'Rule description','rules.pattern_placeholder':'Regular expression','rules.rule_id':'Rule ID'}};
var _lang=(function(){var s=document.cookie.match(/waf_lang=([^;]+)/);if(s&&LANGS[s[1]])return s[1];var b=(navigator.language||navigator.userLanguage||'zh-CN').toLowerCase();if(b.indexOf('tw')>=0||b.indexOf('hant')>=0)return 'zh-TW';if(b.indexOf('en')>=0)return 'en';return 'zh-CN';})();
function t(k,a){var s=(LANGS[_lang]&&LANGS[_lang][k])||k;if(a)for(var p in a)s=s.replace('{'+p+'}',a[p]);return s;}
function setLang(l){if(!LANGS[l])return;_lang=l;document.cookie='waf_lang='+l+';path=/;max-age=31536000;SameSite=Strict';applyI18n();}
function applyI18n(){document.querySelectorAll('[data-i18n]').forEach(function(el){el.textContent=t(el.getAttribute('data-i18n'));});document.querySelectorAll('[data-i18n-placeholder]').forEach(function(el){el.placeholder=t(el.getAttribute('data-i18n-placeholder'));});var ls=document.getElementById('lang-select');if(ls)ls.value=_lang;}
var _confirmCb=null;
function showConfirm(title,msg,okText,cancelText){return new Promise(function(resolve){
document.getElementById('confirm-title').textContent=title;
document.getElementById('confirm-message').textContent=msg;
document.getElementById('confirm-ok').textContent=t(okText||'common.confirm');
document.getElementById('confirm-cancel').textContent=t(cancelText||'common.cancel');
document.getElementById('confirm-overlay').classList.add('active');
_confirmCb=resolve;});}
function closeConfirm(result){document.getElementById('confirm-overlay').classList.remove('active');if(_confirmCb){_confirmCb(result);_confirmCb=null;}}
var token='';
function getToken(){
if(!token){var m=document.cookie.match(/waf_token=([^;]+)/);if(m)token=m[1];}
return token;
}
function api(method,path,body){
var opts={method:method,headers:{'Authorization':'Bearer '+getToken(),'Content-Type':'application/json'}};
if(body)opts.body=JSON.stringify(body);
return fetch(path,opts).then(function(r){
if(r.status===401||r.status===403){document.cookie='waf_token=;path=/;max-age=0';location.reload();return null;}
return r.json();
});
}
function toast(msg,type){var t=document.getElementById('toast');t.textContent=msg;t.className=type;t.style.display='block';setTimeout(function(){t.style.display='none';},3000);}
function updateModeUI(mode){
var btn=document.getElementById('mode-btn');
var txt=document.getElementById('mode-text');
if(!btn||!txt)return;
btn.className='mode-btn '+(mode==='log_only'?'log_only':'block');
txt.textContent=mode==='log_only'?t('header.log_only'):t('header.intercept');
}
function loadMode(){
api('GET','__SG_ADMIN__mode').then(function(d){
if(d&&d.mode)updateModeUI(d.mode);
});
}
function toggleMode(){
var btn=document.getElementById('mode-btn');
var current=btn.classList.contains('log_only')?'log_only':'block';
var next=current==='block'?'log_only':'block';
var label=next==='log_only'?t('header.log_only'):t('header.intercept');
showConfirm(t('mode.switched')+label,t('mode.confirm',{mode:label})).then(function(ok){
if(!ok)return;
api('POST','__SG_ADMIN__mode',{mode:next}).then(function(d){
if(d&&d.ok){updateModeUI(d.mode);toast(t('mode.switched')+label,'success');}
else{toast(t('common.error'),'error');}
});
});
}
function loadStats(){
api('GET','__SG_ADMIN__stats').then(function(d){
if(!d)return;
document.getElementById('stat-total').textContent=d.total_requests||0;
document.getElementById('stat-blocked').textContent=d.blocked_total||0;
document.getElementById('stat-passed').textContent=d.passed_total||0;
var total=d.total_requests||0,blocked=d.blocked_total||0;
document.getElementById('stat-rate').textContent=total>0?(blocked/total*100).toFixed(1)+'%':'0%';
});
api('GET','__SG_ADMIN__status').then(function(d){
if(!d)return;
document.getElementById('status-info').innerHTML=
'v'+d.version+' | '+d.status+' | '+Math.floor((d.uptime||0)/60)+'min';
});
loadList('blacklist');loadList('whitelist');
}
function loadList(type){
api('GET','__SG_ADMIN__ip/'+type).then(function(d){
if(!d)return;
var entries=d.entries||{};
var tbody=document.getElementById(type+'-table').querySelector('tbody');
var empty=document.getElementById(type+'-empty');
tbody.innerHTML='';
var keys=Object.keys(entries);
if(keys.length===0){empty.style.display='block';return;}
empty.style.display='none';
keys.forEach(function(k){
var tr=document.createElement('tr');
if(type==='blacklist'){
var ttl=entries[k].ttl;
var ttlText=ttl===0?'永久':ttl+'秒';
tr.innerHTML='<td>'+k+'</td><td>'+ttlText+'</td><td><button class="danger" style="padding:4px 10px;font-size:11px" onclick="removeIP(\''+type+'\',\''+k+'\')">删除</button></td>';
}else{
tr.innerHTML='<td>'+k+'</td><td><button class="danger" style="padding:4px 10px;font-size:11px" onclick="removeIP(\''+type+'\',\''+k+'\')">删除</button></td>';
}
tbody.appendChild(tr);
});
});
}
function reloadRules(){
api('POST','__SG_ADMIN__rules/reload').then(function(d){
if(d&&!d.error)toast('规则已重载','success');else toast('重载失败','error');
});
}
var modalType='';
function showAddModal(type){
modalType=type;
document.getElementById('modal-title').textContent=type==='blacklist'?'添加 IP 到黑名单':'添加 IP 到白名单';
document.getElementById('modal-ttl').style.display=type==='whitelist'?'none':'block';
document.getElementById('modal-overlay').classList.add('active');
document.getElementById('modal-ip').value='';
document.getElementById('modal-ip').focus();
}
function closeModal(){document.getElementById('modal-overlay').classList.remove('active');}
function confirmAdd(){
var ip=document.getElementById('modal-ip').value.trim();
if(!ip){toast('请输入 IP 地址','error');return;}
var body={ip:ip};
if(modalType==='blacklist'){body.ttl=parseInt(document.getElementById('modal-ttl').value)||0;}
api('POST','__SG_ADMIN__ip/'+modalType,body).then(function(d){
if(d&&!d.error){toast(t('ip.added'),'success');closeModal();loadList(modalType);}else{toast(d&&d.message||t('ip.add_failed'),'error');}
});
}
function removeIP(type,ip){
showConfirm(t('common.delete'),t('ip.delete_confirm'),'common.delete','common.cancel').then(function(ok){
if(!ok)return;
api('DELETE','__SG_ADMIN__ip/'+type+'/'+ip).then(function(d){
if(d&&!d.error){toast(t('ip.deleted'),'success');loadList(type);}else{toast(t('ip.delete_failed'),'error');}
});
});
}
var currentTab='dashboard',logPage=1,logTotal=0,logPerPage=20,logTimer=null;
function switchTab(tab){
currentTab=tab;
document.querySelectorAll('.tabs button').forEach(function(b,i){b.classList.toggle('active',(i===0&&tab==='dashboard')||(i===1&&tab==='logs')||(i===2&&tab==='rules')||(i===3&&tab==='nginx'));});
document.querySelectorAll('.tab-content').forEach(function(c){c.classList.remove('active');});
document.getElementById('tab-'+tab).classList.add('active');
stopLogRefresh();
if(tab==='dashboard'){loadStats();loadCharts();}else if(tab==='logs'){loadLogs();startLogRefresh();}else if(tab==='rules'){loadRuleFiles();loadCustomRules();}else if(tab==='nginx'){loadNginxConfig();}
}
function startLogRefresh(){stopLogRefresh();if(document.getElementById('realtime-toggle')&&document.getElementById('realtime-toggle').checked){logTimer=setInterval(loadLogs,5000);}}
function toggleRealtime(){if(document.getElementById('realtime-toggle').checked){startLogRefresh();toast('实时模式已开启','success');}else{stopLogRefresh();toast('实时模式已关闭','success');}}
function stopLogRefresh(){if(logTimer){clearInterval(logTimer);logTimer=null;}}
function formatTime(ts){if(!ts)return'-';var d=new Date(ts*1000);return d.toLocaleString('zh-CN',{hour12:false});}
function loadLogs(){
var params='?page='+logPage+'&per_page='+logPerPage;
var ruleId=document.getElementById('filter-rule-id').value;
var severity=document.getElementById('filter-severity').value;
var ip=document.getElementById('filter-ip').value;
var action=document.getElementById('filter-action')?document.getElementById('filter-action').value:'';
if(ruleId)params+='&rule_id='+encodeURIComponent(ruleId);
if(severity)params+='&severity='+encodeURIComponent(severity);
if(ip)params+='&source_ip='+encodeURIComponent(ip);
if(action)params+='&action='+encodeURIComponent(action);
if(logRangeStart)params+='&start_time='+encodeURIComponent(logRangeStart);
if(logRangeEnd)params+='&end_time='+encodeURIComponent(logRangeEnd);
document.getElementById('logs-status').textContent=t('logs.loading');
api('GET','__SG_ADMIN__logs'+params).then(function(d){
if(!d){document.getElementById('logs-status').textContent=t('logs.query_failed');return;}
logTotal=d.total||0;
var tbody=document.getElementById('logs-table').querySelector('tbody');
var empty=document.getElementById('logs-empty');
tbody.innerHTML='';
if(!d.logs||d.logs.length===0){empty.style.display='block';renderPagination();document.getElementById('logs-status').textContent='共 '+logTotal+' 条';return;}
empty.style.display='none';
d.logs.forEach(function(log){
var tr=document.createElement('tr');
tr.style.cursor='pointer';
tr.setAttribute('onclick',"expandLogDetail('"+log.id+"',this)");
tr.innerHTML='<td>'+formatTime(log.timestamp)+'</td><td>'+(log.source_ip||'-')+'</td><td>'+(log.method||'-')+'</td><td title="'+(log.uri||'')+'">'+(log.uri||'-')+'</td><td>'+(log.rule_id||'-')+'</td><td><span class="severity-badge '+(log.severity||'low')+'">'+(log.severity||'-')+'</span></td><td><button class="ban-btn" onclick="event.stopPropagation();banIP(\''+(log.source_ip||'')+'\')">封禁</button></td>';
tbody.appendChild(tr);
});
renderPagination();
document.getElementById('logs-status').textContent='共 '+logTotal+' 条 | 更新于 '+new Date().toLocaleTimeString('zh-CN',{hour12:false});
});
}
function renderPagination(){
var container=document.getElementById('logs-pagination');
container.innerHTML='';
var totalPages=Math.ceil(logTotal/logPerPage);
if(totalPages<=1)return;
var prev=document.createElement('button');prev.textContent='<';prev.disabled=logPage<=1;prev.onclick=function(){logPage--;loadLogs();};container.appendChild(prev);
var start=Math.max(1,logPage-2),end=Math.min(totalPages,logPage+2);
for(var i=start;i<=end;i++){var btn=document.createElement('button');btn.textContent=i;btn.className=i===logPage?'active':'';btn.onclick=(function(p){return function(){logPage=p;loadLogs();};})(i);container.appendChild(btn);}
var info=document.createElement('span');info.className='page-info';info.textContent=logPage+'/'+totalPages;container.appendChild(info);
var next=document.createElement('button');next.textContent='>';next.disabled=logPage>=totalPages;next.onclick=function(){logPage++;loadLogs();};container.appendChild(next);
}
function clearFilters(){
document.getElementById('filter-rule-id').value='';
document.getElementById('filter-severity').value='';
document.getElementById('filter-ip').value='';
if(document.getElementById('filter-action'))document.getElementById('filter-action').value='';
logRangeStart=0;logRangeEnd=0;
document.querySelectorAll('.range-btn').forEach(function(b){b.classList.remove('active');});
document.querySelectorAll('.range-btn')[2].classList.add('active');
logPage=1;loadLogs();
}
function showLogDetail(id){
api('GET','__SG_ADMIN__logs/'+id).then(function(log){
if(!log||log.error){toast('获取日志详情失败','error');return;}
var html='';
var fields=[['时间',formatTime(log.timestamp)],['源IP',log.source_ip],['方法',log.method],['URI',log.uri],['Query',log.query_string],['规则ID',log.rule_id],['级别',log.severity],['动作',log.action],['原因',log.reason],['Host',log.host],['User-Agent',log.user_agent]];
fields.forEach(function(f){html+='<div class="label">'+f[0]+':</div><div class="value">'+(f[1]||'-')+'</div>';});
document.getElementById('log-detail-content').innerHTML=html;
document.getElementById('log-detail-modal').classList.add('active');
});
}
function closeLogDetail(){document.getElementById('log-detail-modal').classList.remove('active');}
var editingRuleId=null;
function toggleRuleForm(rule){
var form=document.getElementById('rule-form');
if(form.classList.contains('active')){form.classList.remove('active');editingRuleId=null;return;}
form.classList.add('active');
if(rule){
editingRuleId=rule.id;
document.getElementById('rule-form-title').textContent=t('rules.form_title_edit')+' '+rule.id;
document.getElementById('rf-id').value=rule.id;document.getElementById('rf-id').disabled=true;
document.getElementById('rf-desc').value=rule.description||'';
document.getElementById('rf-severity').value=rule.severity||'medium';
document.getElementById('rf-target').value=rule.target||'URI';
document.getElementById('rf-action').value=rule.action||'BLOCK';
document.getElementById('rf-pattern').value=rule.pattern||'';
}else{
editingRuleId=null;
document.getElementById('rule-form-title').textContent=t('rules.form_title_add');
document.getElementById('rf-id').value='';document.getElementById('rf-id').disabled=false;
document.getElementById('rf-desc').value='';
document.getElementById('rf-severity').value='medium';
document.getElementById('rf-target').value='URI';
document.getElementById('rf-action').value='BLOCK';
document.getElementById('rf-pattern').value='';
}
document.getElementById('rule-form-msg').textContent='';
}
function loadCustomRules(){
api('GET','__SG_ADMIN__rules/custom').then(function(d){
if(!d)return;
var rules=Array.isArray(d.rules)?d.rules:Object.values(d.rules||{});
var tbody=document.getElementById('custom-rules-table').querySelector('tbody');
var empty=document.getElementById('custom-rules-empty');
tbody.innerHTML='';
if(rules.length===0){empty.style.display='block';return;}
empty.style.display='none';
rules.forEach(function(r){
var tr=document.createElement('tr');
var hits=r.hit_count||r.hits||0;
var hitClass=hits>0?'active':'zero';
tr.innerHTML='<td>'+r.id+'</td><td><span class="hit-badge '+hitClass+'">'+hits+'</span></td><td>'+(r.description||'-')+'</td><td><span class="severity-badge '+(r.severity||'low')+'">'+(r.severity||'-')+'</span></td><td>'+(r.target||'-')+'</td><td style="max-width:200px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap" title="'+(r.pattern||'')+'">'+(r.pattern||'-')+'</td><td>'+(r.action||'-')+'</td><td><button class="test-btn" onclick="testRule(\''+r.id+'\')">测试</button><button style="padding:3px 8px;font-size:11px;background:#334155;border:1px solid #475569;color:#cbd5e1;border-radius:4px;cursor:pointer;margin-right:4px" onclick="editRule(\''+r.id+'\')">编辑</button><button style="padding:3px 8px;font-size:11px;background:#dc2626;border:1px solid #dc2626;color:#fff;border-radius:4px;cursor:pointer" onclick="deleteRule(\''+r.id+'\')">删除</button></td>';
tbody.appendChild(tr);
});
});
}
function loadRuleFiles(){
api('GET','__SG_ADMIN__rules/list').then(function(d){
if(!d||!d.files)return;
var html='';
d.files.forEach(function(f){
html+='<span style="display:inline-block;margin:4px 8px 4px 0;padding:4px 10px;background:#1e293b;border:1px solid #334155;border-radius:4px">'+f.filename+': <b>'+(f.rule_count||0)+'</b> '+t('rules.file_count')+'</span>';
});
document.getElementById('rule-files-list').innerHTML=html||'无规则文件';
});
}
function saveRule(){
var id=document.getElementById('rf-id').value.trim();
var desc=document.getElementById('rf-desc').value.trim();
var severity=document.getElementById('rf-severity').value;
var target=document.getElementById('rf-target').value;
var action=document.getElementById('rf-action').value;
var pattern=document.getElementById('rf-pattern').value.trim();
if(!id||!desc||!pattern){document.getElementById('rule-form-msg').textContent='请填写所有必填字段';return;}
var rule={id:id,description:desc,severity:severity,target:target,action:action,pattern:pattern};
if(editingRuleId){
api('PUT','__SG_ADMIN__rules/custom/'+editingRuleId,rule).then(function(d){
if(d&&!d.error){toast('规则已更新','success');toggleRuleForm();loadCustomRules();}else{document.getElementById('rule-form-msg').textContent=d&&d.message||'更新失败';}
});
}else{
api('POST','__SG_ADMIN__rules/custom',rule).then(function(d){
if(d&&!d.error){toast('规则已添加','success');toggleRuleForm();loadCustomRules();}else{document.getElementById('rule-form-msg').textContent=d&&d.message||'添加失败';}
});
}
}
function editRule(id){
api('GET','__SG_ADMIN__rules/custom').then(function(d){
if(!d||!d.rules)return;
var rule=d.rules.find(function(r){return r.id===id;});
if(rule)toggleRuleForm(rule);
});
}
function deleteRule(id){
showConfirm(t('common.delete'),t('rules.delete_confirm'),'common.delete','common.cancel').then(function(ok){
if(!ok)return;
api('DELETE','__SG_ADMIN__rules/custom/'+id).then(function(d){
if(d&&!d.error){toast(t('rules.deleted'),'success');loadCustomRules();}else{toast(d&&d.message||t('common.error'),'error');}
});
});
}
function restoreDefaultRules(){
showConfirm(t('rules.restore'),t('rules.restore_confirm'),'rules.restore','common.cancel').then(function(ok){
if(!ok)return;
api('POST','__SG_ADMIN__rules/restore-default').then(function(d){
if(d&&!d.error){toast(t('rules.restored'),'success');loadCustomRules();}else{toast(d&&d.message||t('rules.restore_failed'),'error');}
});
});
}
var trendChart,categoryChart,topIpChart;
function initCharts(){
Chart.defaults.color='#a78bfa';
Chart.defaults.borderColor='rgba(138,43,226,0.1)';
trendChart=new Chart(document.getElementById('trendChart'),{type:'line',data:{labels:[],datasets:[{label:'拦截',data:[],borderColor:'#ff006e',backgroundColor:'rgba(255,0,110,0.1)',fill:true,tension:0.4},{label:'放行',data:[],borderColor:'#00ff88',backgroundColor:'rgba(0,255,136,0.1)',fill:true,tension:0.4}]},options:{responsive:true,plugins:{legend:{position:'top',labels:{font:{family:'Rajdhani'}}}},scales:{x:{grid:{color:'rgba(138,43,226,0.06)'}},y:{grid:{color:'rgba(138,43,226,0.06)'},beginAtZero:true}}}});
categoryChart=new Chart(document.getElementById('categoryChart'),{type:'doughnut',data:{labels:[],datasets:[{data:[],backgroundColor:[]}]},options:{responsive:true,plugins:{legend:{position:'bottom',labels:{font:{family:'Rajdhani'}}}},cutout:'60%'}});
topIpChart=new Chart(document.getElementById('topIpChart'),{type:'bar',data:{labels:[],datasets:[{label:'攻击次数',data:[],backgroundColor:'rgba(138,43,226,0.4)',borderColor:'#8a2be2',borderWidth:1}]},options:{indexAxis:'y',responsive:true,plugins:{legend:{display:false}},scales:{x:{grid:{color:'rgba(138,43,226,0.06)'}},y:{grid:{display:false}}}}});
}
function loadTrend(r){
api('GET','__SG_ADMIN__stats/trend?range='+r).then(function(d){
if(!d)return;trendChart.data.labels=d.labels;trendChart.data.datasets[0].data=d.blocked;trendChart.data.datasets[1].data=d.passed;trendChart.update();
});
document.querySelectorAll('.range-btn').forEach(function(b){b.classList.toggle('active',b.textContent.indexOf(r==='24h'?'24':'7')>-1);});
}
function loadCharts(){
loadTrend('24h');
api('GET','__SG_ADMIN__stats/categories').then(function(d){
if(!d||!d.categories)return;categoryChart.data.labels=d.categories.map(function(c){return c.name});categoryChart.data.datasets[0].data=d.categories.map(function(c){return c.count});categoryChart.data.datasets[0].backgroundColor=d.categories.map(function(c){return c.color});categoryChart.update();
});
api('GET','__SG_ADMIN__stats/top-ip?limit=10').then(function(d){
if(!d||!d.items)return;topIpChart.data.labels=d.items.map(function(i){return i.ip});topIpChart.data.datasets[0].data=d.items.map(function(i){return i.count});topIpChart.update();
});
}
initCharts();
loadMode();
loadStats();
loadCharts();
setInterval(loadStats,30000);
applyI18n();
function showNginxOutput(text,isSuccess){
var el=document.getElementById('nginx-output');
el.textContent=text;el.className='output-area show '+(isSuccess?'success':'error');
}
function clearNginxOutput(){document.getElementById('nginx-output').className='output-area';}
function setNginxStatus(msg){document.getElementById('nginx-status').textContent=msg;}
function loadNginxConfig(){
setNginxStatus(t('common.loading'));
api('GET','__SG_ADMIN__nginx/config').then(function(d){
if(d&&!d.error){
document.getElementById('nginx-editor').value=d.content||'';
setNginxStatus(t('nginx.loaded')+' | '+new Date().toLocaleTimeString('zh-CN',{hour12:false})+' | '+d.content.length+' bytes');
clearNginxOutput();
}else{setNginxStatus(t('common.error'));showNginxOutput(d&&d.error||t('common.error'),false);}
});
}
function saveNginxConfig(){
var content=document.getElementById('nginx-editor').value;
if(!content){toast(t('common.error'),'error');return;}
showConfirm(t('nginx.save'),t('nginx.save_confirm'),'nginx.save','common.cancel').then(function(ok){
if(!ok)return;
setNginxStatus(t('common.loading'));
api('PUT','__SG_ADMIN__nginx/config',{content:content}).then(function(d){
if(d&&!d.error){toast(t('nginx.saved'),'success');setNginxStatus(t('nginx.saved')+' | '+new Date().toLocaleTimeString('zh-CN',{hour12:false}));showNginxOutput(d.message||t('nginx.saved'),true);}
else{toast(t('common.error'),'error');setNginxStatus(t('common.error'));showNginxOutput(d&&d.message||t('common.error'),false);}
});
});
}
function testNginxConfig(){
setNginxStatus(t('common.loading'));
api('POST','__SG_ADMIN__nginx/test').then(function(d){
if(!d){setNginxStatus(t('common.error'));return;}
var ok=d.ok;
showNginxOutput(d.output||'',ok);
setNginxStatus(ok?t('nginx.syntax_ok'):t('nginx.test_failed'));
toast(ok?t('nginx.syntax_ok'):t('nginx.test_failed'),ok?'success':'error');
});
}
function reloadNginx(){
showConfirm(t('nginx.reload'),t('nginx.reload_confirm'),'nginx.reload','common.cancel').then(function(ok){
if(!ok)return;
setNginxStatus(t('common.loading'));
api('POST','__SG_ADMIN__nginx/reload').then(function(d){
if(!d){setNginxStatus(t('common.error'));return;}
showNginxOutput(d.output||'',d.ok);
setNginxStatus(d.ok?t('nginx.reloaded'):t('nginx.reload_failed'));
toast(d.ok?t('nginx.reloaded'):t('nginx.reload_failed'),d.ok?'success':'error');
});
});
}
function restoreNginxBackup(){
showConfirm(t('nginx.restore'),t('nginx.save_confirm'),'nginx.restore','common.cancel').then(function(ok){
if(!ok)return;
setNginxStatus(t('common.loading'));
api('POST','__SG_ADMIN__nginx/restore-backup').then(function(d){
if(d&&!d.error){toast(t('nginx.restored'),'success');loadNginxConfig();}
else{toast(t('nginx.restore_failed'),'error');setNginxStatus(t('common.error'));}
});
});
}
var logRangeStart=0,logRangeEnd=0;
function setRange(range){
var now=Math.floor(Date.now()/1000);
var map={'1h':3600,'6h':21600,'24h':86400,'7d':604800};
logRangeEnd=now;logRangeStart=now-(map[range]||86400);
document.querySelectorAll('.range-btn').forEach(function(b){b.classList.remove('active');});
event.target.classList.add('active');
loadLogs();
}
function expandLogDetail(id,row){
var next=row.nextElementSibling;
if(next&&next.querySelector('.log-detail')){next.style.display=next.style.display==='none'?'':'none';return;}
api('GET','__SG_ADMIN__logs/'+id).then(function(log){
if(!log||log.error)return;
var h='<div class="log-detail"><div class="detail-grid">';
[['时间',formatTime(log.timestamp)],['源IP',log.source_ip],['方法',log.method],['URI',log.uri],['Query',log.query_string],['规则ID',log.rule_id],['级别',log.severity],['动作',log.action],['原因',log.reason],['Host',log.host],['UA',log.user_agent]].forEach(function(f){h+='<div class="dlabel">'+f[0]+':</div><div class="dvalue">'+(f[1]||'-')+'</div>';});
h+='</div></div>';
var tr=document.createElement('tr');tr.innerHTML='<td colspan="7">'+h+'</td>';
row.parentNode.insertBefore(tr,row.nextSibling);
});
}
function banIP(ip){
showConfirm(t('logs.ban'),t('logs.ban_confirm'),'logs.ban','common.cancel').then(function(ok){
if(!ok)return;
api('POST','__SG_ADMIN__logs/ban-ip',{ip:ip,ttl:0}).then(function(d){
if(d&&!d.error)toast(t('logs.banned'),'success');else toast(t('logs.ban_failed'),'error');
});
});
}
function testRule(id){
var payload=prompt('请输入测试载荷:','');
if(!payload)return;
api('POST','__SG_ADMIN__rules/custom/'+id+'/test',{payload:payload}).then(function(d){
if(d&&!d.error){var msg=d.matched?'规则匹配! 命中: '+d.matched:'未匹配';toast(msg,d.matched?'success':'error');}
else{toast('测试失败: '+(d&&d.error||''),'error');}
});
}
function filterRules(){
var q=document.getElementById('rule-search').value.toLowerCase();
var rows=document.getElementById('custom-rules-table').querySelector('tbody').querySelectorAll('tr');
rows.forEach(function(tr){
var text=tr.textContent.toLowerCase();
tr.style.display=(!q||text.indexOf(q)>-1)?'':'none';
});
}
</script>
</body>
</html>
]=]

-- Inject configurable admin path prefix into HTML/JS
LOGIN_HTML = LOGIN_HTML:gsub("__SG_ADMIN__", ADMIN_PATH)
DASHBOARD_HTML = DASHBOARD_HTML:gsub("__SG_ADMIN__", ADMIN_PATH)

-- JS Challenge page for CC protection (placeholders replaced at render time in challenge.lua)
local CHALLENGE_HTML = [=[<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>安全验证 - Moat WAF</title>
<link href="/__waf_static__/fonts.css" rel="stylesheet">
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:'Rajdhani',sans-serif;background:#0d0221;color:#e0d7ff;min-height:100vh;display:flex;align-items:center;justify-content:center}
body::before{content:'';position:fixed;inset:0;background:linear-gradient(rgba(138,43,226,0.06) 1px,transparent 1px),linear-gradient(90deg,rgba(138,43,226,0.06) 1px,transparent 1px);background-size:40px 40px;pointer-events:none}
.card{background:rgba(13,2,33,0.8);backdrop-filter:blur(20px);border:1px solid rgba(138,43,226,0.2);border-radius:16px;padding:40px;text-align:center;max-width:400px;width:90%;position:relative}
.card::before{content:'';position:absolute;top:0;left:0;right:0;height:2px;background:linear-gradient(90deg,transparent,#8a2be2,#00b4ff,transparent);border-radius:16px 16px 0 0}
h1{font-family:'Orbitron',sans-serif;font-size:16px;background:linear-gradient(135deg,#8a2be2,#00b4ff);-webkit-background-clip:text;-webkit-text-fill-color:transparent;margin-bottom:12px;letter-spacing:2px}
p{color:#a78bfa;font-size:14px;margin-bottom:20px}
.spinner{width:40px;height:40px;border:3px solid rgba(138,43,226,0.2);border-top-color:#8a2be2;border-radius:50%;animation:spin 0.8s linear infinite;margin:0 auto 20px}
@keyframes spin{to{transform:rotate(360deg)}}
.status{font-size:13px;color:#6b5b8a}
.error{color:#ff006e;margin-top:12px;display:none}
.retry-btn{background:linear-gradient(135deg,rgba(138,43,226,0.3),rgba(0,180,255,0.2));border:1px solid rgba(138,43,226,0.5);color:#e0d7ff;padding:10px 24px;border-radius:8px;cursor:pointer;font-family:'Orbitron',sans-serif;font-size:11px;letter-spacing:1px;margin-top:16px;display:none}
</style>
</head>
<body>
<div class="card">
<h1>SECURITY CHECK</h1>
<div class="spinner" id="spinner"></div>
<p>安全验证中，请稍候...</p>
<div class="status" id="status">正在计算验证...</div>
<div class="error" id="error">验证失败，请重试</div>
<button class="retry-btn" id="retryBtn" onclick="doChallenge()">重试</button>
</div>
<script>
var challenge=__CHALLENGE_DATA__;
function doChallenge(){
document.getElementById('spinner').style.display='block';
document.getElementById('error').style.display='none';
document.getElementById('retryBtn').style.display='none';
document.getElementById('status').textContent='正在计算验证...';
try{
var answer=challenge.a+challenge.b;
fetch('__SG_ADMIN__challenge/verify',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({answer:answer,token:challenge.token,redirect:challenge.redirect})})
.then(function(r){return r.json()})
.then(function(d){
if(d.ok){document.getElementById('status').textContent='验证通过，正在跳转...';window.location.href=d.redirect||'/';}
else{showError();}
}).catch(function(){showError();});
}catch(e){showError();}
}
function showError(){
document.getElementById('spinner').style.display='none';
document.getElementById('error').style.display='block';
document.getElementById('retryBtn').style.display='inline-block';
document.getElementById('status').textContent='';
}
doChallenge();
</script>
</body>
</html>]=]

return { LOGIN_HTML = LOGIN_HTML, DASHBOARD_HTML = DASHBOARD_HTML, CHALLENGE_HTML = CHALLENGE_HTML }
