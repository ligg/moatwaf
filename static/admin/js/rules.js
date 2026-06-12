var Rules = (function () {
    function showStatus(el, message, isError) {
        el.hidden = false;
        el.className = "reload-status " + (isError ? "error" : "success");
        el.textContent = message;
    }

    function escapeHTML(str) {
        var div = document.createElement("div");
        div.appendChild(document.createTextNode(str));
        return div.innerHTML;
    }

    function initReload() {
        var btn = document.getElementById("reload-rules-btn");
        var status = document.getElementById("reload-status");
        if (!btn) return;

        btn.addEventListener("click", function () {
            btn.disabled = true;
            btn.textContent = "Reloading...";

            API.reloadRules().then(function (data) {
                showStatus(status, data.message || "Rules reloaded successfully.", false);
            }).catch(function (err) {
                showStatus(status, err.message, true);
            }).finally(function () {
                btn.disabled = false;
                btn.textContent = "Reload Rules";
            });
        });
    }

    function renderIPTable(tbodyId, emptyId, entries, removeFn) {
        var tbody = document.getElementById(tbodyId);
        var emptyMsg = document.getElementById(emptyId);
        tbody.innerHTML = "";

        var keys = Object.keys(entries || {});
        if (keys.length === 0) {
            emptyMsg.hidden = false;
            return;
        }
        emptyMsg.hidden = true;

        keys.forEach(function (ip) {
            var tr = document.createElement("tr");

            var tdIP = document.createElement("td");
            tdIP.textContent = ip;

            var tdVal = document.createElement("td");
            tdVal.textContent = String(entries[ip]);

            var tdAction = document.createElement("td");
            var btn = document.createElement("button");
            btn.className = "btn btn-danger btn-sm";
            btn.textContent = "Remove";
            btn.addEventListener("click", function () {
                btn.disabled = true;
                removeFn(ip).then(function () {
                    loadBlacklist();
                    loadWhitelist();
                }).catch(function () {
                    btn.disabled = false;
                });
            });
            tdAction.appendChild(btn);

            tr.appendChild(tdIP);
            tr.appendChild(tdVal);
            tr.appendChild(tdAction);
            tbody.appendChild(tr);
        });
    }

    function loadBlacklist() {
        API.getBlacklist().then(function (data) {
            renderIPTable("blacklist-tbody", "blacklist-empty", data.entries, API.removeBlacklist);
        }).catch(function () {});
    }

    function loadWhitelist() {
        API.getWhitelist().then(function (data) {
            renderIPTable("whitelist-tbody", "whitelist-empty", data.entries, API.removeWhitelist);
        }).catch(function () {});
    }

    function initBlacklist() {
        var form = document.getElementById("blacklist-add-form");
        var refreshBtn = document.getElementById("refresh-blacklist-btn");
        if (!form) return;

        form.addEventListener("submit", function (e) {
            e.preventDefault();
            var ipInput = document.getElementById("blacklist-ip-input");
            var ttlInput = document.getElementById("blacklist-ttl-input");
            var ip = ipInput.value.trim();
            var ttl = ttlInput.value ? parseInt(ttlInput.value, 10) : null;

            if (!ip) return;

            API.addBlacklist(ip, ttl).then(function () {
                ipInput.value = "";
                ttlInput.value = "";
                loadBlacklist();
            }).catch(function (err) {
                alert(err.message);
            });
        });

        if (refreshBtn) {
            refreshBtn.addEventListener("click", loadBlacklist);
        }
    }

    function initWhitelist() {
        var form = document.getElementById("whitelist-add-form");
        var refreshBtn = document.getElementById("refresh-whitelist-btn");
        if (!form) return;

        form.addEventListener("submit", function (e) {
            e.preventDefault();
            var ipInput = document.getElementById("whitelist-ip-input");
            var ip = ipInput.value.trim();
            if (!ip) return;

            API.addWhitelist(ip).then(function () {
                ipInput.value = "";
                loadWhitelist();
            }).catch(function (err) {
                alert(err.message);
            });
        });

        if (refreshBtn) {
            refreshBtn.addEventListener("click", loadWhitelist);
        }
    }

    function loadCCConfig() {
        API.getCCConfig().then(function (data) {
            if (data.ip_qps_limit !== undefined) document.getElementById("cc-ip-qps").value = data.ip_qps_limit;
            if (data.ip_conn_limit !== undefined) document.getElementById("cc-ip-conn").value = data.ip_conn_limit;
            if (data.global_qps_limit !== undefined) document.getElementById("cc-global-qps").value = data.global_qps_limit;
            if (data.window_size !== undefined) document.getElementById("cc-window").value = data.window_size;
        }).catch(function () {});
    }

    function initCCConfig() {
        var form = document.getElementById("cc-config-form");
        var status = document.getElementById("cc-config-status");
        if (!form) return;

        form.addEventListener("submit", function (e) {
            e.preventDefault();
            var config = {};

            var ipQps = document.getElementById("cc-ip-qps").value;
            var ipConn = document.getElementById("cc-ip-conn").value;
            var globalQps = document.getElementById("cc-global-qps").value;
            var window = document.getElementById("cc-window").value;

            if (ipQps) config.ip_qps_limit = parseInt(ipQps, 10);
            if (ipConn) config.ip_conn_limit = parseInt(ipConn, 10);
            if (globalQps) config.global_qps_limit = parseInt(globalQps, 10);
            if (window) config.window_size = parseInt(window, 10);

            if (Object.keys(config).length === 0) {
                showStatus(status, "No changes to save.", true);
                return;
            }

            API.saveCCConfig(config).then(function (data) {
                showStatus(status, data.message || "Configuration saved.", false);
                if (data.config) {
                    if (data.config.ip_qps_limit !== undefined) document.getElementById("cc-ip-qps").value = data.config.ip_qps_limit;
                    if (data.config.ip_conn_limit !== undefined) document.getElementById("cc-ip-conn").value = data.config.ip_conn_limit;
                    if (data.config.global_qps_limit !== undefined) document.getElementById("cc-global-qps").value = data.config.global_qps_limit;
                    if (data.config.window_size !== undefined) document.getElementById("cc-window").value = data.config.window_size;
                }
            }).catch(function (err) {
                showStatus(status, err.message, true);
            });
        });
    }

    function init() {
        initReload();
        initBlacklist();
        initWhitelist();
        initCCConfig();
    }

    return {
        init: init,
        loadBlacklist: loadBlacklist,
        loadWhitelist: loadWhitelist,
        loadCCConfig: loadCCConfig
    };
})();
