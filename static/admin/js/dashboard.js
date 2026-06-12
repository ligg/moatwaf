var Dashboard = (function () {
    var refreshTimer = null;
    var REFRESH_INTERVAL = 5000;

    var ATTACK_TYPES = [
        { key: "blocked_sqli",    label: "SQL Injection", cls: "sqli" },
        { key: "blocked_xss",     label: "XSS",          cls: "xss" },
        { key: "blocked_cmdi",    label: "CMD Injection", cls: "cmdi" },
        { key: "blocked_cc",      label: "CC Attack",    cls: "cc" },
        { key: "blocked_ip",      label: "Blocked IP",   cls: "blocked-ip" },
        { key: "blocked_other",   label: "Other",        cls: "other" }
    ];

    function formatNumber(n) {
        if (n === null || n === undefined) return "--";
        return Number(n).toLocaleString();
    }

    function formatTime(ts) {
        if (!ts || ts === 0) return "Never";
        var d = new Date(ts * 1000);
        return d.toLocaleTimeString();
    }

    function updateStats(data) {
        document.getElementById("stat-total").textContent = formatNumber(data.total_requests);
        document.getElementById("stat-passed").textContent = formatNumber(data.passed_total);
        document.getElementById("stat-blocked").textContent = formatNumber(data.blocked_total);
        document.getElementById("stat-last-time").textContent = formatTime(data.last_request_time);

        var max = 1;
        ATTACK_TYPES.forEach(function (t) {
            var v = Number(data[t.key]) || 0;
            if (v > max) max = v;
        });

        var container = document.getElementById("attack-bars");
        container.innerHTML = "";

        ATTACK_TYPES.forEach(function (t) {
            var count = Number(data[t.key]) || 0;
            var pct = max > 0 ? (count / max) * 100 : 0;

            var row = document.createElement("div");
            row.className = "bar-row";

            var label = document.createElement("span");
            label.className = "bar-label";
            label.textContent = t.label;

            var track = document.createElement("div");
            track.className = "bar-track";

            var bar = document.createElement("div");
            bar.className = "bar " + t.cls;
            track.appendChild(bar);

            var countEl = document.createElement("span");
            countEl.className = "bar-count";
            countEl.textContent = formatNumber(count);

            row.appendChild(label);
            row.appendChild(track);
            row.appendChild(countEl);
            container.appendChild(row);

            requestAnimationFrame(function () {
                bar.style.width = pct + "%";
            });
        });
    }

    function updateStatus(data) {
        var container = document.getElementById("system-status");
        container.innerHTML = "";

        if (data.modules) {
            Object.keys(data.modules).forEach(function (name) {
                var item = document.createElement("div");
                item.className = "status-item";

                var dot = document.createElement("span");
                dot.className = "status-dot ok";

                var text = document.createElement("span");
                text.className = "status-name";
                text.textContent = name;

                item.appendChild(dot);
                item.appendChild(text);
                container.appendChild(item);
            });
        }

        if (data.version) {
            var badge = document.getElementById("version-badge");
            if (badge) badge.textContent = "v" + data.version;
        }
    }

    function refresh() {
        API.getStats().then(updateStats).catch(function () {});
        API.getStatus().then(updateStatus).catch(function () {});
    }

    function start() {
        refresh();
        stop();
        refreshTimer = setInterval(refresh, REFRESH_INTERVAL);
    }

    function stop() {
        if (refreshTimer) {
            clearInterval(refreshTimer);
            refreshTimer = null;
        }
    }

    return { start: start, stop: stop, refresh: refresh };
})();
