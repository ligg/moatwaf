var API = (function () {
    var BASE = "/admin";

    function getToken() {
        return localStorage.getItem("moat_admin_token") || "";
    }

    function setToken(token) {
        localStorage.setItem("moat_admin_token", token);
    }

    function clearToken() {
        localStorage.removeItem("moat_admin_token");
    }

    function hasToken() {
        return !!getToken();
    }

    function request(method, path, body) {
        var opts = {
            method: method,
            headers: {
                "Authorization": "Bearer " + getToken(),
                "Content-Type": "application/json"
            }
        };
        if (body !== undefined) {
            opts.body = JSON.stringify(body);
        }
        return fetch(BASE + path, opts).then(function (res) {
            return res.json().then(function (data) {
                if (!res.ok) {
                    var msg = data.message || data.error || ("HTTP " + res.status);
                    throw new Error(msg);
                }
                return data;
            });
        });
    }

    return {
        getToken: getToken,
        setToken: setToken,
        clearToken: clearToken,
        hasToken: hasToken,
        getStatus: function () { return request("GET", "/status"); },
        getStats: function () { return request("GET", "/stats"); },
        reloadRules: function () { return request("POST", "/rules/reload"); },
        getBlacklist: function () { return request("GET", "/ip/blacklist"); },
        addBlacklist: function (ip, ttl) {
            var body = { ip: ip };
            if (ttl) body.ttl = ttl;
            return request("POST", "/ip/blacklist", body);
        },
        removeBlacklist: function (ip) { return request("DELETE", "/ip/blacklist/" + encodeURIComponent(ip)); },
        getWhitelist: function () { return request("GET", "/ip/whitelist"); },
        addWhitelist: function (ip) { return request("POST", "/ip/whitelist", { ip: ip }); },
        removeWhitelist: function (ip) { return request("DELETE", "/ip/whitelist/" + encodeURIComponent(ip)); },
        getCCConfig: function () { return request("GET", "/cc/config"); },
        saveCCConfig: function (config) { return request("POST", "/cc/config", config); }
    };
})();
