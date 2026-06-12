var App = (function () {
    var currentPage = "dashboard";

    function showLogin() {
        document.getElementById("login-page").hidden = false;
        document.getElementById("app").hidden = true;
    }

    function showApp() {
        document.getElementById("login-page").hidden = true;
        document.getElementById("app").hidden = false;
    }

    function navigateTo(page) {
        document.querySelectorAll(".page").forEach(function (el) {
            el.classList.remove("active");
        });
        document.querySelectorAll(".nav-item").forEach(function (el) {
            el.classList.remove("active");
        });

        var pageEl = document.getElementById("page-" + page);
        if (pageEl) pageEl.classList.add("active");

        var navItem = document.querySelector('.nav-item[data-page="' + page + '"]');
        if (navItem) navItem.classList.add("active");

        currentPage = page;

        if (page === "dashboard") {
            Dashboard.start();
        } else {
            Dashboard.stop();
        }

        if (page === "blacklist") Rules.loadBlacklist();
        if (page === "whitelist") Rules.loadWhitelist();
        if (page === "cc-config") Rules.loadCCConfig();
    }

    function initNav() {
        document.querySelectorAll(".nav-item").forEach(function (el) {
            el.addEventListener("click", function (e) {
                e.preventDefault();
                var page = el.getAttribute("data-page");
                if (page) navigateTo(page);
            });
        });
    }

    function initLogin() {
        var form = document.getElementById("login-form");
        var errorEl = document.getElementById("login-error");

        form.addEventListener("submit", function (e) {
            e.preventDefault();
            var token = document.getElementById("token-input").value.trim();
            if (!token) return;

            errorEl.hidden = true;
            API.setToken(token);

            API.getStatus().then(function () {
                showApp();
                Rules.init();
                navigateTo("dashboard");
            }).catch(function (err) {
                API.clearToken();
                errorEl.hidden = false;
                errorEl.textContent = err.message || "Authentication failed.";
            });
        });
    }

    function initLogout() {
        var btn = document.getElementById("logout-btn");
        btn.addEventListener("click", function () {
            Dashboard.stop();
            API.clearToken();
            showLogin();
            document.getElementById("token-input").value = "";
        });
    }

    function init() {
        initLogin();
        initLogout();
        initNav();

        if (API.hasToken()) {
            API.getStatus().then(function () {
                showApp();
                Rules.init();
                navigateTo("dashboard");
            }).catch(function () {
                API.clearToken();
                showLogin();
            });
        } else {
            showLogin();
        }
    }

    return { init: init };
})();

document.addEventListener("DOMContentLoaded", App.init);
