(function installAuthFetchGuard() {
    const originalFetch = window.fetch.bind(window);
    let refreshing = null;

    window.fetch = async function (input, init) {
        const url = typeof input === "string" ? input : input.url;
        const response = await originalFetch(input, init);

        if (response.status !== 401 || !url.startsWith("/api/") || url.startsWith("/api/auth/")) {
            return response;
        }

        if (!refreshing) {
            refreshing = Auth.refresh().finally(() => { refreshing = null; });
        }
        const refreshed = await refreshing;
        if (!refreshed) {
            window.location.href = "/login";
            return response;
        }
        return originalFetch(input, init);
    };
})();

const Auth = {
    async me() {
        const res = await fetch("/api/auth/me");
        if (!res.ok) return null;
        const data = await res.json();
        return data.ok ? data.user : null;
    },
    async login(username, password) {
        const res = await fetch("/api/auth/login", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ username, password })
        });
        const data = await res.json();
        return { status: res.status, data };
    },
    async logout() {
        await fetch("/api/auth/logout", { method: "POST" });
        window.location.href = "/login";
    },
    async refresh() {
        const res = await fetch("/api/auth/refresh", { method: "POST" });
        return res.ok;
    }
};

function initLoginForm() {
    const form = document.getElementById("login-form");
    if (!form) return;

    const errorBox = document.getElementById("login-error");
    const errorText = document.getElementById("login-error-text");
    const submitBtn = document.getElementById("login-submit");
    const usernameInput = document.getElementById("login-username");
    const passwordInput = document.getElementById("login-password");
    const toggleBtn = document.getElementById("toggle-password");

    const showError = (message) => {
        errorText.textContent = message;
        errorBox.classList.remove("visible");
        void errorBox.offsetWidth;
        errorBox.classList.add("visible");
    };

    if (toggleBtn) {
        toggleBtn.addEventListener("click", () => {
            const isHidden = passwordInput.type === "password";
            passwordInput.type = isHidden ? "text" : "password";
            toggleBtn.classList.toggle("active", isHidden);
        });
    }

    form.addEventListener("submit", async (event) => {
        event.preventDefault();
        errorBox.classList.remove("visible");
        submitBtn.disabled = true;
        submitBtn.classList.add("is-loading");

        const username = usernameInput.value.trim();
        const password = passwordInput.value;

        try {
            const { status, data } = await Auth.login(username, password);
            if (status === 200 && data.ok) {
                submitBtn.querySelector(".auth-submit-label").textContent = "Redirecting...";
                window.location.href = "/";
                return;
            }
            showError(data.error || "Could not sign in");
        } catch (err) {
            showError("Network error. Please try again.");
        } finally {
            submitBtn.disabled = false;
            submitBtn.classList.remove("is-loading");
        }
    });
}

async function initSessionBar() {
    const topbar = document.querySelector(".topbar");
    if (!topbar) return;

    const user = await Auth.me();
    if (!user) {
        window.location.href = "/login";
        return;
    }

    AppState.user = user;
    AppState.canCreate = ["analyst", "operator", "admin", "super_admin"].includes(user.role);
    AppState.canDelete = ["operator", "admin", "super_admin"].includes(user.role);

    const wrap = document.createElement("div");
    wrap.className = "topbar-user";
    wrap.innerHTML = `
        <span class="topbar-username">${Util.esc(user.username)}</span>
        <span class="topbar-role-badge">${Util.esc(user.role)}</span>
        <button type="button" class="topbar-logout" id="logout-btn">Logout</button>
    `;
    topbar.appendChild(wrap);

    document.getElementById("logout-btn").addEventListener("click", () => Auth.logout());

    if (["manager", "admin", "super_admin"].includes(user.role)) {
        const adminLink = document.getElementById("nav-admin-panel");
        if (adminLink) adminLink.hidden = false;
    }
}

document.addEventListener("DOMContentLoaded", () => {
    initLoginForm();
    const ready = initSessionBar();
    if (typeof AppState !== "undefined") AppState.ready = ready;
});
