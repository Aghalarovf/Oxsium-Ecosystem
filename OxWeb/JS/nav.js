let applicationViewToken = 0;

const Nav = {
    async show(view) {
        const applicationViews = [
            "whois-dns-information", "application-technologies", "subdomain-discovery",
            "archive-dorks", "traffic-analyzer", "sitemap-graph",
            "javascript-analysis", "risk-assessment"
        ];
        if (applicationViews.includes(view)) {
            const token = ++applicationViewToken;
            document.querySelectorAll(".main > .view").forEach(el => el.classList.remove("active"));
            const root = document.getElementById("application-result-root");
            root.innerHTML = '<div class="view-loading" role="status">Rendering view</div>';
            let response;
            try {
                response = await fetch(`/html/${view}.html`);
            } catch {
                if (token !== applicationViewToken) return;
                root.innerHTML = '<div class="view-loading view-loading-error" role="alert">Unable to render this view</div>';
                return;
            }
            if (!response.ok || token !== applicationViewToken) {
                if (token === applicationViewToken) {
                    root.innerHTML = '<div class="view-loading view-loading-error" role="alert">Unable to render this view</div>';
                }
                return;
            }
            root.innerHTML = await response.text();
            if (token !== applicationViewToken) return;
            document.querySelectorAll(".nav-item[data-view]").forEach(el => {
                el.classList.toggle("active", el.dataset.view === view);
            });
            AppState.currentView = view;
            const script = document.createElement("script");
            script.src = `/js/${view}.js`;
            script.onload = () => window[`init${view.replace(/(^|-)(\w)/g, (_, __, letter) => letter.toUpperCase())}`]?.();
            document.body.appendChild(script);
            return;
        }
        document.getElementById("application-result-root").replaceChildren();
        document.querySelectorAll(".view").forEach(el => el.classList.toggle("active", el.id === `view-${view}`));
        document.querySelectorAll(".nav-item[data-view]").forEach(el => el.classList.toggle("active", el.dataset.view === view));
        AppState.currentView = view;
        if (Views[view]) Views[view].load();
    },
    async checkConnection() {
        const dot = document.getElementById("conn-dot");
        const label = document.getElementById("conn-label");
        const result = await Api.getMeta();
        const state = result.ok ? "connected" : "error";
        dot.className = `conn-dot ${state}`;
        label.className = `conn-label ${state}`;
        label.textContent = result.ok ? "Loaded" : "Offline";
    },
    async init() {
        if (AppState.ready) await AppState.ready;
        document.querySelectorAll(".nav-item[data-view]").forEach(el => {
            el.addEventListener("click", () => Nav.show(el.dataset.view));
        });
        Nav.show(AppState.currentView);
        Nav.checkConnection();
        setInterval(Nav.checkConnection, 15000);
    }
};

document.addEventListener("DOMContentLoaded", () => Nav.init());
