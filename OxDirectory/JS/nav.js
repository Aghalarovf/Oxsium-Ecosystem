let viewToken = 0;
const viewCache = new Map();

async function loadView(view) {
    const token = ++viewToken;
    const root = document.getElementById("view-root");
    root.innerHTML = `
        <div class="view-loading" role="status" aria-live="polite">
            <div class="view-loading-spinner" aria-hidden="true"></div>
            <div class="view-loading-label">Rendering view</div>
            <div class="view-loading-dots" aria-hidden="true"><span></span><span></span><span></span></div>
        </div>`;
    let viewElement = viewCache.get(view);
    try {
        if (!viewElement) {
            const res = await fetch(`/html/${view}.html`);
            if (!res.ok) throw new Error(`Could not load ${view}`);
            const html = await res.text();
            if (token !== viewToken) return;
            const template = document.createElement("template");
            template.innerHTML = html.trim();
            viewElement = document.createElement("div");
            viewElement.className = "view-cache-root";
            viewElement.append(...template.content.childNodes);
            viewCache.set(view, viewElement);
        }
    } catch (error) {
        if (token !== viewToken) return;
        root.innerHTML = '<div class="view-loading view-loading-error" role="alert">Unable to render this view</div>';
        return;
    }
    if (token !== viewToken) return;
    root.replaceChildren(viewElement);

    document.querySelectorAll(".nav-item").forEach(el => {
        el.classList.toggle("active", el.dataset.view === view);
    });

    AppState.currentView = view;
    document.getElementById("status-view").textContent = view;
    if (view === "dashboard" && window.initDashboard && !viewElement.dataset.initialized) window.initDashboard();
    if (view === "upload" && window.initUpload && !viewElement.dataset.initialized) window.initUpload();
    if ((view === "domain" || view.startsWith("domain-"))
        && window.initDomainResults && !viewElement.dataset.initialized) {
        window.initDomainResults();
    }
}

function invalidateDomainViews() {
    for (const [view, element] of viewCache) {
        if (view === "domain" || view.startsWith("domain-")) {
            viewCache.delete(view);
            if (element.parentElement) element.remove();
        }
    }
}

async function refreshPanel() {
    const meta = await Api.getMeta();
    const connDot = document.getElementById("conn-dot");
    const connLabel = document.getElementById("conn-label");
    const statusText = document.getElementById("status-text");
    const panelStatus = document.getElementById("panel-status");

    if (meta.ok) {
        AppState.connected = true;
        connDot.classList.add("connected");
        connDot.classList.remove("error");
        connLabel.textContent = "Loaded";
        connLabel.classList.add("connected");
        connLabel.classList.remove("error");
        statusText.textContent = "idle";
        panelStatus.textContent = "Ready";
    } else {
        AppState.connected = false;
        connDot.classList.remove("connected");
        connDot.classList.add("error");
        connLabel.textContent = "No data";
        connLabel.classList.remove("connected");
        connLabel.classList.add("error");
        statusText.textContent = "idle";
        panelStatus.textContent = "-";
    }
}

document.addEventListener("DOMContentLoaded", () => {
    document.querySelectorAll(".nav-item[data-view]").forEach(el => {
        el.addEventListener("click", () => loadView(el.dataset.view));
    });
    loadView("dashboard");
    refreshPanel();
});
