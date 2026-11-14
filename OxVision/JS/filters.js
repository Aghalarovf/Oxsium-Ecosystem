const Filters = (() => {
    const $ = id => document.getElementById(id);
    const ARRAY_KEYS = ["os", "role"];
    let timer = null;
    let lastOptions = { os: [], roles: [], services: [] };

    function activeCount() {
        const f = AppState.filters;
        return [f.q, f.os.length, f.role.length, f.port, f.service, f.min_ports].filter(Boolean).length;
    }

    function isActive() {
        return activeCount() > 0;
    }

    function renderChips(containerId, key, options) {
        const container = $(containerId);
        if (!container) return;
        const selected = AppState.filters[key];
        const known = new Set(options.map(o => o.value));
        const merged = options.concat(
            selected.filter(v => !known.has(v)).map(v => ({ value: v, label: v, count: 0 }))
        );
        if (!merged.length) {
            container.innerHTML = '<span class="sf-empty">No data</span>';
            return;
        }
        container.innerHTML = merged.map(o => `
            <button type="button" class="sf-chip${selected.includes(o.value) ? " active" : ""}" data-key="${key}" data-value="${Util.esc(o.value)}">
                ${Util.esc(o.label)}<span class="sf-count">${o.count}</span>
            </button>`).join("");
    }

    function syncUI() {
        const f = AppState.filters;
        const setValue = (id, value) => {
            const el = $(id);
            if (el && el.value !== String(value)) el.value = value;
        };
        setValue("sf-q", f.q);
        setValue("sf-port", f.port);
        setValue("sf-service", f.service);
        setValue("sf-min", f.min_ports);
        setValue("sf-sort", f.sort);
        const dir = $("sf-dir");
        if (dir) {
            dir.textContent = f.dir === "desc" ? "DESC" : "ASC";
            dir.disabled = !f.sort;
        }
        const count = activeCount();
        const badge = $("sf-badge");
        if (badge) {
            badge.textContent = count;
            badge.hidden = count === 0;
        }
        const reset = $("sf-reset");
        if (reset) reset.disabled = count === 0 && !f.sort;
        renderChips("sf-os", "os", lastOptions.os);
        renderChips("sf-roles", "role", lastOptions.roles);
    }

    function schedule(delay) {
        clearTimeout(timer);
        timer = setTimeout(async () => {
            await refreshPanel();
            await loadView(AppState.currentView);
        }, delay);
    }

    function commit(delay = 0) {
        syncUI();
        schedule(delay);
    }

    function setValue(key, value) {
        AppState.filters[key] = value;
        commit(0);
    }

    function toggleValue(key, value) {
        const list = AppState.filters[key];
        const index = list.indexOf(value);
        if (index >= 0) list.splice(index, 1);
        else list.push(value);
        commit(0);
    }

    function reset() {
        const f = AppState.filters;
        f.q = "";
        f.os = [];
        f.role = [];
        f.port = "";
        f.service = "";
        f.min_ports = "";
        f.sort = "";
        f.dir = "asc";
        commit(0);
    }

    function syncOptions(options) {
        lastOptions = options || { os: [], roles: [], services: [] };
        AppState.roleNames = (lastOptions.roles || []).filter(o => o.value !== "__none__").map(o => o.value);
        const list = $("sf-services");
        if (list) list.innerHTML = (lastOptions.services || []).map(s => `<option value="${Util.esc(s)}">`).join("");
        syncUI();
    }

    function init() {
        const bindText = (id, key, delay) => {
            const el = $(id);
            if (!el) return;
            el.addEventListener("input", () => {
                AppState.filters[key] = el.value.trim();
                syncUI();
                schedule(delay);
            });
            el.addEventListener("keydown", event => {
                if (event.key === "Enter") {
                    clearTimeout(timer);
                    schedule(0);
                }
            });
        };
        bindText("sf-q", "q", 250);
        bindText("sf-port", "port", 350);
        bindText("sf-service", "service", 350);
        bindText("sf-min", "min_ports", 350);

        $("sf-sort").addEventListener("change", event => {
            AppState.filters.sort = event.target.value;
            commit(0);
        });
        $("sf-dir").addEventListener("click", () => {
            AppState.filters.dir = AppState.filters.dir === "asc" ? "desc" : "asc";
            commit(0);
        });
        $("sf-reset").addEventListener("click", reset);

        $("sf-panel").addEventListener("click", event => {
            const chip = event.target.closest(".sf-chip");
            if (chip && ARRAY_KEYS.includes(chip.dataset.key)) {
                toggleValue(chip.dataset.key, chip.dataset.value);
            }
        });

        const toggle = () => {
            const panel = $("sf-panel");
            const collapsed = panel.classList.toggle("collapsed");
            $("sf-toggle").setAttribute("aria-expanded", String(!collapsed));
        };
        $("sf-toggle").addEventListener("click", toggle);
        $("sf-toggle").addEventListener("keydown", event => {
            if (event.key === "Enter" || event.key === " ") {
                event.preventDefault();
                toggle();
            }
        });
        $("sf-toggle").setAttribute("aria-expanded", "false");

        syncUI();
    }

    return { init, syncOptions, setValue, toggleValue, reset, isActive, activeCount };
})();