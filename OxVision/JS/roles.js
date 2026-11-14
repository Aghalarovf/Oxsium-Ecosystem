const Roles = (() => {
    const PRESET_COLORS = {
        "Domain Controller": "#e8a33c",
        "Web Server": "#3b82d6",
        "Database": "#a77be0",
        "File Server": "#2fa36b",
        "Mail Server": "#e0659a",
        "DNS Server": "#3fb8c4",
        "Remote Access": "#d9763a",
        "Printer": "#9a8f7a",
        "Network Device": "#b4a688",
        "Workstation": "#6f9fd8",
        "Jump Host": "#7fcf6a",
        "Out of Scope": "#7a7261",
        "Compromised": "#d9453a",
        "High Value": "#f0c030"
    };
    const MAX_ROLES = 8;

    const SUGGESTIONS = [
        { role: "Domain Controller", test: s => s.has(88) && (s.has(389) || s.has(636) || s.has(3268)) },
        { role: "Web Server", test: s => [80, 443, 8000, 8080, 8443, 8888].some(p => s.has(p)) },
        { role: "Database", test: s => [1433, 1521, 3306, 5432, 6379, 9200, 27017].some(p => s.has(p)) },
        { role: "File Server", test: s => [21, 873, 2049].some(p => s.has(p)) },
        { role: "Mail Server", test: s => [25, 110, 143, 465, 587, 993, 995].some(p => s.has(p)) },
        { role: "DNS Server", test: s => s.has(53) },
        { role: "Remote Access", test: s => [23, 3389, 5900, 5985, 5986].some(p => s.has(p)) },
        { role: "Printer", test: s => [515, 631, 9100].some(p => s.has(p)) }
    ];

    function color(name) {
        if (PRESET_COLORS[name]) return PRESET_COLORS[name];
        let hash = 0;
        for (const ch of String(name)) hash = (hash * 31 + ch.charCodeAt(0)) % 360;
        return `hsl(${hash} 58% 62%)`;
    }

    function chip(name, extraClass = "") {
        return `<span class="role-chip ${extraClass}" style="--rc:${color(name)}">${Util.esc(name)}</span>`;
    }

    function chips(roles) {
        return roles && roles.length
            ? roles.map(r => chip(r)).join("")
            : '<span class="role-none">No roles</span>';
    }

    function suggest(ports, os, existing) {
        const set = new Set((ports || []).map(p => Number(p.port)));
        const found = SUGGESTIONS.filter(s => s.test(set)).map(s => s.role);
        if (os === "Network") found.push("Network Device");
        return found.filter(r => !existing.includes(r));
    }

    let overlay = null;
    let current = null;

    function $(id) {
        return document.getElementById(id);
    }

    function ensureModal() {
        if (overlay) return;
        overlay = document.createElement("div");
        overlay.className = "role-modal-overlay";
        overlay.hidden = true;
        overlay.innerHTML = `
            <div class="role-modal" role="dialog" aria-modal="true" aria-labelledby="role-modal-title">
                <div class="role-modal-head">
                    <div id="role-modal-title" class="role-modal-title">Edit Roles</div>
                    <button type="button" class="role-modal-close" id="role-close" aria-label="Close">&times;</button>
                </div>
                <div class="role-modal-host" id="role-host"></div>
                <div class="role-modal-label">Assigned</div>
                <div class="role-chip-row" id="role-selected"></div>
                <div id="role-suggest-wrap">
                    <div class="role-modal-label">Suggested from open ports</div>
                    <div class="role-chip-row" id="role-suggested"></div>
                </div>
                <div class="role-modal-label">Available roles</div>
                <div class="role-chip-row" id="role-available"></div>
                <div class="role-modal-label role-custom-label">
                    <span>Custom roles</span>
                    <button type="button" class="role-custom-trigger" id="role-custom-trigger">Add custom role</button>
                </div>
                <div class="role-custom">
                    <input id="role-custom-input" class="sf-input" maxlength="24" placeholder="e.g. VPN Gateway" autocomplete="off">
                    <button type="button" id="role-custom-add" class="btn-secondary">Add</button>
                </div>
                <div class="role-modal-error" id="role-error" hidden></div>
                <div class="role-modal-actions">
                    <button type="button" id="role-cancel" class="btn-secondary">Cancel</button>
                    <button type="button" id="role-save" class="btn-primary">Save Roles</button>
                </div>
            </div>`;
        document.body.appendChild(overlay);

        overlay.addEventListener("mousedown", event => {
            if (event.target === overlay) close();
        });
        $("role-close").addEventListener("click", close);
        $("role-cancel").addEventListener("click", close);
        $("role-save").addEventListener("click", save);
        $("role-custom-add").addEventListener("click", addCustom);
        $("role-custom-trigger").addEventListener("click", () => {
            $("role-custom-input").focus();
        });
        $("role-custom-input").addEventListener("keydown", event => {
            if (event.key === "Enter") {
                event.preventDefault();
                addCustom();
            }
        });
        overlay.addEventListener("click", event => {
            const chipEl = event.target.closest("[data-role]");
            if (!chipEl) return;
            toggle(chipEl.dataset.role);
        });
        document.addEventListener("keydown", event => {
            if (event.key === "Escape" && overlay && !overlay.hidden) close();
        });
    }

    function showError(message) {
        const el = $("role-error");
        el.textContent = message || "";
        el.hidden = !message;
    }

    function toggle(role) {
        const list = current.working;
        const index = list.findIndex(r => r.toLowerCase() === role.toLowerCase());
        if (index >= 0) {
            list.splice(index, 1);
            showError("");
        } else if (list.length >= MAX_ROLES) {
            showError(`A host can have at most ${MAX_ROLES} roles.`);
            return;
        } else {
            list.push(role);
            showError("");
        }
        render();
    }

    function addCustom() {
        const input = $("role-custom-input");
        const value = input.value.replace(/,/g, " ").replace(/\s+/g, " ").trim();
        if (!value) return;
        input.value = "";
        if (!current.working.some(r => r.toLowerCase() === value.toLowerCase())) toggle(value);
    }

    function pill(role, mode) {
        const mark = mode === "selected" ? " &times;" : mode === "suggested" ? "+ " : "";
        const body = mode === "suggested" ? `${mark}${Util.esc(role)}` : `${Util.esc(role)}${mark}`;
        return `<button type="button" class="role-chip role-chip-btn ${mode}" data-role="${Util.esc(role)}" style="--rc:${color(role)}">${body}</button>`;
    }

    function render() {
        const working = current.working;
        const lower = new Set(working.map(r => r.toLowerCase()));
        $("role-selected").innerHTML = working.length
            ? working.map(r => pill(r, "selected")).join("")
            : '<span class="role-none">No roles assigned</span>';

        const suggestions = suggest(current.ports, current.os, working);
        $("role-suggest-wrap").hidden = suggestions.length === 0;
        $("role-suggested").innerHTML = suggestions.map(r => pill(r, "suggested")).join("");

        const pool = [...new Set([...(AppState.defaultRoles || []), ...(AppState.roleNames || [])])];
        $("role-available").innerHTML = pool
            .filter(r => !lower.has(r.toLowerCase()))
            .map(r => pill(r, "available")).join("") || '<span class="role-none">All roles assigned</span>';
    }

    function close() {
        if (overlay) overlay.hidden = true;
        current = null;
    }

    async function save() {
        if (!current) return;
        const button = $("role-save");
        button.disabled = true;
        try {
            const result = await Api.updateHostRoles(current.host, current.working);
            if (!result.ok) {
                showError(result.error || "Could not save roles");
                return;
            }
            const callback = current.onSaved;
            close();
            if (callback) callback(result.roles);
            refreshPanel();
        } catch (error) {
            showError("Could not reach the server");
        } finally {
            button.disabled = false;
        }
    }

    function openEditor({ host, roles, ports, os }, onSaved) {
        ensureModal();
        current = { host, working: [...(roles || [])], ports: ports || [], os, onSaved };
        $("role-host").textContent = host;
        $("role-custom-input").value = "";
        showError("");
        render();
        overlay.hidden = false;
        $("role-custom-input").focus();
    }

    return { color, chip, chips, suggest, openEditor };
})();