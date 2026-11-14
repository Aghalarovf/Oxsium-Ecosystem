let viewToken = 0;

async function loadView(view) {
    if (AppState.user?.role === "viewer" && !["dashboard", "graph-view", "hosts-table", "vulnerabilities", "all-vulnerabilities"].includes(view)) {
        return;
    }
    if (["viewer", "analyst", "manager"].includes(AppState.user?.role) && view === "upload") {
        return;
    }
    const token = ++viewToken;
    const root = document.getElementById("view-root");
    const res = await fetch(`/html/${view}.html`);
    const html = await res.text();
    if (token !== viewToken) return;
    root.innerHTML = html;

    document.querySelectorAll(".nav-item").forEach(el => {
        el.classList.toggle("active", el.dataset.view === view);
    });

    AppState.currentView = view;
    document.getElementById("status-view").textContent = view;

    if (view === "dashboard" && window.initDashboard) window.initDashboard();
    if (view === "graph-view" && window.initGraph) window.initGraph();
    if (view === "hosts-table" && window.initHostsTable) window.initHostsTable();
    if (view === "subnets" && window.initSubnets) window.initSubnets();
    if (view === "upload" && window.initUpload) window.initUpload();
    if (view === "all-vulnerabilities" && window.initAllVulnerabilities) window.initAllVulnerabilities();
}

async function refreshPanel() {
    const meta = await Api.getMeta();
    const connDot = document.getElementById("conn-dot");
    const connLabel = document.getElementById("conn-label");
    const statusText = document.getElementById("status-text");

    if (meta.ok) {
        AppState.connected = true;
        AppState.defaultRoles = meta.default_roles || [];
        connDot.classList.add("connected");
        connLabel.textContent = "Loaded";
        connLabel.classList.add("connected");
        document.getElementById("panel-hosts").textContent = meta.host_count === meta.total_hosts
            ? meta.host_count
            : `${meta.host_count} / ${meta.total_hosts}`;
        document.getElementById("panel-mode").textContent = meta.mode || "-";
        statusText.textContent = Filters.isActive()
            ? `filtered ${meta.host_count}/${meta.total_hosts}`
            : "idle";
        Filters.syncOptions(meta.options);
        const subnets = meta.subnets || [];
        AppState.subnetData = {
            items: subnets.map(formatSubnet),
            counts: meta.subnet_counts || {},
            names: meta.subnet_names || {},
            groups: meta.subnet_groups || {},
            groupNames: meta.subnet_group_names || []
        };
        renderSubnetPanel();
        const portsRes = await Api.getPorts();
        document.getElementById("panel-ports").textContent = portsRes.ok ? portsRes.total : "-";
    } else {
        connLabel.textContent = "No data";
        connDot.classList.remove("connected");
        connLabel.classList.remove("connected");
        statusText.textContent = "idle";
        document.getElementById("panel-hosts").textContent = "-";
        document.getElementById("panel-ports").textContent = "-";
        document.getElementById("panel-mode").textContent = "-";
        AppState.subnetData = { items: [], counts: {}, names: {}, groups: {}, groupNames: [] };
        renderSubnetPanel();
        Filters.syncOptions({ os: [], roles: [], services: [] });
    }

    function formatSubnet(subnet) {
        if (typeof subnet === "string") return subnet;
        if (!subnet || typeof subnet !== "object") return String(subnet);
        return subnet.subnet || subnet.network || subnet.cidr || JSON.stringify(subnet);
    }
}

document.addEventListener("DOMContentLoaded", () => {
    document.querySelectorAll(".nav-item[data-view]").forEach(el => {
        el.addEventListener("click", () => loadView(el.dataset.view));
    });
    Filters.init();
    loadView("dashboard");
    refreshPanel();
});

let subnetMenu = null;

function hideSubnetMenu() {
    if (subnetMenu) {
        subnetMenu.remove();
        subnetMenu = null;
    }
}

function exportSubnetHosts(subnet) {
    const safeSubnet = subnet.replace(/[^a-z0-9._-]+/gi, "_").replace(/^_+|_+$/g, "") || "subnet";
    const filename = `${safeSubnet}_hosts.txt`;

    (async () => {
        try {
            const result = await Api.getHostsForSubnet(subnet);
            if (!result.ok) {
                window.alert(result.error || "Could not load subnet hosts");
                return;
            }

            const content = result.hosts.map(host => host.host).filter(Boolean).join("\r\n");
            const link = document.createElement("a");
            link.href = URL.createObjectURL(new Blob([content ? `${content}\r\n` : ""], {
                type: "text/plain;charset=utf-8"
            }));
            link.download = filename;
            link.click();
            URL.revokeObjectURL(link.href);
        } catch (error) {
            console.error("Could not export subnet hosts", error);
            window.alert("Export failed. The host list could not be saved.");
        }
    })();
}

function showSubnetMenu(event, subnet) {
    hideSubnetMenu();
    closeSubnetEditor();
    const point = { x: event.clientX, y: event.clientY };
    const menu = document.createElement("div");
    menu.className = "subnet-menu";
    menu.setAttribute("role", "menu");

    const addItem = (text, className, handler) => {
        const button = document.createElement("button");
        button.type = "button";
        button.textContent = text;
        if (className) button.className = className;
        button.addEventListener("click", () => {
            hideSubnetMenu();
            handler();
        });
        menu.appendChild(button);
    };

    const pinned = readPins().includes(subnet);
    addItem(pinned ? "Unpin" : "Pin to top", "", () => toggleSubnetPin(subnet));
    addItem("Export hosts", "", () => exportSubnetHosts(subnet));
    if (AppState.canManageSubnets) {
        const picked = subnetSelect.active && subnetSelect.selected.has(subnet);
        addItem("Edit", "", () => openSubnetEditor(subnet, point));
        addItem(picked ? "Deselect" : "Select", "", () => toggleSubnetSelected(subnet));
        addItem("Delete", "danger", () => deleteSubnet(subnet));
    }
    document.body.appendChild(menu);

    const box = menu.getBoundingClientRect();
    const x = Math.min(point.x, window.innerWidth - box.width - 8);
    const y = Math.min(point.y, window.innerHeight - box.height - 8);
    menu.style.left = `${Math.max(8, x)}px`;
    menu.style.top = `${Math.max(8, y)}px`;
    subnetMenu = menu;
    menu.querySelector("button").focus();
}

let subnetEditor = null;

function closeSubnetEditor() {
    if (subnetEditor) {
        subnetEditor.remove();
        subnetEditor = null;
    }
}

function openSubnetEditor(subnet, point) {
    closeSubnetEditor();
    const names = (AppState.subnetData && AppState.subnetData.names) || {};
    const form = document.createElement("form");
    form.className = "subnet-editor";
    form.innerHTML = `
        <div class="subnet-editor-title">Edit subnet</div>
        <div class="subnet-editor-subnet">${Util.esc(subnet)}</div>
        <label for="subnet-editor-name">special_name</label>
        <input id="subnet-editor-name" type="text" maxlength="40" autocomplete="off" placeholder="e.g. DMZ servers">
        <div class="subnet-editor-error" hidden></div>
        <div class="subnet-editor-actions">
            <button type="submit" class="primary">Save</button>
            <button type="button" data-cancel>Cancel</button>
        </div>`;
    const input = form.querySelector("input");
    const errorBox = form.querySelector(".subnet-editor-error");
    input.value = names[subnet] || "";

    form.querySelector("[data-cancel]").addEventListener("click", closeSubnetEditor);
    form.addEventListener("submit", async event => {
        event.preventDefault();
        const save = form.querySelector(".primary");
        save.disabled = true;
        const result = await Api.updateSubnetName(subnet, input.value);
        save.disabled = false;
        if (!result.ok) {
            errorBox.textContent = result.error || "Could not save";
            errorBox.hidden = false;
            return;
        }
        const data = AppState.subnetData;
        if (data) {
            if (result.special_name) data.names[subnet] = result.special_name;
            else delete data.names[subnet];
        }
        closeSubnetEditor();
        renderSubnetPanel();
    });

    document.body.appendChild(form);
    const box = form.getBoundingClientRect();
    const x = Math.min(point.x, window.innerWidth - box.width - 8);
    const y = Math.min(point.y, window.innerHeight - box.height - 8);
    form.style.left = `${Math.max(8, x)}px`;
    form.style.top = `${Math.max(8, y)}px`;
    subnetEditor = form;
    input.focus();
    input.select();
}

const subnetSelect = { active: false, selected: new Set() };

function setSelectMode(active) {
    subnetSelect.active = active;
    if (!active) subnetSelect.selected.clear();
    const panel = document.getElementById("panel-subnets");
    const bar = document.getElementById("subnet-selectbar");
    if (panel) panel.classList.toggle("select-mode", active);
    if (bar) bar.hidden = !active;
    syncSubnetSelection();
}

function syncSubnetSelection() {
    const panel = document.getElementById("panel-subnets");
    if (panel) {
        panel.querySelectorAll(".panel-subnet").forEach(row => {
            const on = subnetSelect.selected.has(decodeURIComponent(row.dataset.subnet));
            row.classList.toggle("checked", on);
            const box = row.querySelector(".panel-subnet-check");
            if (box) box.setAttribute("aria-checked", String(on));
        });
    }
    const total = subnetSelect.selected.size;
    const count = document.getElementById("subnet-select-count");
    const remove = document.getElementById("subnet-select-delete");
    if (count) count.textContent = `${total} selected`;
    if (remove) {
        remove.disabled = total === 0;
        remove.hidden = !AppState.canManageSubnets;
    }

}

function toggleSubnetSelected(subnet) {
    if (!subnetSelect.active) setSelectMode(true);
    if (subnetSelect.selected.has(subnet)) {
        subnetSelect.selected.delete(subnet);
    } else {
        subnetSelect.selected.add(subnet);
    }
    syncSubnetSelection();
}

async function deleteSelectedSubnets() {
    const list = [...subnetSelect.selected];
    if (!list.length) return;
    if (!window.confirm(`Delete ${list.length} subnet${list.length === 1 ? "" : "s"} and all of their hosts?`)) return;

    const result = await Api.deleteSubnet(list);
    if (!result.ok) {
        window.alert(`Could not delete subnets: ${result.error || "Unknown error"}`);
        return;
    }

    if (AppState.selectedSubnet && list.includes(AppState.selectedSubnet)) AppState.selectedSubnet = null;
    setSelectMode(false);
    loadView(AppState.currentView || "dashboard");
    refreshPanel();
}

async function deleteSubnet(subnet) {
    if (!window.confirm(`Delete subnet ${subnet} and all of its hosts?`)) return;

    const result = await Api.deleteSubnet(subnet);
    if (!result.ok) {
        window.alert(`Could not delete subnet: ${result.error || "Unknown error"}`);
        return;
    }

    if (AppState.selectedSubnet === subnet) AppState.selectedSubnet = null;
    loadView(AppState.currentView || "dashboard");
    refreshPanel();
}

document.addEventListener("mousedown", event => {
    if (subnetMenu && !subnetMenu.contains(event.target)) hideSubnetMenu();
    if (subnetEditor && !subnetEditor.contains(event.target)) closeSubnetEditor();
});
document.addEventListener("contextmenu", event => {
    if (subnetMenu && !subnetMenu.contains(event.target)) hideSubnetMenu();
    if (subnetEditor && !subnetEditor.contains(event.target)) closeSubnetEditor();
});
document.addEventListener("keydown", event => {
    if (event.key !== "Escape") return;
    if (subnetEditor) closeSubnetEditor();
    else if (subnetMenu) hideSubnetMenu();
    else if (subnetSelect.active) setSelectMode(false);
});
window.addEventListener("resize", hideSubnetMenu);
window.addEventListener("blur", hideSubnetMenu);
document.addEventListener("scroll", hideSubnetMenu, true);


const MAX_PINNED_SUBNETS = 10;
const PIN_ICON = '<svg viewBox="0 0 16 16" width="12" height="12" fill="currentColor" aria-hidden="true"><path d="M9.5 1.5l5 5-1.2 1.2-.9-.3-2.6 2.6.2 2.4-1 1L6 10.2 2.7 13.5 2 12.8l3.3-3.3-3.2-3.2 1-1 2.4.2 2.6-2.6-.3-.9z"/></svg>';
let subnetNoteTimer = null;

const memoryStore = {};

function readStored(key, fallback) {
    try {
        const value = window.localStorage.getItem(key);
        return value === null ? fallback : value;
    } catch (error) {
        return key in memoryStore ? memoryStore[key] : fallback;
    }
}

function writeStored(key, value) {
    memoryStore[key] = value;
    try {
        window.localStorage.setItem(key, value);
    } catch (error) {
        return;
    }
}

function readPins() {
    try {
        const pins = JSON.parse(readStored("ox.subnetPins", "[]"));
        return Array.isArray(pins) ? pins.filter(item => typeof item === "string").slice(0, MAX_PINNED_SUBNETS) : [];
    } catch (error) {
        return [];
    }
}

function writePins(pins) {
    writeStored("ox.subnetPins", JSON.stringify(pins));
}

function showSubnetNote(text) {
    const note = document.getElementById("subnet-note");
    if (!note) return;
    note.textContent = text;
    note.hidden = false;
    window.clearTimeout(subnetNoteTimer);
    subnetNoteTimer = window.setTimeout(() => { note.hidden = true; }, 2800);
}

function toggleSubnetPin(subnet) {
    const pins = readPins();
    if (pins.includes(subnet)) {
        writePins(pins.filter(item => item !== subnet));
    } else {
        if (pins.length >= MAX_PINNED_SUBNETS) {
            showSubnetNote(`Pin limit reached (${MAX_PINNED_SUBNETS}). Unpin a subnet first.`);
            return;
        }
        writePins([...pins, subnet]);
    }
    renderSubnetPanel();
}

function subnetNumbers(label) {
    return (String(label).match(/\d+/g) || []).map(Number);
}

function compareSubnetNames(a, b) {
    const left = subnetNumbers(a);
    const right = subnetNumbers(b);
    const length = Math.max(left.length, right.length);
    for (let i = 0; i < length; i += 1) {
        if (left[i] === undefined) return -1;
        if (right[i] === undefined) return 1;
        if (left[i] !== right[i]) return left[i] - right[i];
    }
    return String(a).localeCompare(String(b), undefined, { numeric: true });
}

function sortedSubnets(items, counts, mode) {
    const list = [...items];
    if (mode === "hosts") {
        list.sort((a, b) => (counts[b] || 0) - (counts[a] || 0) || compareSubnetNames(a, b));
    } else if (mode === "name-asc") {
        list.sort(compareSubnetNames);
    } else if (mode === "name-desc") {
        list.sort((a, b) => compareSubnetNames(b, a));
    }
    return list;
}

function renderSubnetPanel() {
    const panel = document.getElementById("panel-subnets");
    if (!panel) return;
    const data = AppState.subnetData || { items: [], counts: {}, names: {} };
    const names = data.names || {};
    const groups = data.groups || {};
    const visibleItems = AppState.selectedSubnetGroup
        ? data.items.filter(item => groups[item] === AppState.selectedSubnetGroup)
        : data.items;
    const groupNames = [...new Set([...(data.groupNames || []), ...Object.values(groups)])]
        .sort((a, b) => a.localeCompare(b));
    const select = document.getElementById("subnet-sort");
    const mode = select ? select.value : "default";

    if (!visibleItems.length) {
        panel.innerHTML = `<div class="panel-empty">${AppState.selectedSubnetGroup
            ? "No subnets in this group"
            : "No subnets"}</div>`;
        subnetSelect.selected.clear();
        syncSubnetSelection();
        return;
    }

    const existing = new Set(visibleItems);
    const storedPins = readPins();
    const pins = storedPins.filter(item => existing.has(item));
    if (pins.length !== storedPins.length) writePins(pins);
    const pinSet = new Set(pins);
    [...subnetSelect.selected].forEach(item => {
        if (!existing.has(item)) subnetSelect.selected.delete(item);
    });

    const ordered = sortedSubnets(visibleItems, data.counts, mode);
    const list = [...ordered.filter(item => pinSet.has(item)), ...ordered.filter(item => !pinSet.has(item))];

    panel.innerHTML = list.map(label => {
        const count = data.counts[label] || 0;
        const pinned = pinSet.has(label);
        const special = names[label] || "";
        const checked = subnetSelect.selected.has(label);
        return `<div class="panel-subnet${AppState.selectedSubnet === label ? " selected" : ""}${pinned ? " pinned" : ""}${checked ? " checked" : ""}${special ? " has-special" : ""}" data-subnet="${encodeURIComponent(label)}">
            <button type="button" class="panel-subnet-check" role="checkbox" aria-checked="${checked}" aria-label="Select ${Util.esc(label)}"><span></span></button>
            <span class="panel-subnet-name">${special ? `<span class="panel-subnet-special">${Util.esc(special)}</span>` : ""}<span class="panel-subnet-label">${Util.esc(label)}</span></span>
            <span class="panel-subnet-count" title="${count} host${count === 1 ? "" : "s"}">${count}</span>
            <button type="button" class="panel-subnet-pin" aria-pressed="${pinned}" aria-label="${pinned ? "Unpin" : "Pin"} ${Util.esc(label)}" title="${pinned ? "Unpin" : "Pin to top"}">${PIN_ICON}</button>
        </div>`;
    }).join("");

    panel.querySelectorAll("[data-subnet]").forEach(element => {
        const subnet = decodeURIComponent(element.dataset.subnet);
        element.addEventListener("click", () => {
            if (subnetSelect.active) {
                toggleSubnetSelected(subnet);
                return;
            }
            AppState.selectedSubnet = AppState.selectedSubnet === subnet ? null : subnet;
            loadView("dashboard");
            refreshPanel();
        });
        element.querySelector(".panel-subnet-check").addEventListener("click", event => {
            event.stopPropagation();
            toggleSubnetSelected(subnet);
        });
        element.querySelector(".panel-subnet-pin").addEventListener("click", event => {
            event.stopPropagation();
            toggleSubnetPin(subnet);
        });
        element.addEventListener("contextmenu", event => {
            event.preventDefault();
            event.stopPropagation();
            showSubnetMenu(event, subnet);
        });
    });
    syncSubnetSelection();
}

document.addEventListener("DOMContentLoaded", () => {
    const select = document.getElementById("subnet-sort");
    if (!select) return;
    const saved = readStored("ox.subnetSort", "default");
    if ([...select.options].some(option => option.value === saved)) select.value = saved;
    select.addEventListener("change", () => {
        writeStored("ox.subnetSort", select.value);
        renderSubnetPanel();
    });
    document.getElementById("subnet-select-delete").addEventListener("click", deleteSelectedSubnets);
    document.getElementById("subnet-select-done").addEventListener("click", () => setSelectMode(false));
});