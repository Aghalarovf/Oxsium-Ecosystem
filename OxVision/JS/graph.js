const DISCOVERY_TYPE_LABEL = {
    tcp_ping: "TCP",
    arp: "ARP",
    icmp: "ICMP",
    skipped: "SKIPPED",
    none: "NONE"
};

const OS_TYPES = [
    { label: "Unknown", icon: "unknown", group: "os-other" },
    { label: "Linux", icon: "linux", group: "os-linux" },
    { label: "Windows", icon: "windows", group: "os-windows" },
    { label: "Network", icon: "network", group: "os-network" },
    { label: "Virtual Machine", icon: "virtualmachine", group: "os-virtualmachine" },
    { label: "Gateway", icon: "gateway", group: "os-gateway" },
    { label: "Firewall", icon: "firewall", group: "os-firewall" },
    { label: "Camera", icon: "camera", group: "os-camera" }
];

const osType = os => OS_TYPES.find(item => item.label === os) || OS_TYPES[0];

window.initGraph = async function() {
    const container = document.getElementById("graph-container");
    const legend = document.getElementById("graph-legend");
    const details = document.getElementById("graph-details");
    const notePanel = document.getElementById("graph-note-panel");
    const noteHost = document.getElementById("graph-note-host");
    const noteInput = document.getElementById("graph-note-input");
    const noteClose = document.getElementById("graph-note-close");
    const noteCancel = document.getElementById("graph-note-cancel");
    const noteSave = document.getElementById("graph-note-save");
    let noteTarget = null;
    let detailsTarget = null;
    let vulnerabilitiesOverlay = null;

    async function openVulnerabilitiesPanel(host) {
        if (vulnerabilitiesOverlay) vulnerabilitiesOverlay.remove();

        const overlay = document.createElement("div");
        overlay.className = "vulnerabilities-overlay";
        overlay.setAttribute("role", "presentation");
        overlay.innerHTML = '<div class="vulnerabilities-backdrop"></div><section class="vulnerabilities-modal" role="dialog" aria-modal="true" aria-labelledby="vulnerabilities-title"><div class="data-empty">Loading...</div></section>';
        document.body.appendChild(overlay);
        vulnerabilitiesOverlay = overlay;

        const close = () => {
            if (vulnerabilitiesOverlay !== overlay) return;
            overlay.remove();
            vulnerabilitiesOverlay = null;
            document.removeEventListener("keydown", onKeyDown);
        };
        const onKeyDown = event => {
            if (event.key === "Escape") close();
        };
        overlay.querySelector(".vulnerabilities-backdrop").addEventListener("click", close);
        document.addEventListener("keydown", onKeyDown);

        try {
            const response = await fetch("/html/vulnerabilities.html");
            if (!response.ok) throw new Error(`HTTP ${response.status}`);
            overlay.querySelector(".vulnerabilities-modal").innerHTML = await response.text();
            overlay.querySelector("[data-close-vulnerabilities]").addEventListener("click", close);
            const hostId = host.ip || host.label || AppState.selectedHost || "";
            const hostLabel = overlay.querySelector("[data-vulnerabilities-host]");
            if (hostLabel) hostLabel.textContent = hostId;

            const addBtn = overlay.querySelector("[data-add-vulnerability]");
            if (addBtn) {
                addBtn.addEventListener("click", () => Vulnerabilities.openForm(null));
            }

            const panel = overlay.querySelector("#vulnerabilities-panel");
            if (panel && hostId) {
                await Vulnerabilities.render(hostId, panel, addBtn);
            } else if (panel) {
                panel.innerHTML = '<div class="data-empty">No host selected.</div>';
            }
        } catch (error) {
            console.error("Could not load vulnerabilities panel", error);
            overlay.querySelector(".vulnerabilities-modal").innerHTML = '<div class="data-empty">Could not load vulnerabilities panel.</div>';
        }
    }

    const legendItems = [
        { label: "Linux host", color: "var(--green)" },
        { label: "Windows host", color: "var(--blue)" },
        { label: "Network device", color: "#9a8f7a" },
        { label: "Other host", color: "var(--text-dim)" },
        { label: "Scanner (this host)", color: "var(--accent)" }
    ];
    legend.innerHTML = legendItems.map(i =>
        `<div class="graph-legend-item"><div class="graph-legend-dot" style="background:${i.color}"></div>${i.label}</div>`
    ).join("");

    details.innerHTML = '<div class="graph-details-empty">Click a node to see its details.</div>';

    const res = await Api.getGraph();
    container.innerHTML = "";

    if (!res.ok) {
        container.innerHTML = '<div class="data-empty">No dataset loaded yet. Go to Upload.</div>';
        return;
    }

    const allNodes = res.nodes || [];
    const edges = res.edges || [];
    const scanner = allNodes.find(n => n.group === "scanner");
    const hostNodes = allNodes.filter(n => n.group !== "scanner");
    const portCount = hostNodes.reduce((total, node) => total + (node.ports || []).length, 0);
    document.getElementById("graph-stat-nodes").textContent = hostNodes.length;
    document.getElementById("graph-stat-edges").textContent = edges.length;
    document.getElementById("graph-stat-ports").textContent = portCount;

    if (hostNodes.length === 0) {
        container.innerHTML = `<div class="data-empty">${Filters.isActive() ? "No hosts match the current filters." : "No hosts found."}</div>`;
        return;
    }

    const viewWidth = container.clientWidth;
    const viewHeight = container.clientHeight;
    const spacing = 110;
    const margin = 60;
    const hostRowY = 90;
    const scannerY = viewHeight - 90;
    const contentWidth = Math.max(viewWidth, (hostNodes.length - 1) * spacing + margin * 2);

    hostNodes.forEach((d, i) => {
        d.x = margin + i * spacing;
        d.y = hostRowY;
    });

    if (scanner) {
        scanner.x = contentWidth / 2;
        scanner.y = scannerY;
    }

    const byId = {};
    allNodes.forEach(n => { byId[n.id] = n; });

    const svg = d3.select(container)
        .append("svg")
        .attr("width", viewWidth)
        .attr("height", viewHeight)
        .attr("viewBox", [0, 0, viewWidth, viewHeight]);

    const zoomLayer = svg.append("g");

    svg.call(d3.zoom()
        .scaleExtent([0.4, 4])
        .translateExtent([[-margin, -margin], [contentWidth + margin, viewHeight + margin]])
        .on("zoom", event => {
            zoomLayer.attr("transform", event.transform);
        }));

    const edgeLayer = zoomLayer.append("g").attr("class", "graph-edge-layer");
    const nodeLayer = zoomLayer.append("g").attr("class", "graph-node-layer");

    const edgeGroups = edgeLayer.selectAll("g")
        .data(edges)
        .join("g")
        .attr("class", "graph-edge");

    edgeGroups.append("line")
        .attr("x1", d => byId[d.from].x)
        .attr("y1", d => byId[d.from].y)
        .attr("x2", d => byId[d.to].x)
        .attr("y2", d => byId[d.to].y);

    edgeGroups.append("rect")
        .attr("class", "graph-edge-label-bg")
        .attr("x", d => (byId[d.from].x + byId[d.to].x) / 2 - 24)
        .attr("y", d => (byId[d.from].y + byId[d.to].y) / 2 - 8)
        .attr("width", 48)
        .attr("height", 14);

    edgeGroups.append("text")
        .attr("class", "graph-edge-label")
        .attr("x", d => (byId[d.from].x + byId[d.to].x) / 2)
        .attr("y", d => (byId[d.from].y + byId[d.to].y) / 2 + 3)
        .attr("text-anchor", "middle")
        .text(d => DISCOVERY_TYPE_LABEL[d.type] || (d.type || "-").toUpperCase());

    const hostNode = nodeLayer.append("g")
        .selectAll("g")
        .data(hostNodes)
        .join("g")
        .attr("class", d => `graph-node host-${d.group}`)
        .attr("transform", d => `translate(${d.x},${d.y})`)
        .call(d3.drag()
            .clickDistance(4)
            .on("start", dragstarted)
            .on("drag", dragged)
            .on("end", dragended));

    hostNode.append("rect")
        .attr("class", "graph-node-hit-area")
        .attr("x", -30)
        .attr("y", -22)
        .attr("width", 60)
        .attr("height", 82);

    hostNode.append("image")
        .attr("class", "graph-node-icon")
        .attr("href", d => `/assets/${osType(d.os).icon}.png`)
        .attr("x", d => d.group === "os-other" ? -20 : -16)
        .attr("y", d => d.group === "os-other" ? -20 : -16)
        .attr("width", d => d.group === "os-other" ? 40 : 32)
        .attr("height", d => d.group === "os-other" ? 40 : 32)
        .attr("preserveAspectRatio", "xMidYMid meet");

    hostNode.append("text")
        .attr("class", "graph-node-name")
        .attr("dy", 34)
        .attr("text-anchor", "middle")
        .text(d => d.label);

    hostNode.append("text")
        .attr("class", "graph-node-role")
        .attr("dy", -27)
        .attr("text-anchor", "middle")
        .style("fill", roleColor)
        .text(roleLabel);

    hostNode.on("pointerdown", (event, d) => {
        if (event.button !== 0) return;
        hideHostMenu();
        allSelectable.classed("selected", n => n === d);
        renderHostDetails(d);
    });

    hostNode.on("contextmenu", (event, d) => {
        event.preventDefault();
        event.stopPropagation();
        showHostMenu(event, d);
    });

    const hostMenu = document.createElement("div");
    hostMenu.className = "graph-host-menu";
    hostMenu.setAttribute("role", "menu");
    container.appendChild(hostMenu);

    function showHostMenu(event, d) {
        hostMenu.innerHTML = "";

        const addNote = document.createElement("button");
        addNote.type = "button";
        addNote.textContent = "Add Note";
        addNote.addEventListener("click", () => {
            openNotePanel(d);
        });

        const editHost = document.createElement("button");
        editHost.type = "button";
        editHost.textContent = "Edit";
        editHost.addEventListener("click", () => {
            hideHostMenu();
            openHostEditor(d);
        });

        const copyIp = document.createElement("button");
        copyIp.type = "button";
        copyIp.textContent = "Copy IP";
        copyIp.addEventListener("click", async () => {
            try {
                await navigator.clipboard.writeText(String(d.label || ""));
                copyIp.textContent = "Copied";
            } catch (error) {
                copyIp.textContent = "Copy failed";
            }
            window.setTimeout(hideHostMenu, 700);
        });

        const showDetails = document.createElement("button");
        showDetails.type = "button";
        showDetails.textContent = "Show Details";
        showDetails.addEventListener("click", () => {
            allSelectable.classed("selected", n => n === d);
            renderHostDetails(d);
            hideHostMenu();
            revealDetails();
        });

        const vulnerabilities = document.createElement("button");
        vulnerabilities.type = "button";
        vulnerabilities.textContent = "Vulnerabilities";
        vulnerabilities.addEventListener("click", () => {
            AppState.selectedHost = d.ip || d.label;
            hideHostMenu();
            openVulnerabilitiesPanel(d);
        });

        const menuItems = [copyIp, showDetails, vulnerabilities];
        if (AppState.canEditHostDetails) menuItems.splice(1, 0, editHost);
        if (AppState.canEditHosts) menuItems.unshift(addNote);
        hostMenu.append(...menuItems);
        const bounds = container.getBoundingClientRect();
        hostMenu.style.left = `${event.clientX - bounds.left}px`;
        hostMenu.style.top = `${event.clientY - bounds.top}px`;
        hostMenu.hidden = false;
    }

    function hideHostMenu() {
        if (hostMenu) hostMenu.hidden = true;
    }

    function revealDetails() {
        details.classList.remove("graph-details-reveal");
        void details.offsetWidth;
        details.classList.add("graph-details-reveal");
        window.requestAnimationFrame(() => {
            details.scrollIntoView({ behavior: "smooth", block: "start" });
        });
    }

    function roleLabel(d) {
        const roles = d.roles || [];
        if (!roles.length) return "";
        return roles.length > 1 ? `${roles[0]} +${roles.length - 1}` : roles[0];
    }

    function roleColor(d) {
        const roles = d.roles || [];
        return roles.length ? Roles.color(roles[0]) : "var(--text-dim)";
    }

    function openRoleEditor(d) {
        Roles.openEditor({ host: d.label, roles: d.roles || [], ports: d.ports || [], os: d.os }, roles => {
            d.roles = roles;
            hostNode.filter(n => n === d)
                .select(".graph-node-role")
                .style("fill", roleColor(d))
                .text(roleLabel(d));
            if (detailsTarget === d) renderHostDetails(d);
        });
    }

    function openHostEditor(d) {
        if (!AppState.canEditHostDetails) return;
        const overlay = document.createElement("div");
        overlay.className = "host-edit-overlay";
        overlay.innerHTML = `
            <form class="host-edit-modal" role="dialog" aria-modal="true" aria-labelledby="host-edit-title">
                <div class="role-modal-head">
                    <div id="host-edit-title" class="role-modal-title">Edit Host</div>
                    <button type="button" class="role-modal-close" aria-label="Close">&times;</button>
                </div>
                <div class="role-modal-host">${escapeHtml(d.ip || d.label)}</div>
                <label class="role-modal-label" for="host-edit-name">Hostname</label>
                <input id="host-edit-name" class="sf-input" maxlength="253" value="${escapeHtml(d.hostname || "")}" placeholder="e.g. web-server-01">
                <label class="role-modal-label" for="host-edit-os">Operating system</label>
                <select id="host-edit-os" class="sf-input">
                    ${OS_TYPES.map(item => `<option${d.os === item.label ? " selected" : ""}>${item.label}</option>`).join("")}
                </select>
                <div class="role-modal-label">Assigned roles</div>
                <div class="role-chip-row" id="host-edit-roles"></div>
                <div class="role-modal-label">Available roles</div>
                <div class="role-chip-row" id="host-edit-available"></div>
                <div class="role-modal-label">Custom role</div>
                <div class="role-custom">
                    <input id="host-edit-custom-role" class="sf-input" maxlength="24" placeholder="e.g. VPN Gateway" autocomplete="off">
                    <button type="button" class="btn-secondary" id="host-edit-add-role">Add</button>
                </div>
                <div class="role-modal-error" hidden></div>
                <div class="role-modal-actions">
                    <button type="button" class="btn-secondary host-edit-cancel">Cancel</button>
                    <button type="submit" class="btn-primary host-edit-save">Save Changes</button>
                </div>
            </form>`;
        document.body.appendChild(overlay);

        const form = overlay.querySelector("form");
        const nameInput = overlay.querySelector("#host-edit-name");
        const osInput = overlay.querySelector("#host-edit-os");
        const error = overlay.querySelector(".role-modal-error");
        let roles = [...(d.roles || [])];
        const rolesContainer = overlay.querySelector("#host-edit-roles");
        const availableContainer = overlay.querySelector("#host-edit-available");
        const customInput = overlay.querySelector("#host-edit-custom-role");
        const rolePool = [...new Set([...(AppState.defaultRoles || []), ...(AppState.roleNames || [])])];
        const renderRoles = () => {
            const assigned = new Set(roles.map(role => role.toLowerCase()));
            rolesContainer.innerHTML = roles.length
                ? roles.map(role => `<button type="button" class="role-chip role-chip-btn selected" data-role="${escapeHtml(role)}" style="--rc:${Roles.color(role)}">${escapeHtml(role)} &times;</button>`).join("")
                : '<span class="role-none">No roles assigned</span>';
            availableContainer.innerHTML = rolePool
                .filter(role => !assigned.has(role.toLowerCase()))
                .map(role => `<button type="button" class="role-chip role-chip-btn available" data-role="${escapeHtml(role)}" style="--rc:${Roles.color(role)}">+ ${escapeHtml(role)}</button>`).join("")
                || '<span class="role-none">No more preset roles</span>';
        };
        const addRole = role => {
            const value = role.replace(/,/g, " ").replace(/\s+/g, " ").trim().slice(0, 24);
            if (!value || roles.some(existing => existing.toLowerCase() === value.toLowerCase()) || roles.length >= 8) return;
            roles.push(value);
            renderRoles();
        };
        rolesContainer.addEventListener("click", event => {
            const role = event.target.closest("[data-role]");
            if (!role) return;
            roles = roles.filter(value => value.toLowerCase() !== role.dataset.role.toLowerCase());
            renderRoles();
        });
        availableContainer.addEventListener("click", event => {
            const role = event.target.closest("[data-role]");
            if (role) addRole(role.dataset.role);
        });
        overlay.querySelector("#host-edit-add-role").addEventListener("click", () => {
            addRole(customInput.value);
            customInput.value = "";
            customInput.focus();
        });
        customInput.addEventListener("keydown", event => {
            if (event.key === "Enter") {
                event.preventDefault();
                overlay.querySelector("#host-edit-add-role").click();
            }
        });
        renderRoles();
        const close = () => overlay.remove();
        overlay.querySelector(".role-modal-close").addEventListener("click", close);
        overlay.querySelector(".host-edit-cancel").addEventListener("click", close);
        overlay.addEventListener("mousedown", event => {
            if (event.target === overlay) close();
        });
        form.addEventListener("submit", async event => {
            event.preventDefault();
            const button = overlay.querySelector(".host-edit-save");
            button.disabled = true;
            error.hidden = true;
            try {
                const result = await Api.updateHostDetails(d.ip, {
                    hostname: nameInput.value.trim(),
                    os: osInput.value,
                    roles
                });
                if (!result.ok) {
                    error.textContent = result.error || "Could not save host details";
                    error.hidden = false;
                    return;
                }
                d.hostname = result.hostname;
                d.os = result.os;
                d.roles = result.roles;
                d.label = result.hostname || d.ip;
                d.group = osType(d.os).group;
                const node = hostNode.filter(n => n === d);
                node.attr("class", `graph-node host-${d.group}`);
                node.select(".graph-node-icon").attr("href", `/assets/${osType(d.os).icon}.png`)
                    .attr("x", d.group === "os-other" ? -20 : -16)
                    .attr("y", d.group === "os-other" ? -20 : -16)
                    .attr("width", d.group === "os-other" ? 40 : 32)
                    .attr("height", d.group === "os-other" ? 40 : 32);
                node.select(".graph-node-name").text(d.label);
                node.select(".graph-node-role").style("fill", roleColor(d)).text(roleLabel(d));
                if (detailsTarget === d) renderHostDetails(d);
                close();
                refreshPanel();
            } catch (saveError) {
                error.textContent = "Could not reach the server";
                error.hidden = false;
            } finally {
                button.disabled = false;
            }
        });
        nameInput.focus();
    }

    function openNotePanel(d) {
        noteTarget = d;
        noteHost.textContent = d.label;
        noteInput.value = d.note || "";
        notePanel.hidden = false;
        noteInput.focus();
        hideHostMenu();
    }

    function closeNotePanel() {
        noteTarget = null;
        notePanel.hidden = true;
    }

    noteClose.addEventListener("click", closeNotePanel);
    noteCancel.addEventListener("click", closeNotePanel);
    noteSave.addEventListener("click", async () => {
        if (!noteTarget) return;
        noteSave.disabled = true;
        try {
            await saveHostNote(noteTarget, noteInput.value.trim());
        } finally {
            noteSave.disabled = false;
        }
    });

    async function saveHostNote(d, note) {
        const result = await Api.updateHostNote(d.ip, note);
        if (!result.ok) {
            window.alert(`Could not save note: ${result.error || "Unknown error"}`);
            return;
        }
        d.note = result.note;
        renderHostDetails(d);
        closeNotePanel();
    }

    container.addEventListener("pointerdown", event => {
        if (!event.target.closest(".graph-host-menu")) hideHostMenu();
    });

    let scannerNode = null;

    if (scanner) {
        scannerNode = nodeLayer.append("g")
            .datum(scanner)
            .attr("class", "graph-node scanner")
            .attr("transform", `translate(${scanner.x},${scanner.y})`)
            .call(d3.drag()
                .clickDistance(4)
                .on("start", dragstarted)
                .on("drag", dragged)
                .on("end", dragended));

        scannerNode.append("circle")
            .attr("r", 20);

        scannerNode.append("path")
            .attr("class", "graph-scanner-icon")
            .attr("d", "M-9,-6 L9,-6 L9,4 L-9,4 Z M-12,7 L12,7 M-5,7 L-5,10 M5,7 L5,10 M-6,-6 L-6,-9 L6,-9 L6,-6")
            .attr("fill", "none");

        scannerNode.append("text")
            .attr("class", "graph-node-label")
            .attr("dy", -30)
            .attr("text-anchor", "middle")
            .text(d => d.label);

        scannerNode.on("click", (event, d) => {
            allSelectable.classed("selected", n => n === d);
            renderScannerDetails(d);
        });
    }

    const allSelectable = scannerNode ? hostNode.merge(scannerNode) : hostNode;

    function updateEdges() {
        edgeGroups.select("line")
            .attr("x1", d => byId[d.from].x)
            .attr("y1", d => byId[d.from].y)
            .attr("x2", d => byId[d.to].x)
            .attr("y2", d => byId[d.to].y);

        edgeGroups.select("rect")
            .attr("x", d => (byId[d.from].x + byId[d.to].x) / 2 - 24)
            .attr("y", d => (byId[d.from].y + byId[d.to].y) / 2 - 8);

        edgeGroups.select("text")
            .attr("x", d => (byId[d.from].x + byId[d.to].x) / 2)
            .attr("y", d => (byId[d.from].y + byId[d.to].y) / 2 + 3);
    }

    function dragstarted(event, d) {
        d3.select(this).raise();
    }

    function dragged(event, d) {
        d.x = event.x;
        d.y = event.y;
        d3.select(this).attr("transform", `translate(${d.x},${d.y})`);
        updateEdges();
    }

    function dragended(event, d) {}

    function escapeHtml(value) {
        if (value === null || value === undefined) return "-";
        return String(value)
            .replace(/&/g, "&amp;")
            .replace(/</g, "&lt;")
            .replace(/>/g, "&gt;")
            .replace(/"/g, "&quot;")
            .replace(/'/g, "&#39;");
    }

    function renderScannerDetails(d) {
        detailsTarget = null;
        details.innerHTML = `
            <div class="graph-details-title">Scanner host <span class="graph-details-sub">(this machine)</span></div>
            <table class="graph-details-table">
                <thead><tr><th>IP</th><th>Interface</th></tr></thead>
                <tbody><tr><td>${escapeHtml(d.ip)}</td><td>${escapeHtml(d.interface)}</td></tr></tbody>
            </table>
        `;
    }

    function renderHostDetails(d) {
        detailsTarget = d;
        const hostIp = `<div class="graph-details-host-ip">IP: ${escapeHtml(d.ip || "-")}</div>`;
        const rolesRow = `
            <div class="graph-details-roles">
                <span class="graph-details-roles-label">Roles</span>
                ${Roles.chips(d.roles)}
                ${AppState.canEditHosts ? '<button type="button" class="graph-details-edit" id="graph-edit-roles">Edit Roles</button>' : ""}
            </div>`;
        const bindRoles = () => {
            const button = document.getElementById("graph-edit-roles");
            if (button) button.addEventListener("click", () => openRoleEditor(d));
        };

        if (!d.ports || d.ports.length === 0) {
            details.innerHTML = `
                <div class="graph-details-title">${escapeHtml(d.label)} <span class="graph-details-sub">(${escapeHtml(d.os || "Unknown OS")})</span></div>
                ${hostIp}
                ${rolesRow}
                ${d.note ? `<div class="graph-details-note">${escapeHtml(d.note)}</div>` : ""}
                <div class="graph-details-empty">No open ports.</div>
            `;
            bindRoles();
            return;
        }

        const rows = d.ports.map(p => {
            const protocol = String(p.protocol || "").toUpperCase();
            const protocolClass = protocol === "TCP" || protocol === "UDP" ? protocol.toLowerCase() : "";
            return `
            <tr>
                <td class="graph-details-port">${escapeHtml(p.port)}</td>
                <td class="graph-details-protocol ${protocolClass}">${escapeHtml(protocol)}</td>
                <td class="graph-details-service">${escapeHtml(p.service)}</td>
                <td>${escapeHtml(p.version || p.product)}</td>
                <td>${escapeHtml(p.state)}</td>
            </tr>
        `;
        }).join("");

        details.innerHTML = `
            <div class="graph-details-title">${escapeHtml(d.label)} <span class="graph-details-sub">(${escapeHtml(d.os || "Unknown OS")}, ${d.port_count} open port${d.port_count === 1 ? "" : "s"}, discovered via ${DISCOVERY_TYPE_LABEL[d.type] || d.type || "-"})</span></div>
            ${hostIp}
            ${rolesRow}
            ${d.note ? `<div class="graph-details-note">${escapeHtml(d.note)}</div>` : ""}
            <table class="graph-details-table">
                <thead>
                    <tr><th>Port</th><th>Protocol</th><th>Service</th><th>Version</th><th>State</th></tr>
                </thead>
                <tbody>${rows}</tbody>
            </table>
        `;
        bindRoles();
    }
};