window.initHostsTable = async function() {
    const body = document.getElementById("hosts-table-body");
    const sub = document.getElementById("hosts-table-sub");
    const res = await Api.getHosts();

    if (!res.ok) {
        body.innerHTML = '<div class="data-empty">No dataset loaded yet.</div>';
        return;
    }

    document.getElementById("hosts-count").textContent = res.total;
    document.getElementById("hosts-ports").textContent = res.hosts.reduce((sum, host) => sum + host.port_count, 0);

    if (sub) {
        sub.textContent = res.total === res.unfiltered_total
            ? `${res.total} hosts and their open ports. Click a Roles cell to edit.`
            : `Showing ${res.total} of ${res.unfiltered_total} hosts. Click a Roles cell to edit.`;
    }

    if (!res.hosts.length) {
        body.innerHTML = '<div class="data-empty">No hosts match the current filters.</div>';
        return;
    }

    const hosts = res.hosts;
    body.innerHTML = hosts.map((h, i) => `
        <div class="security-proto-item">
            <div class="data-col w120">${Util.esc(h.host)}</div>
            <div class="data-col w90">${Util.esc(h.os || "-")}</div>
            <div class="data-col w70">${h.port_count}</div>
            <div class="data-col w220 ${AppState.canEditHosts ? "host-roles-cell" : ""}" data-i="${i}" title="${AppState.canEditHosts ? "Click to edit roles" : ""}">${Roles.chips(h.roles)}</div>
            <div class="data-col flex1">${Util.esc(h.ports.map(p => `${p.port}/${p.protocol}`).join(", "))}</div>
        </div>
    `).join("");

    body.addEventListener("click", event => {
        const cell = event.target.closest(".host-roles-cell");
        if (!cell || !AppState.canEditHosts) return;
        const h = hosts[Number(cell.dataset.i)];
        Roles.openEditor({ host: h.host, roles: h.roles, ports: h.ports, os: h.os }, roles => {
            h.roles = roles;
            cell.innerHTML = Roles.chips(roles);
        });
    });
};