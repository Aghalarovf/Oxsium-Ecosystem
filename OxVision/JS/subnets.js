function subnetLabel(subnet) {
    if (typeof subnet === "string") return subnet;
    if (!subnet || typeof subnet !== "object") return String(subnet);
    return subnet.subnet || subnet.network || subnet.cidr || JSON.stringify(subnet);
}

window.initSubnets = async function() {
    const body = document.getElementById("subnets-table-body");
    const res = await Api.getMeta();

    if (!res.ok) {
        body.innerHTML = '<div class="data-empty">No dataset loaded yet.</div>';
        return;
    }

    const subnets = res.subnets || [];
    const groups = { ...(res.subnet_groups || {}) };
    const groupNames = new Set(res.subnet_group_names || []);
    const filter = document.getElementById("subnet-group-filter");
    const groupNameInput = document.getElementById("subnet-group-name");
    const createGroup = document.getElementById("subnet-group-create");
    let activeGroup = "";

    function renderGroupOptions() {
        filter.innerHTML = '<option value="">All groups</option>' +
            [...groupNames].sort((a, b) => a.localeCompare(b)).map(name =>
                `<option value="${Util.esc(name)}">${Util.esc(name)}</option>`).join("");
        filter.value = activeGroup;
    }

    function render() {
        const visible = subnets
            .map(subnet => ({ subnet, label: subnetLabel(subnet) }))
            .filter(item => !activeGroup || groups[item.label] === activeGroup)
            .sort((a, b) => (groups[a.label] || "Unassigned").localeCompare(groups[b.label] || "Unassigned")
                || a.label.localeCompare(b.label));
        body.replaceChildren(...visible.map(item => {
            const row = document.createElement("div");
            row.className = "security-proto-item";
            row.innerHTML = `<span class="flex1">${Util.esc(item.label)}</span>`;
            const select = document.createElement("select");
            select.className = "subnet-group-select";
            select.disabled = !AppState.canManageSubnets;
            select.innerHTML = '<option value="">Unassigned</option>' +
                [...groupNames].sort((a, b) => a.localeCompare(b)).map(name =>
                    `<option value="${Util.esc(name)}">${Util.esc(name)}</option>`).join("");
            select.value = groups[item.label] || "";
            select.addEventListener("change", async () => {
                select.disabled = true;
                const result = await Api.updateSubnetGroup(item.label, select.value);
                select.disabled = !AppState.canManageSubnets;
                if (!result.ok) {
                    window.alert(result.error || "Could not save subnet group");
                    select.value = groups[item.label] || "";
                    return;
                }
                if (result.group_name) {
                    groups[item.label] = result.group_name;
                    groupNames.add(result.group_name);
                } else {
                    delete groups[item.label];
                }
                renderGroupOptions();
                render();
            });
            row.appendChild(select);
            row.tabIndex = 0;
            row.classList.toggle("selected", AppState.selectedSubnet === item.label);
            row.addEventListener("click", event => {
                if (event.target === select) return;
                selectSubnet(item.label);
            });
            row.addEventListener("contextmenu", event => {
                event.preventDefault();
                event.stopPropagation();
                showSubnetMenu(event, item.label);
            });
            row.addEventListener("keydown", event => {
                if (event.key === "Enter" || event.key === " ") selectSubnet(item.label);
            });
            return row;
        }));
        if (!visible.length) body.innerHTML = '<div class="data-empty">No subnets in this group.</div>';
    }

    document.getElementById("subnets-count").textContent = subnets.length;
    document.getElementById("subnets-selection").textContent = AppState.selectedSubnet ? "1" : "ALL";
    if (subnets.length === 0) {
        body.innerHTML = '<div class="data-empty">No subnets found.</div>';
        return;
    }

    renderGroupOptions();
    filter.addEventListener("change", () => {
        activeGroup = filter.value;
        render();
    });
    createGroup.addEventListener("click", async () => {
        const name = groupNameInput.value.trim();
        if (!name) return;
        const result = await Api.createSubnetGroup(name);
        if (!result.ok) {
            window.alert(result.error || "Could not create subnet group");
            return;
        }
        groupNames.add(result.group_name);
        groupNameInput.value = "";
        renderGroupOptions();
        activeGroup = name;
        filter.value = name;
        render();
    });
    createGroup.disabled = !AppState.canManageSubnets;
    groupNameInput.disabled = !AppState.canManageSubnets;
    render();
};

function selectSubnet(subnet) {
    AppState.selectedSubnet = AppState.selectedSubnet === subnet ? null : subnet;
    loadView("dashboard");
    refreshPanel();
}
