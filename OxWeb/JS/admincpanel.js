const AdminApi = {
    async listUsers() {
        const res = await fetch("/api/admin/users");
        return res.json();
    },
    async createUser(username, password, role, team) {
        const res = await fetch("/api/admin/users", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ username, password, role, team })
        });
        return res.json();
    },
    async updateRole(id, role) {
        const res = await fetch(`/api/admin/users/${id}/role`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ role })
        });
        return res.json();
    },
    async setActive(id, is_active) {
        const res = await fetch(`/api/admin/users/${id}/active`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ is_active })
        });
        return res.json();
    },
    async deleteUser(id) {
        const res = await fetch(`/api/admin/users/${id}`, { method: "DELETE" });
        return res.json();
    }
};

let currentAdminRole = null;

function formatTimestamp(value) {
    if (!value) return "Never";
    return new Date(value * 1000).toLocaleString();
}

function renderUsersTable(users) {
    const body = document.getElementById("users-table-body");
    document.getElementById("admin-total-users").textContent = users.length;
    document.getElementById("admin-active-users").textContent = users.filter(user => user.is_active).length;
    document.getElementById("admin-privileged-users").textContent = users.filter(user => user.role !== "user").length;
    body.innerHTML = users.map(u => `
        <tr data-id="${u.id}">
            <td>${Util.esc(u.username)}</td>
            <td><span class="role-pill ${Util.esc(u.role)}">${Util.esc(u.role)}</span></td>
            <td>
                <span class="status-pill ${u.is_active ? "active" : "disabled"}">${u.is_active ? "Active" : "Disabled"}</span>
                ${u.locked ? '<span class="status-pill disabled">Locked</span>' : ""}
            </td>
            <td>${formatTimestamp(u.last_login_at)}</td>
            <td>
                <div class="admin-row-actions">
                    <select class="role-select">
                        <option value="viewer" ${u.role === "viewer" ? "selected" : ""}>Viewer</option>
                        <option value="analyst" ${u.role === "analyst" ? "selected" : ""}>Analyst</option>
                        <option value="operator" ${u.role === "operator" ? "selected" : ""}>Operator</option>
                        <option value="manager" ${u.role === "manager" ? "selected" : ""}>Manager</option>
                        <option value="user" ${u.role === "user" ? "selected" : ""}>User</option>
                        ${currentAdminRole === "super_admin" ? `<option value="admin" ${u.role === "admin" ? "selected" : ""}>Admin</option>
                        <option value="super_admin" ${u.role === "super_admin" ? "selected" : ""}>Super Admin</option>` : ""}
                    </select>
                    ${currentAdminRole === "super_admin" ? `<button type="button" class="btn-secondary toggle-active">${u.is_active ? "Disable" : "Enable"}</button>
                    <button type="button" class="btn-danger delete-user">Delete</button>` : ""}
                </div>
            </td>
        </tr>
    `).join("");

    body.querySelectorAll("tr").forEach(row => {
        const id = row.dataset.id;

        row.querySelector(".role-select").addEventListener("change", async (event) => {
            const result = await AdminApi.updateRole(id, event.target.value);
            if (!result.ok) {
                alert(result.error);
            }
            await loadUsers();
        });

        const activeButton = row.querySelector(".toggle-active");
        if (activeButton) activeButton.addEventListener("click", async () => {
            const nowActive = row.querySelector(".status-pill").textContent.trim() !== "Active";
            const result = await AdminApi.setActive(id, nowActive);
            if (!result.ok) {
                alert(result.error);
            }
            await loadUsers();
        });

        const deleteButton = row.querySelector(".delete-user");
        if (deleteButton) deleteButton.addEventListener("click", async () => {
            if (!confirm("Delete this user permanently?")) return;
            const result = await AdminApi.deleteUser(id);
            if (!result.ok) {
                alert(result.error);
            }
            await loadUsers();
        });
    });
}

async function loadUsers() {
    const result = await AdminApi.listUsers();
    if (result.ok) {
        renderUsersTable(result.users);
    }
}

document.addEventListener("DOMContentLoaded", () => {
    Auth.me().then(user => {
        if (!user || !["manager", "admin", "super_admin"].includes(user.role)) {
            window.location.href = "/";
            return;
        }
        currentAdminRole = user.role;
        const manager = user.role === "manager";
        document.querySelector(".admin-section-heading").hidden = manager;
        document.getElementById("create-user-form").hidden = manager;
        document.getElementById("admin-error").hidden = manager;
        loadUsers();
    });

    const form = document.getElementById("create-user-form");
    const errorBox = document.getElementById("admin-error");

    form.addEventListener("submit", async (event) => {
        event.preventDefault();
        errorBox.classList.remove("visible");

        const username = document.getElementById("new-username").value.trim();
        const password = document.getElementById("new-password").value;
        const role = document.getElementById("new-role").value;
        const team = document.getElementById("new-team").value.trim();

        const result = await AdminApi.createUser(username, password, role, team);
        if (!result.ok) {
            errorBox.textContent = result.error;
            errorBox.classList.add("visible");
            return;
        }

        form.reset();
        await loadUsers();
    });
});
