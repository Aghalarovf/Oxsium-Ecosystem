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

const DataApi = {
    async list() {
        const res = await fetch("/api/admin/data-files");
        return res.json();
    },
    async createSnapshot(label) {
        const res = await fetch("/api/admin/snapshots", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ label })
        });
        return res.json();
    },
    async deleteSnapshot(name) {
        const res = await fetch(`/api/admin/snapshots/${encodeURIComponent(name)}`, { method: "DELETE" });
        return res.json();
    },
    async restore(kind, name, password) {
        const res = await fetch("/api/admin/restore", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ kind, name, password })
        });
        return res.json();
    },
    async optimize() {
        const res = await fetch("/api/admin/optimize", { method: "POST" });
        return res.json();
    }
};

let currentAdminRole = null;

function formatSize(bytes) {
    if (bytes < 1024) return `${bytes} B`;
    if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
    return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
}

function showDataError(message) {
    const box = document.getElementById("data-error");
    box.textContent = message || "";
    box.classList.toggle("visible", !!message);
}

function openRestoreDialog(kind, name) {
    return new Promise(resolve => {
        const overlay = document.createElement("div");
        overlay.className = "restore-overlay";
        overlay.innerHTML = `
            <form class="restore-dialog" role="dialog" aria-modal="true" aria-labelledby="restore-title">
                <div class="restore-title" id="restore-title">Restore database</div>
                <p>Scan data and subnet names will be replaced with the contents of <code>${Util.esc(name)}</code>. The current data is archived first, and user accounts are not changed.</p>
                <label for="restore-password">Administrator password</label>
                <input id="restore-password" type="password" autocomplete="current-password">
                <div class="restore-error" hidden></div>
                <div class="restore-actions">
                    <button type="button" data-cancel>Cancel</button>
                    <button type="submit" class="danger">Restore</button>
                </div>
            </form>`;
        const form = overlay.querySelector("form");
        const input = overlay.querySelector("input");
        const errorBox = overlay.querySelector(".restore-error");
        const submit = overlay.querySelector("[type=submit]");

        function close(value) {
            document.removeEventListener("keydown", onKey, true);
            overlay.remove();
            resolve(value);
        }

        function onKey(event) {
            if (event.key === "Escape") {
                event.stopPropagation();
                close(null);
            }
        }

        overlay.addEventListener("mousedown", event => {
            if (event.target === overlay) close(null);
        });
        overlay.querySelector("[data-cancel]").addEventListener("click", () => close(null));
        form.addEventListener("submit", async event => {
            event.preventDefault();
            if (!input.value) {
                errorBox.textContent = "Enter your administrator password";
                errorBox.hidden = false;
                return;
            }
            submit.disabled = true;
            errorBox.hidden = true;
            let result;
            try {
                result = await DataApi.restore(kind, name, input.value);
            } catch (error) {
                result = { ok: false, error: "Request failed" };
            }
            submit.disabled = false;
            if (!result.ok) {
                errorBox.textContent = result.error || "Could not restore the database";
                errorBox.hidden = false;
                input.select();
                return;
            }
            close(result);
        });

        document.addEventListener("keydown", onKey, true);
        document.body.appendChild(overlay);
        input.focus();
    });
}

function renderDataTables(data) {
    const snapshots = document.getElementById("snapshots-table-body");
    const backups = document.getElementById("backups-table-body");

    snapshots.innerHTML = data.snapshots.length ? data.snapshots.map(item => `
        <tr data-kind="snapshot" data-name="${Util.esc(item.name)}">
            <td>${Util.esc(item.name)}</td>
            <td>${item.label ? Util.esc(item.label) : "-"}</td>
            <td>${formatTimestamp(item.created_at)}</td>
            <td>${item.datasets}</td>
            <td>${formatSize(item.size)}</td>
            <td>
                <div class="admin-row-actions">
                    ${item.restoreable ? '<button type="button" class="btn-secondary restore-data">Restore</button>' : '<span>Current database</span>'}
                    <button type="button" class="btn-danger delete-snapshot">Delete</button>
                </div>
            </td>
        </tr>
    `).join("") : '<tr><td colspan="6" class="admin-empty">No snapshots yet</td></tr>';

    backups.innerHTML = data.backups.length ? data.backups.map(item => `
        <tr data-kind="backup" data-name="${Util.esc(item.name)}">
            <td>${Util.esc(item.name)}</td>
            <td>${formatTimestamp(item.created_at)}</td>
            <td>${item.datasets}</td>
            <td>${formatSize(item.size)}</td>
            <td>
                <div class="admin-row-actions">
                    ${item.restoreable ? '<button type="button" class="btn-secondary restore-data">Restore</button>' : '<span>Current database</span>'}
                </div>
            </td>
        </tr>
    `).join("") : '<tr><td colspan="5" class="admin-empty">No database backups found</td></tr>';

    document.querySelectorAll("#data-admin tr[data-name]").forEach(row => {
        const kind = row.dataset.kind;
        const name = row.dataset.name;

        const restoreButton = row.querySelector(".restore-data");
        if (restoreButton) restoreButton.addEventListener("click", async () => {
            showDataError("");
            const result = await openRestoreDialog(kind, name);
            if (!result) return;
            await loadDataFiles();
        });

        const deleteButton = row.querySelector(".delete-snapshot");
        if (deleteButton) deleteButton.addEventListener("click", async () => {
            if (!confirm("Delete this snapshot permanently?")) return;
            const result = await DataApi.deleteSnapshot(name);
            if (!result.ok) showDataError(result.error);
            await loadDataFiles();
        });
    });
}

async function loadDataFiles() {
    const result = await DataApi.list();
    if (result.ok) renderDataTables(result);
}

async function optimizeDatabase() {
    showDataError("");
    const button = document.getElementById("database-optimize");
    button.disabled = true;
    try {
        const result = await DataApi.optimize();
        if (!result.ok) {
            showDataError(result.error || "Could not optimize the database");
            return;
        }
        alert(result.removed
            ? `Database optimized. Removed ${result.removed} duplicate host${result.removed === 1 ? "" : "s"}.`
            : "Database is already optimized. No duplicate hosts found.");
        await loadDataFiles();
    } catch (error) {
        showDataError("Request failed");
    } finally {
        button.disabled = false;
    }
}

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
        if (!manager) {
            document.getElementById("data-admin").hidden = false;
            loadDataFiles();
            document.getElementById("database-optimize").addEventListener("click", optimizeDatabase);
        }
    });

    const snapshotForm = document.getElementById("create-snapshot-form");
    snapshotForm.addEventListener("submit", async (event) => {
        event.preventDefault();
        showDataError("");
        const submit = document.getElementById("snapshot-submit");
        const label = document.getElementById("snapshot-label").value.trim();
        submit.disabled = true;
        let result;
        try {
            result = await DataApi.createSnapshot(label);
        } catch (error) {
            result = { ok: false, error: "Request failed" };
        }
        submit.disabled = false;
        if (!result.ok) {
            showDataError(result.error);
            return;
        }
        snapshotForm.reset();
        await loadDataFiles();
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
