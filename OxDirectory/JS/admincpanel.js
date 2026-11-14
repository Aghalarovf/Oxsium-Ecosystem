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
    },
    async resetDatabase(password, sections) {
        const controller = new AbortController();
        const timeout = setTimeout(() => controller.abort(), 30000);
        try {
            const res = await fetch("/api/admin/reset-database", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ password, sections }),
                signal: controller.signal
            });
            const contentType = res.headers.get("content-type") || "";
            const body = await res.text();
            if (!contentType.includes("application/json")) {
                throw new Error(`Server returned ${res.status} ${res.statusText || "an invalid response"}`);
            }
            return JSON.parse(body);
        } finally {
            clearTimeout(timeout);
        }
    },
    async optimizeDatabase() {
        const res = await fetch("/api/admin/optimize", { method: "POST" });
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
    body.innerHTML = users.map(user => `
        <tr data-id="${user.id}" class="${user.is_active ? "" : "user-disabled"}">
            <td>${Util.esc(user.username)}</td>
            <td><span class="role-pill ${Util.esc(user.role)}">${Util.esc(user.role)}</span></td>
            <td>${formatTimestamp(user.last_login_at)}</td>
            <td>
                <div class="admin-row-actions">
                    <select class="role-select">
                        <option value="viewer" ${user.role === "viewer" ? "selected" : ""}>Viewer</option>
                        <option value="analyst" ${user.role === "analyst" ? "selected" : ""}>Analyst</option>
                        <option value="operator" ${user.role === "operator" ? "selected" : ""}>Operator</option>
                        <option value="manager" ${user.role === "manager" ? "selected" : ""}>Manager</option>
                        <option value="user" ${user.role === "user" ? "selected" : ""}>User</option>
                        ${currentAdminRole === "super_admin" ? `<option value="admin" ${user.role === "admin" ? "selected" : ""}>Admin</option>
                        <option value="super_admin" ${user.role === "super_admin" ? "selected" : ""}>Super Admin</option>` : ""}
                    </select>
                    ${currentAdminRole === "super_admin" ? `<button type="button" class="btn-secondary toggle-active">${user.is_active ? "Disable" : "Enable"}</button>
                    <button type="button" class="btn-danger delete-user">Delete</button>` : ""}
                </div>
            </td>
        </tr>
    `).join("");

    body.querySelectorAll("tr").forEach(row => {
        const id = row.dataset.id;
        row.querySelector(".role-select").addEventListener("change", async event => {
            const result = await AdminApi.updateRole(id, event.target.value);
            if (!result.ok) alert(result.error);
            await loadUsers();
        });

        const activeButton = row.querySelector(".toggle-active");
        if (activeButton) {
            activeButton.addEventListener("click", async () => {
                const nowActive = !row.classList.contains("user-disabled");
                const result = await AdminApi.setActive(id, nowActive);
                if (!result.ok) alert(result.error);
                await loadUsers();
            });
        }

        const deleteButton = row.querySelector(".delete-user");
        if (deleteButton) {
            deleteButton.addEventListener("click", async () => {
                if (!confirm("Delete this user permanently?")) return;
                const result = await AdminApi.deleteUser(id);
                if (!result.ok) alert(result.error);
                await loadUsers();
            });
        }
    });
}

async function loadUsers() {
    const result = await AdminApi.listUsers();
    if (result.ok) renderUsersTable(result.users);
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
        const resetSection = document.getElementById("database-reset-section");
        if (resetSection) resetSection.hidden = user.role !== "super_admin";
        const optimizationSection = document.getElementById("database-optimization-section");
        if (optimizationSection) optimizationSection.hidden = !["admin", "super_admin"].includes(user.role);
        loadUsers();
    });

    const form = document.getElementById("create-user-form");
    const errorBox = document.getElementById("admin-error");
    form.addEventListener("submit", async event => {
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

    const resetButton = document.getElementById("reset-database-button");
    const resetStatus = document.getElementById("database-reset-status");
    if (resetButton) {
        resetButton.addEventListener("click", async () => {
            const result = await openResetDialog();
            if (!result) return;
            resetButton.disabled = true;
            resetStatus.textContent = "Resetting databases...";
            if (result.ok) {
                resetStatus.textContent = "Reset complete. User accounts were preserved.";
                await loadUsers();
                resetButton.disabled = false;
                window.location.href = "/";
            }
        });

        function openResetDialog() {
            return new Promise(resolve => {
                const overlay = document.createElement("div");
                overlay.className = "reset-overlay";
                overlay.innerHTML = `
                    <form class="reset-dialog" role="dialog" aria-modal="true" aria-labelledby="reset-title">
                        <div class="reset-title" id="reset-title">Reset database</div>
                        <p>Select the directory sections to permanently delete. Platform user accounts and administrator access will be preserved.</p>
                        <div class="reset-section-picker">
                            <div class="reset-section-heading">
                                <span>Sections to reset</span>
                                <button type="button" class="reset-select-all">Select all</button>
                            </div>
                            ${[
                                ["domain", "Domain"],
                                ["aces", "ACEs"],
                                ["users", "Users"],
                                ["groups", "Groups"],
                                ["computers", "Computers"],
                                ["ous", "OUs"],
                                ["gpos", "GPOs"],
                                ["trusts", "Trusts"],
                                ["certificates", "Certificates"]
                            ].map(([value, label]) => `
                                <label class="reset-section-option">
                                    <input type="checkbox" name="reset-section" value="${value}" checked>
                                    <span>${label}</span>
                                </label>`).join("")}
                        </div>
                        <label for="reset-password">Administrator password</label>
                        <input id="reset-password" type="password" autocomplete="current-password">
                        <div class="reset-error" hidden></div>
                        <div class="reset-actions">
                            <button type="button" data-cancel>Cancel</button>
                            <button type="submit" class="danger">Reset</button>
                        </div>
                    </form>`;
                const form = overlay.querySelector("form");
                const input = overlay.querySelector("#reset-password");
                const sectionInputs = overlay.querySelectorAll("input[name=reset-section]");
                const errorBox = overlay.querySelector(".reset-error");
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
                overlay.querySelector(".reset-select-all").addEventListener("click", event => {
                    const selectAll = Array.from(sectionInputs).some(section => !section.checked);
                    sectionInputs.forEach(section => { section.checked = selectAll; });
                    event.currentTarget.textContent = selectAll ? "Clear all" : "Select all";
                });
                form.addEventListener("submit", async event => {
                    event.preventDefault();
                    if (!input.value) {
                        errorBox.textContent = "Enter your administrator password";
                        errorBox.hidden = false;
                        return;
                    }
                    const sections = Array.from(sectionInputs)
                        .filter(section => section.checked)
                        .map(section => section.value);
                    if (!sections.length) {
                        errorBox.textContent = "Select at least one section to reset";
                        errorBox.hidden = false;
                        return;
                    }
                    submit.disabled = true;
                    errorBox.hidden = true;
                    try {
                        const result = await AdminApi.resetDatabase(input.value, sections);
                        if (!result.ok) {
                            errorBox.textContent = result.error || "Could not reset database";
                            errorBox.hidden = false;
                            input.select();
                            submit.disabled = false;
                            return;
                        }
                        close(result);
                    } catch (error) {
                        errorBox.textContent = error.name === "AbortError"
                            ? "Database reset timed out. Check the server logs."
                            : `Request failed: ${error.message || "Unknown error"}`;
                        console.error("Database reset request failed", error);
                        errorBox.hidden = false;
                        submit.disabled = false;
                    }
                });
                document.addEventListener("keydown", onKey, true);
                document.body.appendChild(overlay);
                input.focus();
            });
        }
    }

    const optimizeButton = document.getElementById("database-optimize");
    const optimizeStatus = document.getElementById("database-optimization-status");
    if (optimizeButton) {
        optimizeButton.addEventListener("click", async () => {
            optimizeButton.disabled = true;
            optimizeStatus.classList.remove("visible");
            try {
                const result = await AdminApi.optimizeDatabase();
                if (!result.ok) {
                    optimizeStatus.textContent = result.error || "Could not optimize the database";
                    optimizeStatus.classList.add("visible");
                    return;
                }
                alert(result.removed
                    ? `Database optimized. Removed ${result.removed} duplicate record${result.removed === 1 ? "" : "s"}.`
                    : "Database is already optimized. No duplicate records found.");
            } catch (error) {
                optimizeStatus.textContent = "Request failed";
                optimizeStatus.classList.add("visible");
            } finally {
                optimizeButton.disabled = false;
            }
        });
    }
});
