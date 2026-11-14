const Views = {
    dashboard: {
        async load() {
            const result = await Api.listTargets();
            if (result.ok) {
                document.getElementById("metric-targets").textContent = result.targets.length;
            }
        }
    },
    targets: {
        bound: false,
        async load() {
            if (!this.bound) this.bind();
            const result = await Api.listTargets();
            if (result.ok) this.render(result.targets);
        },
        render(targets) {
            const body = document.getElementById("targets-table-body");
            body.innerHTML = targets.length ? targets.map(t => `
                <tr data-id="${t.id}">
                    <td>${Util.esc(t.url)}</td>
                    <td>${Util.esc(t.name)}</td>
                    <td>${new Date(t.created_at * 1000).toLocaleString()}</td>
                    <td>${AppState.canDelete ? '<button type="button" class="btn-danger delete-target">Delete</button>' : ""}</td>
                </tr>
            `).join("") : '<tr><td colspan="4" class="admin-empty">No targets yet</td></tr>';

            body.querySelectorAll(".delete-target").forEach(button => {
                button.addEventListener("click", async () => {
                    if (!confirm("Delete this target permanently?")) return;
                    const result = await Api.deleteTarget(button.closest("tr").dataset.id);
                    if (!result.ok) alert(result.error);
                    await this.load();
                });
            });
        },
        bind() {
            this.bound = true;
            const form = document.getElementById("target-form");
            const errorBox = document.getElementById("target-error");
            form.hidden = !AppState.canCreate;
            form.addEventListener("submit", async event => {
                event.preventDefault();
                errorBox.classList.remove("visible");
                const result = await Api.addTarget({
                    url: document.getElementById("target-url").value.trim(),
                    name: document.getElementById("target-name").value.trim()
                });
                if (!result.ok) {
                    errorBox.textContent = result.error;
                    errorBox.classList.add("visible");
                    return;
                }
                form.reset();
                await this.load();
            });
        }
    }
};
