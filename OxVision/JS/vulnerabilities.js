const Vulnerabilities = (() => {
    const SEVERITIES = ["Critical", "High", "Medium", "Low", "Info"];
    const STATUSES = ["Open", "In Progress", "Fixed", "False Positive", "Accepted Risk"];
    const CATEGORIES = ["Vulnerability Scanner", "Post Exploitation"];

    let currentHost = null;
    let currentList = [];
    let formOverlay = null;
    let editingId = null;
    let cwePick = null;
    let cvssState = {};
    let activeFilter = null;
    let vulnMenu = null;
    let hostAssign = [];
    let hostAssignAll = [];
    let detailOverlay = null;

    function canEdit() {
        return !!AppState.canEditHosts || ["analyst", "operator", "admin", "super_admin"].includes(AppState.user && AppState.user.role);
    }

    function fmtDate(ts) {
        if (!ts) return "";
        const d = new Date(ts * 1000);
        return d.toLocaleDateString(undefined, { year: "numeric", month: "short", day: "numeric" });
    }

    async function render(hostId, container, addBtn) {
        currentHost = hostId;
        activeFilter = null;
        container.innerHTML = '<div class="data-empty">Loading...</div>';
        if (addBtn) {
            addBtn.hidden = !canEdit();
            addBtn.title = "Add vulnerability manually";
            addBtn.setAttribute("aria-label", "Add vulnerability manually");
        }

        const res = await Api.getVulnerabilities(hostId);
        if (!res.ok) {
            container.innerHTML = `<div class="data-empty">${Util.esc(res.error || "Could not load vulnerabilities")}</div>`;
            return;
        }
        currentList = res.vulnerabilities || [];
        renderList(container);
    }

    function statusClass(status) {
        return "st-" + String(status || "Open").toLowerCase().replace(/\s+/g, "-");
    }

    function renderList(container) {
        if (!currentList.length) {
            container.innerHTML = `
                <div class="vuln-empty">
                    <div class="vuln-empty-icon">
                        <svg width="26" height="26" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M12 3l8 3v6c0 4.5-3.2 8.2-8 9-4.8-.8-8-4.5-8-9V6l8-3z"/><path d="M9 12l2 2 4-4"/></svg>
                    </div>
                    <div class="vuln-empty-title">No vulnerabilities recorded</div>
                    <div class="vuln-empty-text">Findings added for this host will appear here.</div>
                </div>`;
            return;
        }

        const counts = {};
        SEVERITIES.forEach(s => counts[s] = 0);
        currentList.forEach(v => { if (counts[v.severity] !== undefined) counts[v.severity]++; });

        const open = currentList.filter(v => (v.status || "Open") === "Open").length;
        const visible = activeFilter ? currentList.filter(v => v.severity === activeFilter) : currentList;

        const overview = `
            <div class="vuln-overview">
                <div class="vuln-total">
                    <div class="vuln-total-label">Total findings</div>
                    <div class="vuln-total-value">${currentList.length}</div>
                    <div class="vuln-total-note">${open} open</div>
                </div>
                <div class="vuln-distribution">
                    <div class="vuln-bar">
                        ${SEVERITIES.filter(s => counts[s]).map(s => `<span class="sev-${s}" style="flex-grow:${counts[s]}"></span>`).join("")}
                    </div>
                    <div class="vuln-summary">
                        ${SEVERITIES.map(s => `
                            <button type="button" class="vuln-summary-chip sev-${s} ${activeFilter === s ? "active" : ""} ${counts[s] ? "" : "zero"}" data-vuln-filter="${s}">
                                <b>${counts[s]}</b>
                                <span><i></i>${s}</span>
                            </button>
                        `).join("")}
                    </div>
                </div>
            </div>
            <div class="vuln-list-head">
                <span>${activeFilter ? `${activeFilter} findings` : "All findings"} &middot; ${visible.length}</span>
                ${activeFilter ? '<button type="button" data-vuln-filter-clear>Clear filter</button>' : ""}
            </div>
        `;

        const cards = visible.map(v => renderCard(v)).join("");
        container.innerHTML = overview + `<div class="vuln-list">${cards}</div>`;

        container.querySelectorAll("[data-vuln-filter]").forEach(el => {
            el.addEventListener("click", () => {
                activeFilter = activeFilter === el.dataset.vulnFilter ? null : el.dataset.vulnFilter;
                renderList(container);
            });
        });
        const clearFilter = container.querySelector("[data-vuln-filter-clear]");
        if (clearFilter) {
            clearFilter.addEventListener("click", () => {
                activeFilter = null;
                renderList(container);
            });
        }

        container.querySelectorAll("[data-vuln-toggle]").forEach(el => {
            el.addEventListener("click", event => {
                if (event.target.closest("button, select, a")) return;
                const vuln = currentList.find(item => item.id === el.closest(".vuln-card").dataset.vulnId);
                if (vuln) openDetail(vuln);
            });
        });
        container.querySelectorAll("[data-vuln-edit]").forEach(el => {
            el.addEventListener("click", event => {
                event.stopPropagation();
                openForm(currentList.find(v => v.id === el.dataset.vulnEdit));
            });
        });
        container.querySelectorAll("[data-vuln-delete]").forEach(el => {
            el.addEventListener("click", async event => {
                event.stopPropagation();
                if (!confirm("Delete this vulnerability? This cannot be undone.")) return;
                const res = await Api.deleteVulnerability(currentHost, el.dataset.vulnDelete);
                if (res.ok) {
                    currentList = currentList.filter(v => v.id !== el.dataset.vulnDelete);
                    renderList(container);
                } else {
                    alert(res.error || "Could not delete vulnerability");
                }
            });
        });
        container.querySelectorAll(".vuln-card").forEach(card => {
            card.addEventListener("contextmenu", event => {
                event.preventDefault();
                event.stopPropagation();
                const vuln = currentList.find(v => v.id === card.dataset.vulnId);
                if (vuln) showVulnMenu(event, vuln, currentHost);
            });
        });
        container.querySelectorAll("[data-vuln-status]").forEach(el => {
            el.addEventListener("click", event => event.stopPropagation());
            el.addEventListener("change", async () => {
                const id = el.dataset.vulnStatus;
                const vuln = currentList.find(v => v.id === id);
                if (!vuln) return;
                const res = await Api.updateVulnerability(currentHost, id, { ...stripMeta(vuln), status: el.value });
                if (res.ok) {
                    Object.assign(vuln, res.vulnerability);
                } else {
                    alert(res.error || "Could not update status");
                    el.value = vuln.status;
                }
            });
            container.querySelectorAll("[data-vuln-category]").forEach(el => {
                el.addEventListener("click", event => event.stopPropagation());
                el.addEventListener("change", async () => {
                    const vuln = currentList.find(item => item.id === el.dataset.vulnCategory);
                    if (!vuln) return;
                    el.disabled = true;
                    const res = await Api.updateVulnerability(currentHost, vuln.id, {
                        ...stripMeta(vuln),
                        category: el.value
                    });
                    el.disabled = false;
                    if (res.ok) {
                        Object.assign(vuln, res.vulnerability);
                    } else {
                        el.value = vuln.category || CATEGORIES[0];
                        window.alert(res.error || "Could not update category");
                    }
                });
            });
        });
    }

    function stripMeta(vuln) {
        const { id, created_at, updated_at, ...fields } = vuln;
        return fields;
    }

    function renderCard(v) {
        const cvss = v.cvss;
        const score = cvss && cvss.score != null
            ? `<div class="vuln-score sev-${v.severity}"><b>${cvss.score.toFixed(1)}</b><small>CVSS ${cvss.version ? "v" + cvss.version : ""}</small></div>`
            : `<div class="vuln-score sev-${v.severity}"><b>&ndash;</b><small>CVSS</small></div>`;
        const editBtn = canEdit() ? `
            <button type="button" class="vuln-icon-btn" data-vuln-edit="${v.id}" title="Edit" aria-label="Edit vulnerability">&#9998;</button>
            <button type="button" class="vuln-icon-btn danger" data-vuln-delete="${v.id}" title="Delete" aria-label="Delete vulnerability">&times;</button>
        ` : "";
        const statusControl = canEdit() ? `
            <select class="vuln-status-select" data-vuln-status="${v.id}">
                ${STATUSES.map(s => `<option value="${s}" ${s === v.status ? "selected" : ""}>${s}</option>`).join("")}
            </select>
        ` : `<span>${Util.esc(v.status || "Open")}</span>`;
        const status = v.status || "Open";

        return `
            <div class="vuln-card sev-${v.severity}" data-vuln-id="${v.id}">
                <div class="vuln-card-head" data-vuln-toggle>
                    ${score}
                    <div class="vuln-card-main">
                        <div class="vuln-card-title-row">
                            <span class="sev-badge sev-${v.severity}">${v.severity}</span>
                            <span class="vuln-card-title">${Util.esc(v.title)}</span>
                        </div>
                        <div class="vuln-card-meta">
                            <span class="vuln-status-pill ${statusClass(status)}">${Util.esc(status)}</span>
                            ${v.cve_id ? `<span class="vuln-tag">${Util.esc(v.cve_id)}</span>` : ""}
                            ${v.cwe_id ? `<span class="vuln-tag">${Util.esc(v.cwe_id)}</span>` : ""}
                            ${v.affected_service ? `<span class="vuln-tag">${Util.esc(v.affected_service)}</span>` : ""}
                            ${v.created_at ? `<span class="vuln-tag muted">Found ${fmtDate(v.created_at)}</span>` : ""}
                        </div>
                    </div>
                    <div class="vuln-card-actions">${editBtn}<span class="vuln-chevron">&#9656;</span></div>
                </div>
                <div class="vuln-card-body">
                    <div class="vuln-detail-grid">
                        <div class="vuln-detail-block wide">
                            <label>Description</label>
                            ${v.description ? `<p>${Util.esc(v.description)}</p>` : '<p class="empty">No description provided.</p>'}
                        </div>
                        ${v.remediation ? `
                        <div class="vuln-detail-block wide">
                            <label>Remediation</label>
                            <p>${Util.esc(v.remediation)}</p>
                        </div>` : ""}
                        ${cvss && cvss.vector ? `
                        <div class="vuln-detail-block">
                            <label>CVSS Vector</label>
                            <p class="mono">${Util.esc(cvss.vector)}</p>
                        </div>` : ""}
                        ${v.cwe_id ? `
                        <div class="vuln-detail-block">
                            <label>Weakness Class</label>
                            <p><a href="https://cwe.mitre.org/data/definitions/${v.cwe_id.replace("CWE-", "")}.html" target="_blank" rel="noopener">${Util.esc(v.cwe_id)}</a></p>
                        </div>` : ""}
                        <div class="vuln-detail-block">
                            <label>Status</label>
                            ${statusControl}
                        </div>
                        <div class="vuln-detail-block">
                            <label>Category</label>
                            ${canEdit() ? `
                                <select class="vuln-status-select" data-vuln-category="${v.id}">
                                    ${CATEGORIES.map(category => `<option value="${category}" ${category === (v.category || CATEGORIES[0]) ? "selected" : ""}>${category}</option>`).join("")}
                                </select>
                            ` : `<p>${Util.esc(v.category || CATEGORIES[0])}</p>`}
                        </div>
                    </div>
                </div>
            </div>
        `;
    }

    function closeDetail() {
        if (detailOverlay) detailOverlay.remove();
        detailOverlay = null;
    }

    function detailBlock(label, value, code = false) {
        if (!value) return "";
        return `<section class="vuln-detail-panel-block"><h3>${Util.esc(label)}</h3><pre class="${code ? "vuln-command" : ""}">${Util.esc(value)}</pre></section>`;
    }

    function openDetail(vuln, hostId = currentHost) {
        closeDetail();
        currentHost = hostId || currentHost;
        const overlay = document.createElement("div");
        overlay.className = "vuln-detail-overlay";
        const cvss = vuln.cvss && vuln.cvss.score != null
            ? `${vuln.cvss.score.toFixed(1)} (${vuln.cvss.version ? `CVSS v${vuln.cvss.version}` : "CVSS"})`
            : "Not provided";
        overlay.innerHTML = `
            <div class="vuln-detail-backdrop"></div>
            <aside class="vuln-detail-panel" role="dialog" aria-modal="true" aria-labelledby="vuln-detail-title">
                <header class="vuln-detail-panel-header">
                    <div>
                        <span class="sev-badge sev-${Util.esc(vuln.severity)}">${Util.esc(vuln.severity)}</span>
                        <h2 id="vuln-detail-title">${Util.esc(vuln.title)}</h2>
                        <p>${Util.esc(vuln.category || CATEGORIES[0])} · ${Util.esc(vuln.status || "Open")}</p>
                    </div>
                    <button type="button" class="vulnerabilities-close" data-detail-close aria-label="Close">&times;</button>
                </header>
                <div class="vuln-detail-panel-body">
                    <div class="vuln-detail-facts">
                        <div><span>Host</span><strong>${Util.esc(currentHost || "Unknown")}</strong></div>
                        <div><span>CVSS</span><strong>${Util.esc(cvss)}</strong></div>
                        <div><span>CVE</span><strong>${Util.esc(vuln.cve_id || "Not provided")}</strong></div>
                        <div><span>CWE</span><strong>${Util.esc(vuln.cwe_id || "Not provided")}</strong></div>
                        <div><span>Service</span><strong>${Util.esc(vuln.affected_service || "Not provided")}</strong></div>
                    </div>
                    ${detailBlock("Description", vuln.description)}
                    ${detailBlock("Remediation", vuln.remediation)}
                    ${detailBlock("Proof of Concept (PoC)", vuln.poc, true)}
                    ${detailBlock("Exploit Commands", vuln.exploit_commands, true)}
                    ${!vuln.description && !vuln.remediation && !vuln.poc && !vuln.exploit_commands ? '<p class="vuln-detail-empty">No additional details recorded.</p>' : ""}
                </div>
                <footer class="vuln-detail-panel-footer">
                    ${canEdit() ? '<button type="button" class="btn-primary" data-detail-edit>Edit vulnerability</button>' : ""}
                    <button type="button" class="btn-secondary" data-detail-close>Close</button>
                </footer>
            </aside>`;
        document.body.appendChild(overlay);
        detailOverlay = overlay;
        overlay.querySelectorAll("[data-detail-close]").forEach(button => button.addEventListener("click", closeDetail));
        overlay.querySelector("[data-detail-edit]")?.addEventListener("click", () => {
            closeDetail();
            openForm(vuln);
        });
        overlay.querySelector(".vuln-detail-backdrop").addEventListener("click", closeDetail);
    }

    async function removeVulnerability(vuln, hostId) {
        if (!window.confirm("Delete this vulnerability? This cannot be undone.")) return;
        const res = await Api.deleteVulnerability(hostId, vuln.id);
        if (!res.ok) {
            window.alert(res.error || "Could not delete vulnerability");
            return;
        }
        if (String(hostId) === String(currentHost)) {
            currentList = currentList.filter(v => v.id !== vuln.id);
            const container = document.getElementById("vulnerabilities-panel");
            if (container) renderList(container);
        }
        if (window.refreshAllVulnerabilities) window.refreshAllVulnerabilities();
    }

    function hideVulnMenu() {
        if (vulnMenu) {
            vulnMenu.remove();
            vulnMenu = null;
        }
    }

    function showVulnMenu(event, vuln, hostId) {
        hideVulnMenu();
        if (!canEdit()) return;
        const point = { x: event.clientX, y: event.clientY };
        const menu = document.createElement("div");
        menu.className = "vuln-ctx-menu";
        menu.setAttribute("role", "menu");

        const addItem = (text, className, handler) => {
            const button = document.createElement("button");
            button.type = "button";
            button.textContent = text;
            if (className) button.className = className;
            button.addEventListener("click", () => {
                hideVulnMenu();
                handler();
            });
            menu.appendChild(button);
        };

        addItem("Edit", "", () => {
            currentHost = hostId || vuln.host || currentHost;
            openForm(vuln);
        });
        addItem("Remove", "danger", () => removeVulnerability(vuln, hostId || vuln.host || currentHost));
        document.body.appendChild(menu);

        const box = menu.getBoundingClientRect();
        const x = Math.min(point.x, window.innerWidth - box.width - 8);
        const y = Math.min(point.y, window.innerHeight - box.height - 8);
        menu.style.left = `${Math.max(8, x)}px`;
        menu.style.top = `${Math.max(8, y)}px`;
        vulnMenu = menu;
        menu.querySelector("button").focus();
    }

    document.addEventListener("mousedown", event => {
        if (vulnMenu && !vulnMenu.contains(event.target)) hideVulnMenu();
    });
    document.addEventListener("contextmenu", event => {
        if (vulnMenu && !vulnMenu.contains(event.target)) hideVulnMenu();
    });
    document.addEventListener("keydown", event => {
        if (event.key === "Escape" && vulnMenu) hideVulnMenu();
    });
    window.addEventListener("resize", hideVulnMenu);
    window.addEventListener("blur", hideVulnMenu);
    document.addEventListener("scroll", hideVulnMenu, true);

    function closeForm() {
        if (formOverlay) formOverlay.remove();
        formOverlay = null;
        editingId = null;
        cwePick = null;
        cvssState = {};
        hostAssign = [];
        hostAssignAll = [];
    }

    function openForm(vuln) {
        editingId = vuln ? vuln.id : null;
        cwePick = vuln && vuln.cwe_id ? { id: vuln.cwe_id, name: "" } : null;
        cvssState = vuln && vuln.cvss && vuln.cvss.vector ? (Cvss31.parseVector(vuln.cvss.vector) || {}) : {};

        if (formOverlay) formOverlay.remove();
        const overlay = document.createElement("div");
        overlay.className = "vuln-form-overlay";
        overlay.innerHTML = `
            <div class="vuln-form-backdrop"></div>
            <section class="vuln-form-modal" role="dialog" aria-modal="true">
                <div class="vuln-form-header">
                    <div>
                        <div class="vuln-form-title">${vuln ? "Edit Vulnerability" : "Add Vulnerability"}</div>
                        <div class="vuln-form-subtitle">${vuln ? "Update the details of this finding" : "Record a new finding for this host"}</div>
                    </div>
                    <button type="button" class="vulnerabilities-close" data-vuln-form-close aria-label="Close">&times;</button>
                </div>
                <div class="vuln-form-body">
                    <div class="vuln-form-section">
                    <div class="vuln-form-section-title">General</div>
                    ${vuln ? `
                    <div class="vuln-field">
                        <div class="vuln-host-label">
                            <label>Hosts</label>
                            <div class="vuln-host-add">
                                <button type="button" class="vuln-host-add-btn" id="vf-hosts-add-btn" title="Assign to another host" aria-label="Assign to another host">+</button>
                                <div class="vuln-host-add-picker" id="vf-hosts-picker" hidden></div>
                            </div>
                        </div>
                        <div class="vuln-host-chips" id="vf-hosts-chips">
                            <span class="vuln-host-chip-loading">Loading hosts...</span>
                        </div>
                        <small class="vuln-field-hint">Use + to enter an IP directly or choose an active host from the list.</small>
                    </div>` : ""}
                    <div class="vuln-field">
                        <label for="vf-title">Title</label>
                        <input id="vf-title" class="sf-input" placeholder="e.g. Outdated OpenSSH allows user enumeration" value="${vuln ? Util.esc(vuln.title) : ""}">
                    </div>
                    <div class="vuln-field-row">
                        <div class="vuln-field">
                            <label for="vf-cve">CVE ID (optional)</label>
                            <input id="vf-cve" class="sf-input" placeholder="CVE-2024-12345" value="${vuln ? Util.esc(vuln.cve_id || "") : ""}">
                        </div>
                        <div class="vuln-field">
                            <label for="vf-service">Affected service / port</label>
                            <input id="vf-service" class="sf-input" placeholder="443/tcp - nginx" value="${vuln ? Util.esc(vuln.affected_service || "") : ""}">
                        </div>
                    </div>
                    <div class="vuln-field">
                        <label for="vf-cwe">Weakness class (CWE)</label>
                        <div class="vuln-cwe-autocomplete">
                            <input id="vf-cwe" class="sf-input" placeholder="Search CWE by name or number (e.g. injection, 89)" autocomplete="off">
                            <div id="vf-cwe-results" class="vuln-cwe-results" hidden></div>
                        </div>
                        <div id="vf-cwe-selected" class="vuln-cwe-selected ${cwePick ? "active" : ""}">
                            <span id="vf-cwe-selected-label">${cwePick ? Util.esc(cwePick.id) : ""}</span>
                            <span class="clear-cwe" id="vf-cwe-clear">Remove</span>
                        </div>
                    </div>
                    </div>
                    <div class="vuln-form-section">
                    <div class="vuln-form-section-title">Details</div>
                    <div class="vuln-field">
                        <label for="vf-description">Description</label>
                        <textarea id="vf-description" class="sf-input" placeholder="What the finding is and how it was observed">${vuln ? Util.esc(vuln.description || "") : ""}</textarea>
                    </div>
                    <div class="vuln-field">
                        <label for="vf-remediation">Remediation</label>
                        <textarea id="vf-remediation" class="sf-input" placeholder="Recommended fix">${vuln ? Util.esc(vuln.remediation || "") : ""}</textarea>
                    </div>
                    <div class="vuln-field">
                        <label for="vf-poc">Proof of Concept (PoC)</label>
                        <textarea id="vf-poc" class="sf-input vuln-code-input" placeholder="Steps or evidence demonstrating the finding">${vuln ? Util.esc(vuln.poc || "") : ""}</textarea>
                    </div>
                    <div class="vuln-field">
                        <label for="vf-exploit-commands">Exploit Commands</label>
                        <textarea id="vf-exploit-commands" class="sf-input vuln-code-input" placeholder="Authorized exploitation commands">${vuln ? Util.esc(vuln.exploit_commands || "") : ""}</textarea>
                    </div>

                    </div>
                    <div class="cvss-calc" id="vf-cvss-calc"></div>
                    <div class="vuln-form-section">
                    <div class="vuln-form-section-title">Classification</div>

                    <div class="vuln-field-row">
                        <div class="vuln-field">
                            <label for="vf-severity">Severity</label>
                            <select id="vf-severity" class="sf-input">
                                ${SEVERITIES.map(s => `<option value="${s}" ${vuln && vuln.severity === s ? "selected" : ""}>${s}</option>`).join("")}
                            </select>
                        </div>
                        <div class="vuln-field">
                            <label for="vf-status">Status</label>
                            <select id="vf-status" class="sf-input">
                                ${STATUSES.map(s => `<option value="${s}" ${vuln && vuln.status === s ? "selected" : (!vuln && s === "Open" ? "selected" : "")}>${s}</option>`).join("")}
                            </select>
                        </div>
                    </div>
                    </div>
                </div>
                <div class="vuln-form-footer">
                    <button type="button" class="btn-secondary" data-vuln-form-cancel>Cancel</button>
                    <button type="button" class="btn-primary" id="vf-save">${vuln ? "Save Changes" : "Add Vulnerability"}</button>
                </div>
            </section>
        `;
        document.body.appendChild(overlay);
        formOverlay = overlay;

        overlay.querySelector(".vuln-form-backdrop").addEventListener("click", closeForm);
        overlay.querySelector("[data-vuln-form-close]").addEventListener("click", closeForm);
        overlay.querySelector("[data-vuln-form-cancel]").addEventListener("click", closeForm);

        if (vuln) loadHostAssignment(overlay, vuln);
        renderCvssCalc(overlay.querySelector("#vf-cvss-calc"));
        wireCweAutocomplete(overlay);

        overlay.querySelector("#vf-save").addEventListener("click", () => submitForm(overlay));
    }

    async function loadHostAssignment(overlay, vuln) {
        const chips = overlay.querySelector("#vf-hosts-chips");
        if (!chips) return;

        const [allVulnsRes, allHostsRes] = await Promise.all([Api.getAllVulnerabilities(), Api.getAllHosts()]);
        if (formOverlay !== overlay) return;

        hostAssign = allVulnsRes.ok
            ? Array.from(new Set((allVulnsRes.vulnerabilities || []).filter(v => v.id === vuln.id).map(v => String(v.host || "")).filter(Boolean)))
            : [];
        if (!hostAssign.length) hostAssign = [String(currentHost)];
        if (!hostAssign.includes(String(currentHost))) hostAssign.push(String(currentHost));

        hostAssignAll = allHostsRes.ok
            ? Array.from(new Set((allHostsRes.hosts || []).map(host => String(host.host || "")).filter(Boolean)))
            : hostAssign.slice();

        renderHostChips(overlay);
        wireHostAddPicker(overlay);
    }

    function renderHostChips(overlay) {
        const chips = overlay.querySelector("#vf-hosts-chips");
        if (!chips) return;
        chips.innerHTML = hostAssign.map(host => `
            <span class="vuln-host-chip" data-host="${Util.esc(host)}">
                ${Util.esc(host)}
                ${host !== String(currentHost) ? `<button type="button" class="vuln-host-chip-remove" data-remove-host="${Util.esc(host)}" aria-label="Unassign ${Util.esc(host)}">&times;</button>` : ""}
            </span>
        `).join("");
        chips.querySelectorAll("[data-remove-host]").forEach(btn => {
            btn.addEventListener("click", () => {
                hostAssign = hostAssign.filter(host => host !== btn.dataset.removeHost);
                renderHostChips(overlay);
                renderHostPickerList(overlay);
            });
        });
    }

    function renderHostPickerList(overlay) {
        const picker = overlay.querySelector("#vf-hosts-picker");
        if (!picker) return;
        const available = hostAssignAll.filter(host => !hostAssign.includes(host));
        picker.innerHTML = `
            <div class="vuln-host-add-manual">
                <input type="text" class="vuln-host-add-input" id="vf-host-input"
                    placeholder="Enter host IP" autocomplete="off" inputmode="url">
                <button type="button" class="vuln-host-add-submit" id="vf-host-submit">Add</button>
            </div>
            <div class="vuln-host-add-options">
                ${available.length
                    ? available.map(host => `
                        <div class="vuln-host-add-option" data-add-host="${Util.esc(host)}">${Util.esc(host)}</div>
                    `).join("")
                    : '<div class="vuln-host-add-option vuln-host-add-empty">No other hosts available</div>'}
            </div>`;

        const input = picker.querySelector("#vf-host-input");
        const submit = picker.querySelector("#vf-host-submit");
        const addManualHost = () => {
            const host = input.value.trim();
            if (!host || hostAssign.includes(host)) return;
            hostAssign.push(host);
            input.value = "";
            picker.hidden = true;
            renderHostChips(overlay);
            renderHostPickerList(overlay);
        };
        submit.addEventListener("click", addManualHost);
        input.addEventListener("keydown", event => {
            if (event.key === "Enter") {
                event.preventDefault();
                addManualHost();
            }
        });
        picker.querySelectorAll("[data-add-host]").forEach(opt => {
            opt.addEventListener("click", () => {
                if (!hostAssign.includes(opt.dataset.addHost)) hostAssign.push(opt.dataset.addHost);
                picker.hidden = true;
                renderHostChips(overlay);
                renderHostPickerList(overlay);
            });
        });
    }

    function wireHostAddPicker(overlay) {
        const addBtn = overlay.querySelector("#vf-hosts-add-btn");
        const picker = overlay.querySelector("#vf-hosts-picker");
        if (!addBtn || !picker) return;

        renderHostPickerList(overlay);
        addBtn.addEventListener("click", event => {
            event.stopPropagation();
            picker.hidden = !picker.hidden;
            if (!picker.hidden) {
                const input = picker.querySelector("#vf-host-input");
                if (input) input.focus();
            }
        });
        document.addEventListener("click", event => {
            if (formOverlay === overlay && !picker.hidden && !event.target.closest(".vuln-host-add")) {
                picker.hidden = true;
            }
        });
    }

    function renderCvssCalc(el) {
        const metrics = Cvss31.METRICS;
        const order = Cvss31.METRIC_ORDER;
        el.innerHTML = `
            <div class="cvss-calc-title">CVSS v3.1 Calculator</div>
            <div class="cvss-metrics">
            ${order.map(key => `
                <div class="cvss-metric-group">
                    <div class="cvss-metric-label">${metrics[key].label}</div>
                    <div class="cvss-options" data-cvss-metric="${key}">
                        ${Object.entries(metrics[key].values).map(([code, label]) => `
                            <button type="button" class="cvss-option ${cvssState[key] === code ? "active" : ""}" data-cvss-value="${code}">${label}</button>
                        `).join("")}
                    </div>
                </div>
            `).join("")}
            </div>
            <div class="cvss-result" id="cvss-result"></div>
        `;

        el.querySelectorAll("[data-cvss-metric]").forEach(group => {
            const key = group.dataset.cvssMetric;
            group.querySelectorAll(".cvss-option").forEach(btn => {
                btn.addEventListener("click", () => {
                    cvssState[key] = btn.dataset.cvssValue;
                    group.querySelectorAll(".cvss-option").forEach(b => b.classList.toggle("active", b === btn));
                    updateCvssResult(el);
                });
            });
        });

        updateCvssResult(el);
    }

    function updateCvssResult(el) {
        const resultEl = el.querySelector("#cvss-result");
        const result = Cvss31.calculate(cvssState);
        if (!result.valid) {
            resultEl.innerHTML = `<div class="cvss-result-incomplete">Select all 8 metrics to compute a base score.</div>`;
            return;
        }
        resultEl.innerHTML = `
            <div class="cvss-result-score sev-${result.severity}">${result.baseScore.toFixed(1)}</div>
            <div class="cvss-result-meta">
                <div class="cvss-result-severity sev-${result.severity}">${result.severity}</div>
                <div class="cvss-result-vector">${Util.esc(result.vector)}</div>
            </div>
        `;
        const formEl = el.closest(".vuln-form-modal");
        if (formEl) {
            const sevSelect = formEl.querySelector("#vf-severity");
            if (sevSelect) sevSelect.value = result.severity;
        }
    }

    let cweSearchTimer = null;

    function wireCweAutocomplete(overlay) {
        const input = overlay.querySelector("#vf-cwe");
        const results = overlay.querySelector("#vf-cwe-results");
        const selectedWrap = overlay.querySelector("#vf-cwe-selected");
        const selectedLabel = overlay.querySelector("#vf-cwe-selected-label");
        const clearBtn = overlay.querySelector("#vf-cwe-clear");

        input.addEventListener("input", () => {
            clearTimeout(cweSearchTimer);
            const query = input.value.trim();
            if (!query) { results.hidden = true; return; }
            cweSearchTimer = setTimeout(async () => {
                const res = await Api.searchCwe(query);
                if (!res.ok || !res.results.length) {
                    results.innerHTML = '<div class="vuln-cwe-option">No matches</div>';
                    results.hidden = false;
                    return;
                }
                results.innerHTML = res.results.map(entry => `
                    <div class="vuln-cwe-option" data-cwe-id="${entry.id}" data-cwe-name="${Util.esc(entry.name)}">
                        <b>${entry.id}</b> &mdash; ${Util.esc(entry.name)}
                    </div>
                `).join("");
                results.hidden = false;
                results.querySelectorAll("[data-cwe-id]").forEach(opt => {
                    opt.addEventListener("click", () => {
                        cwePick = { id: opt.dataset.cweId, name: opt.dataset.cweName };
                        selectedLabel.textContent = `${cwePick.id} \u2014 ${cwePick.name}`;
                        selectedWrap.classList.add("active");
                        input.value = "";
                        results.hidden = true;
                    });
                });
            }, 200);
        });

        document.addEventListener("click", event => {
            if (formOverlay && !event.target.closest(".vuln-cwe-autocomplete")) {
                results.hidden = true;
            }
        });

        clearBtn.addEventListener("click", () => {
            cwePick = null;
            selectedWrap.classList.remove("active");
            selectedLabel.textContent = "";
        });
    }

    async function submitForm(overlay) {
        const saveBtn = overlay.querySelector("#vf-save");
        const title = overlay.querySelector("#vf-title").value.trim();
        if (!title) {
            alert("A title is required");
            return;
        }

        const cvssResult = Cvss31.calculate(cvssState);
        const fields = {
            title,
            severity: overlay.querySelector("#vf-severity").value,
            status: overlay.querySelector("#vf-status").value,
            cve_id: overlay.querySelector("#vf-cve").value.trim(),
            cwe_id: cwePick ? cwePick.id : "",
            affected_service: overlay.querySelector("#vf-service").value.trim(),
            description: overlay.querySelector("#vf-description").value.trim(),
            remediation: overlay.querySelector("#vf-remediation").value.trim(),
            poc: overlay.querySelector("#vf-poc").value.trim(),
            exploit_commands: overlay.querySelector("#vf-exploit-commands").value.trim(),
            cvss: cvssResult.valid ? {
                vector: cvssResult.vector,
                score: cvssResult.baseScore,
                severity: cvssResult.severity,
            } : null,
        };
        if (editingId) {
            fields.hosts = hostAssign.slice();
            if (!fields.hosts.length) {
                alert("Select at least one host");
                return;
            }
        }

        saveBtn.disabled = true;
        saveBtn.textContent = "Saving...";

        const res = editingId
            ? await Api.updateVulnerability(currentHost, editingId, fields)
            : await Api.addVulnerability(currentHost, fields);

        if (!res.ok) {
            alert(res.error || "Could not save vulnerability");
            saveBtn.disabled = false;
            saveBtn.textContent = editingId ? "Save Changes" : "Add Vulnerability";
            return;
        }

        if (editingId) {
            const idx = currentList.findIndex(v => v.id === editingId);
            if (idx !== -1) currentList[idx] = res.vulnerability;
        } else {
            currentList.unshift(res.vulnerability);
        }

        closeForm();
        const container = document.getElementById("vulnerabilities-panel");
        if (container) renderList(container);
        if (window.refreshAllVulnerabilities) window.refreshAllVulnerabilities();
    }

    return {
        render,
        openForm,
        closeForm,
        showDetail: openDetail,
        showContextMenu: showVulnMenu
    };
})();