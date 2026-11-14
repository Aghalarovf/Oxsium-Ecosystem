async function initAllVulnerabilities() {
    const wrap = document.getElementById("av-table-wrap");
    const overviewEl = document.getElementById("av-overview");
    const searchEl = document.getElementById("av-search");
    const sevFilter = document.getElementById("av-sev-filter");
    const statusFilter = document.getElementById("av-status-filter");
    const exportButton = document.getElementById("av-export");

    const SEVERITIES = ["Critical", "High", "Medium", "Low", "Info"];
    const CATEGORIES = ["Vulnerability Scanner", "Post Exploitation"];
    const SEV_COLORS = { Critical: "var(--sev-critical)", High: "var(--sev-high)", Medium: "var(--sev-medium)", Low: "var(--sev-low)", Info: "var(--sev-info)" };

    let allData = [];

    function fmtDate(ts) {
        if (!ts) return "";
        return new Date(ts * 1000).toLocaleDateString(undefined, { year: "numeric", month: "short", day: "numeric" });
    }

    function statusClass(s) {
        return "st-" + String(s || "Open").toLowerCase().replace(/\s+/g, "-");
    }

    function filtered() {
        const q = (searchEl.value || "").toLowerCase().trim();
        const sev = sevFilter.value;
        const st = statusFilter.value;
        return allData.filter(v => {
            if (sev && v.severity !== sev) return false;
            if (st && (v.status || "Open") !== st) return false;
            if (q && ![v.title, v.host, v.cve_id, v.cwe_id, v.affected_service, v.description]
                .some(f => f && String(f).toLowerCase().includes(q))) return false;
            return true;
        });
    }

    function renderOverview(data) {
        // Count each finding once, even if it is assigned to several hosts.
        const unique = groupByFinding(data);
        const counts = {};
        SEVERITIES.forEach(s => counts[s] = 0);
        unique.forEach(v => { if (counts[v.severity] !== undefined) counts[v.severity]++; });
        const open = unique.filter(v => (v.status || "Open") === "Open").length;
        data = unique;

        overviewEl.innerHTML = `
            <div class="av-stat-row">
                <div class="av-stat-box">
                    <span class="av-stat-label">Total</span>
                    <span class="av-stat-val">${data.length}</span>
                </div>
                <div class="av-stat-box">
                    <span class="av-stat-label">Open</span>
                    <span class="av-stat-val" style="color:var(--sev-high)">${open}</span>
                </div>
                ${SEVERITIES.map(s => `
                    <div class="av-stat-box av-stat-sev" data-sev="${s}" style="--sev:${SEV_COLORS[s]}">
                        <span class="av-stat-dot"></span>
                        <span class="av-stat-label">${s}</span>
                        <span class="av-stat-val">${counts[s]}</span>
                    </div>
                `).join("")}
            </div>
        `;

        overviewEl.querySelectorAll("[data-sev]").forEach(el => {
            el.addEventListener("click", () => {
                sevFilter.value = sevFilter.value === el.dataset.sev ? "" : el.dataset.sev;
                render();
            });
        });
    }

    // Multiple hosts can share the same underlying finding (same id). Group
    // them into a single row instead of showing one row per host, so
    // assigning a finding to another host doesn't look like a new finding.
    function groupByFinding(list) {
        const groups = new Map();
        list.forEach(v => {
            let group = groups.get(v.id);
            if (!group) {
                group = { ...v, hosts: [] };
                groups.set(v.id, group);
            }
            if (v.host && !group.hosts.includes(v.host)) group.hosts.push(v.host);
        });
        return Array.from(groups.values());
    }

    function markdownValue(value) {
        if (value === null || value === undefined || value === "") return "—";
        if (Array.isArray(value)) {
            return value.length ? value.map(item => markdownValue(item)).join(", ") : "—";
        }
        if (typeof value === "object") {
            return `\`${JSON.stringify(value).replace(/`/g, "\\`")}\``;
        }
        return String(value).replace(/\r?\n/g, "<br>");
    }

    function exportMarkdown() {
        const findings = groupByFinding(allData);
        const lines = [
            "# Vulnerability Report",
            "",
            `Generated: ${new Date().toISOString()}`,
            `Total vulnerabilities: ${findings.length}`,
            "",
        ];
        if (!findings.length) {
            lines.push("No vulnerabilities found.", "");
        } else {
            findings.forEach((vulnerability, index) => {
                lines.push(`## ${index + 1}. ${markdownValue(vulnerability.title)}`, "");
                lines.push("| Field | Value |", "| --- | --- |");
                Object.entries(vulnerability)
                    .filter(([key]) => key !== "title" && key !== "hosts")
                    .forEach(([key, value]) => {
                        lines.push(`| ${key} | ${markdownValue(value).replace(/\|/g, "\\|")} |`);
                    });
                lines.push(`| hosts | ${markdownValue(vulnerability.hosts)} |`, "");
            });
        }
        const blob = new Blob([lines.join("\n")], { type: "text/markdown;charset=utf-8" });
        const url = URL.createObjectURL(blob);
        const link = document.createElement("a");
        link.href = url;
        link.download = `vulnerabilities-${new Date().toISOString().slice(0, 10)}.md`;
        document.body.appendChild(link);
        link.click();
        link.remove();
        URL.revokeObjectURL(url);
    }

    function render() {
        const list = filtered();
        if (!list.length) {
            wrap.innerHTML = `<div class="data-empty">No vulnerabilities match the current filter.</div>`;
            return;
        }

        const rows = groupByFinding(list);

        wrap.innerHTML = `
            <div class="av-count-row">${rows.length} finding${rows.length === 1 ? "" : "s"}</div>
            <table class="av-table">
                <thead>
                    <tr>
                        <th>Severity</th>
                        <th>Title</th>
                        <th>Hosts</th>
                        <th>CVE</th>
                        <th>CVSS</th>
                        <th>Status</th>
                        <th>Category</th>
                        <th>Found</th>
                    </tr>
                </thead>
                <tbody>
                    ${rows.map(v => {
                        const score = v.cvss && v.cvss.score != null ? v.cvss.score.toFixed(1) : "—";
                        const status = v.status || "Open";
                        const category = v.category || CATEGORIES[0];
                        const hostsHtml = v.hosts.map(h => `<span class="av-host-chip" data-host="${Util.esc(h)}">${Util.esc(h)}</span>`).join("");
                        return `
                            <tr class="av-row sev-${v.severity}" data-hosts="${Util.esc(JSON.stringify(v.hosts))}" data-vuln-id="${Util.esc(v.id)}">
                                <td><span class="sev-badge sev-${v.severity}">${v.severity}</span></td>
                                <td class="av-title-cell">
                                    <span class="av-row-title" title="${Util.esc(v.title)}">${Util.esc(v.title)}</span>
                                    ${v.cwe_id ? `<span class="av-row-cwe">${Util.esc(v.cwe_id)}</span>` : ""}
                                </td>
                                <td class="av-hosts-cell"><div class="av-hosts-scroll">${hostsHtml}</div></td>
                                <td class="av-mono">${v.cve_id ? Util.esc(v.cve_id) : "—"}</td>
                                <td class="av-mono sev-${v.severity}">${score}</td>
                                <td><span class="vuln-status-pill ${statusClass(status)}">${Util.esc(status)}</span></td>
                                <td>
                                    <select class="av-category-select" data-av-category="${Util.esc(v.id)}">
                                        ${CATEGORIES.map(option => `<option value="${Util.esc(option)}" ${option === category ? "selected" : ""}>${Util.esc(option)}</option>`).join("")}
                                    </select>
                                </td>
                                <td class="av-mono av-muted">${fmtDate(v.created_at)}</td>
                            </tr>
                        `;
                    }).join("")}
                </tbody>
            </table>
        `;

        wrap.querySelectorAll(".av-row[data-hosts]").forEach(row => {
            row.style.cursor = "pointer";
            let hosts = [];
            try { hosts = JSON.parse(row.dataset.hosts || "[]"); } catch (e) { hosts = []; }

            row.addEventListener("click", event => {
                if (event.target.closest("[data-av-category]")) return;
                // Clicking a specific host chip opens that host; clicking
                // elsewhere on the row opens the first assigned host.
                const chip = event.target.closest("[data-host]");
                const host = (chip && chip.dataset.host) || hosts[0];
                const vuln = allData.find(item => item.id === row.dataset.vulnId);
                if (vuln && typeof Vulnerabilities !== "undefined" && Vulnerabilities.showDetail) {
                    Vulnerabilities.showDetail(vuln, host);
                } else if (host && window.openVulnerabilitiesForHost) {
                    window.openVulnerabilitiesForHost(host);
                }
            });
            row.addEventListener("contextmenu", event => {
                event.preventDefault();
                event.stopPropagation();
                const vuln = allData.find(item => item.id === row.dataset.vulnId);
                if (vuln && typeof Vulnerabilities !== "undefined") {
                    Vulnerabilities.showContextMenu(event, vuln, hosts[0]);
                }
            });
        });
        wrap.querySelectorAll("[data-av-category]").forEach(select => {
            select.addEventListener("click", event => event.stopPropagation());
            select.addEventListener("change", async () => {
                const vuln = allData.find(item => item.id === select.dataset.avCategory);
                const row = select.closest("[data-hosts]");
                let hosts = [];
                try { hosts = JSON.parse(row.dataset.hosts || "[]"); } catch (e) { hosts = []; }
                if (!vuln || !hosts.length) return;
                select.disabled = true;
                const fields = { ...vuln };
                delete fields.id;
                delete fields.host;
                delete fields.hosts;
                delete fields.created_at;
                delete fields.updated_at;
                fields.category = select.value;
                const result = await Api.updateVulnerability(hosts[0], vuln.id, {
                    ...fields,
                    hosts
                });
                select.disabled = false;
                if (!result.ok) {
                    select.value = vuln.category || CATEGORIES[0];
                    window.alert(result.error || "Could not update category");
                    return;
                }
                allData.filter(item => item.id === vuln.id).forEach(item => {
                    item.category = select.value;
                });
            });
        });
    }

    const res = await Api.getAllVulnerabilities();
    if (!res.ok) {
        wrap.innerHTML = `<div class="data-empty">${Util.esc(res.error || "Could not load vulnerabilities")}</div>`;
        return;
    }

    allData = res.vulnerabilities || [];
    renderOverview(allData);
    render();
    exportButton.addEventListener("click", exportMarkdown);

    searchEl.addEventListener("input", render);
    sevFilter.addEventListener("change", render);
    statusFilter.addEventListener("change", render);

    window.refreshAllVulnerabilities = async function() {
        const refreshed = await Api.getAllVulnerabilities();
        if (!refreshed.ok) return;
        allData = refreshed.vulnerabilities || [];
        renderOverview(allData);
        render();
    };
}