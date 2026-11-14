window.initDashboard = function() {
    const root = document.querySelector(".dashboard");
    if (!root || root.dataset.initialized) return;
    root.dataset.initialized = "true";

    const number = value => Number(value || 0).toLocaleString("en-US");
    const esc = value => Util.esc(value);
    const item = (label, value, note, tone = "") =>
        `<div class="dashboard-kpi ${tone}"><span>${esc(label)}</span><strong>${number(value)}</strong><small>${esc(note)}</small></div>`;

    Api.getDashboardSummary().then(result => {
        if (!result.ok) {
            root.innerHTML = `<div class="dashboard-error">${esc(result.error || "Dashboard data could not be loaded")}</div>`;
            return;
        }
        const data = result.summary;
        const s = data.sections || {};
        const users = s.users || {};
        const computers = s.computers || {};
        const groups = s.groups || {};
        const aces = data.aces || {};
        const domain = data.domain || {};

        document.getElementById("dash-domain-name").textContent = domain.name || "Unknown domain";
        document.getElementById("dash-domain-meta").textContent =
            `${number(domain.domain_controllers)} domain controller${domain.domain_controllers === 1 ? "" : "s"} · ${number(domain.dns_zones)} DNS zones`;

        document.getElementById("dashboard-kpis").innerHTML = [
            item("Identities", users.total, `${number(users.admins)} privileged admins`, "kpi-gold"),
            item("Endpoints", computers.total, `${number(computers.domain_controllers)} domain controllers`, "kpi-blue"),
            item("Groups", groups.total, `${number(groups.privileged)} privileged groups`, "kpi-purple"),
            item("Access rules", aces.total, `${number(aces.dangerous)} dangerous ACEs`, "kpi-red"),
            item("Risk score", domain.risk_score, `${esc(domain.highest_severity || "info")} severity`, "kpi-amber")
        ].join("");

        const cards = [
            ["Users", "domain-users", users, [["Admins", users.admins], ["Disabled", users.disabled], ["Locked", users.locked], ["Kerberoastable", users.kerberoastable]]],
            ["Groups", "domain-groups", groups, [["Privileged", groups.privileged], ["Empty", groups.empty], ["Nested", groups.nested], ["Protected", groups.protected]]],
            ["Computers", "domain-computers", computers, [["Servers", computers.servers], ["Workstations", computers.workstations], ["Stale", computers.stale], ["Delegation", computers.delegation]]],
            ["OUs", "domain-ous", s.ous || {}, [["GPO linked", (s.ous || {}).gpo_links], ["Protected", (s.ous || {}).protected], ["High value", (s.ous || {}).high_value], ["Total", (s.ous || {}).total]]],
            ["GPOs", "domain-gpos", s.gpos || {}, [["Linked", (s.gpos || {}).linked], ["Enforced", (s.gpos || {}).enforced], ["High value", (s.gpos || {}).high_value], ["Total", (s.gpos || {}).total]]],
            ["Trusts", "domain-trusts", s.trusts || {}, [["Total relationships", (s.trusts || {}).total], ["Protected", (s.trusts || {}).protected], ["High value", (s.trusts || {}).high_value], ["Records", (s.trusts || {}).total]]],
            ["Certificates", "domain-certificates", s.certificates || {}, [["Total", (s.certificates || {}).total], ["High value", (s.certificates || {}).high_value], ["Protected", (s.certificates || {}).protected], ["Records", (s.certificates || {}).total]]],
            ["ACEs", "domain-aces", aces, [["Dangerous", aces.dangerous], ["Extended", aces.extended], ["Standard", Math.max(0, (aces.total || 0) - (aces.dangerous || 0))], ["Total", aces.total]]]
        ];
        document.getElementById("section-cards").innerHTML = cards.map(([title, view, stats, rows]) => {
            return `<article class="section-card"><div class="section-card-top"><div class="section-icon">${esc(title.slice(0, 2).toUpperCase())}</div><div><h3>${esc(title)}</h3><span>${number(stats.total)} records</span></div><button data-dashboard-view="${view}" aria-label="Open ${esc(title)}">OPEN ↗</button></div><div class="section-stat-grid">${rows.map(([label, value]) => `<div><span>${esc(label)}</span><strong>${number(value)}</strong></div>`).join("")}</div></article>`;
        }).join("");

        document.getElementById("risk-signals").innerHTML = [
            ["Dangerous ACEs", aces.dangerous, aces.total, "red"],
            ["Admin identities", users.admins, users.total, "amber"],
            ["Delegation exposure", computers.delegation, computers.total, "purple"],
            ["Kerberoastable users", users.kerberoastable, users.total, "blue"],
            ["AS-REP roastable", users.asrep, users.total, "red"]
        ].map(([label, value, total, tone]) => {
            const percent = total ? Math.min(100, Math.round(value / total * 100)) : 0;
            return `<div class="risk-row"><div><span>${esc(label)}</span><strong>${number(value)} <small>/ ${number(total)}</small></strong></div><div class="risk-track"><i class="risk-fill ${tone}" style="width:${percent}%"></i></div></div>`;
        }).join("");

        document.getElementById("domain-posture").innerHTML = [
            ["Anonymous LDAP bind", domain.anonymous_bind, "Review unauthenticated directory exposure"],
            ["LDAP signing required", domain.ldap_signing, "Transport protection policy"],
            ["Enterprise CA", domain.enterprise_ca, "Certificate authority discovered"],
            ["Domain controllers", domain.domain_controllers > 0, `${number(domain.domain_controllers)} controller(s) online`]
        ].map(([label, active, note]) => `<div class="posture-row"><span class="posture-icon ${active ? "ok" : "warn"}">${active ? "✓" : "!"}</span><div><strong>${esc(label)}</strong><small>${esc(note)}</small></div><b class="${active ? "posture-ok" : "posture-warn"}">${active ? "ACTIVE" : "REVIEW"}</b></div>`).join("");

        const files = data.files || [];
        const maxRecords = Math.max(1, ...files.map(file => file.records));
        document.getElementById("dash-file-count").textContent = `${number(files.length)} source files`;
        document.getElementById("file-bars").innerHTML = files.map(file =>
            `<div class="file-bar-row"><div><strong>${esc(file.name)}</strong><span>${esc(file.kind)}</span></div><div class="file-track"><i style="width:${Math.max(3, file.records / maxRecords * 100)}%"></i></div><b>${number(file.records)}</b></div>`
        ).join("") || '<div class="dashboard-muted">No source files discovered.</div>';

        root.querySelectorAll("[data-dashboard-view]").forEach(button => {
            button.addEventListener("click", () => document.querySelector(`[data-view="${button.dataset.dashboardView}"]`)?.click());
        });
    }).catch(error => {
        root.innerHTML = `<div class="dashboard-error">${esc(error.message || "Dashboard request failed")}</div>`;
    });
};
