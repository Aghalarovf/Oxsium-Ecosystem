function esc(value) {
    return Util.esc(value);
}

function renderValue(value) {
    if (value === null || value === undefined || value === "") return '<span class="domain-muted">-</span>';
    if (Array.isArray(value)) {
        if (!value.length) return '<span class="domain-muted">-</span>';
        return value.map(renderValue).join(", ");
    }
    if (typeof value === "object") {
        return Object.entries(value).map(([key, item]) =>
            `<span><b>${esc(key)}:</b> ${renderValue(item)}</span>`).join("<br>");
    }
    return esc(String(value));
}

function badge(text, tone = "muted") {
    return `<span class="domain-badge domain-badge-${tone}">${esc(text)}</span>`;
}

function flagRow(flags) {
    const active = flags.filter(flag => flag.active);
    if (!active.length) return '<span class="domain-muted">None</span>';
    return `<div class="domain-flag-list">${active.map(flag => badge(flag.label, flag.tone)).join("")}</div>`;
}

function fmtDate(value) {
    if (!value) return '<span class="domain-muted">-</span>';
    const date = new Date(value);
    if (Number.isNaN(date.getTime())) return esc(String(value));
    return esc(date.toLocaleString("en-US", { year: "numeric", month: "short", day: "2-digit", hour: "2-digit", minute: "2-digit" }));
}

function fmtNumber(value) {
    const number = Number(value);
    return Number.isFinite(number) ? number.toLocaleString("en-US") : esc(String(value ?? "0"));
}

function isDisabledUser(user) {
    return !!user.disabled || (Number(user.uac) & 2) === 2;
}

const FALLBACK_COLUMNS = [
    {
        label: "Record",
        render: data => {
            const entries = Object.entries(data || {});
            const half = Math.ceil(entries.length / 2);
            return entries.slice(0, half).map(([key, value]) =>
                `<strong>${esc(key)}:</strong> ${renderValue(value)}`).join("<br>") || '<span class="domain-muted">-</span>';
        }
    },
    {
        label: "Details",
        render: data => {
            const entries = Object.entries(data || {});
            const half = Math.ceil(entries.length / 2);
            return entries.slice(half).map(([key, value]) =>
                `<span><b>${esc(key)}:</b> ${renderValue(value)}</span>`).join("<br>") || '<span class="domain-muted">-</span>';
        }
    }
];

const RIGHTS_MAX_LENGTH = 35;

function rightsText(rights) {
    return Array.isArray(rights) ? rights.join(", ") : String(rights ?? "");
}

function rightsChip(rights) {
    const full = rightsText(rights);
    if (!full) return '<span class="domain-muted">-</span>';
    const shown = full.length > RIGHTS_MAX_LENGTH ? full.slice(0, RIGHTS_MAX_LENGTH) + "..." : full;
    return `<span class="right-chip right-chip-single" title="${esc(full)}">${esc(shown)}</span>`;
}

const ESC_RISK_SCORES = {
    ESC1: 9.5, ESC2: 8, ESC3: 8.5, ESC4: 9.3, ESC5: 9,
    ESC6: 8.5, ESC7: 9, ESC8: 9, ESC9: 7.5, ESC10: 7,
    ESC11: 8, ESC12: 5.5, ESC13: 7, ESC14: 6.5, ESC15: 6.8
};

function certificateFindingScore(finding) {
    const rule = String(finding && finding.rule || "").toUpperCase();
    return ESC_RISK_SCORES[rule] || 0;
}

function certificateSeverity(score) {
    if (score > 9.5) return { label: "Critical", tone: "cert-critical" };
    if (score >= 8) return { label: "High", tone: "cert-high" };
    if (score >= 6) return { label: "Medium", tone: "cert-medium" };
    if (score >= 4) return { label: "Low-Medium", tone: "cert-low-medium" };
    return { label: "Informational", tone: "muted" };
}

function certificateFindingRisk(finding) {
    return String(finding && finding.rule || "").toUpperCase() === "ESC1"
        ? { label: "Critical", tone: "cert-critical" }
        : certificateSeverity(certificateFindingScore(finding));
}

function certificateRisk(record) {
    const findings = Array.isArray(record.esc_findings) ? record.esc_findings : [];
    if (findings.some(finding => String(finding && finding.rule || "").toUpperCase() === "ESC1")) {
        return { label: "Critical", tone: "cert-critical" };
    }
    const score = findings.reduce((highest, finding) => Math.max(highest, certificateFindingScore(finding)), 0);
    return certificateSeverity(score);
}

/* ------------------------------------------------------------------ */
/* Simple attribute filter (used only for OUs / Trusts / ACEs)         */
/* ------------------------------------------------------------------ */

const ENTITY_FILTER_CONFIG = {
    ous: {
        title: "OU Filters",
        text: [["name", "OU Name"], ["dn", "Distinguished Name"]],
        numbers: [["object_count", "Object Count"], ["privileged_users_count", "Privileged Users"], ["privileged_computers_count", "Privileged Computers"]],
        booleans: [["has_gpo_links", "Has GPO Links"]]
    },
    trusts: {
        title: "Trust Filters",
        text: [["name", "Trust Name"], ["partner", "Partner"], ["flat_name", "Flat Name"], ["direction", "Direction"], ["trust_type", "Trust Type"]],
        booleans: [["dangerous", "Dangerous"], ["sid_filtering_enabled", "SID Filtering"], ["transitive", "Transitive"], ["forest", "Forest Trust"]]
    },
    aces: {
        title: "ACE Filters",
        text: [["target_name", "Target"], ["principal_name", "Principal"], ["principal_sid", "Principal SID"], ["target_dn", "Target DN"], ["rights", "Rights"]],
        booleans: [["dangerous_ace", "Dangerous"], ["extended_rights", "Extended Rights"]]
    }
};

function createEntityFilter(root, config, onChange) {
    if (!root || !config) return null;
    root.classList.add("user-filter");
    const text = Object.fromEntries(config.text.map(([key]) => [key, ""]));
    const numbers = Object.fromEntries((config.numbers || []).map(([key]) => [key, { min: "", max: "" }]));
    const booleans = Object.fromEntries((config.booleans || []).map(([key]) => [key, "any"]));
    const rules = [];
    let availableKeys = [...new Set([
        ...config.text.map(([key]) => key),
        ...(config.numbers || []).map(([key]) => key),
        ...(config.booleans || []).map(([key]) => key)
    ])];
    const ruleOptions = UF_RULE_OPS.map(([value, label]) => `<option value="${value}">${esc(label)}</option>`).join("");
    root.innerHTML = `
        <div class="uf-bar">
            <button type="button" class="uf-toggle"><span class="uf-icon">${ufIcon("funnel")}</span><span class="uf-titles"><strong>${esc(config.title)}</strong><small>Filter records by their attributes</small></span><span class="uf-badge">0 active</span><span class="uf-chevron">${ufIcon("chevron")}</span></button>
            <button type="button" class="uf-btn uf-btn-danger" data-ef="reset">${ufIcon("reset", 14)} Reset</button>
        </div>
        <div class="uf-collapse"><div class="uf-collapse-inner"><div class="uf-content">
            <div class="uf-panels">
                <div class="uf-section"><div class="uf-section-title"><span>Text Attributes</span></div><div class="uf-grid uf-grid-text">
                    ${config.text.map(([key, label]) => `<label class="uf-field"><span class="uf-label">${esc(label)}</span><input class="uf-input" data-ef="text" data-key="${key}" placeholder="Contains..." autocomplete="off"></label>`).join("")}
                </div></div>
                ${config.numbers && config.numbers.length ? `<div class="uf-section"><div class="uf-section-title"><span>Numeric Attributes</span></div><div class="uf-grid uf-grid-num">${config.numbers.map(([key, label]) => `<div class="uf-card"><div class="uf-card-title">${ufIcon("sliders", 14)}${esc(label)}</div><div class="uf-mini-grid"><label class="uf-mini"><span>Minimum</span><input class="uf-input" type="number" data-ef="num" data-key="${key}" data-part="min" placeholder="No limit"></label><label class="uf-mini"><span>Maximum</span><input class="uf-input" type="number" data-ef="num" data-key="${key}" data-part="max" placeholder="No limit"></label></div></div>`).join("")}</div></div>` : ""}
                ${config.booleans && config.booleans.length ? `<div class="uf-section"><div class="uf-section-title"><span>Boolean Attributes</span></div><div class="uf-grid uf-grid-tri">${config.booleans.map(([key, label]) => `<div class="uf-tri uf-tone-info" data-ef="bool" data-key="${key}" data-state="any"><span class="uf-tri-name"><i class="uf-dot"></i>${esc(label)}</span><div class="uf-seg"><button type="button" class="uf-seg-btn active" data-value="any">Any</button><button type="button" class="uf-seg-btn" data-value="yes">Yes</button><button type="button" class="uf-seg-btn" data-value="no">No</button></div></div>`).join("")}</div></div>` : ""}
                <div class="uf-section"><div class="uf-section-title"><span>All Attributes</span><button type="button" class="uf-btn uf-btn-accent" data-ef="add-rule">${ufIcon("plus", 13)} Add condition</button></div>
                    <div class="uf-rules" data-ef="rules"></div>
                    <small class="uf-hint">Every attribute in the loaded records is available. Conditions are combined with AND.</small>
                </div>
            </div>
        </div></div></div>`;
    const update = () => {
        let active = 0;
        root.querySelectorAll('[data-ef="text"]').forEach(input => { text[input.dataset.key] = input.value.trim(); if (text[input.dataset.key]) active++; });
        root.querySelectorAll('[data-ef="num"]').forEach(input => { numbers[input.dataset.key][input.dataset.part] = input.value; });
        Object.values(numbers).forEach(rule => { if (rule.min !== "" || rule.max !== "") active++; });
        root.querySelectorAll('[data-ef="bool"]').forEach(field => { booleans[field.dataset.key] = field.dataset.state; if (field.dataset.state !== "any") active++; });
        rules.forEach(rule => { if (rule.field.trim() && (UF_VALUELESS_OPS.includes(rule.op) || rule.value.trim())) active++; });
        root.querySelector(".uf-badge").textContent = `${active} active`;
        root.classList.toggle("open", active > 0);
        onChange();
    };
    const matches = record => {
        for (const [key, value] of Object.entries(text)) if (value && !ufRuleText(ufRuleValue(record, key)).toLowerCase().includes(value.toLowerCase())) return false;
        for (const [key, rule] of Object.entries(numbers)) if ((rule.min !== "" || rule.max !== "") && !ufNumMatch(ufNum(ufRuleValue(record, key)), rule)) return false;
        for (const [key, state] of Object.entries(booleans)) if (state !== "any" && ufIsTrue(ufRuleValue(record, key)) !== (state === "yes")) return false;
        for (const rule of rules) if (rule.field.trim() && (UF_VALUELESS_OPS.includes(rule.op) || rule.value.trim()) && !ufRuleMatch(record, rule)) return false;
        return true;
    };
    const renderRules = () => {
        root.querySelector('[data-ef="rules"]').innerHTML = rules.map((rule, index) => `
            <div class="uf-rule is-active">
                <input class="uf-input" list="entity-filter-keys" data-ef="rule-field" data-index="${index}" placeholder="Attribute name" value="${esc(rule.field)}" autocomplete="off">
                <select class="uf-select" data-ef="rule-op" data-index="${index}">${ruleOptions.replace(`value="${rule.op}"`, `value="${rule.op}" selected`)}</select>
                <input class="uf-input" data-ef="rule-value" data-index="${index}" placeholder="${UF_VALUELESS_OPS.includes(rule.op) ? "Not required" : "Value"}" value="${esc(rule.value)}"${UF_VALUELESS_OPS.includes(rule.op) ? " disabled" : ""}>
                <button type="button" class="uf-icon-btn" data-ef="remove-rule" data-index="${index}" aria-label="Remove condition">${ufIcon("close", 14)}</button>
            </div>`).join("");
    };
    const renderKeyList = () => {
        let list = root.querySelector("#entity-filter-keys");
        if (!list) {
            list = document.createElement("datalist");
            list.id = "entity-filter-keys";
            root.appendChild(list);
        }
        list.innerHTML = availableKeys.map(key => `<option value="${esc(key)}"></option>`).join("");
    };
    root.querySelector(".uf-toggle").addEventListener("click", () => root.classList.toggle("open"));
    root.querySelector('[data-ef="reset"]').addEventListener("click", () => {
        root.querySelectorAll('[data-ef="text"]').forEach(input => { input.value = ""; });
        root.querySelectorAll('[data-ef="num"]').forEach(input => { input.value = ""; });
        root.querySelectorAll('[data-ef="bool"]').forEach(field => { field.dataset.state = "any"; field.querySelectorAll(".uf-seg-btn").forEach(button => button.classList.toggle("active", button.dataset.value === "any")); });
        rules.length = 0;
        renderRules();
        update();
    });
    root.addEventListener("input", event => {
        const index = Number(event.target.dataset.index);
        if (Number.isInteger(index) && rules[index]) {
            if (event.target.dataset.ef === "rule-field") rules[index].field = event.target.value;
            if (event.target.dataset.ef === "rule-value") rules[index].value = event.target.value;
        }
        update();
    });
    root.addEventListener("click", event => {
        const addRule = event.target.closest('[data-ef="add-rule"]');
        if (addRule) {
            rules.push({ field: availableKeys[0] || "", op: "contains", value: "" });
            renderRules();
            update();
            return;
        }
        const removeRule = event.target.closest('[data-ef="remove-rule"]');
        if (removeRule) {
            rules.splice(Number(removeRule.dataset.index), 1);
            renderRules();
            update();
            return;
        }
        const button = event.target.closest('[data-ef="bool"] .uf-seg-btn');
        if (!button) return;
        const field = button.closest('[data-ef="bool"]');
        field.dataset.state = button.dataset.value;
        field.querySelectorAll(".uf-seg-btn").forEach(item => item.classList.toggle("active", item === button));
        update();
    });
    root.addEventListener("change", event => {
        const index = Number(event.target.dataset.index);
        if (!Number.isInteger(index) || !rules[index]) return;
        if (event.target.dataset.ef === "rule-field") rules[index].field = event.target.value;
        if (event.target.dataset.ef === "rule-op") rules[index].op = event.target.value;
        if (event.target.dataset.ef === "rule-value") rules[index].value = event.target.value;
        renderRules();
        update();
    });
    renderKeyList();
    return {
        serverSide: true,
        getServerFilters: () => ({
            text: Object.fromEntries(Object.entries(text).map(([key, value]) => [
                key, { op: "contains", value }
            ])),
            tri: booleans,
            num: numbers,
            rules
        }),
        needsClientMode: () => false,
        legacyNeedsClientMode: () => [...Object.values(text), ...Object.values(booleans)].some(value => value && value !== "any")
            || Object.values(numbers).some(rule => rule.min !== "" || rule.max !== "")
            || rules.some(rule => rule.field.trim()),
        apply: records => records.filter(matches),
        setCounts: () => {},
        setAvailableKeys: keys => {
            availableKeys = [...new Set([...availableKeys, ...keys])].sort();
            renderKeyList();
        }
    };
}



const SCHEMAS = {
    aces: {
        columns: [
            {
                label: "Target",
                render: d => `<strong>${renderValue(d.target_name)}</strong><small class="domain-dn-trunc" title="${esc(d.target_dn || "")}">${renderValue(d.target_dn)}</small>`
            },
            {
                label: "Principal",
                render: d => {
                    const principal = d.principal_name || d.principal_sid;
                    return principal
                        ? `<span class="domain-dn-trunc ace-principal" title="${esc(principal)}">${esc(principal)}</span>`
                        : '<span class="domain-muted">-</span>';
                }
            },
            {
                label: "Rights",
                render: d => {
                    const extra = Math.max((Number(d.ace_count) || 1) - 1, 0);
                    return `${rightsChip(d.rights)}${extra ? `<small>+${fmtNumber(extra)} more ${extra === 1 ? "ACE" : "ACEs"}</small>` : ""}`;
                }
            },
            {
                label: "Flags",
                render: d => d.extended_rights
                    ? `<div class="domain-flag-list">${badge("Extended Rights", "info")}</div>`
                    : '<span class="domain-muted">Empty</span>'
            }
        ],
        rowClass: d => d.dangerous_ace && !d.is_deny ? "dangerous" : "",
        clickable: true
    },
    users: {
        columns: [
            {
                label: "User",
                render: d => `<strong>${esc(d.username || d.display_name || "Unknown")}</strong><small class="domain-dn-trunc" title="${esc(d.dn || "")}">${esc(d.dn || "")}</small>`
            },
            {
                label: "Status",
                render: d => isDisabledUser(d)
                    ? badge("Disabled", "muted")
                    : badge("Enabled", "ok")
            },
            {
                label: "Description",
                render: d => d.description ? esc(d.description) : '<span class="domain-muted">-</span>'
            },
            { label: "Last Logon", render: d => fmtDate(d.last_logon) }
        ],
        rowClass: d => {
            const isHighAdmin = !!d.absolute_admin || !!d.nested_admin;
            const isPotentialAdmin = !!d.potential_admin;
            const isRoastable = !!d.kerberoastable || !!d.asrep;
            return [
                isDisabledUser(d) ? "user-disabled" : "",
                isHighAdmin ? "user-admin-high" : (isPotentialAdmin ? "user-admin-potential" : ""),
                isRoastable ? "user-roastable" : ""
            ].filter(Boolean).join(" ");
        },
        clickable: true
    },
    computers: {
        columns: [
            {
                label: "Computer",
                render: d => `<strong>${esc(d.computer_name || "Unknown")}</strong><small>${esc(d.dns_name || "Empty")}</small>`
            },
            { label: "Operating System", render: d => esc(d.os || "Unknown") },
            {
                label: "IP Address",
                render: d => {
                    const addresses = [].concat(d.ipv4_addresses || d.ip_address || []).filter(Boolean);
                    return addresses.length ? esc(addresses.join(", ")) : '<span class="domain-muted">-</span>';
                }
            },
            {
                label: "Role",
                render: d => d.is_domain_controller ? badge("Domain Controller", "admin-potential")
                    : d.is_server ? badge("Server", "muted")
                    : d.is_workstation ? badge("Workstation", "muted")
                    : badge("Unknown", "muted")
            }
        ],
        rowClass: d => d.is_domain_controller ? "user-admin-high"
            : (d.unconstrained_delegation || d.rbcd_enabled) ? "flagged" : "",
        clickable: true
    },
    groups: {
        columns: [
            {
                label: "Group",
                render: d => `<strong>${esc(d.group_name || "Unknown")}</strong><small>${esc(d.group_sid || "")}</small>`
            },
            {
                label: "Members",
                render: d => `
                    <div class="domain-members-cell">
                    <strong>${fmtNumber(d.member_count)} ${Number(d.member_count) === 1 ? "member" : "members"}</strong>
                    <button type="button" class="domain-members-button">
                        <svg class="domain-members-icon" viewBox="0 0 24 24" width="12" height="12" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M17 21v-2a4 4 0 0 0-4-4H7a4 4 0 0 0-4 4v2"/><circle cx="10" cy="7" r="4"/><path d="M21 21v-2a4 4 0 0 0-3-3.87"/><path d="M16 3.13a4 4 0 0 1 0 7.75"/></svg>
                        <span>View members</span>
                        <svg class="domain-members-arrow" viewBox="0 0 24 24" width="11" height="11" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M9 18l6-6-6-6"/></svg>
                    </button>
                    </div>`
            },
            {
                label: "Privileged",
                render: d => d.is_privileged ? badge("Yes", "danger") : badge("No", "muted")
            }
        ],
        rowClass: d => d.is_privileged ? "flagged" : "",
        clickable: true,
        sort: { field: "member_count", dir: "desc" }
    },
    gpos: {
        columns: [
            {
                label: "Policy",
                render: d => `<strong>${esc(d.display_name || d.name || "Unknown")}</strong><small>${esc(d.guid || "")}</small>`
            },
            {
                label: "Links",
                render: d => {
                    const count = Number(d.linked_count) || 0;
                    return `
                    <div class="domain-members-cell">
                    <div class="gpo-links-summary">
                        <strong>${fmtNumber(count)} ${count === 1 ? "Object" : "Objects"}</strong>
                        ${d.enforced ? '<small class="gpo-enforced">Enforced</small>' : "<small>Not Enforced</small>"}
                    </div>
                    <button type="button" class="domain-members-button">
                        <svg class="domain-members-icon" viewBox="0 0 24 24" width="12" height="12" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M10 13a5 5 0 0 0 7.54.54l3-3a5 5 0 0 0-7.07-7.07l-1.72 1.71"/><path d="M14 11a5 5 0 0 0-7.54-.54l-3 3a5 5 0 0 0 7.07 7.07l1.71-1.71"/></svg>
                        <span>View links</span>
                        <svg class="domain-members-arrow" viewBox="0 0 24 24" width="11" height="11" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M9 18l6-6-6-6"/></svg>
                    </button>
                    </div>`;
                }
            }
        ],
        rowClass: d => d.highvalue ? "gpo-highvalue" : "",
        clickable: true,
        sort: { field: "linked_count", dir: "desc" }
    },
    ous: {
        columns: [
            {
                label: "Organizational Unit",
                render: d => `<strong>${esc(d.name || "Unknown")}</strong><small class="domain-dn-trunc" title="${esc(d.dn || "")}">${esc(d.dn || "")}</small>`
            },
            {
                label: "Objects",
                render: d => `
                    <div class="domain-members-cell">
                    <strong>${fmtNumber(d.object_count)} ${Number(d.object_count) === 1 ? "object" : "objects"}</strong>
                    <button type="button" class="domain-members-button">
                        <svg class="domain-members-icon" viewBox="0 0 24 24" width="12" height="12" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M21 16V8a2 2 0 0 0-1-1.73l-7-4a2 2 0 0 0-2 0l-7 4A2 2 0 0 0 3 8v8a2 2 0 0 0 1 1.73l7 4a2 2 0 0 0 2 0l7-4A2 2 0 0 0 21 16z"/><path d="M3.27 6.96 12 12.01l8.73-5.05"/><path d="M12 22.08V12"/></svg>
                        <span>View objects</span>
                        <svg class="domain-members-arrow" viewBox="0 0 24 24" width="11" height="11" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M9 18l6-6-6-6"/></svg>
                    </button>
                    </div>`
            },
            {
                label: "GPO Links",
                render: d => d.has_gpo_links ? badge("Linked", "info") : badge("None", "muted")
            }
        ],
        rowClass: d => (d.privileged_users_count || d.privileged_computers_count) ? "flagged" : "",
        clickable: true,
        sort: { field: "object_count", dir: "desc" }
    },
    trusts: {
        columns: [
            {
                label: "Trust",
                render: d => `<strong>${esc(d.name || d.partner || "Unknown")}</strong><small>${esc(d.flat_name || "")}${d.partner && d.partner !== d.name ? ` · ${esc(d.partner)}` : ""}</small>`
            },
            {
                label: "Direction",
                render: d => trustDirectionBadge(d)
            },
            {
                label: "Type",
                render: d => `<div class="domain-flag-list">${badge(trustTypeLabel(d), d.forest ? "admin-potential" : "info")}</div><small>${d.transitive ? "Transitive" : "Non-transitive"}</small>`
            },
            {
                label: "Security",
                render: d => `<div class="domain-flag-list">${trustSecurityBadges(d).join("")}</div>`
            },
            { label: "Last Changed", render: d => fmtDate(d.when_changed) }
        ],
        rowClass: d => d.dangerous ? "dangerous" : (!d.sid_filtering_enabled ? "flagged" : ""),
        clickable: true
    },
    certificates: {
        columns: [
            {
                label: "Object",
                render: d => `<strong>${esc(d.name || d.raw?.cn || "Unknown")}</strong><small>${esc(d.record_type || "")}</small>`
            },
            {
                label: "Findings",
                render: d => Number(d.finding_count)
                    ? badge(`${d.finding_count} ESC finding${Number(d.finding_count) === 1 ? "" : "s"}`, "danger")
                    : badge("No findings", "ok")
            },
            {
                label: "Risk",
                render: d => {
                    const risk = certificateRisk(d);
                    return badge(risk.label, risk.tone);
                }
            },
            {
                label: "Details",
                render: d => {
                    const findings = Array.isArray(d.esc_findings) ? d.esc_findings : [];
                    return findings.length
                        ? findings.map(item => {
                            const score = certificateFindingScore(item);
                            const risk = certificateFindingRisk(item);
                            return badge(`${item.rule} · ${score.toFixed(1)} · ${risk.label}`, risk.tone);
                        }).join("")
                        : '<span class="domain-muted">-</span>';
                }
            }
        ],
        rowClass: d => Number(d.finding_count) ? `flagged ${certificateRisk(d).tone}` : "",
        clickable: true
    }
};

function trustList(value) {
    if (Array.isArray(value)) return value.filter(item => item !== null && item !== undefined && item !== "");
    if (value === null || value === undefined || value === "" || value === "-") return [];
    return String(value).split(/[,;|]/).map(item => item.trim()).filter(Boolean);
}

function trustLabel(value) {
    return String(value || "").toLowerCase().split("_").filter(Boolean)
        .map(word => word.charAt(0).toUpperCase() + word.slice(1)).join(" ");
}

function trustTypeLabel(trust) {
    const map = { uplevel: "Uplevel", downlevel: "Downlevel", mit: "MIT Kerberos", dce: "DCE" };
    if (trust.forest) return "Forest";
    const raw = String(trust.trust_type || "").toLowerCase();
    return map[raw] || trustLabel(raw) || "Unknown";
}

function trustDirectionBadge(trust) {
    const direction = String(trust.direction || "").toLowerCase();
    const arrows = { bidirectional: "\u21C4", inbound: "\u2192", outbound: "\u2190" };
    const labels = { bidirectional: "Bidirectional", inbound: "Inbound", outbound: "Outbound" };
    const tone = direction === "bidirectional" ? "warn" : "info";
    if (!labels[direction]) return badge(trustLabel(direction) || "Unknown", "muted");
    return `<div class="domain-flag-list">${badge(`${arrows[direction]} ${labels[direction]}`, tone)}</div>`;
}

function trustSecurityBadges(trust) {
    const items = [];
    items.push(trust.sid_filtering_enabled ? badge("SID Filtering", "ok") : badge("No SID Filtering", "danger"));
    if (trust.forest_wide_auth) items.push(badge("Forest-Wide Auth", "warn"));
    if (trust.selective_auth) items.push(badge("Selective Auth", "ok"));
    if (trust.tgt_delegation_enabled) items.push(badge("TGT Delegation", "danger"));
    if (trust.uses_rc4_encryption) items.push(badge("RC4", "warn"));
    if (trust.dangerous) items.push(badge("Dangerous", "danger"));
    return items;
}

let UF_COUNTER = 0;

const UF_ICONS = {
    funnel: '<path d="M3 5h18l-7 8v6l-4 2v-8z"/>',
    chevron: '<path d="M6 9l6 6 6-6"/>',
    reset: '<path d="M3 12a9 9 0 1 0 3-6.7"/><path d="M3 4v5h5"/>',
    plus: '<path d="M12 5v14M5 12h14"/>',
    close: '<path d="M6 6l12 12M18 6L6 18"/>',
    trash: '<path d="M4 7h16"/><path d="M9 7V4h6v3"/><path d="M6 7l1 13h10l1-13"/>',
    bolt: '<path d="M13 2L4 14h7l-1 8 9-12h-7z"/>',
    user: '<circle cx="12" cy="8" r="4"/><path d="M4 21v-1a6 6 0 0 1 6-6h4a6 6 0 0 1 6 6v1"/>',
    status: '<circle cx="12" cy="12" r="9"/><path d="M8 12l3 3 5-6"/>',
    shield: '<path d="M12 3l8 3v6c0 4.5-3.2 8-8 9-4.8-1-8-4.5-8-9V6z"/>',
    clock: '<circle cx="12" cy="12" r="9"/><path d="M12 7v5l3 2"/>',
    users: '<path d="M17 21v-2a4 4 0 0 0-4-4H7a4 4 0 0 0-4 4v2"/><circle cx="10" cy="7" r="4"/><path d="M21 21v-2a4 4 0 0 0-3-3.87"/><path d="M16 3.13a4 4 0 0 1 0 7.75"/>',
    sliders: '<path d="M4 6h9M17 6h3M4 12h3M11 12h9M4 18h11M19 18h1"/><circle cx="15" cy="6" r="2"/><circle cx="9" cy="12" r="2"/><circle cx="17" cy="18" r="2"/>',
    sort: '<path d="M7 4v16M3 16l4 4 4-4"/><path d="M17 20V4M13 8l4-4 4 4"/>'
};

function ufIcon(name, size = 16) {
    return `<svg viewBox="0 0 24 24" width="${size}" height="${size}" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">${UF_ICONS[name]}</svg>`;
}

async function copyText(value) {
    if (navigator.clipboard && typeof navigator.clipboard.writeText === "function") {
        await navigator.clipboard.writeText(value);
        return;
    }
    const textarea = document.createElement("textarea");
    textarea.value = value;
    textarea.setAttribute("readonly", "");
    textarea.style.position = "fixed";
    textarea.style.opacity = "0";
    document.body.appendChild(textarea);
    textarea.select();
    const copied = document.execCommand("copy");
    textarea.remove();
    if (!copied) throw new Error("Clipboard access is unavailable");
}

const UF_TEXT_OPS = [
    ["contains", "Contains"],
    ["equals", "Equals"],
    ["starts", "Starts with"],
    ["ends", "Ends with"],
    ["excludes", "Does not contain"],
    ["empty", "Is empty"],
    ["filled", "Is not empty"]
];

const UF_RULE_OPS = [
    ["contains", "Contains"],
    ["not_contains", "Does not contain"],
    ["equals", "Equals"],
    ["not_equals", "Does not equal"],
    ["starts", "Starts with"],
    ["ends", "Ends with"],
    ["gt", "Greater than"],
    ["gte", "Greater or equal"],
    ["lt", "Less than"],
    ["lte", "Less or equal"],
    ["regex", "Matches regex"],
    ["empty", "Is empty"],
    ["filled", "Is not empty"],
    ["true", "Is true"],
    ["false", "Is false"]
];

const UF_VALUELESS_OPS = ["empty", "filled", "true", "false"];

function ufTime(value) {
    if (value === null || value === undefined || value === "") return null;
    const time = new Date(value).getTime();
    return Number.isFinite(time) && time > 0 ? time : null;
}

function ufNum(value) {
    if (value === null || value === undefined || value === "" || typeof value === "boolean") return NaN;
    return Number(value);
}

function ufHasText(value) {
    return String(value ?? "").trim() !== "";
}

function ufTextActive(rule) {
    return rule.op === "empty" || rule.op === "filled"
        || (Array.isArray(rule.values) ? rule.values.length > 0 : rule.value.trim() !== "");
}

function ufTextValues(rule) {
    return Array.isArray(rule.values) ? rule.values : (rule.value.trim() ? [rule.value.trim()] : []);
}

function ufTextMatch(op, raw, needle) {
    const hay = String(raw ?? "").toLowerCase();
    const term = needle.toLowerCase();
    if (op === "empty") return hay.trim() === "";
    if (op === "filled") return hay.trim() !== "";
    if (op === "equals") return hay === term;
    if (op === "starts") return hay.startsWith(term);
    if (op === "ends") return hay.endsWith(term);
    if (op === "excludes") return !hay.includes(term);
    return hay.includes(term);
}

function ufDateActive(rule) {
    return !!(rule.from || rule.to || rule.within !== "" || rule.older !== "");
}

function ufDateMatch(time, rule) {
    const day = 86400000;
    const now = Date.now();
    if (rule.older !== "" && Number.isFinite(Number(rule.older)) && time !== null && time > now - Number(rule.older) * day) return false;
    if (time === null) return !(rule.from || rule.to || rule.within !== "");
    if (rule.from && time < new Date(rule.from + "T00:00:00").getTime()) return false;
    if (rule.to && time > new Date(rule.to + "T23:59:59.999").getTime()) return false;
    if (rule.within !== "" && Number.isFinite(Number(rule.within)) && time < now - Number(rule.within) * day) return false;
    return true;
}

function ufNumActive(rule) {
    return rule.min !== "" || rule.max !== "";
}

function ufNumMatch(value, rule) {
    if (!Number.isFinite(value)) return false;
    if (rule.min !== "" && value < Number(rule.min)) return false;
    if (rule.max !== "" && value > Number(rule.max)) return false;
    return true;
}

function ufRuleValue(user, path) {
    return path.split(".").reduce((node, key) => (node === null || node === undefined) ? undefined : node[key], user);
}

function ufRuleText(value) {
    if (value === null || value === undefined) return "";
    if (Array.isArray(value)) return value.map(ufRuleText).join(", ");
    if (typeof value === "object") return JSON.stringify(value);
    return String(value);
}

function ufIsEmpty(value) {
    return value === null || value === undefined || value === "" || (Array.isArray(value) && !value.length);
}

function ufIsTrue(value) {
    if (value === true || value === 1) return true;
    return typeof value === "string" && value.trim().toLowerCase() === "true";
}

function ufRuleReady(rule) {
    return rule.field.trim() !== "" && (UF_VALUELESS_OPS.includes(rule.op) || rule.value.trim() !== "");
}

function ufCompare(raw, needle, test) {
    const a = ufNum(raw);
    const b = ufNum(needle);
    if (Number.isFinite(a) && Number.isFinite(b)) return test(a, b);
    const ta = ufTime(raw);
    const tb = ufTime(needle);
    if (ta !== null && tb !== null) return test(ta, tb);
    return false;
}

function ufRuleMatch(user, rule) {
    const raw = ufRuleValue(user, rule.field.trim());
    const text = ufRuleText(raw).toLowerCase();
    const term = rule.value.trim().toLowerCase();
    switch (rule.op) {
        case "empty": return ufIsEmpty(raw);
        case "filled": return !ufIsEmpty(raw);
        case "true": return ufIsTrue(raw);
        case "false": return !ufIsTrue(raw);
        case "equals": return text === term;
        case "not_equals": return text !== term;
        case "starts": return text.startsWith(term);
        case "ends": return text.endsWith(term);
        case "not_contains": return !text.includes(term);
        case "gt": return ufCompare(raw, rule.value, (a, b) => a > b);
        case "gte": return ufCompare(raw, rule.value, (a, b) => a >= b);
        case "lt": return ufCompare(raw, rule.value, (a, b) => a < b);
        case "lte": return ufCompare(raw, rule.value, (a, b) => a <= b);
        case "regex":
            try { return new RegExp(rule.value.trim(), "i").test(ufRuleText(raw)); } catch (error) { return false; }
        default: return text.includes(term);
    }
}

/* ------------------------------------------------------------------ */
/* Full, Users-style attribute filter — used for Users, Groups,        */
/* Computers and GPOs so all four panels share exactly the same UI     */
/* and let every one of the entity's attributes be filtered on.        */
/* ------------------------------------------------------------------ */

function ufCanonicalSortFields(config) {
    return [{ key: "", label: "Default order" }, ...(config.sortFields || [])];
}

function ufBuildTabs(config) {
    return [
        ...config.tabs,
        ...(config.membership ? [{ key: "membership", label: config.membership.tabLabel || "Membership", icon: "users" }] : []),
        { key: "advanced", label: "Advanced", icon: "sliders" }
    ];
}

function ufBuildTabOf(config) {
    const tabOf = {};
    Object.entries(config.layout || {}).forEach(([tab, sections]) => {
        sections.forEach(section => section.keys.forEach(key => { tabOf[`${section.kind}:${key}`] = tab; }));
    });
    if (config.membership) {
        tabOf[`num:${config.membership.numField.key}`] = "membership";
        tabOf.membership = "membership";
    }
    tabOf.rule = "advanced";
    return tabOf;
}

function ufInitialFullState(config) {
    const text = {};
    config.textFields.forEach(field => {
        text[field.key] = config.multiTextFields && config.multiTextFields.includes(field.key)
            ? { op: "contains", values: [] }
            : { op: "contains", value: "" };
    });
    const tri = {};
    config.triFields.forEach(field => { tri[field.key] = "any"; });
    const date = {};
    config.dateFields.forEach(field => { date[field.key] = { from: "", to: "", within: "", older: "" }; });
    const num = {};
    config.numFields.forEach(field => { num[field.key] = { min: "", max: "" }; });
    const state = { text, tri, date, num, rules: [], sort: { field: "", dir: "asc" } };
    if (config.membership) state.membership = { include: [], exclude: [], mode: "any" };
    return state;
}

function createAttributeFilter(root, config, onChange) {
    if (!root || !config) return null;
    const uid = `uf${++UF_COUNTER}`;
    const textMap = Object.fromEntries(config.textFields.map(field => [field.key, field]));
    const triMap = Object.fromEntries(config.triFields.map(field => [field.key, field]));
    const dateMap = Object.fromEntries(config.dateFields.map(field => [field.key, field]));
    const numMap = Object.fromEntries(config.numFields.map(field => [field.key, field]));
    const presets = config.presets || [];
    const sortFields = ufCanonicalSortFields(config);
    const tabs = ufBuildTabs(config);
    const tabOf = ufBuildTabOf(config);
    const keys = new Set(config.knownKeys || []);
    let state = ufInitialFullState(config);
    let activeTab = tabs[0].key;
    let items = [];
    let timer = null;

    root.classList.add("user-filter");
    root.innerHTML = `
        <div class="uf-bar">
            <button type="button" class="uf-toggle" data-uf="toggle" aria-expanded="false" aria-controls="${uid}-body">
                <span class="uf-icon">${ufIcon("funnel", 18)}</span>
                <span class="uf-titles">
                    <strong>Filters</strong>
                    <small>${esc(config.subtitle || "Narrow down records by any attribute, flag, date or group")}</small>
                </span>
                <span class="uf-badge" hidden></span>
                <span class="uf-chevron">${ufIcon("chevron", 18)}</span>
            </button>
            <button type="button" class="uf-btn uf-btn-bar" data-uf="reset" hidden>${ufIcon("reset", 13)}<span>Reset</span></button>
        </div>
        <div class="uf-active" hidden>
            <div class="uf-active-list"></div>
        </div>
        <div class="uf-collapse">
            <div class="uf-collapse-inner" id="${uid}-body" inert>
                <div class="uf-content">
                    ${presets.length ? `<div class="uf-presets">
                        <span class="uf-presets-label">${ufIcon("bolt", 13)}Quick filters</span>
                        ${presets.map(preset => `<button type="button" class="uf-preset" data-uf="preset" data-id="${preset.id}">${esc(preset.label)}</button>`).join("")}
                    </div>` : ""}
                    <div class="uf-tabs" role="tablist">
                        ${tabs.map(tab => `
                            <button type="button" class="uf-tab" role="tab" data-uf="tab" data-tab="${tab.key}">
                                ${ufIcon(tab.icon, 14)}<span>${esc(tab.label)}</span><em class="uf-tab-count" hidden></em>
                            </button>`).join("")}
                    </div>
                    <div class="uf-panels"></div>
                    <div class="uf-footer">
                        <div class="uf-sort">
                            <span class="uf-sort-label">${ufIcon("sort", 14)}Sort by</span>
                            <select class="uf-select" data-uf="sort-field" aria-label="Sort field">
                                ${sortFields.map(field => `<option value="${field.key}">${esc(field.label)}</option>`).join("")}
                            </select>
                            <button type="button" class="uf-btn" data-uf="sort-dir">Ascending</button>
                        </div>
                        <div class="uf-result"></div>
                        <button type="button" class="uf-btn uf-btn-danger" data-uf="reset">${ufIcon("trash", 13)}<span>Reset all</span></button>
                    </div>
                </div>
            </div>
        </div>
        <datalist id="${uid}-keys"></datalist>`;

    const inner = root.querySelector(".uf-collapse-inner");
    const panels = root.querySelector(".uf-panels");
    const badgeEl = root.querySelector(".uf-badge");
    const activeWrap = root.querySelector(".uf-active");
    const activeList = root.querySelector(".uf-active-list");
    const resultEl = root.querySelector(".uf-result");
    const sortField = root.querySelector('[data-uf="sort-field"]');
    const sortDir = root.querySelector('[data-uf="sort-dir"]');
    const datalist = root.querySelector(`#${uid}-keys`);
    const resetButtons = root.querySelectorAll('[data-uf="reset"]');

    function optionList(list, selected) {
        return list.map(([value, label]) => `<option value="${value}"${value === selected ? " selected" : ""}>${esc(label)}</option>`).join("");
    }

    function textFieldHtml(key) {
        const field = textMap[key];
        const rule = state.text[key];
        const multi = config.multiTextFields && config.multiTextFields.includes(key);
        const valueless = rule.op === "empty" || rule.op === "filled";
        const values = ufTextValues(rule);
        return `
            <div class="uf-field${ufTextActive(rule) ? " is-active" : ""}">
                <label class="uf-label" for="${uid}-text-${key}">${esc(field.label)}</label>
                <div class="uf-combo">
                    <select class="uf-select" data-uf="text-op" data-key="${key}" aria-label="${esc(field.label)} operator">${optionList(UF_TEXT_OPS, rule.op)}</select>
                    <input class="uf-input" id="${uid}-text-${key}" type="text" data-uf="text-val" data-key="${key}" placeholder="${esc(valueless ? "Not required" : (field.placeholder || ""))}" value="${esc(multi ? "" : rule.value)}" autocomplete="off" spellcheck="false"${valueless ? " disabled" : ""}>
                    ${multi ? `<button type="button" class="uf-btn uf-text-add" data-uf="text-add" data-key="${key}" aria-label="Add ${esc(field.label)} value">+</button>` : ""}
                </div>
                ${multi && values.length ? `<div class="uf-text-chips">${values.map((value, index) => `<span class="uf-chip">${esc(value)}<button type="button" data-uf="text-remove" data-key="${key}" data-index="${index}" aria-label="Remove ${esc(value)}">${ufIcon("close", 11)}</button></span>`).join("")}</div>` : ""}
            </div>`;
    }

    function triFieldHtml(key) {
        const field = triMap[key];
        const value = state.tri[key];
        return `
            <div class="uf-tri uf-tone-${field.tone || "info"}" data-state="${value}">
                <span class="uf-tri-name"><i class="uf-dot"></i>${esc(field.label)}</span>
                <div class="uf-seg" role="group" aria-label="${esc(field.label)}">
                    ${[["any", "Any"], ["yes", "Yes"], ["no", "No"]].map(([val, label]) => `
                        <button type="button" class="uf-seg-btn${value === val ? " active" : ""}" data-uf="tri" data-key="${key}" data-val="${val}" aria-pressed="${value === val}">${label}</button>`).join("")}
                </div>
            </div>`;
    }

    function dateFieldHtml(key) {
        const field = dateMap[key];
        const rule = state.date[key];
        const mini = (part, label, type, placeholder) => `
            <label class="uf-mini"><span>${label}</span>
                <input class="uf-input" type="${type}" data-uf="date" data-key="${key}" data-part="${part}" value="${esc(rule[part])}"${placeholder ? ` placeholder="${placeholder}" min="0"` : ""}>
            </label>`;
        return `
            <div class="uf-card${ufDateActive(rule) ? " is-active" : ""}">
                <div class="uf-card-title">${ufIcon("clock", 14)}${esc(field.label)}</div>
                <div class="uf-mini-grid">
                    ${mini("from", "From", "date")}
                    ${mini("to", "To", "date")}
                    ${mini("within", "Within last (days)", "number", "e.g. 30")}
                    ${mini("older", "Older than (days)", "number", "e.g. 90")}
                </div>
            </div>`;
    }

    function numFieldHtml(key) {
        const field = numMap[key];
        const rule = state.num[key];
        const mini = (part, label, placeholder) => `
            <label class="uf-mini"><span>${label}</span>
                <input class="uf-input" type="number" min="0" data-uf="num" data-key="${key}" data-part="${part}" value="${esc(rule[part])}" placeholder="${placeholder}">
            </label>`;
        return `
            <div class="uf-card${ufNumActive(rule) ? " is-active" : ""}">
                <div class="uf-card-title">${ufIcon("sliders", 14)}${esc(field.label)}</div>
                <div class="uf-mini-grid uf-mini-grid-2">
                    ${mini("min", "Minimum", "0")}
                    ${mini("max", "Maximum", "no limit")}
                </div>
            </div>`;
    }

    function sectionHtml(section) {
        const render = { text: textFieldHtml, tri: triFieldHtml, date: dateFieldHtml, num: numFieldHtml }[section.kind];
        return `
            <div class="uf-section">
                <div class="uf-section-title"><span>${esc(section.title)}</span></div>
                <div class="uf-grid uf-grid-${section.kind}">${section.keys.map(render).join("")}</div>
            </div>`;
    }

    function chipsHtml(list) {
        const values = state.membership[list];
        return values.map((term, index) => `
            <span class="uf-chip">${esc(term)}<button type="button" data-uf="chip-remove" data-list="${list}" data-index="${index}" aria-label="Remove ${esc(term)}">${ufIcon("close", 11)}</button></span>`).join("");
    }

    function chipBoxHtml(list, title, hint, placeholder) {
        return `
            <div class="uf-card uf-chip-card${state.membership[list].length ? " is-active" : ""}" data-list-card="${list}">
                <div class="uf-card-head">
                    <div class="uf-card-title">${ufIcon("users", 14)}${esc(title)}</div>
                    ${list === "include" ? `
                    <div class="uf-seg uf-seg-mode" data-state="${state.membership.mode}" role="group" aria-label="Match mode">
                        <button type="button" class="uf-seg-btn${state.membership.mode === "any" ? " active" : ""}" data-uf="group-mode" data-val="any">Any of</button>
                        <button type="button" class="uf-seg-btn${state.membership.mode === "all" ? " active" : ""}" data-uf="group-mode" data-val="all">All of</button>
                    </div>` : ""}
                </div>
                <div class="uf-chip-box">
                    <div class="uf-chip-host" data-list="${list}">${chipsHtml(list)}</div>
                    <input class="uf-chip-input" type="text" data-uf="chip-input" data-list="${list}" placeholder="${esc(placeholder)}" autocomplete="off" spellcheck="false">
                </div>
                <small class="uf-hint">${esc(hint)}</small>
            </div>`;
    }

    function membershipPanelHtml() {
        if (!config.membership) return "";
        const m = config.membership;
        return `
            <div class="uf-section">
                <div class="uf-section-title"><span>${esc(m.sectionTitle || "Membership")}</span></div>
                <div class="uf-grid uf-grid-groups">
                    ${chipBoxHtml("include", m.includeLabel || "Member of", m.includeHint || "Press Enter or comma to add.", m.placeholder || "Type a value and press Enter")}
                    ${chipBoxHtml("exclude", m.excludeLabel || "Not member of", m.excludeHint || "Records matching any of these are hidden.", m.placeholder || "Type a value and press Enter")}
                </div>
            </div>
            <div class="uf-section">
                <div class="uf-section-title"><span>Membership Size</span></div>
                <div class="uf-grid uf-grid-num">${numFieldHtml(m.numField.key)}</div>
            </div>`;
    }

    function ruleHtml(rule, index) {
        const valueless = UF_VALUELESS_OPS.includes(rule.op);
        return `
            <div class="uf-rule${ufRuleReady(rule) ? " is-active" : ""}" data-index="${index}">
                <input class="uf-input" type="text" list="${uid}-keys" data-uf="rule-field" data-index="${index}" placeholder="Attribute name" value="${esc(rule.field)}" autocomplete="off" spellcheck="false" aria-label="Attribute">
                <select class="uf-select" data-uf="rule-op" data-index="${index}" aria-label="Operator">${optionList(UF_RULE_OPS, rule.op)}</select>
                <input class="uf-input" type="text" data-uf="rule-value" data-index="${index}" placeholder="${valueless ? "Not required" : "Value"}" value="${esc(rule.value)}" autocomplete="off" spellcheck="false" aria-label="Value"${valueless ? " disabled" : ""}>
                <button type="button" class="uf-icon-btn" data-uf="rule-remove" data-index="${index}" aria-label="Remove rule">${ufIcon("close", 14)}</button>
            </div>`;
    }

    function rulesHtml() {
        return state.rules.length
            ? state.rules.map(ruleHtml).join("")
            : `<div class="uf-empty">${ufIcon("sliders", 22)}<strong>No custom rules yet</strong><span>Add a rule to filter on any attribute returned for this record, including nested paths such as owner.name.</span></div>`;
    }

    function advancedPanelHtml() {
        return `
            <div class="uf-section">
                <div class="uf-section-title"><span>Custom Attribute Rules</span>
                    <button type="button" class="uf-btn uf-btn-accent" data-uf="rule-add">${ufIcon("plus", 13)}<span>Add rule</span></button>
                </div>
                <div class="uf-rules">${rulesHtml()}</div>
                <small class="uf-hint">All rules must match. Attribute names are suggested from the loaded records.</small>
            </div>`;
    }

    function renderPanels() {
        const html = tabs.map(tab => {
            let content = "";
            if (tab.key === "membership") content = membershipPanelHtml();
            else if (tab.key === "advanced") content = advancedPanelHtml();
            else content = (config.layout[tab.key] || []).map(sectionHtml).join("");
            return `<div class="uf-panel" role="tabpanel" data-panel="${tab.key}"${tab.key === activeTab ? "" : " hidden"}>${content}</div>`;
        }).join("");
        panels.innerHTML = html;
    }

    function refreshKeys() {
        datalist.innerHTML = Array.from(keys).sort().map(key => `<option value="${esc(key)}"></option>`).join("");
    }

    function collect() {
        const list = [];
        config.textFields.forEach(field => {
            const rule = state.text[field.key];
            if (!ufTextActive(rule)) return;
            const op = UF_TEXT_OPS.find(entry => entry[0] === rule.op)[1].toLowerCase();
            const valueless = rule.op === "empty" || rule.op === "filled";
            const values = ufTextValues(rule);
            list.push({
                tab: tabOf[`text:${field.key}`],
                label: `${field.label} ${op}${valueless ? "" : ` "${values.join("\" and \"")}"`}`,
                clear: () => {
                    rule.op = "contains";
                    if (Array.isArray(rule.values)) rule.values = [];
                    rule.value = "";
                }
            });
        });
        config.triFields.forEach(field => {
            const value = state.tri[field.key];
            if (value === "any") return;
            list.push({
                tab: tabOf[`tri:${field.key}`],
                label: `${field.label}: ${value === "yes" ? "Yes" : "No"}`,
                tone: field.tone,
                clear: () => { state.tri[field.key] = "any"; }
            });
        });
        config.dateFields.forEach(field => {
            const rule = state.date[field.key];
            if (!ufDateActive(rule)) return;
            const parts = [];
            if (rule.from) parts.push(`from ${rule.from}`);
            if (rule.to) parts.push(`to ${rule.to}`);
            if (rule.within !== "") parts.push(`within last ${rule.within} days`);
            if (rule.older !== "") parts.push(`older than ${rule.older} days`);
            list.push({
                tab: tabOf[`date:${field.key}`],
                label: `${field.label}: ${parts.join(", ")}`,
                clear: () => { rule.from = ""; rule.to = ""; rule.within = ""; rule.older = ""; }
            });
        });
        config.numFields.forEach(field => {
            const rule = state.num[field.key];
            if (!ufNumActive(rule)) return;
            const parts = [];
            if (rule.min !== "") parts.push(`min ${rule.min}`);
            if (rule.max !== "") parts.push(`max ${rule.max}`);
            list.push({
                tab: tabOf[`num:${field.key}`],
                label: `${field.label}: ${parts.join(", ")}`,
                clear: () => { rule.min = ""; rule.max = ""; }
            });
        });
        if (config.membership) {
            if (state.membership.include.length) {
                list.push({
                    tab: "membership",
                    label: `${config.membership.includeLabel || "Member of"} ${state.membership.mode === "all" ? "all" : "any"}: ${state.membership.include.join(", ")}`,
                    clear: () => { state.membership.include = []; }
                });
            }
            if (state.membership.exclude.length) {
                list.push({
                    tab: "membership",
                    label: `${config.membership.excludeLabel || "Not member of"}: ${state.membership.exclude.join(", ")}`,
                    clear: () => { state.membership.exclude = []; }
                });
            }
        }
        state.rules.forEach(rule => {
            if (!ufRuleReady(rule)) return;
            const op = UF_RULE_OPS.find(entry => entry[0] === rule.op)[1].toLowerCase();
            list.push({
                tab: "advanced",
                label: `${rule.field.trim()} ${op}${UF_VALUELESS_OPS.includes(rule.op) ? "" : ` "${rule.value.trim()}"`}`,
                clear: () => { state.rules = state.rules.filter(entry => entry !== rule); }
            });
        });
        return list;
    }

    function refreshMeta() {
        items = collect();
        const total = items.length;
        badgeEl.hidden = !total;
        badgeEl.textContent = `${total} active`;
        activeWrap.hidden = !total;
        activeList.innerHTML = items.map((item, index) => `
            <span class="uf-active-chip${item.tone ? ` uf-tone-${item.tone}` : ""}"><span>${esc(item.label)}</span><button type="button" data-uf="item-clear" data-index="${index}" aria-label="Remove filter">${ufIcon("close", 11)}</button></span>`).join("")
            + (total ? `<button type="button" class="uf-clear-all" data-uf="reset">Clear all</button>` : "");
        resetButtons.forEach(button => { button.hidden = button.classList.contains("uf-btn-bar") && !total && !state.sort.field; });
        root.querySelectorAll(".uf-tab").forEach(button => {
            const tab = button.dataset.tab;
            const count = items.filter(item => item.tab === tab).length;
            const counter = button.querySelector(".uf-tab-count");
            counter.hidden = !count;
            counter.textContent = String(count);
            button.classList.toggle("active", tab === activeTab);
            button.setAttribute("aria-selected", String(tab === activeTab));
        });
        sortField.value = state.sort.field;
        sortDir.textContent = state.sort.dir === "asc" ? "Ascending" : "Descending";
        sortDir.disabled = !state.sort.field;
        root.classList.toggle("has-filters", total > 0);
    }

    function commit(immediate) {
        refreshMeta();
        clearTimeout(timer);
        if (immediate) onChange();
        else timer = setTimeout(onChange, 280);
    }

    function addChip(list, input) {
        const value = input.value.replace(/,/g, "").trim();
        input.value = "";
        if (!value) return;
        const existing = state.membership[list];
        if (existing.some(term => term.toLowerCase() === value.toLowerCase())) return;
        existing.push(value);
        root.querySelector(`.uf-chip-host[data-list="${list}"]`).innerHTML = chipsHtml(list);
        root.querySelector(`[data-list-card="${list}"]`).classList.add("is-active");
        commit(true);
    }

    function setOpen(open) {
        root.classList.toggle("open", open);
        inner.inert = !open;
        root.querySelector(".uf-toggle").setAttribute("aria-expanded", String(open));
    }

    function resetAll() {
        state = ufInitialFullState(config);
        renderPanels();
        commit(true);
    }

    root.addEventListener("click", event => {
        const target = event.target.closest("[data-uf]");
        if (!target) return;
        const action = target.dataset.uf;
        const key = target.dataset.key;
        if (action === "toggle") {
            setOpen(!root.classList.contains("open"));
        } else if (action === "reset") {
            resetAll();
        } else if (action === "tab") {
            activeTab = target.dataset.tab;
            panels.querySelectorAll(".uf-panel").forEach(panel => { panel.hidden = panel.dataset.panel !== activeTab; });
            refreshMeta();
        } else if (action === "preset") {
            const preset = presets.find(entry => entry.id === target.dataset.id);
            if (!preset) return;
            if (!config.multiPreset) state = ufInitialFullState(config);
            preset.apply(state);
            renderPanels();
            commit(true);
        } else if (action === "tri") {
            state.tri[key] = target.dataset.val;
            const card = target.closest(".uf-tri");
            card.dataset.state = target.dataset.val;
            card.querySelectorAll(".uf-seg-btn").forEach(button => {
                const on = button === target;
                button.classList.toggle("active", on);
                button.setAttribute("aria-pressed", String(on));
            });
            commit(true);
        } else if (action === "group-mode") {
            state.membership.mode = target.dataset.val;
            const seg = target.closest(".uf-seg");
            seg.dataset.state = target.dataset.val;
            seg.querySelectorAll(".uf-seg-btn").forEach(button => button.classList.toggle("active", button === target));
            commit(state.membership.include.length > 1);
        } else if (action === "chip-remove") {
            const list = target.dataset.list;
            state.membership[list].splice(Number(target.dataset.index), 1);
            root.querySelector(`.uf-chip-host[data-list="${list}"]`).innerHTML = chipsHtml(list);
            root.querySelector(`[data-list-card="${list}"]`).classList.toggle("is-active", state.membership[list].length > 0);
            commit(true);
        } else if (action === "item-clear") {
            const item = items[Number(target.dataset.index)];
            if (!item) return;
            item.clear();
            renderPanels();
            commit(true);
        } else if (action === "text-add") {
            const rule = state.text[key];
            const input = target.closest(".uf-field").querySelector('[data-uf="text-val"]');
            const value = input.value.trim();
            if (!value || rule.op === "empty" || rule.op === "filled") return;
            if (!Array.isArray(rule.values)) rule.values = [];
            if (!rule.values.some(entry => entry.toLowerCase() === value.toLowerCase())) {
                rule.values.push(value);
            }
            rule.value = "";
            renderPanels();
            commit(true);
        } else if (action === "text-remove") {
            const rule = state.text[key];
            if (Array.isArray(rule.values)) rule.values.splice(Number(target.dataset.index), 1);
            renderPanels();
            commit(true);
        } else if (action === "rule-add") {
            state.rules.push({ field: "", op: "contains", value: "" });
            panels.querySelector(".uf-rules").innerHTML = rulesHtml();
            const fields = panels.querySelectorAll('[data-uf="rule-field"]');
            if (fields.length) fields[fields.length - 1].focus();
            refreshMeta();
        } else if (action === "rule-remove") {
            const [removed] = state.rules.splice(Number(target.dataset.index), 1);
            panels.querySelector(".uf-rules").innerHTML = rulesHtml();
            commit(removed ? ufRuleReady(removed) : false);
        } else if (action === "sort-dir") {
            state.sort.dir = state.sort.dir === "asc" ? "desc" : "asc";
            commit(true);
        }
    });

    root.addEventListener("input", event => {
        const target = event.target;
        const action = target.dataset && target.dataset.uf;
        if (!action) return;
        const key = target.dataset.key;
        if (action === "text-val") {
            if (!Array.isArray(state.text[key].values)) state.text[key].value = target.value;
            target.closest(".uf-field").classList.toggle("is-active", ufTextActive(state.text[key]));
        } else if (action === "date") {
            state.date[key][target.dataset.part] = target.value;
            target.closest(".uf-card").classList.toggle("is-active", ufDateActive(state.date[key]));
        } else if (action === "num") {
            state.num[key][target.dataset.part] = target.value;
            target.closest(".uf-card").classList.toggle("is-active", ufNumActive(state.num[key]));
        } else if (action === "rule-field" || action === "rule-value") {
            const rule = state.rules[Number(target.dataset.index)];
            rule[action === "rule-field" ? "field" : "value"] = target.value;
            target.closest(".uf-rule").classList.toggle("is-active", ufRuleReady(rule));
        } else {
            return;
        }
        commit(false);
    });

    root.addEventListener("change", event => {
        const target = event.target;
        const action = target.dataset && target.dataset.uf;
        if (action === "text-op") {
            const rule = state.text[target.dataset.key];
            rule.op = target.value;
            if (rule.op === "empty" || rule.op === "filled") {
                if (Array.isArray(rule.values)) rule.values = [];
                rule.value = "";
            }
            const input = target.parentElement.querySelector("input");
            const valueless = rule.op === "empty" || rule.op === "filled";
            input.disabled = valueless;
            input.placeholder = valueless ? "Not required" : (textMap[target.dataset.key].placeholder || "");
            target.closest(".uf-field").classList.toggle("is-active", ufTextActive(rule));
            if (config.multiTextFields && config.multiTextFields.includes(target.dataset.key)) renderPanels();
            commit(true);
        } else if (action === "rule-op") {
            const rule = state.rules[Number(target.dataset.index)];
            rule.op = target.value;
            const input = target.closest(".uf-rule").querySelector('[data-uf="rule-value"]');
            const valueless = UF_VALUELESS_OPS.includes(rule.op);
            input.disabled = valueless;
            input.placeholder = valueless ? "Not required" : "Value";
            target.closest(".uf-rule").classList.toggle("is-active", ufRuleReady(rule));
            commit(true);
        } else if (action === "sort-field") {
            state.sort.field = target.value;
            commit(true);
        }
    });

    root.addEventListener("keydown", event => {
        const target = event.target;
        if (target.dataset && target.dataset.uf === "text-val"
            && target.closest(".uf-field").querySelector('[data-uf="text-add"]')
            && event.key === "Enter") {
            event.preventDefault();
            target.closest(".uf-field").querySelector('[data-uf="text-add"]').click();
            return;
        }
        if (!target.dataset || target.dataset.uf !== "chip-input") return;
        const list = target.dataset.list;
        if (event.key === "Enter" || event.key === ",") {
            event.preventDefault();
            addChip(list, target);
        } else if (event.key === "Backspace" && !target.value && state.membership[list].length) {
            state.membership[list].pop();
            root.querySelector(`.uf-chip-host[data-list="${list}"]`).innerHTML = chipsHtml(list);
            root.querySelector(`[data-list-card="${list}"]`).classList.toggle("is-active", state.membership[list].length > 0);
            commit(true);
        }
    });

    root.addEventListener("focusout", event => {
        const target = event.target;
        if (target.dataset && target.dataset.uf === "chip-input" && target.value.trim()) addChip(target.dataset.list, target);
    });

    function matches(entity) {
        for (const field of config.textFields) {
            const rule = state.text[field.key];
            if (ufTextActive(rule) && !ufTextValues(rule).every(value => ufTextMatch(rule.op, field.get(entity), value))) return false;
        }
        for (const field of config.triFields) {
            const value = state.tri[field.key];
            if (value === "any") continue;
            if (!!field.get(entity) !== (value === "yes")) return false;
        }
        for (const field of config.dateFields) {
            const rule = state.date[field.key];
            if (ufDateActive(rule) && !ufDateMatch(field.get(entity), rule)) return false;
        }
        for (const field of config.numFields) {
            const rule = state.num[field.key];
            if (ufNumActive(rule) && !ufNumMatch(field.get(entity), rule)) return false;
        }
        if (config.membership) {
            const include = state.membership.include;
            const exclude = state.membership.exclude;
            if (include.length || exclude.length) {
                const memberships = (config.membership.getList(entity) || []).map(item => String(item).toLowerCase());
                const hit = term => memberships.some(item => item.includes(term.toLowerCase()));
                if (include.length && !(state.membership.mode === "all" ? include.every(hit) : include.some(hit))) return false;
                if (exclude.some(hit)) return false;
            }
        }
        for (const rule of state.rules) {
            if (ufRuleReady(rule) && !ufRuleMatch(entity, rule)) return false;
        }
        return true;
    }

    function apply(records) {
        return items.length ? records.filter(matches) : records.slice();
    }

    function sort(records) {
        const field = sortFields.find(entry => entry.key === state.sort.field);
        if (!field || !field.key) return records;
        const factor = state.sort.dir === "asc" ? 1 : -1;
        return records.map((record, index) => ({ record, index, value: field.get(record) }))
            .sort((a, b) => {
                const aEmpty = a.value === null || a.value === undefined || a.value === "";
                const bEmpty = b.value === null || b.value === undefined || b.value === "";
                if (aEmpty && bEmpty) return a.index - b.index;
                if (aEmpty) return 1;
                if (bEmpty) return -1;
                if (a.value === b.value) return a.index - b.index;
                if (field.type === "text") return a.value.localeCompare(b.value) * factor;
                return (a.value - b.value) * factor;
            })
            .map(entry => entry.record);
    }

    function registerKeys(records) {
        const before = keys.size;
        records.slice(0, 300).forEach(record => {
            if (record && typeof record === "object") Object.keys(record).forEach(key => keys.add(key));
        });
        if (keys.size !== before) refreshKeys();
    }

    function setCounts(shown, total) {
        resultEl.innerHTML = (shown === null || shown === undefined)
            ? ""
            : `<strong>${fmtNumber(shown)}</strong> of <strong>${fmtNumber(total)}</strong> records match`;
    }

    renderPanels();
    refreshKeys();
    refreshMeta();

    return {
        serverSide: !!config.serverSide,
        getServerFilters: () => state,
        needsClientMode: () => !config.serverSide && (items.length > 0 || !!state.sort.field),
        apply,
        sort,
        registerKeys,
        setCounts
    };
}

/* ------------------------------------------------------------------ */
/* Per-kind field configurations                                       */
/* ------------------------------------------------------------------ */

const USERS_PRESETS = [
    { id: "active-admins", label: "Active admins", apply: s => { s.tri.enabled = "yes"; s.tri.tier0 = "yes"; } },
    { id: "disabled-privileged", label: "Disabled privileged", apply: s => { s.tri.enabled = "no"; s.tri.tier0 = "yes"; } },
    { id: "roastable", label: "Roastable accounts", apply: s => { s.tri.enabled = "yes"; s.tri.roastable = "yes"; } },
    { id: "delegation", label: "Delegation enabled", apply: s => { s.tri.any_delegation = "yes"; } },
    { id: "pwd-never", label: "Password never expires", apply: s => { s.tri.enabled = "yes"; s.tri.pwd_never_expires = "yes"; } },
    { id: "pwd-not-required", label: "Password not required", apply: s => { s.tri.pwd_not_required = "yes"; } },
    { id: "stale-pwd", label: "Password older than 1 year", apply: s => { s.tri.enabled = "yes"; s.date.pwd_last_set.older = "365"; } },
    { id: "inactive", label: "Inactive 90+ days", apply: s => { s.tri.enabled = "yes"; s.date.last_logon.older = "90"; } },
    { id: "never-logged", label: "Never logged on", apply: s => { s.tri.never_logged_on = "yes"; } },
    { id: "locked", label: "Locked out", apply: s => { s.tri.locked_out = "yes"; } },
    { id: "recent", label: "Created last 30 days", apply: s => { s.date.when_created.within = "30"; } }
];

const USERS_FILTER_CONFIG = {
    subtitle: "Narrow down users by any attribute, flag, date or group",
    presets: USERS_PRESETS,
    textFields: [
        { key: "username", label: "Username", placeholder: "e.g. jsmith", get: u => u.username },
        { key: "display_name", label: "Display Name", placeholder: "e.g. John Smith", get: u => u.display_name },
        { key: "upn", label: "User Principal Name", placeholder: "e.g. jsmith@corp.local", get: u => u.upn },
        { key: "description", label: "Description", placeholder: "e.g. service account", get: u => u.description },
        { key: "mail", label: "Email", placeholder: "e.g. @corp.local", get: u => u.mail },
        { key: "phone", label: "Phone", placeholder: "e.g. +1 555", get: u => u.phone },
        { key: "department", label: "Department", placeholder: "e.g. Finance", get: u => u.department },
        { key: "title", label: "Job Title", placeholder: "e.g. Engineer", get: u => u.title },
        { key: "dn", label: "Distinguished Name", placeholder: "e.g. OU=Finance", get: u => u.dn },
        { key: "sid", label: "SID", placeholder: "e.g. S-1-5-21", get: u => u.sid },
        { key: "primary_group_id", label: "Primary Group ID", placeholder: "e.g. 513", get: u => u.primary_group_id },
        { key: "domain_sid", label: "Domain SID", placeholder: "e.g. S-1-5-21", get: u => u.domain_sid },
        { key: "admin_description", label: "Admin Description", placeholder: "e.g. Domain Admins", get: u => u.admin_description },
        { key: "admin_evidence", label: "Admin Evidence", placeholder: "e.g. nested membership", get: u => u.admin_evidence }
    ],
    triFields: [
        { key: "enabled", label: "Account Enabled", tone: "ok", get: u => !isDisabledUser(u) },
        { key: "locked_out", label: "Locked Out", tone: "danger", get: u => !!u.locked_out },
        { key: "never_logged_on", label: "Never Logged On", tone: "warn", get: u => ufTime(u.last_logon) === null },
        { key: "account_never_expires", label: "Account Never Expires", tone: "info", get: u => !!u.account_never_expires },
        { key: "pwd_never_expires", label: "Password Never Expires", tone: "warn", get: u => !!u.pwd_never_expires },
        { key: "pwd_not_required", label: "Password Not Required", tone: "danger", get: u => !!u.pwd_not_required },
        { key: "must_change_pwd", label: "Must Change Password", tone: "info", get: u => !!u.must_change_pwd },
        { key: "smartcard_required", label: "Smartcard Required", tone: "ok", get: u => !!u.smartcard_required },
        { key: "has_description", label: "Has Description", tone: "info", get: u => ufHasText(u.description) },
        { key: "has_mail", label: "Has Email", tone: "info", get: u => ufHasText(u.mail) },
        { key: "has_phone", label: "Has Phone", tone: "info", get: u => ufHasText(u.phone) },
        { key: "has_department", label: "Has Department", tone: "info", get: u => ufHasText(u.department) },
        { key: "has_title", label: "Has Job Title", tone: "info", get: u => ufHasText(u.title) },
        { key: "tier0", label: "Tier-0 Admin", tone: "danger", get: u => !!u.absolute_admin || !!u.nested_admin },
        { key: "absolute_admin", label: "Absolute Admin", tone: "danger", get: u => !!u.absolute_admin },
        { key: "nested_admin", label: "Nested Admin", tone: "danger", get: u => !!u.nested_admin },
        { key: "potential_admin", label: "Potential Admin", tone: "warn", get: u => !!u.potential_admin },
        { key: "dcsync", label: "DCSync Rights", tone: "danger", get: u => !!u.dcsync },
        { key: "has_admin_description", label: "Has Admin Description", tone: "info", get: u => ufHasText(u.admin_description) },
        { key: "roastable", label: "Roastable (Any)", tone: "info", get: u => !!u.kerberoastable || !!u.asrep },
        { key: "kerberoastable", label: "Kerberoastable", tone: "info", get: u => !!u.kerberoastable },
        { key: "asrep", label: "AS-REP Roastable", tone: "info", get: u => !!u.asrep },
        { key: "any_delegation", label: "Any Delegation", tone: "warn", get: u => !!u.unconstrained_delegation || !!u.constrained_delegation },
        { key: "unconstrained_delegation", label: "Unconstrained Delegation", tone: "danger", get: u => !!u.unconstrained_delegation },
        { key: "constrained_delegation", label: "Constrained Delegation", tone: "warn", get: u => !!u.constrained_delegation }
    ],
    dateFields: [
        { key: "when_created", label: "Created", get: u => ufTime(u.when_created) },
        { key: "when_changed", label: "Last Changed", get: u => ufTime(u.when_changed) },
        { key: "last_logon", label: "Last Logon", get: u => ufTime(u.last_logon) },
        { key: "pwd_last_set", label: "Password Last Set", get: u => ufTime(u.pwd_last_set) },
        { key: "account_expires", label: "Account Expires", get: u => u.account_never_expires ? null : ufTime(u.account_expires) }
    ],
    numFields: [
        { key: "logon_count", label: "Logon Count", get: u => ufNum(u.logon_count) },
        { key: "bad_pwd_count", label: "Bad Password Count", get: u => ufNum(u.bad_pwd_count) },
        { key: "group_count", label: "Group Memberships", get: u => Array.isArray(u.member_of) ? u.member_of.length : 0 }
    ],
    sortFields: [
        { key: "username", label: "Username", type: "text", get: u => String(u.username || u.display_name || "").toLowerCase() },
        { key: "display_name", label: "Display Name", type: "text", get: u => String(u.display_name || "").toLowerCase() },
        { key: "department", label: "Department", type: "text", get: u => String(u.department || "").toLowerCase() },
        { key: "last_logon", label: "Last Logon", type: "num", get: u => ufTime(u.last_logon) },
        { key: "pwd_last_set", label: "Password Last Set", type: "num", get: u => ufTime(u.pwd_last_set) },
        { key: "when_created", label: "Created", type: "num", get: u => ufTime(u.when_created) },
        { key: "when_changed", label: "Last Changed", type: "num", get: u => ufTime(u.when_changed) },
        { key: "logon_count", label: "Logon Count", type: "num", get: u => { const n = ufNum(u.logon_count); return Number.isFinite(n) ? n : null; } },
        { key: "bad_pwd_count", label: "Bad Password Count", type: "num", get: u => { const n = ufNum(u.bad_pwd_count); return Number.isFinite(n) ? n : null; } },
        { key: "group_count", label: "Group Memberships", type: "num", get: u => Array.isArray(u.member_of) ? u.member_of.length : 0 }
    ],
    tabs: [
        { key: "identity", label: "Identity", icon: "user" },
        { key: "status", label: "Account", icon: "status" },
        { key: "security", label: "Security", icon: "shield" },
        { key: "activity", label: "Activity", icon: "clock" }
    ],
    layout: {
        identity: [
            { title: "Account Names", kind: "text", keys: ["username", "display_name", "upn", "description"] },
            { title: "Contact", kind: "text", keys: ["mail", "phone"] },
            { title: "Organization", kind: "text", keys: ["department", "title", "dn"] },
            { title: "Directory Identifiers", kind: "text", keys: ["sid", "primary_group_id", "domain_sid"] },
            { title: "Profile Completeness", kind: "tri", keys: ["has_description", "has_mail", "has_phone", "has_department", "has_title"] }
        ],
        status: [
            { title: "Account State", kind: "tri", keys: ["enabled", "locked_out", "never_logged_on", "account_never_expires"] },
            { title: "Password Policy", kind: "tri", keys: ["pwd_never_expires", "pwd_not_required", "must_change_pwd", "smartcard_required"] }
        ],
        security: [
            { title: "Administrative Rights", kind: "tri", keys: ["tier0", "absolute_admin", "nested_admin", "potential_admin", "dcsync", "has_admin_description"] },
            { title: "Roasting Exposure", kind: "tri", keys: ["roastable", "kerberoastable", "asrep"] },
            { title: "Delegation", kind: "tri", keys: ["any_delegation", "unconstrained_delegation", "constrained_delegation"] },
            { title: "Admin Analysis", kind: "text", keys: ["admin_description", "admin_evidence"] }
        ],
        activity: [
            { title: "Timeline", kind: "date", keys: ["last_logon", "pwd_last_set", "when_created", "when_changed", "account_expires"] },
            { title: "Counters", kind: "num", keys: ["logon_count", "bad_pwd_count"] }
        ]
    },
    membership: {
        tabLabel: "Groups",
        sectionTitle: "Group Membership",
        includeLabel: "Member of",
        excludeLabel: "Not member of",
        includeHint: "Press Enter or comma to add. Matches group names and distinguished names.",
        excludeHint: "Users belonging to any of these groups are hidden.",
        placeholder: "Type a group name and press Enter",
        getList: u => Array.isArray(u.member_of) ? u.member_of : [],
        numField: { key: "group_count", label: "Group Memberships" }
    },
    knownKeys: [
        "username", "display_name", "dn", "upn", "sid", "mail", "phone", "department", "title", "description",
        "primary_group_id", "domain_sid", "admin_description", "admin_evidence", "uac", "disabled",
        "when_created", "when_changed", "last_logon", "logon_count", "pwd_last_set", "bad_pwd_count",
        "account_expires", "account_never_expires", "member_of", "absolute_admin", "nested_admin",
        "potential_admin", "kerberoastable", "asrep", "unconstrained_delegation", "constrained_delegation",
        "pwd_never_expires", "pwd_not_required", "must_change_pwd", "locked_out", "smartcard_required", "dcsync"
    ]
};

const GROUPS_FILTER_CONFIG = {
    subtitle: "Narrow down groups by any attribute, flag, date or membership",
    presets: [],
    textFields: [
        { key: "group_name", label: "Group Name", placeholder: "e.g. Domain Admins", get: g => g.group_name },
        { key: "group_dn", label: "Distinguished Name", placeholder: "e.g. CN=Domain Admins", get: g => g.group_dn },
        { key: "description", label: "Description", placeholder: "e.g. built-in group", get: g => g.description },
        { key: "info", label: "Notes", placeholder: "e.g. info field", get: g => g.info },
        { key: "managed_by", label: "Managed By", placeholder: "e.g. CN=IT Admins", get: g => g.managed_by },
        { key: "admin_description", label: "Admin Description", placeholder: "e.g. Tier-0 evidence", get: g => g.admin_description },
        { key: "admin_evidence", label: "Admin Evidence", placeholder: "e.g. nested membership", get: g => g.admin_evidence },
        { key: "group_sid", label: "Group SID", placeholder: "e.g. S-1-5-21", get: g => g.group_sid },
        { key: "domainsid", label: "Domain SID", placeholder: "e.g. S-1-5-21", get: g => g.domainsid }
    ],
    triFields: [
        { key: "is_privileged", label: "Privileged", tone: "danger", get: g => !!g.is_privileged },
        { key: "absolute_admin", label: "Absolute Admin", tone: "danger", get: g => !!g.absolute_admin },
        { key: "nested_admin", label: "Nested Admin", tone: "danger", get: g => !!g.nested_admin },
        { key: "potential_admin", label: "Potential Admin", tone: "warn", get: g => !!g.potential_admin },
        { key: "admin_count", label: "Admin Count", tone: "warn", get: g => !!g.admin_count },
        { key: "is_protected", label: "Protected", tone: "info", get: g => !!g.is_protected },
        { key: "isaclprotected", label: "ACL Protected", tone: "info", get: g => !!g.isaclprotected },
        { key: "is_critical_system_object", label: "Critical System Object", tone: "info", get: g => !!g.is_critical_system_object },
        { key: "security_enabled", label: "Security Enabled", tone: "ok", get: g => !!g.security_enabled },
        { key: "is_nested", label: "Nested Group", tone: "info", get: g => !!g.is_nested },
        { key: "is_empty", label: "Empty", tone: "info", get: g => !!g.is_empty },
        { key: "has_description", label: "Has Description", tone: "info", get: g => ufHasText(g.description) },
        { key: "has_managed_by", label: "Has Managed By", tone: "info", get: g => ufHasText(g.managed_by) }
    ],
    dateFields: [
        { key: "when_created", label: "Created", get: g => ufTime(g.when_created) },
        { key: "when_changed", label: "Last Changed", get: g => ufTime(g.when_changed) }
    ],
    numFields: [
        { key: "member_count", label: "Member Count", get: g => ufNum(g.member_count) },
        { key: "rid", label: "RID", get: g => ufNum(g.rid) },
        { key: "primary_group_token", label: "Primary Group Token", get: g => ufNum(g.primary_group_token) }
    ],
    sortFields: [
        { key: "group_name", label: "Group Name", type: "text", get: g => String(g.group_name || "").toLowerCase() },
        { key: "member_count", label: "Member Count", type: "num", get: g => { const n = ufNum(g.member_count); return Number.isFinite(n) ? n : null; } },
        { key: "when_created", label: "Created", type: "num", get: g => ufTime(g.when_created) },
        { key: "when_changed", label: "Last Changed", type: "num", get: g => ufTime(g.when_changed) },
        { key: "rid", label: "RID", type: "num", get: g => { const n = ufNum(g.rid); return Number.isFinite(n) ? n : null; } }
    ],
    tabs: [
        { key: "identity", label: "Identity", icon: "user" },
        { key: "security", label: "Security", icon: "shield" },
        { key: "activity", label: "Activity", icon: "clock" }
    ],
    layout: {
        identity: [
            { title: "Group Names", kind: "text", keys: ["group_name", "group_dn"] },
            { title: "Description & Notes", kind: "text", keys: ["description", "info"] },
            { title: "Administration", kind: "text", keys: ["managed_by", "admin_description", "admin_evidence"] },
            { title: "Identifiers", kind: "text", keys: ["group_sid", "domainsid"] },
            { title: "Profile Completeness", kind: "tri", keys: ["has_description", "has_managed_by"] }
        ],
        security: [
            { title: "Administrative Rights", kind: "tri", keys: ["is_privileged", "absolute_admin", "nested_admin", "potential_admin", "admin_count"] },
            { title: "Protection & Type", kind: "tri", keys: ["is_protected", "isaclprotected", "is_critical_system_object", "security_enabled", "is_nested", "is_empty"] }
        ],
        activity: [
            { title: "Timeline", kind: "date", keys: ["when_created", "when_changed"] },
            { title: "Counters", kind: "num", keys: ["member_count", "rid", "primary_group_token"] }
        ]
    },
    membership: {
        tabLabel: "Membership",
        sectionTitle: "Nested Group Membership",
        includeLabel: "Member of",
        excludeLabel: "Not member of",
        includeHint: "Press Enter or comma to add. Matches group names and distinguished names this group belongs to.",
        excludeHint: "Groups belonging to any of these groups are hidden.",
        placeholder: "Type a group name and press Enter",
        getList: g => Array.isArray(g.member_of) ? g.member_of : [],
        numField: { key: "member_count", label: "Member Count" }
    },
    knownKeys: [
        "group_name", "group_dn", "group_sid", "domainsid", "description", "info", "managed_by",
        "admin_description", "admin_evidence", "rid", "primary_group_token", "group_type", "member_count",
        "member_of", "members", "is_privileged", "absolute_admin", "nested_admin", "potential_admin",
        "admin_count", "is_protected", "isaclprotected", "is_critical_system_object", "security_enabled",
        "is_nested", "is_empty", "when_created", "when_changed"
    ]
};

const COMPUTERS_FILTER_CONFIG = {
    subtitle: "Narrow down computers by any attribute, flag, date or counter",
    presets: [],
    textFields: [
        { key: "computer_name", label: "Computer Name", placeholder: "e.g. SRV-01", get: c => c.computer_name },
        { key: "dns_name", label: "DNS Name", placeholder: "e.g. srv-01.corp.local", get: c => c.dns_name },
        { key: "display_name", label: "Display Name", placeholder: "e.g. SRV-01$", get: c => c.display_name },
        { key: "sid", label: "SID", placeholder: "e.g. S-1-5-21", get: c => c.sid },
        { key: "os", label: "Operating System", placeholder: "e.g. Windows Server 2022", get: c => c.os },
        { key: "os_version", label: "OS Version", placeholder: "e.g. 10.0.20348", get: c => c.os_version },
        { key: "os_service_pack", label: "Service Pack", placeholder: "e.g. SP1", get: c => c.os_service_pack },
        { key: "location", label: "Location", placeholder: "e.g. Datacenter 1", get: c => c.location },
        { key: "domain_name", label: "Domain", placeholder: "e.g. corp.local", get: c => c.domain_name },
        { key: "domainsid", label: "Domain SID", placeholder: "e.g. S-1-5-21", get: c => c.domainsid },
        { key: "description", label: "Description", placeholder: "e.g. file server", get: c => c.description },
        { key: "admin_description", label: "Admin Description", placeholder: "e.g. Tier-0 evidence", get: c => c.admin_description },
        { key: "admin_evidence", label: "Admin Evidence", placeholder: "e.g. nested membership", get: c => c.admin_evidence },
        { key: "smb_version", label: "SMB Version", placeholder: "e.g. 3.1.1", get: c => c.smb_version }
    ],
    triFields: [
        { key: "enabled", label: "Account Enabled", tone: "ok", get: c => !c.disabled },
        { key: "is_domain_controller", label: "Domain Controller", tone: "danger", get: c => !!c.is_domain_controller },
        { key: "is_server", label: "Server", tone: "info", get: c => !!c.is_server },
        { key: "is_workstation", label: "Workstation", tone: "info", get: c => !!c.is_workstation },
        { key: "is_stale", label: "Stale", tone: "warn", get: c => !!c.is_stale },
        { key: "smb_port_open", label: "SMB Port Open", tone: "info", get: c => !!c.smb_port_open },
        { key: "smb_signing_required", label: "SMB Signing Required", tone: "ok", get: c => !!c.smb_signing_required },
        { key: "has_laps", label: "LAPS", tone: "ok", get: c => !!c.has_laps || !!c.haslaps },
        { key: "absolute_admin", label: "Absolute Admin", tone: "danger", get: c => !!c.absolute_admin },
        { key: "nested_admin", label: "Nested Admin", tone: "danger", get: c => !!c.nested_admin },
        { key: "potential_admin", label: "Potential Admin", tone: "warn", get: c => !!c.potential_admin },
        { key: "potential_privileged", label: "Potential Privileged", tone: "warn", get: c => !!c.potential_privileged },
        { key: "unconstrained_delegation", label: "Unconstrained Delegation", tone: "danger", get: c => !!c.unconstrained_delegation },
        { key: "constrained_delegation", label: "Constrained Delegation", tone: "warn", get: c => !!c.constrained_delegation },
        { key: "protocol_transition_delegation", label: "Protocol Transition", tone: "warn", get: c => !!c.protocol_transition_delegation },
        { key: "trusted_for_delegation", label: "Trusted For Delegation", tone: "warn", get: c => !!c.trusted_for_delegation },
        { key: "rbcd_enabled", label: "RBCD Enabled", tone: "danger", get: c => !!c.rbcd_enabled },
        { key: "kerberoastable", label: "Kerberoastable", tone: "info", get: c => !!c.kerberoastable },
        { key: "asrep", label: "AS-REP Roastable", tone: "info", get: c => !!c.asrep },
        { key: "has_shadow_credential", label: "Shadow Credential", tone: "danger", get: c => !!c.has_shadow_credential },
        { key: "has_spn", label: "Has SPN", tone: "info", get: c => !!c.has_spn },
        { key: "isaclprotected", label: "ACL Protected", tone: "info", get: c => !!c.isaclprotected }
    ],
    dateFields: [
        { key: "when_created", label: "Created", get: c => ufTime(c.when_created) },
        { key: "when_changed", label: "Last Changed", get: c => ufTime(c.when_changed) },
        { key: "last_logon", label: "Last Logon", get: c => ufTime(c.last_logon) },
        { key: "pwd_last_set", label: "Password Last Set", get: c => ufTime(c.pwd_last_set) },
        { key: "laps_expiration", label: "LAPS Expiration", get: c => ufTime(c.laps_expiration) }
    ],
    numFields: [
        { key: "risk_score", label: "Risk Score", get: c => ufNum(c.risk_score) },
        { key: "primary_group_id", label: "Primary Group ID", get: c => ufNum(c.primary_group_id) }
    ],
    sortFields: [
        { key: "computer_name", label: "Computer Name", type: "text", get: c => String(c.computer_name || "").toLowerCase() },
        { key: "os", label: "Operating System", type: "text", get: c => String(c.os || "").toLowerCase() },
        { key: "last_logon", label: "Last Logon", type: "num", get: c => ufTime(c.last_logon) },
        { key: "risk_score", label: "Risk Score", type: "num", get: c => { const n = ufNum(c.risk_score); return Number.isFinite(n) ? n : null; } },
        { key: "when_created", label: "Created", type: "num", get: c => ufTime(c.when_created) }
    ],
    tabs: [
        { key: "identity", label: "Identity", icon: "user" },
        { key: "status", label: "Account", icon: "status" },
        { key: "security", label: "Security", icon: "shield" },
        { key: "activity", label: "Activity", icon: "clock" }
    ],
    layout: {
        identity: [
            { title: "Computer Names", kind: "text", keys: ["computer_name", "dns_name", "display_name"] },
            { title: "Location & Domain", kind: "text", keys: ["location", "domain_name", "domainsid"] },
            { title: "Operating System", kind: "text", keys: ["os", "os_version", "os_service_pack"] },
            { title: "Identifiers & Description", kind: "text", keys: ["sid", "smb_version", "description", "admin_description", "admin_evidence"] }
        ],
        status: [
            { title: "Role", kind: "tri", keys: ["enabled", "is_domain_controller", "is_server", "is_workstation"] },
            { title: "Health & SMB", kind: "tri", keys: ["is_stale", "smb_port_open", "smb_signing_required", "has_laps"] }
        ],
        security: [
            { title: "Administrative Rights", kind: "tri", keys: ["absolute_admin", "nested_admin", "potential_admin", "potential_privileged"] },
            { title: "Delegation", kind: "tri", keys: ["unconstrained_delegation", "constrained_delegation", "protocol_transition_delegation", "trusted_for_delegation", "rbcd_enabled"] },
            { title: "Exposure", kind: "tri", keys: ["kerberoastable", "asrep", "has_shadow_credential", "has_spn", "isaclprotected"] }
        ],
        activity: [
            { title: "Timeline", kind: "date", keys: ["when_created", "when_changed", "last_logon", "pwd_last_set", "laps_expiration"] },
            { title: "Counters", kind: "num", keys: ["risk_score", "primary_group_id"] }
        ]
    },
    knownKeys: [
        "computer_name", "dns_name", "display_name", "sid", "os", "os_version", "os_service_pack", "location",
        "domain_name", "domainsid", "description", "admin_description", "admin_evidence", "smb_version",
        "risk_score", "primary_group_id", "when_created", "when_changed", "last_logon", "pwd_last_set",
        "laps_expiration", "disabled", "is_domain_controller", "is_server", "is_workstation", "is_stale",
        "smb_port_open", "smb_signing_required", "has_laps", "haslaps", "absolute_admin", "nested_admin",
        "potential_admin", "potential_privileged", "unconstrained_delegation", "constrained_delegation",
        "protocol_transition_delegation", "trusted_for_delegation", "rbcd_enabled", "kerberoastable", "asrep",
        "has_shadow_credential", "has_spn", "isaclprotected", "ipv4_addresses", "ipv6_addresses"
    ]
};

const GPOS_FILTER_CONFIG = {
    subtitle: "Narrow down GPOs by any attribute, flag, date or counter",
    presets: [],
    textFields: [
        { key: "name", label: "Name", placeholder: "e.g. {GUID}", get: g => g.name },
        { key: "display_name", label: "Display Name", placeholder: "e.g. Default Domain Policy", get: g => g.display_name },
        { key: "guid", label: "GUID", placeholder: "e.g. {31B2F340-...}", get: g => g.guid },
        { key: "domain", label: "Domain", placeholder: "e.g. corp.local", get: g => g.domain },
        { key: "domainsid", label: "Domain SID", placeholder: "e.g. S-1-5-21", get: g => g.domainsid },
        { key: "path", label: "SYSVOL Path", placeholder: "e.g. \\\\corp.local\\SysVol", get: g => g.path },
        { key: "owner_name", label: "Owner", placeholder: "e.g. Domain Admins", get: g => g.owner_name },
        { key: "owner_sid", label: "Owner SID", placeholder: "e.g. S-1-5-21", get: g => g.owner_sid },
        { key: "description", label: "Description", placeholder: "e.g. baseline policy", get: g => g.description },
        { key: "tier0_description", label: "Tier-0 Description", placeholder: "e.g. evidence", get: g => g.tier0_description },
        { key: "control_description", label: "Control Description", placeholder: "e.g. evidence", get: g => g.control_description }
    ],
    triFields: [
        { key: "tier0", label: "Tier-0", tone: "danger", get: g => !!g.tier0 },
        { key: "highvalue", label: "High Value", tone: "danger", get: g => !!g.highvalue },
        { key: "controlled_by_non_admin", label: "Controlled By Non-Admin", tone: "danger", get: g => !!g.controlled_by_non_admin },
        { key: "enforced", label: "Enforced", tone: "info", get: g => !!g.enforced },
        { key: "link_disabled", label: "Link Disabled", tone: "warn", get: g => !!g.link_disabled },
        { key: "inheritance_blocked", label: "Inheritance Blocked", tone: "warn", get: g => !!g.inheritance_blocked },
        { key: "user_settings_disabled", label: "User Settings Disabled", tone: "warn", get: g => !!g.user_settings_disabled },
        { key: "computer_settings_disabled", label: "Computer Settings Disabled", tone: "warn", get: g => !!g.computer_settings_disabled },
        { key: "isaclprotected", label: "ACL Protected", tone: "info", get: g => !!g.isaclprotected },
        { key: "is_critical_system_object", label: "Critical System Object", tone: "info", get: g => !!g.is_critical_system_object }
    ],
    dateFields: [
        { key: "created", label: "Created", get: g => ufTime(g.created) },
        { key: "modified", label: "Modified", get: g => ufTime(g.modified) }
    ],
    numFields: [
        { key: "linked_count", label: "Linked Objects", get: g => ufNum(g.linked_count) },
        { key: "version", label: "Version", get: g => ufNum(g.version) },
        { key: "user_version", label: "User Version", get: g => ufNum(g.user_version) },
        { key: "computer_version", label: "Computer Version", get: g => ufNum(g.computer_version) }
    ],
    sortFields: [
        { key: "display_name", label: "Policy Name", type: "text", get: g => String(g.display_name || g.name || "").toLowerCase() },
        { key: "linked_count", label: "Linked Objects", type: "num", get: g => { const n = ufNum(g.linked_count); return Number.isFinite(n) ? n : null; } },
        { key: "created", label: "Created", type: "num", get: g => ufTime(g.created) },
        { key: "modified", label: "Modified", type: "num", get: g => ufTime(g.modified) }
    ],
    tabs: [
        { key: "identity", label: "Identity", icon: "user" },
        { key: "status", label: "Links", icon: "status" },
        { key: "security", label: "Security", icon: "shield" },
        { key: "activity", label: "Activity", icon: "clock" }
    ],
    layout: {
        identity: [
            { title: "Policy Names", kind: "text", keys: ["name", "display_name", "guid"] },
            { title: "Ownership & Domain", kind: "text", keys: ["domain", "domainsid", "owner_name", "owner_sid", "path"] }
        ],
        status: [
            { title: "Link Status", kind: "tri", keys: ["enforced", "link_disabled", "inheritance_blocked"] },
            { title: "Settings", kind: "tri", keys: ["user_settings_disabled", "computer_settings_disabled"] }
        ],
        security: [
            { title: "Risk Flags", kind: "tri", keys: ["tier0", "highvalue", "controlled_by_non_admin"] },
            { title: "Protection", kind: "tri", keys: ["isaclprotected", "is_critical_system_object"] },
            { title: "Descriptions", kind: "text", keys: ["description", "tier0_description", "control_description"] }
        ],
        activity: [
            { title: "Timeline", kind: "date", keys: ["created", "modified"] },
            { title: "Counters", kind: "num", keys: ["linked_count", "version", "user_version", "computer_version"] }
        ]
    },
    knownKeys: [
        "name", "display_name", "guid", "domain", "domainsid", "path", "owner_name", "owner_sid",
        "description", "tier0_description", "tier0_evidence", "control_description", "linked_count",
        "version", "user_version", "computer_version", "flags", "created", "modified", "tier0", "highvalue",
        "enforced", "link_disabled", "inheritance_blocked", "controlled_by_non_admin", "user_settings_disabled",
        "computer_settings_disabled", "isaclprotected", "is_critical_system_object", "linked_containers", "controllers"
    ]
};

const ACES_FILTER_CONFIG = {
    serverSide: true,
    multiPreset: true,
    multiTextFields: [
        "target_name", "target_dn", "target_type", "target_sid",
        "principal_name", "principal_sid"
    ],
    subtitle: "Narrow down ACEs by any attribute or flag",
    presets: [
        { id: "dangerous", label: "Dangerous ACEs", apply: s => { s.tri.dangerous_ace = "yes"; } },
        { id: "extended", label: "Extended rights", apply: s => { s.tri.extended_rights = "yes"; } },
        { id: "orphaned", label: "Orphaned SID", apply: s => { s.tri.orphaned_sid = "yes"; } },
        { id: "deny", label: "Deny ACEs", apply: s => { s.tri.is_deny = "yes"; } }
    ],
    textFields: [
        { key: "target_name", label: "Target Name", placeholder: "e.g. Domain Admins", get: a => a.target_name },
        { key: "target_dn", label: "Target DN", placeholder: "e.g. CN=Domain Admins", get: a => a.target_dn },
        { key: "target_type", label: "Target Type", placeholder: "e.g. group, user", get: a => a.target_type },
        { key: "target_sid", label: "Target SID", placeholder: "e.g. S-1-5-21", get: a => a.target_sid },
        { key: "principal_name", label: "Principal Name", placeholder: "e.g. jsmith", get: a => a.principal_name },
        { key: "principal_sid", label: "Principal SID", placeholder: "e.g. S-1-5-21", get: a => a.principal_sid },
        { key: "principal_scope", label: "Principal Scope", placeholder: "e.g. user, group", get: a => a.principal_scope },
        { key: "rights", label: "Rights", placeholder: "e.g. GenericAll", get: a => rightsText(a.rights) },
        { key: "object_acetype", label: "Object ACE Type", placeholder: "e.g. WriteProperty", get: a => a.object_acetype }
    ],
    triFields: [
        { key: "dangerous_ace", label: "Dangerous ACE", tone: "danger", get: a => !!a.dangerous_ace },
        { key: "extended_rights", label: "Extended Rights", tone: "info", get: a => !!a.extended_rights },
        {
            key: "orphaned_sid",
            label: "Orphaned SID",
            tone: "warn",
            get: a => ufHasText(a.principal_name) && ufHasText(a.target_name)
        },
        { key: "is_deny", label: "Deny ACE", tone: "warn", get: a => !!a.is_deny },
        { key: "inherited", label: "Inherited", tone: "info", get: a => (Number(a.ace_flags) & 0x10) === 0x10 },
        { key: "has_target_dn", label: "Has Target DN", tone: "info", get: a => ufHasText(a.target_dn) },
        { key: "has_principal_name", label: "Has Principal Name", tone: "info", get: a => ufHasText(a.principal_name) }
    ],
    dateFields: [],
    numFields: [
        { key: "ace_count", label: "ACE Count", get: a => ufNum(a.ace_count) },
        { key: "ace_type_raw", label: "ACE Type Code", get: a => ufNum(a.ace_type_raw) },
        { key: "ace_flags", label: "ACE Flags Value", get: a => ufNum(a.ace_flags) }
    ],
    sortFields: [
        { key: "target_name", label: "Target Name", type: "text", get: a => String(a.target_name || "").toLowerCase() },
        { key: "principal_name", label: "Principal Name", type: "text", get: a => String(a.principal_name || a.principal_sid || "").toLowerCase() },
        { key: "ace_count", label: "ACE Count", type: "num", get: a => { const n = ufNum(a.ace_count); return Number.isFinite(n) ? n : null; } }
    ],
    tabs: [
        { key: "identity", label: "Identity", icon: "user" },
        { key: "security", label: "Security", icon: "shield" }
    ],
    layout: {
        identity: [
            { title: "Target", kind: "text", keys: ["target_name", "target_dn", "target_type", "target_sid"] },
            { title: "Principal", kind: "text", keys: ["principal_name", "principal_sid", "principal_scope"] },
            { title: "Profile Completeness", kind: "tri", keys: ["has_target_dn", "has_principal_name"] }
        ],
        security: [
            { title: "Rights", kind: "text", keys: ["rights", "object_acetype"] },
            { title: "ACE Flags", kind: "tri", keys: ["dangerous_ace", "extended_rights", "is_deny", "inherited"] },
            { title: "Counters", kind: "num", keys: ["ace_count", "ace_type_raw", "ace_flags"] }
        ]
    },
    knownKeys: [
        "target_name", "target_dn", "target_type", "target_sid", "principal_name", "principal_sid",
        "principal_scope", "rights", "ace_count", "ace_type_raw", "object_acetype", "ace_flags",
        "dangerous_ace", "extended_rights", "is_deny", "aces"
    ]
};

const TRUSTS_FILTER_CONFIG = {
    subtitle: "Narrow down trusts by any attribute or flag",
    presets: [
        { id: "dangerous", label: "Dangerous trusts", apply: s => { s.tri.dangerous = "yes"; } },
        { id: "no-sid-filtering", label: "No SID filtering", apply: s => { s.tri.sid_filtering_enabled = "no"; } },
        { id: "bidirectional", label: "Bidirectional", apply: s => { s.text.direction.op = "equals"; s.text.direction.value = "bidirectional"; } },
        { id: "forest", label: "Forest trusts", apply: s => { s.tri.forest = "yes"; } }
    ],
    textFields: [
        { key: "name", label: "Trust Name", placeholder: "e.g. corp.local", get: t => t.name },
        { key: "partner", label: "Partner", placeholder: "e.g. partner.local", get: t => t.partner },
        { key: "flat_name", label: "NetBIOS Name", placeholder: "e.g. PARTNER", get: t => t.flat_name },
        { key: "direction", label: "Direction", placeholder: "e.g. bidirectional", get: t => t.direction },
        { key: "trust_type", label: "Trust Type", placeholder: "e.g. uplevel", get: t => t.trust_type },
        { key: "sid", label: "Trusted Domain SID", placeholder: "e.g. S-1-5-21", get: t => t.sid },
        { key: "object_guid", label: "Object GUID", placeholder: "e.g. GUID", get: t => t.object_guid },
        { key: "dn", label: "Distinguished Name", placeholder: "e.g. CN=partner.local", get: t => t.dn }
    ],
    triFields: [
        { key: "dangerous", label: "Dangerous", tone: "danger", get: t => !!t.dangerous },
        { key: "sid_filtering_enabled", label: "SID Filtering", tone: "ok", get: t => !!t.sid_filtering_enabled },
        { key: "transitive", label: "Transitive", tone: "info", get: t => !!t.transitive },
        { key: "forest", label: "Forest Trust", tone: "info", get: t => !!t.forest },
        { key: "within_forest", label: "Within Forest", tone: "info", get: t => !!t.within_forest },
        { key: "inbound", label: "Inbound", tone: "info", get: t => !!t.inbound },
        { key: "outbound", label: "Outbound", tone: "info", get: t => !!t.outbound },
        { key: "tgt_delegation_enabled", label: "TGT Delegation", tone: "danger", get: t => !!t.tgt_delegation_enabled },
        { key: "forest_wide_auth", label: "Forest-Wide Auth", tone: "warn", get: t => !!t.forest_wide_auth },
        { key: "selective_auth", label: "Selective Auth", tone: "ok", get: t => !!t.selective_auth },
        { key: "treat_as_external", label: "Treat As External", tone: "warn", get: t => !!t.treat_as_external },
        { key: "uses_rc4_encryption", label: "Uses RC4", tone: "warn", get: t => !!t.uses_rc4_encryption },
        { key: "uses_aes_keys", label: "Uses AES Keys", tone: "ok", get: t => !!t.uses_aes_keys },
        { key: "pim_trust", label: "PIM Trust", tone: "info", get: t => !!t.pim_trust },
        { key: "uplevel_only", label: "Uplevel Only", tone: "info", get: t => !!t.uplevel_only }
    ],
    dateFields: [
        { key: "when_created", label: "Created", get: t => ufTime(t.when_created) },
        { key: "when_changed", label: "Last Changed", get: t => ufTime(t.when_changed) }
    ],
    numFields: [
        { key: "usn_created", label: "USN Created", get: t => ufNum(t.usn_created) },
        { key: "usn_changed", label: "USN Changed", get: t => ufNum(t.usn_changed) },
        { key: "trust_type_raw", label: "Trust Type Code", get: t => ufNum(t.trust_type_raw) },
        { key: "direction_raw", label: "Direction Code", get: t => ufNum(t.direction_raw) },
        { key: "attributes_raw", label: "Attributes Value", get: t => ufNum(t.attributes_raw) }
    ],
    sortFields: [
        { key: "name", label: "Trust Name", type: "text", get: t => String(t.name || t.partner || "").toLowerCase() },
        { key: "partner", label: "Partner", type: "text", get: t => String(t.partner || "").toLowerCase() },
        { key: "when_created", label: "Created", type: "num", get: t => ufTime(t.when_created) },
        { key: "when_changed", label: "Last Changed", type: "num", get: t => ufTime(t.when_changed) }
    ],
    tabs: [
        { key: "identity", label: "Identity", icon: "user" },
        { key: "security", label: "Security", icon: "shield" },
        { key: "activity", label: "Activity", icon: "clock" }
    ],
    layout: {
        identity: [
            { title: "Trust Names", kind: "text", keys: ["name", "partner", "flat_name"] },
            { title: "Type & Direction", kind: "text", keys: ["direction", "trust_type"] },
            { title: "Identifiers", kind: "text", keys: ["sid", "object_guid", "dn"] },
            { title: "Trust Scope", kind: "tri", keys: ["transitive", "forest", "within_forest", "inbound", "outbound"] }
        ],
        security: [
            { title: "Risk Flags", kind: "tri", keys: ["dangerous", "tgt_delegation_enabled", "forest_wide_auth", "treat_as_external", "uses_rc4_encryption"] },
            { title: "Protections", kind: "tri", keys: ["sid_filtering_enabled", "selective_auth", "uses_aes_keys", "pim_trust", "uplevel_only"] },
            { title: "Codes", kind: "num", keys: ["trust_type_raw", "direction_raw", "attributes_raw"] }
        ],
        activity: [
            { title: "Timeline", kind: "date", keys: ["when_created", "when_changed"] },
            { title: "Update Sequence", kind: "num", keys: ["usn_created", "usn_changed"] }
        ]
    },
    knownKeys: [
        "name", "partner", "flat_name", "direction", "trust_type", "sid", "object_guid", "dn",
        "dangerous", "sid_filtering_enabled", "transitive", "forest", "within_forest", "inbound", "outbound",
        "tgt_delegation_enabled", "forest_wide_auth", "selective_auth", "treat_as_external",
        "uses_rc4_encryption", "uses_aes_keys", "pim_trust", "uplevel_only", "when_created", "when_changed",
        "usn_created", "usn_changed", "trust_type_raw", "direction_raw", "attributes_raw",
        "attributes_decoded", "risk_controls", "security_posture", "supported_encryption_types", "forest_trust_info"
    ]
};

const FULL_FILTER_CONFIGS = {
    users: USERS_FILTER_CONFIG,
    groups: GROUPS_FILTER_CONFIG,
    computers: COMPUTERS_FILTER_CONFIG,
    gpos: GPOS_FILTER_CONFIG,
    aces: ACES_FILTER_CONFIG,
    trusts: TRUSTS_FILTER_CONFIG
};

Object.values(FULL_FILTER_CONFIGS).forEach(config => { config.serverSide = true; });

function createAceExceptionPanel(onChange) {
    const panel = document.createElement("div");
    panel.className = "uf-section ace-exception-panel";
    panel.innerHTML = `
        <div class="uf-section-title ace-exception-header">
            <span>Exceptions</span>
            <div class="ace-exception-actions">
                <button type="button" class="uf-btn ace-exception-optimize">Optimization</button>
                <button type="button" class="uf-btn uf-btn-accent ace-exception-add" aria-label="Add exception">+ Add</button>
            </div>
        </div>
        <div class="ace-exception-form" hidden>
            <input class="uf-input" type="text" placeholder="principal_name" aria-label="Principal name exception">
            <button type="button" class="uf-btn ace-exception-save">Add</button>
        </div>
        <div class="ace-exception-list"><span class="domain-muted">Loading...</span></div>`;
    const form = panel.querySelector(".ace-exception-form");
    const input = form.querySelector("input");
    const list = panel.querySelector(".ace-exception-list");
    let values = [];

    const render = () => {
        list.innerHTML = values.length
            ? values.map(value => `<span class="ace-exception-chip"><span>${esc(value.principal_name || value.principal_sid)}${value.principal_sid ? ` (${esc(value.principal_sid)})` : ""}</span><button type="button" data-exception="${esc(value.principal_name)}" aria-label="Remove exception">&times;</button></span>`).join("")
            : '<span class="domain-muted">No exceptions</span>';
    };
    const refresh = async () => {
        try {
            const result = await Api.getAceExceptions();
            if (!result.ok) throw new Error(result.error || "Could not load exceptions");
            values = Array.isArray(result.exceptions) ? result.exceptions : [];
            render();
        } catch (error) {
            list.innerHTML = `<span class="domain-muted">${esc(error.message || "Could not load exceptions")}</span>`;
        }
    };
    const save = async () => {
        const value = input.value.trim();
        if (!value) return;
        const result = await Api.addAceException(value);
        if (!result.ok) throw new Error(result.error || "Could not save exception");
        values = result.exceptions || values;
        input.value = "";
        render();
        onChange();
    };
    panel.querySelector(".ace-exception-add").addEventListener("click", () => {
        form.hidden = !form.hidden;
        if (!form.hidden) input.focus();
    });
    panel.querySelector(".ace-exception-optimize").addEventListener("click", async event => {
        const button = event.currentTarget;
        button.disabled = true;
        try {
            const result = await Api.optimizeAceExceptions();
            if (!result.ok) throw new Error(result.error || "Could not optimize exceptions");
            values = result.exceptions || values;
            render();
            onChange();
            if (result.unresolved && result.unresolved.length) {
                list.insertAdjacentHTML("beforeend", `<span class="domain-muted">Not found: ${esc(result.unresolved.join(", "))}</span>`);
            }
        } catch (error) {
            list.innerHTML = `<span class="domain-muted">${esc(error.message || "Could not optimize exceptions")}</span>`;
        } finally {
            button.disabled = false;
        }
    });
    panel.querySelector(".ace-exception-save").addEventListener("click", () => {
        save().catch(error => { list.innerHTML = `<span class="domain-muted">${esc(error.message)}</span>`; });
    });
    input.addEventListener("keydown", event => {
        if (event.key !== "Enter") return;
        event.preventDefault();
        panel.querySelector(".ace-exception-save").click();
    });
    list.addEventListener("click", event => {
        const button = event.target.closest("[data-exception]");
        if (!button) return;
        Api.deleteAceException(button.dataset.exception).then(result => {
            if (!result.ok) throw new Error(result.error || "Could not delete exception");
            values = result.exceptions || [];
            render();
            onChange();
        }).catch(error => { list.innerHTML = `<span class="domain-muted">${esc(error.message)}</span>`; });
    });
    refresh();
    return {
        element: panel,
        setVisible: visible => { panel.hidden = !visible; },
        getValues: () => values,
        addValue: async value => {
            input.value = String(value || "").trim();
            if (!input.value) throw new Error("This ACE has no principal name");
            await save();
        }
    };
}

window.initDomainResults = function() {
    const view = document.querySelector(".domain-result-view");
    if (!view || view.dataset.initialized) return;
    view.dataset.initialized = "true";
    const kind = view.dataset.domainKind;
    if (kind === "domain") {
        initDomainSummary(view);
        return;
    }
    if (kind === "certificates") {
        initCertSummary(view);
    }

    const schema = SCHEMAS[kind];
    const columns = schema ? schema.columns : FALLBACK_COLUMNS;
    const head = view.querySelector(".domain-table-head");
    const body = view.querySelector(".domain-table-body");
    const search = view.querySelector(".domain-search");
    const dangerous = view.querySelector(".ace-dangerous-filter");
    const count = view.querySelector(".domain-count");
    let page = 1;
    const pageSize = kind === "aces" || kind === "users" ? 200 : 50;
    let requestToken = 0;

    if (head) head.innerHTML = columns.map(column => `<th>${esc(column.label)}</th>`).join("");

    const fullConfig = FULL_FILTER_CONFIGS[kind];
    const filterRoot = view.querySelector(".user-filter") || view.querySelector(".entity-filter");
    let filterLoadTimer = null;
    const userFilter = fullConfig
        ? createAttributeFilter(filterRoot, fullConfig, () => { page = 1; scheduleLoad(true); })
        : null;
    const entityFilter = (!fullConfig && ENTITY_FILTER_CONFIG[kind])
        ? createEntityFilter(view.querySelector(".entity-filter"), ENTITY_FILTER_CONFIG[kind], () => { page = 1; scheduleLoad(true); })
        : null;
    const dataFilter = userFilter || entityFilter;
    const exceptionPanel = kind === "aces"
        ? createAceExceptionPanel(() => { page = 1; scheduleLoad(true, true); })
        : null;
    if (exceptionPanel && filterRoot) {
        const content = filterRoot.querySelector(".uf-content");
        const presets = filterRoot.querySelector(".uf-presets");
        const tabs = filterRoot.querySelector(".uf-tabs");
        if (content) {
            if (presets) presets.insertAdjacentElement("afterend", exceptionPanel.element);
            else if (tabs) content.insertBefore(exceptionPanel.element, tabs);
            else content.insertBefore(exceptionPanel.element, content.firstChild);
        }
    }
    let allRecords = null;
    let allRecordsQuery = null;
    const queryHistory = new Map();
    const QUERY_LIMIT = 3;
    const QUERY_WINDOW_MS = 60 * 1000;

    function setPagerDisabled(disabled) {
        view.querySelectorAll(".domain-prev, .domain-next").forEach(button => { button.disabled = disabled; });
    }

    function paintError(message) {
        body.innerHTML = `<tr><td colspan="${columns.length}">${esc(message)}</td></tr>`;
        if (count) count.textContent = "";
        if (dataFilter) dataFilter.setCounts(null);
        setPagerDisabled(false);
    }

    function paintRecords(records, meta) {
        body.innerHTML = records.map((record, index) => {
            const rowClass = schema && schema.rowClass ? schema.rowClass(record) : "";
            const clickable = schema && schema.clickable ? " domain-row-clickable" : "";
            return `<tr class="${rowClass}${clickable}" data-row-index="${index}">${columns.map(column => `<td>${column.render(record)}</td>`).join("")}</tr>`;
        }).join("") || `<tr><td colspan="${columns.length}">No records found</td></tr>`;
        if (schema && schema.clickable) {
            body.querySelectorAll("tr[data-row-index]").forEach(row => {
                row.addEventListener("click", () => {
                    const record = records[Number(row.dataset.rowIndex)];
                    if (kind === "groups") openGroupDetailPanel(record);
                    else if (kind === "computers") openComputerDetailPanel(record);
                    else if (kind === "ous") openOuDetailPanel(record);
                    else if (kind === "gpos") openGpoDetailPanel(record);
                    else if (kind === "trusts") openTrustDetailPanel(record);
                    else if (kind === "aces") openAceDetailPanel(record);
                    else if (kind === "certificates") openCertificateDetailPanel(record);
                    else openUserDetailPanel(record);
                });
            });
        }
        if (kind === "aces") {
            body.querySelectorAll("tr[data-row-index]").forEach(row => {
                row.addEventListener("contextmenu", event => {
                    event.preventDefault();
                    event.stopPropagation();
                    const record = records[Number(row.dataset.rowIndex)];
                    const menu = document.createElement("div");
                    menu.className = "ace-context-menu";
                    menu.innerHTML = `
                        <button type="button" data-action="copy-target">Copy Target Name</button>
                        <button type="button" data-action="copy-principal">Copy Principal Name</button>
                        <button type="button" data-action="add-exception">Add Exception</button>`;
                    menu.style.left = `${Math.min(event.clientX, window.innerWidth - 220)}px`;
                    menu.style.top = `${Math.min(event.clientY, window.innerHeight - 140)}px`;
                    document.body.appendChild(menu);
                    const close = () => {
                        menu.remove();
                        document.removeEventListener("click", close);
                        document.removeEventListener("contextmenu", close);
                    };
                    document.addEventListener("click", close);
                    setTimeout(() => {
                        if (menu.isConnected) document.addEventListener("contextmenu", close);
                    }, 0);
                    menu.addEventListener("click", async menuEvent => {
                        menuEvent.stopPropagation();
                        const action = menuEvent.target.closest("[data-action]")?.dataset.action;
                        if (!action) return;
                        if (action === "copy-target" || action === "copy-principal") {
                            const value = action === "copy-target"
                                ? record.target_name
                                : record.principal_name;
                            if (!value) {
                                alert(`This ACE has no ${action === "copy-target" ? "target" : "principal"} name.`);
                                return;
                            }
                            try {
                                await copyText(String(value));
                                close();
                            } catch (error) {
                                alert(`Could not copy value: ${error.message || error}`);
                            }
                            return;
                        }
                        if (action === "add-exception") {
                            try {
                                await exceptionPanel.addValue(record.principal_name);
                                close();
                            } catch (error) {
                                alert(error.message || "Could not add exception");
                            }
                        }
                    });
                });
            });
        }
        if (kind === "groups" || kind === "ous" || kind === "gpos") {
            body.querySelectorAll("tr[data-row-index]").forEach(row => {
                const button = row.querySelector(".domain-members-button");
                if (!button) return;
                const record = records[Number(row.dataset.rowIndex)];
                button.addEventListener("click", event => {
                    event.stopPropagation();
                    if (kind === "groups") openGroupMembersPanel(record);
                    else if (kind === "gpos") openGpoLinksPanel(record);
                    else openOuObjectsPanel(record);
                });
            });
        }
        view.querySelector(".domain-page").textContent = `Page ${meta.page} of ${meta.pages || 1}`;
        view.querySelector(".domain-prev").disabled = meta.page <= 1;
        view.querySelector(".domain-next").disabled = meta.has_more === false
            ? true
            : meta.page >= meta.pages;
        if (count) {
            count.textContent = meta.overall !== undefined && meta.overall !== meta.total
                ? `${fmtNumber(meta.total)} of ${fmtNumber(meta.overall)} records`
                : `${fmtNumber(meta.total)} records`;
        }
    }

    async function fetchEveryRecord(query) {
        const records = [];
        let current = 1;
        let pages = 1;
        do {
            const result = kind === "aces"
                ? await Api.getDomainAces({ page: current, page_size: 200, q: query })
                : await Api.getDomainResults(kind, { page: current, page_size: 200, q: query });
            if (!result.ok) return { ok: false, error: result.error };
            result.items.forEach(item => records.push(kind === "aces" ? item : item.data));
            pages = result.pages || 1;
            current += 1;
        } while (current <= pages);
        return { ok: true, records };
    }

    async function load() {
        const token = ++requestToken;
        const query = search ? search.value.trim() : "";
        const filterState = dataFilter && dataFilter.getServerFilters
            ? dataFilter.getServerFilters()
            : null;
        const queryKey = JSON.stringify({
            kind,
            page,
            query,
            filterState,
            dangerous: !!(dangerous && dangerous.checked)
        });
        const now = Date.now();
        const history = (queryHistory.get(queryKey) || []).filter(timestamp => now - timestamp < QUERY_WINDOW_MS);
        if (history.length >= QUERY_LIMIT) {
            const waitFor = QUERY_WINDOW_MS - (now - history[0]);
            clearTimeout(filterLoadTimer);
            filterLoadTimer = setTimeout(() => {
                filterLoadTimer = null;
                load();
            }, waitFor);
            return;
        }
        history.push(now);
        queryHistory.set(queryKey, history);
        body.innerHTML = `<tr><td colspan="${columns.length}">
            <div class="domain-data-loading" role="status" aria-live="polite">
                <div class="domain-data-spinner" aria-hidden="true"></div>
                <span>Loading records</span>
                <div class="domain-data-dots" aria-hidden="true"><span></span><span></span><span></span></div>
            </div>
        </td></tr>`;
        setPagerDisabled(true);

        if (dataFilter && dataFilter.needsClientMode()) {
            if (!allRecords || allRecordsQuery !== query) {
                let loaded;
                try {
                    loaded = await fetchEveryRecord(query);
                } catch (error) {
                    if (token !== requestToken) return;
                    paintError(error.message || "Unable to load records");
                    return;
                }
                if (token !== requestToken) return;
                if (!loaded.ok) {
                    paintError(loaded.error);
                    return;
                }
                allRecords = loaded.records;
                allRecordsQuery = query;
                if (dataFilter.registerKeys) dataFilter.registerKeys(allRecords);
                if (entityFilter) {
                    entityFilter.setAvailableKeys(allRecords.reduce((keys, record) => {
                        const visit = (value, prefix = "") => {
                            if (!value || typeof value !== "object" || Array.isArray(value)) return;
                            Object.entries(value).forEach(([key, item]) => {
                                const path = prefix ? `${prefix}.${key}` : key;
                                keys.add(path);
                                visit(item, path);
                            });
                        };
                        visit(record);
                        return keys;
                    }, new Set()));
                }
            }
            const filtered = dataFilter.sort
                ? dataFilter.sort(dataFilter.apply(allRecords))
                : dataFilter.apply(allRecords);
            const pages = Math.max(1, Math.ceil(filtered.length / pageSize));
            if (page > pages) page = pages;
            paintRecords(filtered.slice((page - 1) * pageSize, page * pageSize), {
                page, pages, total: filtered.length, overall: allRecords.length
            });
            dataFilter.setCounts(filtered.length, allRecords.length);
            return;
        }

        const params = { page, page_size: pageSize, q: query };
        if (dataFilter && dataFilter.serverSide) {
            params.filters = JSON.stringify(dataFilter.getServerFilters());
        }
        let result;
        try {
            if (kind === "aces") {
                params.dangerous = dangerous && dangerous.checked ? "1" : "0";
                result = await Api.getDomainAces(params);
            } else {
                if (schema && schema.sort) {
                    params.sort = schema.sort.field;
                    params.dir = schema.sort.dir;
                }
                result = await Api.getDomainResults(kind, params);
            }
        } catch (error) {
            if (token !== requestToken) return;
            paintError(error.message || "Unable to load records");
            return;
        }
        if (token !== requestToken) return;
        if (!result.ok) {
            paintError(result.error);
            return;
        }
        const records = result.items.map(item => kind === "aces" ? item : item.data);
        if (dataFilter) {
            if (dataFilter.registerKeys) dataFilter.registerKeys(records);
            dataFilter.setCounts(null);
        }
        paintRecords(records, {
            page: result.page,
            pages: result.pages,
            total: result.total,
            has_more: result.has_more
        });
    }

    function scheduleLoad(invalidateRecords = false, immediate = false) {
        if (invalidateRecords) {
            allRecords = null;
            allRecordsQuery = null;
        }
        clearTimeout(filterLoadTimer);
        if (immediate) {
            filterLoadTimer = null;
            load();
            return;
        }
        filterLoadTimer = setTimeout(() => {
            filterLoadTimer = null;
            load();
        }, 3000);
    }

    if (search) search.addEventListener("input", () => { page = 1; scheduleLoad(true); });
    if (search) search.addEventListener("keydown", event => {
        if (event.key !== "Enter") return;
        event.preventDefault();
        page = 1;
        scheduleLoad(true, true);
    });
    if (filterRoot) filterRoot.addEventListener("keydown", event => {
        if (event.key !== "Enter" || event.target.tagName !== "INPUT") return;
        event.preventDefault();
        page = 1;
        scheduleLoad(true, true);
    });
    if (dangerous) dangerous.addEventListener("change", () => { page = 1; scheduleLoad(true); });
    view.querySelector(".domain-prev").addEventListener("click", () => { page -= 1; load(); });
    view.querySelector(".domain-next").addEventListener("click", () => { page += 1; load(); });
    load();
};

function initials(name) {
    const clean = String(name || "").trim();
    if (!clean) return "?";
    const parts = clean.split(/[\s._-]+/).filter(Boolean);
    if (parts.length === 1) return parts[0].slice(0, 2).toUpperCase();
    return (parts[0][0] + parts[1][0]).toUpperCase();
}

function shortDn(dn) {
    if (!dn) return "";
    const match = String(dn).match(/^CN=([^,]+)/i);
    return match ? match[1] : String(dn);
}

function detailFlag(label, active, tone = "danger") {
    return badge(label, active ? tone : "muted");
}

function closeUserDetailPanel() {
    const overlay = document.querySelector(".user-detail-overlay");
    if (!overlay) return;
    overlay.classList.add("closing");
    setTimeout(() => overlay.remove(), 180);
    document.removeEventListener("keydown", handleUserDetailKeydown);
}

function handleUserDetailKeydown(event) {
    if (event.key === "Escape") closeUserDetailPanel();
}

function openGroupMembersPanel(group) {
    closeUserDetailPanel();
    const members = Array.isArray(group.members) ? group.members : [];
    const overlay = document.createElement("div");
    overlay.className = "user-detail-overlay";
    overlay.innerHTML = `
        <aside class="user-detail-panel" role="dialog" aria-modal="true" aria-label="Group members">
            <div class="user-detail-header">
                <div class="user-detail-avatar">${esc(initials(group.group_name))}</div>
                <div class="user-detail-heading">
                    <h2>${esc(group.group_name || "Unknown group")}</h2>
                    <span class="user-detail-dn">${esc(group.group_dn || "")}</span>
                </div>
                <button class="user-detail-close" type="button" aria-label="Close">&times;</button>
            </div>
            <div class="user-detail-status-row">
                ${badge(`${members.length} member${members.length === 1 ? "" : "s"}`, "info")}
            </div>
            <div class="user-detail-body">
                <section class="user-detail-section">
                    <div class="user-detail-section-title">Members</div>
                    <div class="group-member-list">
                        ${members.length ? members.map(member => `
                            <div class="group-member">
                                <strong>${esc(member.member_name || shortDn(member.member_dn) || "Unknown")}</strong>
                                <span>${member.is_group ? "Group" : member.is_computer ? "Computer" : "User"}</span>
                                <small>${esc(member.member_dn || member.member_sid || "")}</small>
                            </div>`).join("") : '<span class="domain-muted">No members reported</span>'}
                    </div>
                </section>
            </div>
        </aside>`;
    overlay.addEventListener("mousedown", event => {
        if (event.target === overlay) closeUserDetailPanel();
    });
    overlay.querySelector(".user-detail-close").addEventListener("click", closeUserDetailPanel);
    document.body.appendChild(overlay);
    document.addEventListener("keydown", handleUserDetailKeydown);
}

function groupTypeLabel(value) {
    const number = Number(value);
    if (value === null || value === undefined || !Number.isFinite(number)) return "";
    const flags = number >>> 0;
    const kind = (flags & 0x80000000) ? "Security" : "Distribution";
    const scope = (flags & 2) ? "Global" : (flags & 4) ? "Domain Local" : (flags & 8) ? "Universal" : "Unknown";
    return `${kind} / ${scope}${(flags & 1) ? " / Built-in" : ""}`;
}

function openGroupDetailPanel(group) {
    closeUserDetailPanel();
    const members = Array.isArray(group.members) ? group.members : [];
    const memberOf = Array.isArray(group.member_of) ? group.member_of : [];
    const userCount = members.filter(member => member.is_user).length;
    const computerCount = members.filter(member => member.is_computer).length;
    const groupCount = members.filter(member => member.is_group).length;
    const highAdmin = !!group.absolute_admin || !!group.nested_admin;

    const kv = (label, html) => `
        <div class="user-detail-kv">
            <span>${esc(label)}</span>
            <strong>${html}</strong>
        </div>`;
    const text = value => (value === null || value === undefined || value === "")
        ? '<span class="domain-muted">-</span>' : esc(String(value));

    const overview = [
        ["Group Name", text(group.group_name)],
        ["SID", text(group.group_sid)],
        ["RID", text(group.rid)],
        ["Primary Group Token", text(group.primary_group_token)],
        ["Domain SID", text(group.domainsid)],
        ["Group Type", text(groupTypeLabel(group.group_type))],
        ["Managed By", text(group.managed_by)],
        ["Members", esc(fmtNumber(group.member_count))]
    ];

    const timeline = [
        ["Created", fmtDate(group.when_created)],
        ["Changed", fmtDate(group.when_changed)]
    ];

    const overlay = document.createElement("div");
    overlay.className = "user-detail-overlay";
    overlay.innerHTML = `
        <aside class="user-detail-panel" role="dialog" aria-modal="true" aria-label="Group details">
            <div class="user-detail-header">
                <div class="user-detail-avatar">${esc(initials(group.group_name))}</div>
                <div class="user-detail-heading">
                    <h2>${esc(group.group_name || "Unknown group")}</h2>
                    <span class="user-detail-dn">${esc(group.group_dn || "")}</span>
                </div>
                <button class="user-detail-close" type="button" aria-label="Close">&times;</button>
            </div>
            <div class="user-detail-status-row">
                ${group.is_privileged ? badge("Privileged", "danger") : badge("Not Privileged", "muted")}
                ${highAdmin ? badge("Tier-0 Admin", "admin-high") : ""}
                ${!highAdmin && group.potential_admin ? badge("Potential Admin", "admin-potential") : ""}
                ${badge(`${fmtNumber(group.member_count)} member${Number(group.member_count) === 1 ? "" : "s"}`, "info")}
            </div>
            <div class="user-detail-body">
                <section class="user-detail-section">
                    <div class="user-detail-section-title">Group Overview</div>
                    <div class="user-detail-grid">
                        ${overview.map(([label, html]) => kv(label, html)).join("")}
                    </div>
                </section>
                ${group.description ? `
                <section class="user-detail-section">
                    <div class="user-detail-section-title">Description</div>
                    <p>${esc(group.description)}</p>
                </section>` : ""}
                ${group.info ? `
                <section class="user-detail-section">
                    <div class="user-detail-section-title">Notes</div>
                    <p>${esc(group.info)}</p>
                </section>` : ""}
                ${group.admin_description ? `
                <section class="user-detail-section user-admin-description">
                    <div class="user-detail-section-title">Admin Description</div>
                    <p>${esc(group.admin_description)}</p>
                    ${group.admin_evidence ? `<div class="user-detail-evidence"><span>Evidence</span><strong>${esc(group.admin_evidence)}</strong></div>` : ""}
                </section>` : ""}
                <section class="user-detail-section">
                    <div class="user-detail-section-title">Security Flags</div>
                    <div class="domain-flag-list">
                        ${detailFlag("Privileged", !!group.is_privileged)}
                        ${detailFlag("Absolute Admin", !!group.absolute_admin)}
                        ${detailFlag("Nested Admin", !!group.nested_admin)}
                        ${detailFlag("Potential Admin", !!group.potential_admin, "warn")}
                        ${detailFlag("Admin Count", !!group.admin_count, "warn")}
                        ${detailFlag("Protected", !!group.is_protected, "info")}
                        ${detailFlag("ACL Protected", !!group.isaclprotected, "info")}
                        ${detailFlag("Critical System Object", !!group.is_critical_system_object, "info")}
                        ${detailFlag("Security Enabled", !!group.security_enabled, "ok")}
                        ${detailFlag("Nested Group", !!group.is_nested, "info")}
                        ${detailFlag("Empty", !!group.is_empty, "info")}
                    </div>
                </section>
                <section class="user-detail-section">
                    <div class="user-detail-section-title">Timeline</div>
                    <div class="user-detail-grid">
                        ${timeline.map(([label, html]) => kv(label, html)).join("")}
                    </div>
                </section>
                <section class="user-detail-section">
                    <div class="user-detail-section-title">Member Of</div>
                    <div class="domain-chip-list">
                        ${memberOf.length ? memberOf.map(g => `<span class="domain-chip">${esc(shortDn(g))}</span>`).join("") : '<span class="domain-muted">This group is not a member of any other group</span>'}
                    </div>
                </section>
                <section class="user-detail-section">
                    <div class="user-detail-section-title">Members</div>
                    <div class="domain-flag-list">
                        ${badge(`${fmtNumber(userCount)} user${userCount === 1 ? "" : "s"}`, "muted")}
                        ${badge(`${fmtNumber(computerCount)} computer${computerCount === 1 ? "" : "s"}`, "muted")}
                        ${badge(`${fmtNumber(groupCount)} group${groupCount === 1 ? "" : "s"}`, "muted")}
                    </div>
                    <div class="group-member-list" style="margin-top:12px">
                        ${members.length ? members.map(member => `
                            <div class="group-member">
                                <strong>${esc(member.member_name || shortDn(member.member_dn) || "Unknown")}</strong>
                                <span>${member.is_group ? "Group" : member.is_computer ? "Computer" : "User"}</span>
                                <small>${esc(member.member_dn || member.member_sid || "")}</small>
                            </div>`).join("") : '<span class="domain-muted">No members reported</span>'}
                    </div>
                </section>
            </div>
        </aside>`;

    overlay.addEventListener("mousedown", event => {
        if (event.target === overlay) closeUserDetailPanel();
    });
    overlay.querySelector(".user-detail-close").addEventListener("click", closeUserDetailPanel);
    document.body.appendChild(overlay);
    document.addEventListener("keydown", handleUserDetailKeydown);
}

function ouName(dn) {
    if (!dn) return "";
    const match = String(dn).match(/^(?:OU|CN|DC)=((?:\\.|[^,\\])+)/i);
    return match ? match[1].replace(/\\(.)/g, "$1") : String(dn);
}

function openOuObjectsPanel(ou) {
    closeUserDetailPanel();
    const typeLabels = { ou: "OU", group: "Group", computer: "Computer", user: "User" };
    const overlay = document.createElement("div");
    overlay.className = "user-detail-overlay";
    overlay.innerHTML = `
        <aside class="user-detail-panel" role="dialog" aria-modal="true" aria-label="OU objects">
            <div class="user-detail-header">
                <div class="user-detail-avatar">${esc(initials(ou.name))}</div>
                <div class="user-detail-heading">
                    <h2>${esc(ou.name || "Unknown OU")}</h2>
                    <span class="user-detail-dn">${esc(ou.dn || "")}</span>
                </div>
                <button class="user-detail-close" type="button" aria-label="Close">&times;</button>
            </div>
            <div class="user-detail-status-row ou-objects-summary"></div>
            <div class="user-detail-body">
                <section class="user-detail-section">
                    <div class="user-detail-section-title">Objects</div>
                    <div class="group-member-list ou-objects-list"><span class="domain-muted">Loading objects...</span></div>
                </section>
            </div>
        </aside>`;
    overlay.addEventListener("mousedown", event => {
        if (event.target === overlay) closeUserDetailPanel();
    });
    overlay.querySelector(".user-detail-close").addEventListener("click", closeUserDetailPanel);
    document.body.appendChild(overlay);
    document.addEventListener("keydown", handleUserDetailKeydown);

    const listEl = overlay.querySelector(".ou-objects-list");
    const summaryEl = overlay.querySelector(".ou-objects-summary");
    Api.getDomainOuObjects(ou.dn).then(result => {
        if (!overlay.isConnected) return;
        if (!result.ok) {
            listEl.innerHTML = `<span class="domain-muted">${esc(result.error || "Failed to load objects")}</span>`;
            return;
        }
        const items = Array.isArray(result.items) ? result.items : [];
        const counts = { ou: 0, group: 0, computer: 0, user: 0 };
        items.forEach(item => { if (item.type in counts) counts[item.type] += 1; });
        summaryEl.innerHTML = [
            badge(`${items.length} object${items.length === 1 ? "" : "s"}`, "info"),
            ...Object.keys(counts).filter(key => counts[key]).map(key => badge(`${counts[key]} ${typeLabels[key]}${counts[key] === 1 ? "" : "s"}`, "muted"))
        ].join("");
        listEl.innerHTML = items.length ? items.map(item => `
            <div class="group-member">
                <strong>${esc(item.name || shortDn(item.dn) || "Unknown")}</strong>
                <span>${esc(typeLabels[item.type] || item.type || "Object")}</span>
                <small>${esc(item.dn || "")}</small>
            </div>`).join("") : '<span class="domain-muted">No objects in this OU</span>';
    }).catch(error => {
        if (!overlay.isConnected) return;
        listEl.innerHTML = `<span class="domain-muted">${esc(error.message || "Failed to load objects")}</span>`;
    });
}

function openOuDetailPanel(ou) {
    closeUserDetailPanel();
    const list = value => Array.isArray(value) ? value : [];
    const chipText = item => (item !== null && typeof item === "object") ? JSON.stringify(item) : String(item);
    const chips = (items, empty) => items.length
        ? items.map(item => `<span class="domain-chip">${esc(chipText(item))}</span>`).join("")
        : `<span class="domain-muted">${esc(empty)}</span>`;
    const kv = (label, html) => `
        <div class="user-detail-kv">
            <span>${esc(label)}</span>
            <strong>${html}</strong>
        </div>`;
    const text = value => (value === null || value === undefined || value === "")
        ? '<span class="domain-muted">-</span>' : esc(String(value));

    const overview = [
        ["Name", text(ou.name)],
        ["Type", text(ou.type)],
        ["Path", text(ou.path)],
        ["Parent DN", text(ou.parent_dn)],
        ["Depth", text(ou.depth)],
        ["Objects", esc(fmtNumber(ou.object_count))],
        ["Managed By", text(ou.managed_by)],
        ["Object GUID", text(ou.objectguid)],
        ["Object ID", text(ou.objectid)],
        ["Domain SID", text(ou.domainsid)],
        ["Delegated Permissions", esc(fmtNumber(ou.delegated_permissions))],
        ["Privileged Users", esc(fmtNumber(ou.privileged_users_count))],
        ["Privileged Computers", esc(fmtNumber(ou.privileged_computers_count))]
    ];

    const timeline = [
        ["Created", fmtDate(ou.created)],
        ["Modified", fmtDate(ou.modified)]
    ];

    const controllers = list(ou.controllers);
    const linkedGpos = list(ou.linked_gpos);
    const inheritanceBlocked = !!ou.inheritance_blocked || !!ou.blocksinheritance;

    const overlay = document.createElement("div");
    overlay.className = "user-detail-overlay";
    overlay.innerHTML = `
        <aside class="user-detail-panel" role="dialog" aria-modal="true" aria-label="OU details">
            <div class="user-detail-header">
                <div class="user-detail-avatar">${esc(initials(ou.name))}</div>
                <div class="user-detail-heading">
                    <h2>${esc(ou.name || "Unknown OU")}</h2>
                    <span class="user-detail-dn">${esc(ou.dn || "")}</span>
                </div>
                <button class="user-detail-close" type="button" aria-label="Close">&times;</button>
            </div>
            <div class="user-detail-status-row">
                ${ou.tier0 ? badge("Tier-0", "admin-high") : ""}
                ${ou.highvalue ? badge("High Value", "danger") : ""}
                ${ou.has_gpo_links ? badge("GPO Linked", "info") : badge("No GPO Links", "muted")}
                ${inheritanceBlocked ? badge("Inheritance Blocked", "warn") : ""}
                ${ou.controlled_by_non_admin ? badge("Controlled By Non-Admin", "danger") : ""}
            </div>
            <div class="user-detail-body">
                <section class="user-detail-section">
                    <div class="user-detail-section-title">OU Overview</div>
                    <div class="user-detail-grid">
                        ${overview.map(([label, html]) => kv(label, html)).join("")}
                    </div>
                </section>
                ${ou.description ? `
                <section class="user-detail-section">
                    <div class="user-detail-section-title">Description</div>
                    <p>${esc(ou.description)}</p>
                </section>` : ""}
                ${ou.tier0_description ? `
                <section class="user-detail-section user-admin-description">
                    <div class="user-detail-section-title">Tier-0 Description</div>
                    <p>${esc(ou.tier0_description)}</p>
                    ${ou.tier0_evidence ? `<div class="user-detail-evidence"><span>Evidence</span><strong>${esc(ou.tier0_evidence)}</strong></div>` : ""}
                    ${ou.tier0_reason !== null && ou.tier0_reason !== undefined ? `<div class="user-detail-evidence"><span>Reason Code</span><strong>${esc(String(ou.tier0_reason))}</strong></div>` : ""}
                </section>` : ""}
                ${ou.control_description ? `
                <section class="user-detail-section user-admin-description">
                    <div class="user-detail-section-title">Control Description</div>
                    <p>${esc(ou.control_description)}</p>
                    ${ou.control_reason !== null && ou.control_reason !== undefined ? `<div class="user-detail-evidence"><span>Reason Code</span><strong>${esc(String(ou.control_reason))}</strong></div>` : ""}
                </section>` : ""}
                <section class="user-detail-section">
                    <div class="user-detail-section-title">Security Flags</div>
                    <div class="domain-flag-list">
                        ${detailFlag("Tier-0", !!ou.tier0)}
                        ${detailFlag("High Value", !!ou.highvalue)}
                        ${detailFlag("Controlled By Non-Admin", !!ou.controlled_by_non_admin)}
                        ${detailFlag("Protected", !!ou.is_protected, "info")}
                        ${detailFlag("ACL Protected", !!ou.isaclprotected, "info")}
                        ${detailFlag("Critical System Object", !!ou.is_critical_system_object, "info")}
                        ${detailFlag("GPO Links", !!ou.has_gpo_links, "info")}
                        ${detailFlag("Inheritance Blocked", inheritanceBlocked, "warn")}
                    </div>
                </section>
                <section class="user-detail-section">
                    <div class="user-detail-section-title">Timeline</div>
                    <div class="user-detail-grid">
                        ${timeline.map(([label, html]) => kv(label, html)).join("")}
                    </div>
                </section>
                <section class="user-detail-section">
                    <div class="user-detail-section-title">Controllers</div>
                    ${controllers.length ? `<div class="group-member-list">${controllers.map(controller => `
                        <div class="group-member">
                            <strong>${esc(controller.name || controller.sid || "Unknown")}</strong>
                            <span>${esc(controller.type || "-")}</span>
                            <small>${esc(list(controller.rights).join(", ") || controller.sid || "")}</small>
                        </div>`).join("")}</div>` : '<span class="domain-muted">No controllers reported</span>'}
                </section>
                <section class="user-detail-section">
                    <div class="user-detail-section-title">Linked GPOs</div>
                    ${linkedGpos.length ? `<div class="group-member-list">${linkedGpos.map(link => `
                        <div class="group-member">
                            <strong>${esc(link.gpo_guid || shortDn(link.gpo_dn) || "Unknown")}</strong>
                            <span>Order ${esc(String(link.order ?? "-"))}</span>
                            <small>${esc(link.link_enabled === false ? "Link disabled" : "Link enabled")} · ${esc(link.enforced ? "Enforced" : "Not enforced")}${link.gpo_dn ? " · " + esc(link.gpo_dn) : ""}</small>
                        </div>`).join("")}</div>` : '<span class="domain-muted">No GPOs linked to this OU</span>'}
                </section>
                <section class="user-detail-section">
                    <div class="user-detail-section-title">GPO Precedence</div>
                    <div class="domain-chip-list">${chips(list(ou.gpo_precedence), "None reported")}</div>
                </section>
                <section class="user-detail-section">
                    <div class="user-detail-section-title">Inherited GPOs</div>
                    <div class="domain-chip-list">${chips(list(ou.inherited_gpos), "None reported")}</div>
                </section>
                <section class="user-detail-section">
                    <div class="user-detail-section-title">Child OUs</div>
                    <div class="domain-chip-list">${chips(list(ou.childous).map(ouName), "No child OUs")}</div>
                </section>
                <section class="user-detail-section">
                    <div class="user-detail-section-title">Privileged Users</div>
                    <div class="domain-chip-list">${chips(list(ou.privileged_users), "No privileged users")}</div>
                </section>
                <section class="user-detail-section">
                    <div class="user-detail-section-title">Privileged Computers</div>
                    <div class="domain-chip-list">${chips(list(ou.privileged_computers), "No privileged computers")}</div>
                </section>
                <section class="user-detail-section">
                    <div class="user-detail-section-title">Risk Controls</div>
                    <div class="domain-chip-list">${chips(list(ou.risk_controls), "No risk controls reported")}</div>
                </section>
                <section class="user-detail-section">
                    <div class="user-detail-section-title">Objects</div>
                    <div class="domain-members-cell">
                        <strong>${fmtNumber(ou.object_count)} ${Number(ou.object_count) === 1 ? "object" : "objects"}</strong>
                        <button type="button" class="domain-members-button ou-detail-objects-button">
                            <span>View objects</span>
                            <svg class="domain-members-arrow" viewBox="0 0 24 24" width="11" height="11" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M9 18l6-6-6-6"/></svg>
                        </button>
                    </div>
                </section>
            </div>
        </aside>`;

    overlay.addEventListener("mousedown", event => {
        if (event.target === overlay) closeUserDetailPanel();
    });
    overlay.querySelector(".user-detail-close").addEventListener("click", closeUserDetailPanel);
    overlay.querySelector(".ou-detail-objects-button").addEventListener("click", () => openOuObjectsPanel(ou));
    document.body.appendChild(overlay);
    document.addEventListener("keydown", handleUserDetailKeydown);
}

function gpoLinkType(dn) {
    const first = String(dn || "").split(",")[0].trim().toUpperCase();
    if (first.startsWith("OU=")) return "OU";
    if (first.startsWith("DC=")) return "Domain";
    if (first.startsWith("CN=")) return "Site";
    return "Object";
}

function openGpoLinksPanel(gpo) {
    closeUserDetailPanel();
    const links = Array.isArray(gpo.linked_containers) ? gpo.linked_containers : [];
    const overlay = document.createElement("div");
    overlay.className = "user-detail-overlay";
    overlay.innerHTML = `
        <aside class="user-detail-panel" role="dialog" aria-modal="true" aria-label="GPO links">
            <div class="user-detail-header">
                <div class="user-detail-avatar">${esc(initials(gpo.display_name || gpo.name))}</div>
                <div class="user-detail-heading">
                    <h2>${esc(gpo.display_name || gpo.name || "Unknown GPO")}</h2>
                    <span class="user-detail-dn">${esc(gpo.guid || "")}</span>
                </div>
                <button class="user-detail-close" type="button" aria-label="Close">&times;</button>
            </div>
            <div class="user-detail-status-row">
                ${badge(`${links.length} ${links.length === 1 ? "Object" : "Objects"}`, "info")}
                ${gpo.enforced ? badge("Enforced", "info") : badge("Not Enforced", "muted")}
            </div>
            <div class="user-detail-body">
                <section class="user-detail-section">
                    <div class="user-detail-section-title">Linked Objects</div>
                    <div class="group-member-list">
                        ${links.length ? links.map(link => `
                            <div class="group-member">
                                <strong>${esc(ouName(link.dn) || "Unknown")}</strong>
                                <span>${esc(gpoLinkType(link.dn))}</span>
                                <small>${esc(link.link_enabled === false ? "Link disabled" : "Link enabled")} · ${esc(link.enforced ? "Enforced" : "Not enforced")} · ${esc(link.dn || "")}</small>
                            </div>`).join("") : '<span class="domain-muted">No linked objects reported</span>'}
                    </div>
                </section>
            </div>
        </aside>`;
    overlay.addEventListener("mousedown", event => {
        if (event.target === overlay) closeUserDetailPanel();
    });
    overlay.querySelector(".user-detail-close").addEventListener("click", closeUserDetailPanel);
    document.body.appendChild(overlay);
    document.addEventListener("keydown", handleUserDetailKeydown);
}

function openGpoDetailPanel(gpo) {
    closeUserDetailPanel();
    const list = value => Array.isArray(value) ? value : [];
    const itemText = item => {
        if (item === null || item === undefined) return "";
        if (typeof item !== "object") return String(item);
        return Object.entries(item).map(([key, value]) =>
            `${key}: ${Array.isArray(value) ? value.join(", ") : (value === null ? "-" : String(value))}`).join(" | ");
    };
    const chips = (items, empty) => items.length
        ? items.map(item => `<span class="domain-chip">${esc(itemText(item))}</span>`).join("")
        : `<span class="domain-muted">${esc(empty)}</span>`;
    const kv = (label, html) => `
        <div class="user-detail-kv">
            <span>${esc(label)}</span>
            <strong>${html}</strong>
        </div>`;
    const text = value => (value === null || value === undefined || value === "")
        ? '<span class="domain-muted">-</span>' : esc(String(value));

    const links = list(gpo.linked_containers);
    const controllers = list(gpo.controllers);

    const overview = [
        ["Name", text(gpo.name)],
        ["Display Name", text(gpo.display_name)],
        ["GUID", text(gpo.guid)],
        ["Domain", text(gpo.domain)],
        ["Domain SID", text(gpo.domainsid)],
        ["Path", text(gpo.path)],
        ["Owner", text(gpo.owner_name || gpo.owner_sid)],
        ["Owner SID", text(gpo.owner_sid)],
        ["Linked Objects", esc(fmtNumber(gpo.linked_count))],
        ["Version", text(gpo.version)],
        ["User Version", text(gpo.user_version)],
        ["Computer Version", text(gpo.computer_version)],
        ["Flags Value", text(gpo.flags)]
    ];
    const timeline = [
        ["Created", fmtDate(gpo.created)],
        ["Modified", fmtDate(gpo.modified)]
    ];

    const overlay = document.createElement("div");
    overlay.className = "user-detail-overlay";
    overlay.innerHTML = `
        <aside class="user-detail-panel" role="dialog" aria-modal="true" aria-label="GPO details">
            <div class="user-detail-header">
                <div class="user-detail-avatar">${esc(initials(gpo.display_name || gpo.name))}</div>
                <div class="user-detail-heading">
                    <h2>${esc(gpo.display_name || gpo.name || "Unknown GPO")}</h2>
                    <span class="user-detail-dn">${esc(gpo.dn || "")}</span>
                </div>
                <button class="user-detail-close" type="button" aria-label="Close">&times;</button>
            </div>
            <div class="user-detail-status-row">
                ${gpo.tier0 ? badge("Tier-0", "admin-high") : ""}
                ${gpo.highvalue ? badge("High Value", "danger") : ""}
                ${gpo.enforced ? badge("Enforced", "info") : badge("Not Enforced", "muted")}
                ${gpo.link_disabled ? badge("Link Disabled", "warn") : ""}
                ${gpo.inheritance_blocked ? badge("Inheritance Blocked", "warn") : ""}
                ${gpo.controlled_by_non_admin ? badge("Controlled By Non-Admin", "danger") : ""}
            </div>
            <div class="user-detail-body">
                <section class="user-detail-section">
                    <div class="user-detail-section-title">GPO Overview</div>
                    <div class="user-detail-grid">
                        ${overview.map(([label, html]) => kv(label, html)).join("")}
                    </div>
                </section>
                ${gpo.description ? `
                <section class="user-detail-section">
                    <div class="user-detail-section-title">Description</div>
                    <p>${esc(gpo.description)}</p>
                </section>` : ""}
                ${gpo.tier0_description ? `
                <section class="user-detail-section user-admin-description">
                    <div class="user-detail-section-title">Tier-0 Description</div>
                    <p>${esc(gpo.tier0_description)}</p>
                    ${gpo.tier0_evidence ? `<div class="user-detail-evidence"><span>Evidence</span><strong>${esc(gpo.tier0_evidence)}</strong></div>` : ""}
                    ${gpo.tier0_reason !== null && gpo.tier0_reason !== undefined ? `<div class="user-detail-evidence"><span>Reason Code</span><strong>${esc(String(gpo.tier0_reason))}</strong></div>` : ""}
                </section>` : ""}
                ${gpo.control_description ? `
                <section class="user-detail-section user-admin-description">
                    <div class="user-detail-section-title">Control Description</div>
                    <p>${esc(gpo.control_description)}</p>
                    ${gpo.control_reason !== null && gpo.control_reason !== undefined ? `<div class="user-detail-evidence"><span>Reason Code</span><strong>${esc(String(gpo.control_reason))}</strong></div>` : ""}
                </section>` : ""}
                <section class="user-detail-section">
                    <div class="user-detail-section-title">Security Flags</div>
                    <div class="domain-flag-list">
                        ${detailFlag("Tier-0", !!gpo.tier0)}
                        ${detailFlag("High Value", !!gpo.highvalue)}
                        ${detailFlag("Controlled By Non-Admin", !!gpo.controlled_by_non_admin)}
                        ${detailFlag("Enforced", !!gpo.enforced, "info")}
                        ${detailFlag("Link Disabled", !!gpo.link_disabled, "warn")}
                        ${detailFlag("Inheritance Blocked", !!gpo.inheritance_blocked, "warn")}
                        ${detailFlag("User Settings Disabled", !!gpo.user_settings_disabled, "warn")}
                        ${detailFlag("Computer Settings Disabled", !!gpo.computer_settings_disabled, "warn")}
                        ${detailFlag("ACL Protected", !!gpo.isaclprotected, "info")}
                        ${detailFlag("Critical System Object", !!gpo.is_critical_system_object, "info")}
                    </div>
                </section>
                <section class="user-detail-section">
                    <div class="user-detail-section-title">Timeline</div>
                    <div class="user-detail-grid">
                        ${timeline.map(([label, html]) => kv(label, html)).join("")}
                    </div>
                </section>
                <section class="user-detail-section">
                    <div class="user-detail-section-title">Links</div>
                    <div class="domain-members-cell">
                        <strong>${fmtNumber(gpo.linked_count)} ${Number(gpo.linked_count) === 1 ? "Object" : "Objects"}</strong>
                        <button type="button" class="domain-members-button gpo-detail-links-button">
                            <span>View links</span>
                            <svg class="domain-members-arrow" viewBox="0 0 24 24" width="11" height="11" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M9 18l6-6-6-6"/></svg>
                        </button>
                    </div>
                    ${links.length ? `<div class="group-member-list" style="margin-top:12px">${links.map(link => `
                        <div class="group-member">
                            <strong>${esc(ouName(link.dn) || "Unknown")}</strong>
                            <span>${esc(gpoLinkType(link.dn))}</span>
                            <small>${esc(link.link_enabled === false ? "Link disabled" : "Link enabled")} · ${esc(link.enforced ? "Enforced" : "Not enforced")} · ${esc(link.dn || "")}</small>
                        </div>`).join("")}</div>` : ""}
                </section>
                <section class="user-detail-section">
                    <div class="user-detail-section-title">Controllers</div>
                    ${controllers.length ? `<div class="group-member-list">${controllers.map(controller => `
                        <div class="group-member">
                            <strong>${esc(controller.name || controller.sid || "Unknown")}</strong>
                            <span>${esc(controller.type || "-")}</span>
                            <small>${esc(list(controller.rights).join(", ") || controller.sid || "")}</small>
                        </div>`).join("")}</div>` : '<span class="domain-muted">No controllers reported</span>'}
                </section>
                <section class="user-detail-section">
                    <div class="user-detail-section-title">User Extensions</div>
                    <div class="domain-chip-list">${chips(list(gpo.user_extensions), "None reported")}</div>
                </section>
                <section class="user-detail-section">
                    <div class="user-detail-section-title">Machine Extensions</div>
                    <div class="domain-chip-list">${chips(list(gpo.machine_extensions), "None reported")}</div>
                </section>
                <section class="user-detail-section">
                    <div class="user-detail-section-title">OU Inheritance</div>
                    <div class="domain-chip-list">${chips(list(gpo.ou_inheritance), "None reported")}</div>
                </section>
                <section class="user-detail-section">
                    <div class="user-detail-section-title">Risk Controls</div>
                    <div class="domain-chip-list">${chips(list(gpo.risk_controls), "No risk controls reported")}</div>
                </section>
                <section class="user-detail-section">
                    <div class="user-detail-section-title">cPassword Findings</div>
                    <div class="domain-chip-list">${chips(list(gpo.all_cpasswords), "None reported")}</div>
                </section>
                <section class="user-detail-section">
                    <div class="user-detail-section-title">LDAP DACL ACEs</div>
                    <div class="domain-chip-list">${chips(list(gpo.ldap_dacl_aces), "None reported")}</div>
                </section>
                <section class="user-detail-section">
                    <div class="user-detail-section-title">SYSVOL</div>
                    <div class="domain-chip-list">${chips(list(gpo.sysvol), "None reported")}</div>
                </section>
            </div>
        </aside>`;

    overlay.addEventListener("mousedown", event => {
        if (event.target === overlay) closeUserDetailPanel();
    });
    overlay.querySelector(".user-detail-close").addEventListener("click", closeUserDetailPanel);
    overlay.querySelector(".gpo-detail-links-button").addEventListener("click", () => openGpoLinksPanel(gpo));
    document.body.appendChild(overlay);
    document.addEventListener("keydown", handleUserDetailKeydown);
}

function openTrustDetailPanel(trust) {
    closeUserDetailPanel();
    const kv = (label, html) => `
        <div class="user-detail-kv">
            <span>${esc(label)}</span>
            <strong>${html}</strong>
        </div>`;
    const text = value => (value === null || value === undefined || value === "" || value === "-")
        ? '<span class="domain-muted">-</span>' : esc(String(value));
    const yesNo = value => value ? "Yes" : "No";
    const chips = (items, empty, format) => items.length
        ? items.map(item => `<span class="domain-chip">${esc(format ? format(item) : item)}</span>`).join("")
        : `<span class="domain-muted">${esc(empty)}</span>`;

    const attributes = trustList(trust.attributes_decoded);
    const risks = trustList(trust.risk_controls);
    const posture = trustList(trust.security_posture);
    const encryption = trustList(trust.supported_encryption_types);
    const forestInfo = trustList(trust.forest_trust_info);

    const overview = [
        ["Name", text(trust.name)],
        ["NetBIOS Name", text(trust.flat_name)],
        ["Partner", text(trust.partner)],
        ["Direction", text(trustLabel(trust.direction))],
        ["Trust Type", text(trustTypeLabel(trust))],
        ["Trust Type Code", text(trust.trust_type_raw)],
        ["Direction Code", text(trust.direction_raw)],
        ["Attributes Value", text(trust.attributes_raw)],
        ["Trusted Domain SID", text(trust.sid)],
        ["Object GUID", text(trust.object_guid)]
    ];
    const timeline = [
        ["Created", fmtDate(trust.when_created)],
        ["Last Changed", fmtDate(trust.when_changed)],
        ["USN Created", text(trust.usn_created)],
        ["USN Changed", text(trust.usn_changed)]
    ];

    const overlay = document.createElement("div");
    overlay.className = "user-detail-overlay";
    overlay.innerHTML = `
        <aside class="user-detail-panel" role="dialog" aria-modal="true" aria-label="Trust details">
            <div class="user-detail-header">
                <div class="user-detail-avatar">${esc(initials(trust.flat_name || trust.name))}</div>
                <div class="user-detail-heading">
                    <h2>${esc(trust.name || trust.partner || "Unknown trust")}</h2>
                    <span class="user-detail-dn">${esc(trust.dn || "")}</span>
                </div>
                <button class="user-detail-close" type="button" aria-label="Close">&times;</button>
            </div>
            <div class="user-detail-status-row">
                ${trust.dangerous ? badge("Dangerous", "danger") : ""}
                ${badge(trustLabel(trust.direction) || "Unknown", trust.direction === "bidirectional" ? "warn" : "info")}
                ${badge(trustTypeLabel(trust), trust.forest ? "admin-potential" : "info")}
                ${badge(trust.transitive ? "Transitive" : "Non-transitive", "muted")}
                ${trust.sid_filtering_enabled ? badge("SID Filtering", "ok") : badge("No SID Filtering", "danger")}
            </div>
            <div class="user-detail-body">
                <section class="user-detail-section">
                    <div class="user-detail-section-title">Trust Overview</div>
                    <div class="user-detail-grid">
                        ${overview.map(([label, html]) => kv(label, html)).join("")}
                    </div>
                </section>
                <section class="user-detail-section">
                    <div class="user-detail-section-title">Security Flags</div>
                    <div class="domain-flag-list">
                        ${detailFlag("Dangerous", !!trust.dangerous)}
                        ${detailFlag("TGT Delegation", !!trust.tgt_delegation_enabled)}
                        ${detailFlag("Forest-Wide Auth", !!trust.forest_wide_auth, "warn")}
                        ${detailFlag("Treat As External", !!trust.treat_as_external, "warn")}
                        ${detailFlag("RC4 Encryption", !!trust.uses_rc4_encryption, "warn")}
                        ${detailFlag("PIM Trust", !!trust.pim_trust, "info")}
                        ${detailFlag("Selective Auth", !!trust.selective_auth, "ok")}
                        ${detailFlag("SID Filtering", !!trust.sid_filtering_enabled, "ok")}
                        ${detailFlag("AES Keys", !!trust.uses_aes_keys, "ok")}
                        ${detailFlag("Transitive", !!trust.transitive, "info")}
                        ${detailFlag("Within Forest", !!trust.within_forest, "info")}
                        ${detailFlag("Uplevel Only", !!trust.uplevel_only, "info")}
                    </div>
                </section>
                <section class="user-detail-section">
                    <div class="user-detail-section-title">Trust Flow</div>
                    <div class="user-detail-grid">
                        ${kv("Inbound", yesNo(trust.inbound))}
                        ${kv("Outbound", yesNo(trust.outbound))}
                        ${kv("Forest Trust", yesNo(trust.forest))}
                        ${kv("Within Forest", yesNo(trust.within_forest))}
                    </div>
                </section>
                <section class="user-detail-section">
                    <div class="user-detail-section-title">Trust Attributes</div>
                    <div class="domain-chip-list">${chips(attributes, "None reported", trustLabel)}</div>
                </section>
                <section class="user-detail-section">
                    <div class="user-detail-section-title">Security Posture</div>
                    <div class="domain-chip-list">${chips(posture, "None reported", trustLabel)}</div>
                </section>
                <section class="user-detail-section">
                    <div class="user-detail-section-title">Risk Controls</div>
                    <div class="domain-chip-list">${chips(risks, "No risk controls reported", trustLabel)}</div>
                </section>
                <section class="user-detail-section">
                    <div class="user-detail-section-title">Supported Encryption Types</div>
                    <div class="domain-chip-list">${chips(encryption, "None reported")}</div>
                </section>
                <section class="user-detail-section">
                    <div class="user-detail-section-title">Forest Trust Info</div>
                    <div class="domain-chip-list">${chips(forestInfo, "None reported")}</div>
                </section>
                <section class="user-detail-section">
                    <div class="user-detail-section-title">Timeline</div>
                    <div class="user-detail-grid">
                        ${timeline.map(([label, html]) => kv(label, html)).join("")}
                    </div>
                </section>
            </div>
        </aside>`;

    overlay.addEventListener("mousedown", event => {
        if (event.target === overlay) closeUserDetailPanel();
    });
    overlay.querySelector(".user-detail-close").addEventListener("click", closeUserDetailPanel);
    document.body.appendChild(overlay);
    document.addEventListener("keydown", handleUserDetailKeydown);
}

function certificateLabel(key) {
    return String(key)
        .replace(/([a-z])([A-Z])/g, "$1 $2")
        .replace(/[-_]+/g, " ")
        .replace(/\b\w/g, char => char.toUpperCase());
}

function openCertificateDetailPanel(certificate) {
    closeUserDetailPanel();
    const raw = certificate.raw && typeof certificate.raw === "object" ? certificate.raw : {};
    const acl = Array.isArray(certificate.acl) ? certificate.acl : [];
    const findings = Array.isArray(certificate.esc_findings) ? certificate.esc_findings : [];
    const hygieneFindings = Array.isArray(certificate.hygiene_findings) ? certificate.hygiene_findings : [];
    const kv = (label, html) => `
        <div class="user-detail-kv">
            <span>${esc(label)}</span>
            <strong>${html}</strong>
        </div>`;
    const text = value => value === null || value === undefined || value === ""
        ? '<span class="domain-muted">-</span>' : renderValue(value);
    const rawEntries = Object.entries(raw);
    const overview = [
        ["Name", text(certificate.name || raw.cn)],
        ["Display Name", text(raw.displayName)],
        ["Record Type", text(certificate.record_type)],
        ["Distinguished Name", text(certificate.dn || raw.distinguishedName)],
        ["Object GUID", text(raw.objectGUID)],
        ["Template OID", text(raw["msPKI-Cert-Template-OID"])],
        ["Finding Count", fmtNumber(certificate.finding_count)],
        ["ACL Entries", fmtNumber(acl.length)]
    ];
    const findingItems = findings.map(item => {
        const values = item && typeof item === "object" ? Object.entries(item) : [["Finding", item]];
        const score = certificateFindingScore(item);
        const risk = certificateFindingRisk(item);
        return `<div class="group-member">
            <strong>${esc(item && typeof item === "object" ? (item.rule || item.name || "ESC finding") : "ESC finding")} ${badge(`${score.toFixed(1)} · ${risk.label}`, risk.tone)}</strong>
            <small>${values.map(([key, value]) => `${esc(certificateLabel(key))}: ${renderValue(value)}`).join(" · ")}</small>
        </div>`;
    }).join("");
    const aclItems = acl.map(entry => `
        <div class="group-member">
            <strong>${esc(entry.principal_name || entry.principal_sid || "Unknown principal")}</strong>
            <span>${esc(entry.principal_scope || "Unknown scope")}</span>
            <small>${renderValue(entry.rights)}${entry.dangerous_ace ? " · Dangerous ACE" : ""}</small>
        </div>`).join("");

    const overlay = document.createElement("div");
    overlay.className = "user-detail-overlay";
    overlay.innerHTML = `
        <aside class="user-detail-panel" role="dialog" aria-modal="true" aria-label="Certificate details">
            <div class="user-detail-header">
                <div class="user-detail-avatar">${esc(initials(certificate.name || raw.cn))}</div>
                <div class="user-detail-heading">
                    <h2>${esc(certificate.name || raw.cn || "Unknown certificate")}</h2>
                    <span class="user-detail-dn">${esc(certificate.dn || raw.distinguishedName || "")}</span>
                </div>
                <button class="user-detail-close" type="button" aria-label="Close">&times;</button>
            </div>
            <div class="user-detail-status-row">
                ${badge(certificate.record_type || "Certificate", "info")}
                ${badge(certificateRisk(certificate).label, certificateRisk(certificate).tone)}
                ${findings.length ? badge(`${findings.length} ESC finding${findings.length === 1 ? "" : "s"}`, "danger") : badge("No ESC findings", "ok")}
            </div>
            <div class="user-detail-body">
                <section class="user-detail-section">
                    <div class="user-detail-section-title">Certificate Overview</div>
                    <div class="user-detail-grid">
                        ${overview.map(([label, html]) => kv(label, html)).join("")}
                    </div>
                </section>
                <section class="user-detail-section">
                    <div class="user-detail-section-title">Security Findings</div>
                    <div class="group-member-list">
                        ${findingItems || '<span class="domain-muted">No ESC findings reported</span>'}
                    </div>
                </section>
                ${hygieneFindings.length ? `
                <section class="user-detail-section">
                    <div class="user-detail-section-title">Hygiene Findings</div>
                    <div class="domain-chip-list">${hygieneFindings.map(item => `<span class="domain-chip">${esc(typeof item === "object" ? JSON.stringify(item) : String(item))}</span>`).join("")}</div>
                </section>` : ""}
                <section class="user-detail-section">
                    <div class="user-detail-section-title">Template Attributes</div>
                    <div class="user-detail-grid">
                        ${rawEntries.map(([key, value]) => kv(certificateLabel(key), renderValue(value))).join("")}
                    </div>
                </section>
                <section class="user-detail-section">
                    <div class="user-detail-section-title">Access Control</div>
                    <div class="group-member-list">
                        ${aclItems || '<span class="domain-muted">No ACL entries reported</span>'}
                    </div>
                </section>
            </div>
        </aside>`;
    overlay.addEventListener("mousedown", event => {
        if (event.target === overlay) closeUserDetailPanel();
    });
    overlay.querySelector(".user-detail-close").addEventListener("click", closeUserDetailPanel);
    document.body.appendChild(overlay);
    document.addEventListener("keydown", handleUserDetailKeydown);
}

function aceFlagLabels(value) {
    const number = Number(value);
    if (!Number.isFinite(number)) return [];
    const names = [
        [0x1, "Object Inherit"], [0x2, "Container Inherit"], [0x4, "No Propagate Inherit"],
        [0x8, "Inherit Only"], [0x10, "Inherited"], [0x40, "Successful Access"], [0x80, "Failed Access"]
    ];
    return names.filter(([bit]) => (number & bit) === bit).map(([, name]) => name);
}

function aceTypeLabel(ace) {
    const raw = Number(ace.ace_type_raw);
    const isDeny = raw === 1 || raw === 6;
    const isObject = raw === 5 || raw === 6;
    return `${isDeny ? "Deny" : "Allow"}${isObject ? " (Object)" : ""}`;
}

function openAceDetailPanel(record) {
    closeUserDetailPanel();
    const aces = Array.isArray(record.aces) && record.aces.length ? record.aces : [record];
    const primary = aces[0];
    const others = aces.slice(1);
    const kv = (label, html) => `
        <div class="user-detail-kv">
            <span>${esc(label)}</span>
            <strong>${html}</strong>
        </div>`;
    const text = value => (value === null || value === undefined || value === "")
        ? '<span class="domain-muted">-</span>' : esc(String(value));
    const rightChips = rights => (rights || []).length
        ? (rights || []).map(right => `<span class="domain-chip">${esc(right)}</span>`).join("")
        : '<span class="domain-muted">-</span>';
    const flagLabels = ace => aceFlagLabels(ace.ace_flags);

    const targetOverview = [
        ["Target Name", text(primary.target_name)],
        ["Target Type", text(primary.target_type)],
        ["Target SID", text(primary.target_sid)],
        ["Target DN", text(primary.target_dn)],
        ["Principal Name", text(primary.principal_name)],
        ["Principal SID", text(primary.principal_sid)],
        ["Principal Scope", text(primary.principal_scope)],
        ["Total ACEs", esc(fmtNumber(aces.length))]
    ];
    const aceOverview = ace => [
        ["ACE Type", text(aceTypeLabel(ace))],
        ["ACE Type Code", text(ace.ace_type_raw)],
        ["Object ACE Type", text(ace.object_acetype)],
        ["ACE Flags Value", text(ace.ace_flags)],
        ["ACE Flags", text(flagLabels(ace).join(", "))]
    ];

    const overlay = document.createElement("div");
    overlay.className = "user-detail-overlay";
    overlay.innerHTML = `
        <aside class="user-detail-panel" role="dialog" aria-modal="true" aria-label="ACE details">
            <div class="user-detail-header">
                <div class="user-detail-avatar">${esc(initials(primary.target_name))}</div>
                <div class="user-detail-heading">
                    <h2>${esc(primary.target_name || "Unknown target")}</h2>
                    <span class="user-detail-dn">${esc(primary.target_dn || "")}</span>
                </div>
                <button class="user-detail-close" type="button" aria-label="Close">&times;</button>
            </div>
            <div class="user-detail-status-row">
                ${primary.dangerous_ace ? badge("Dangerous", "danger") : badge("Not Dangerous", "muted")}
                ${primary.extended_rights ? badge("Extended Rights", "info") : ""}
                ${badge(aceTypeLabel(primary), primary.is_deny ? "warn" : "muted")}
                ${badge(`${fmtNumber(aces.length)} ${aces.length === 1 ? "ACE" : "ACEs"}`, "info")}
            </div>
            <div class="user-detail-body">
                <section class="user-detail-section">
                    <div class="user-detail-section-title">ACE Overview</div>
                    <div class="user-detail-grid">
                        ${targetOverview.map(([label, html]) => kv(label, html)).join("")}
                    </div>
                </section>
                <section class="user-detail-section">
                    <div class="user-detail-section-title">Most Critical ACE</div>
                    <div class="domain-chip-list">${rightChips(primary.rights)}</div>
                    <div class="user-detail-grid" style="margin-top:12px">
                        ${aceOverview(primary).map(([label, html]) => kv(label, html)).join("")}
                    </div>
                </section>
                <section class="user-detail-section">
                    <div class="user-detail-section-title">Security Flags</div>
                    <div class="domain-flag-list">
                        ${detailFlag("Dangerous", !!primary.dangerous_ace)}
                        ${detailFlag("Extended Rights", !!primary.extended_rights, "info")}
                        ${detailFlag("Deny ACE", !!primary.is_deny, "warn")}
                        ${detailFlag("Inherited", (Number(primary.ace_flags) & 0x10) === 0x10, "info")}
                    </div>
                </section>
                <section class="user-detail-section">
                    <div class="user-detail-section-title">Other ACEs (${fmtNumber(others.length)})</div>
                    ${others.length ? `<div class="group-member-list">${others.map(ace => `
                        <div class="group-member">
                            <strong>${esc(rightsText(ace.rights) || "-")}</strong>
                            <span>${esc(aceTypeLabel(ace))}</span>
                            <small>${ace.dangerous_ace ? "Dangerous" : "Not dangerous"}${ace.extended_rights ? " · Extended rights" : ""}${flagLabels(ace).length ? " · " + esc(flagLabels(ace).join(", ")) : ""}${ace.object_acetype ? " · " + esc(ace.object_acetype) : ""}</small>
                        </div>`).join("")}</div>` : '<span class="domain-muted">No other ACEs for this target and principal</span>'}
                </section>
            </div>
        </aside>`;

    overlay.addEventListener("mousedown", event => {
        if (event.target === overlay) closeUserDetailPanel();
    });
    overlay.querySelector(".user-detail-close").addEventListener("click", closeUserDetailPanel);
    document.body.appendChild(overlay);
    document.addEventListener("keydown", handleUserDetailKeydown);
}

function openComputerDetailPanel(computer) {
    closeUserDetailPanel();
    const disabled = !!computer.disabled;
    const isDc = !!computer.is_domain_controller;
    const highAdmin = !!computer.absolute_admin || !!computer.nested_admin;
    const role = isDc ? "Domain Controller" : computer.is_server ? "Server" : computer.is_workstation ? "Workstation" : "Unknown";

    const list = value => Array.isArray(value) ? value : [];
    const chipText = item => (item !== null && typeof item === "object") ? JSON.stringify(item) : String(item);
    const chips = (items, empty) => items.length
        ? items.map(item => `<span class="domain-chip">${esc(chipText(item))}</span>`).join("")
        : `<span class="domain-muted">${esc(empty)}</span>`;
    const kv = (label, html) => `
        <div class="user-detail-kv">
            <span>${esc(label)}</span>
            <strong>${html}</strong>
        </div>`;
    const text = value => (value === null || value === undefined || value === "")
        ? '<span class="domain-muted">-</span>' : esc(String(value));
    const yesNo = value => value === null || value === undefined ? text(value) : (value ? "Yes" : "No");

    const overview = [
        ["Computer Name", text(computer.computer_name)],
        ["DNS Name", text(computer.dns_name)],
        ["Display Name", text(computer.display_name)],
        ["SID", text(computer.sid)],
        ["Role", text(role)],
        ["Operating System", text(computer.os)],
        ["OS Version", text(computer.os_version)],
        ["Service Pack", text(computer.os_service_pack)],
        ["Location", text(computer.location)],
        ["Primary Group ID", text(computer.primary_group_id)],
        ["Domain", text(computer.domain_name)],
        ["Domain SID", text(computer.domainsid)],
        ["IPv4 Addresses", text(list(computer.ipv4_addresses).join(", "))],
        ["IPv6 Addresses", text(list(computer.ipv6_addresses).join(", "))],
        ["SMB Version", text(computer.smb_version)],
        ["Risk Score", text(computer.risk_score)]
    ];

    const timeline = [
        ["Created", fmtDate(computer.when_created)],
        ["Changed", fmtDate(computer.when_changed)],
        ["Last Logon", fmtDate(computer.last_logon)],
        ["Password Last Set", fmtDate(computer.pwd_last_set)],
        ["LAPS Expiration", fmtDate(computer.laps_expiration)]
    ];

    const delegateTo = list(computer.allowed_to_delegate_to);
    const delegateStructured = list(computer.allowed_to_delegate_to_structured);
    const rbcdNames = list(computer.rbcd_principal_names);
    const rbcdSids = list(computer.rbcd_principals);
    const rbcd = rbcdNames.length ? rbcdNames : rbcdSids;

    const overlay = document.createElement("div");
    overlay.className = "user-detail-overlay";
    overlay.innerHTML = `
        <aside class="user-detail-panel" role="dialog" aria-modal="true" aria-label="Computer details">
            <div class="user-detail-header">
                <div class="user-detail-avatar${disabled ? " is-disabled" : ""}">${esc(initials(computer.computer_name || computer.display_name))}</div>
                <div class="user-detail-heading">
                    <h2>${esc(computer.computer_name || computer.display_name || "Unknown")}</h2>
                    <span class="user-detail-dn">${esc(computer.dn || "")}</span>
                </div>
                <button class="user-detail-close" type="button" aria-label="Close">&times;</button>
            </div>
            <div class="user-detail-status-row">
                ${disabled ? badge("Disabled", "muted") : badge("Enabled", "ok")}
                ${isDc ? badge("Domain Controller", "admin-potential") : badge(role, "muted")}
                ${highAdmin ? badge("Tier-0 Admin", "admin-high") : ""}
                ${!highAdmin && computer.potential_admin ? badge("Potential Admin", "admin-potential") : ""}
                ${computer.is_stale ? badge("Stale", "muted") : ""}
            </div>
            <div class="user-detail-body">
                <section class="user-detail-section">
                    <div class="user-detail-section-title">Computer Overview</div>
                    <div class="user-detail-grid">
                        ${overview.map(([label, html]) => kv(label, html)).join("")}
                    </div>
                </section>
                ${computer.description ? `
                <section class="user-detail-section">
                    <div class="user-detail-section-title">Description</div>
                    <p>${esc(computer.description)}</p>
                </section>` : ""}
                ${computer.admin_description ? `
                <section class="user-detail-section user-admin-description">
                    <div class="user-detail-section-title">Admin Description</div>
                    <p>${esc(computer.admin_description)}</p>
                    ${computer.admin_evidence ? `<div class="user-detail-evidence"><span>Evidence</span><strong>${esc(computer.admin_evidence)}</strong></div>` : ""}
                </section>` : ""}
                <section class="user-detail-section">
                    <div class="user-detail-section-title">Security Flags</div>
                    <div class="domain-flag-list">
                        ${detailFlag("Absolute Admin", !!computer.absolute_admin)}
                        ${detailFlag("Nested Admin", !!computer.nested_admin)}
                        ${detailFlag("Potential Admin", !!computer.potential_admin, "warn")}
                        ${detailFlag("Potential Privileged", !!computer.potential_privileged, "warn")}
                        ${detailFlag("Unconstrained Delegation", !!computer.unconstrained_delegation)}
                        ${detailFlag("Constrained Delegation", !!computer.constrained_delegation, "warn")}
                        ${detailFlag("Protocol Transition", !!computer.protocol_transition_delegation, "warn")}
                        ${detailFlag("Trusted For Delegation", !!computer.trusted_for_delegation, "warn")}
                        ${detailFlag("RBCD Enabled", !!computer.rbcd_enabled)}
                        ${detailFlag("Kerberoastable", !!computer.kerberoastable, "info")}
                        ${detailFlag("AS-REP Roastable", !!computer.asrep, "info")}
                        ${detailFlag("Shadow Credential", !!computer.has_shadow_credential)}
                        ${detailFlag("Has SPN", !!computer.has_spn, "info")}
                        ${detailFlag("LAPS", !!computer.has_laps || !!computer.haslaps, "ok")}
                        ${detailFlag("ACL Protected", !!computer.isaclprotected, "info")}
                        ${detailFlag("Stale", !!computer.is_stale, "warn")}
                        ${detailFlag("SMB Port Open", !!computer.smb_port_open, "info")}
                        ${detailFlag("SMB Signing Required", !!computer.smb_signing_required, "ok")}
                    </div>
                </section>
                <section class="user-detail-section">
                    <div class="user-detail-section-title">Timeline</div>
                    <div class="user-detail-grid">
                        ${timeline.map(([label, html]) => kv(label, html)).join("")}
                    </div>
                </section>
                <section class="user-detail-section">
                    <div class="user-detail-section-title">Service Principal Names</div>
                    <div class="domain-chip-list">${chips(list(computer.spn), "No SPNs reported")}</div>
                </section>
                <section class="user-detail-section">
                    <div class="user-detail-section-title">Delegation Targets</div>
                    <div class="domain-chip-list">${chips(delegateStructured.length ? delegateStructured : delegateTo, "No delegation targets")}</div>
                </section>
                <section class="user-detail-section">
                    <div class="user-detail-section-title">RBCD Principals</div>
                    <div class="domain-chip-list">${chips(rbcd, "No RBCD principals")}</div>
                </section>
                <section class="user-detail-section">
                    <div class="user-detail-section-title">Risk Factors</div>
                    <div class="domain-chip-list">${chips(list(computer.risk_factors), "No risk factors reported")}</div>
                </section>
                <section class="user-detail-section">
                    <div class="user-detail-section-title">Risk Controls</div>
                    <div class="domain-chip-list">${chips(list(computer.risk_controls), "No risk controls reported")}</div>
                </section>
                <section class="user-detail-section">
                    <div class="user-detail-section-title">SID History</div>
                    <div class="domain-chip-list">${chips(list(computer.sid_history), "No SID history")}</div>
                </section>
                <section class="user-detail-section">
                    <div class="user-detail-section-title">LAPS Attributes</div>
                    <div class="domain-chip-list">${chips(list(computer.laps_attributes), "No LAPS attributes")}</div>
                </section>
            </div>
        </aside>`;

    overlay.addEventListener("mousedown", event => {
        if (event.target === overlay) closeUserDetailPanel();
    });
    overlay.querySelector(".user-detail-close").addEventListener("click", closeUserDetailPanel);
    document.body.appendChild(overlay);
    document.addEventListener("keydown", handleUserDetailKeydown);
}

function openUserDetailPanel(user) {
    closeUserDetailPanel();
    const disabled = isDisabledUser(user);
    const highAdmin = !!user.absolute_admin || !!user.nested_admin;
    const potentialAdmin = !!user.potential_admin;
    const roastable = !!user.kerberoastable || !!user.asrep;

    const overview = [
        ["Display Name", user.display_name],
        ["UPN", user.upn],
        ["SID", user.sid],
        ["Mail", user.mail],
        ["Phone", user.phone],
        ["Department", user.department],
        ["Title", user.title],
        ["Primary Group ID", user.primary_group_id],
        ["Domain SID", user.domain_sid]
    ];

    const timeline = [
        ["Created", fmtDate(user.when_created)],
        ["Changed", fmtDate(user.when_changed)],
        ["Last Logon", fmtDate(user.last_logon)],
        ["Logon Count", fmtNumber(user.logon_count)],
        ["Password Last Set", fmtDate(user.pwd_last_set)],
        ["Bad Password Count", fmtNumber(user.bad_pwd_count)],
        ["Account Expires", user.account_never_expires ? "Never" : fmtDate(user.account_expires)]
    ];

    const groups = Array.isArray(user.member_of) ? user.member_of : [];

    const overlay = document.createElement("div");
    overlay.className = "user-detail-overlay";
    overlay.innerHTML = `
        <aside class="user-detail-panel" role="dialog" aria-modal="true" aria-label="User details">
            <div class="user-detail-header">
                <div class="user-detail-avatar${disabled ? " is-disabled" : ""}">${esc(initials(user.username || user.display_name))}</div>
                <div class="user-detail-heading">
                    <h2>${esc(user.username || user.display_name || "Unknown")}</h2>
                    <span class="user-detail-dn">${esc(user.dn || "")}</span>
                </div>
                <button class="user-detail-close" type="button" aria-label="Close">&times;</button>
            </div>
            <div class="user-detail-status-row">
                ${disabled ? badge("Disabled", "muted") : badge("Enabled", "ok")}
                ${highAdmin ? badge("Tier-0 Admin", "admin-high") : ""}
                ${!highAdmin && potentialAdmin ? badge("Potential Admin", "admin-potential") : ""}
                ${roastable ? badge("Roastable", "roastable") : ""}
                ${user.dcsync ? badge("DCSync", "danger") : ""}
            </div>
            <div class="user-detail-body">
                <section class="user-detail-section">
                    <div class="user-detail-section-title">Account Overview</div>
                    <div class="user-detail-grid">
                        ${overview.map(([label, value]) => `
                            <div class="user-detail-kv">
                                <span>${esc(label)}</span>
                                <strong>${value ? esc(String(value)) : '<span class="domain-muted">-</span>'}</strong>
                            </div>`).join("")}
                    </div>
                </section>
                ${user.admin_description ? `
                <section class="user-detail-section user-admin-description">
                    <div class="user-detail-section-title">Admin Description</div>
                    <p>${esc(user.admin_description)}</p>
                    ${user.admin_evidence ? `<div class="user-detail-evidence"><span>Evidence</span><strong>${esc(user.admin_evidence)}</strong></div>` : ""}
                </section>` : ""}
                <section class="user-detail-section">
                    <div class="user-detail-section-title">Security Flags</div>
                    <div class="domain-flag-list">
                        ${detailFlag("Absolute Admin", !!user.absolute_admin)}
                        ${detailFlag("Nested Admin", !!user.nested_admin)}
                        ${detailFlag("Potential Admin", !!user.potential_admin, "warn")}
                        ${detailFlag("Kerberoastable", !!user.kerberoastable, "info")}
                        ${detailFlag("AS-REP Roastable", !!user.asrep, "info")}
                        ${detailFlag("Unconstrained Delegation", !!user.unconstrained_delegation)}
                        ${detailFlag("Constrained Delegation", !!user.constrained_delegation, "warn")}
                        ${detailFlag("Pwd Never Expires", !!user.pwd_never_expires, "warn")}
                        ${detailFlag("Pwd Not Required", !!user.pwd_not_required)}
                        ${detailFlag("Must Change Pwd", !!user.must_change_pwd, "info")}
                        ${detailFlag("Locked Out", !!user.locked_out)}
                        ${detailFlag("Smartcard Required", !!user.smartcard_required, "info")}
                    </div>
                </section>
                <section class="user-detail-section">
                    <div class="user-detail-section-title">Timeline</div>
                    <div class="user-detail-grid">
                        ${timeline.map(([label, value]) => `
                            <div class="user-detail-kv">
                                <span>${esc(label)}</span>
                                <strong>${value ? esc(String(value)) : '<span class="domain-muted">-</span>'}</strong>
                            </div>`).join("")}
                    </div>
                </section>
                <section class="user-detail-section">
                    <div class="user-detail-section-title">Group Memberships</div>
                    <div class="domain-chip-list">
                        ${groups.length ? groups.map(g => `<span class="domain-chip">${esc(shortDn(g))}</span>`).join("") : '<span class="domain-muted">No group memberships reported</span>'}
                    </div>
                </section>
            </div>
        </aside>`;

    overlay.addEventListener("mousedown", event => {
        if (event.target === overlay) closeUserDetailPanel();
    });
    overlay.querySelector(".user-detail-close").addEventListener("click", closeUserDetailPanel);
    document.body.appendChild(overlay);
    document.addEventListener("keydown", handleUserDetailKeydown);
}

function initCertSummary(view) {
    const root = view.querySelector("#cert-summary");
    if (!root) return;

    const ICONS = {
        server: '<rect x="3" y="4" width="18" height="7" rx="2"/><rect x="3" y="13" width="18" height="7" rx="2"/><path d="M7 7.5h.01M7 16.5h.01"/>',
        key: '<circle cx="8" cy="15" r="4"/><path d="M11 12l9-9"/><path d="M16 7l3 3"/>',
        shield: '<path d="M12 3l8 3v6c0 4.5-3.2 8-8 9-4.8-1-8-4.5-8-9V6z"/><path d="M9 12l2 2 4-4"/>',
        link: '<path d="M10 13a5 5 0 0 0 7.54.54l3-3a5 5 0 0 0-7.07-7.07l-1.72 1.71"/><path d="M14 11a5 5 0 0 0-7.54-.54l-3 3a5 5 0 0 0 7.07 7.07l1.71-1.71"/>'
    };

    function icon(name) {
        return `<svg viewBox="0 0 24 24" width="18" height="18" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">${ICONS[name]}</svg>`;
    }

    function value(data, fallback = "Not available") {
        if (data === null || data === undefined || data === "") return fallback;
        return esc(String(data));
    }

    function rawValue(record, key, fallback = "Not available") {
        return value(record && record.raw ? record.raw[key] : undefined, fallback);
    }

    function recordLabel(record) {
        return value(record.name || (record.raw && (record.raw.cn || record.raw.displayName)));
    }

    function templateCount(service) {
        const templates = service.raw ? service.raw.certificateTemplates : null;
        if (Array.isArray(templates)) return templates.length;
        return templates ? 1 : 0;
    }

    function escChips(record) {
        const findings = Array.isArray(record.esc_findings) ? record.esc_findings : [];
        if (!findings.length) return '<span class="domain-state domain-state-good">No findings</span>';
        return `<div class="domain-flag-list">${findings.map(item => badge(item.rule, "danger")).join("")}</div>`;
    }

    function oidLabel(item) {
        const name = recordLabel(item);
        const link = rawValue(item, "msDS-OIDToGroupLink", "");
        return link ? `${name} → ${link}` : name;
    }

    function render(records) {
        const templates = records.filter(record => record.record_type === "template");
        const services = records.filter(record => record.record_type === "enrollment_service");
        const authorities = records.filter(record => record.record_type === "certification_authority");
        const ntauth = records.filter(record => record.record_type === "ntauth");
        const oids = records.filter(record => record.record_type === "oid");
        const users = records.filter(record => record.record_type === "user_mapping");
        const primaryCa = services[0] || authorities[0] || {};

        const findingCounts = {};
        let totalFindings = 0;
        let highRisk = 0;
        records.forEach(record => {
            const findings = Array.isArray(record.esc_findings) ? record.esc_findings : [];
            totalFindings += findings.length;
            if (certificateRisk(record).label === "High" || certificateRisk(record).label === "Critical") highRisk += 1;
            findings.forEach(finding => {
                findingCounts[finding.rule] = (findingCounts[finding.rule] || 0) + 1;
            });
        });
        const vulnerableTemplates = templates.filter(template => Number(template.finding_count) > 0).length;
        const severity = totalFindings === 0 ? "info" : highRisk > 0 ? "critical" : "medium";
        const score = Math.min(100, totalFindings * 8);
        const escRules = Object.keys(findingCounts).sort();

        const stats = [
            { tone: "blue", icon: "server", label: "Certification Authorities", main: String(services.length + authorities.length), sub: `${ntauth.length} trusted in NTAuth` },
            { tone: "amber", icon: "key", label: "Certificate Templates", main: String(templates.length), sub: `${vulnerableTemplates} with ESC findings` },
            { tone: totalFindings ? "red" : "green", icon: "shield", label: "ESC Findings", main: String(totalFindings), sub: `${highRisk} high risk` },
            { tone: "blue", icon: "link", label: "Issuance Policy OIDs", main: String(oids.length), sub: `${users.length} weak cert mappings` }
        ];

        root.innerHTML = `
            <div class="domain-hero domain-hero-${esc(severity)}">
                <div class="domain-hero-main">
                    <div class="domain-eyebrow">CERTIFICATE SERVICES OVERVIEW</div>
                    <h1>${recordLabel(primaryCa) !== "Not available" ? recordLabel(primaryCa) : "No Enterprise CA found"}</h1>
                    <div class="domain-hero-tags">
                        <span class="domain-hero-tag">${icon("server")}${rawValue(primaryCa, "dNSHostName")}</span>
                        <span class="domain-hero-tag domain-hero-tag-mono">${rawValue(primaryCa, "cACertificateDN")}</span>
                    </div>
                </div>
                <div class="domain-risk domain-risk-${esc(severity)}" style="--risk-pct:${score}">
                    <div class="domain-risk-ring"><strong>${totalFindings}</strong></div>
                    <span>ESC findings</span>
                    <small>${esc(severity)}</small>
                </div>
            </div>
            <div class="domain-stat-grid">
                ${stats.map((stat, index) => `
                <div class="domain-stat domain-stat-${stat.tone}" style="--stat-index:${index}">
                    <div class="domain-stat-icon">${icon(stat.icon)}</div>
                    <div class="domain-stat-body">
                        <span>${stat.label}</span>
                        <strong>${stat.main}</strong>
                        <small>${stat.sub}</small>
                    </div>
                </div>`).join("")}
            </div>
            <div class="domain-summary-grid">
                <section class="domain-panel domain-panel-wide domain-panel-blue">
                    <div class="domain-panel-title">Certification Authorities</div>
                    ${services.length || authorities.length ? `<div class="domain-controller-list">${services.concat(authorities).map(service => `
                        <div class="domain-controller">
                            <div class="domain-controller-icon">CA</div>
                            <div>
                                <strong>${recordLabel(service)}</strong>
                                <span>${rawValue(service, "dNSHostName")}</span>
                                <span>${templateCount(service)} templates published</span>
                            </div>
                            <small>${escChips(service)}</small>
                        </div>`).join("")}</div>` : '<div class="domain-muted">No Certification Authorities reported</div>'}
                </section>
                <section class="domain-panel domain-panel-amber">
                    <div class="domain-panel-title">ESC Finding Breakdown</div>
                    <div class="domain-kv-list">${escRules.length ? escRules.map(rule => `
                        <div class="domain-kv"><span>${esc(rule)}</span><strong>${badge(String(findingCounts[rule]), "danger")}</strong></div>`).join("") : '<div class="domain-muted">No ESC findings detected</div>'}</div>
                </section>
                <section class="domain-panel domain-panel-green">
                    <div class="domain-panel-title">NTAuth Store</div>
                    <div class="domain-chip-list">${ntauth.length ? ntauth.map(item => `<span class="domain-chip">${recordLabel(item)}</span>`).join("") : '<span class="domain-muted">No NTAuth-trusted certificates reported</span>'}</div>
                </section>
                <section class="domain-panel domain-panel-purple domain-panel-issuance-oids">
                    <div class="domain-panel-title">Issuance Policy OIDs</div>
                    <div class="domain-chip-list">${oids.length ? oids.map(item => `<span class="domain-chip">${oidLabel(item)}</span>`).join("") : '<span class="domain-muted">No issuance policy OIDs reported</span>'}</div>
                </section>
            </div>`;
    }

    Api.getDomainResults("certificates", { page: 1, page_size: 500 }).then(result => {
        if (!result.ok) {
            root.innerHTML = `<div class="domain-muted">${esc(result.error || "Failed to load certificate services overview")}</div>`;
            return;
        }
        render((result.items || []).map(item => item.data));
    }).catch(error => {
        root.innerHTML = `<div class="domain-muted">${esc(error.message || "Failed to load certificate services overview")}</div>`;
    });
}

function initDomainSummary(view) {
    const root = view.querySelector("#domain-summary");

    const ICONS = {
        level: '<path d="M3 20h18"/><path d="M6 20V10"/><path d="M12 20V4"/><path d="M18 20v-7"/>',
        server: '<rect x="3" y="4" width="18" height="7" rx="2"/><rect x="3" y="13" width="18" height="7" rx="2"/><path d="M7 7.5h.01M7 16.5h.01"/>',
        quota: '<circle cx="12" cy="12" r="9"/><path d="M12 7v5l3 2"/>',
        shield: '<path d="M12 3l8 3v6c0 4.5-3.2 8-8 9-4.8-1-8-4.5-8-9V6z"/><path d="M9 12l2 2 4-4"/>',
        crown: '<path d="M3 8l4 4 5-7 5 7 4-4-2 11H5z"/>',
        key: '<circle cx="8" cy="15" r="4"/><path d="M11 12l9-9"/><path d="M16 7l3 3"/>',
        lock: '<rect x="4" y="11" width="16" height="10" rx="2"/><path d="M8 11V7a4 4 0 0 1 8 0v4"/>',
        globe: '<circle cx="12" cy="12" r="9"/><path d="M3 12h18"/><path d="M12 3a14 14 0 0 1 0 18a14 14 0 0 1 0-18"/>'
    };

    function icon(name) {
        return `<svg viewBox="0 0 24 24" width="18" height="18" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">${ICONS[name]}</svg>`;
    }

    function value(data, fallback = "Not available") {
        if (data === null || data === undefined || data === "") return fallback;
        return esc(String(data));
    }

    function list(items) {
        if (!Array.isArray(items) || !items.length) return '<span class="domain-muted">None reported</span>';
        return items.map((item, index) => `<span class="domain-chip domain-chip-tone-${index % 5}">${value(item)}</span>`).join("");
    }

    function stateValue(state, goodLabel, badLabel, goodWhenTrue = true) {
        const good = goodWhenTrue ? !!state : !state;
        return `<span class="domain-state domain-state-${good ? "good" : "bad"}">${esc(good ? goodLabel : badLabel)}</span>`;
    }

    function rows(items) {
        return items.map(([label, html]) =>
            `<div class="domain-kv"><span>${esc(label)}</span><strong>${html}</strong></div>`).join("");
    }

    function fsmoRows(data) {
        const entries = Object.entries(data || {});
        if (!entries.length) return '<span class="domain-muted">None reported</span>';
        return entries.map(([role, holder], index) => `
            <div class="domain-fsmo domain-fsmo-tone-${index % 5}">
                <span>${value(role)}</span>
                <strong>${value(holder)}</strong>
            </div>`).join("");
    }

    function render(data) {
        const controllers = Array.isArray(data.domain_controllers) ? data.domain_controllers : [];
        const policy = data.password_policy || {};
        const security = data.authentication_security || {};
        const ldap = data.ldap_signing || security.ldap_signing || {};
        const severity = String(data.highest_severity || "info").toLowerCase();
        const score = Math.max(0, Math.min(100, Number(data.risk_score) || 0));
        const ntlm = security.ntlm_supported ?? data.ntlm_supported;
        const anonymous = !!(data.null_anonymous_access && data.null_anonymous_access.allowed);
        const quota = Number(data.machine_account_quota);
        const minLength = Number(policy.min_length);
        const lockout = Number(policy.lockout_threshold);

        const stats = [
            { tone: "amber", icon: "level", label: "Functional level", main: value(data.functional_level_name), sub: `Level ${value(data.functional_level, "-")}` },
            { tone: "blue", icon: "server", label: "Domain controllers", main: String(controllers.length), sub: data.has_enterprise_ca ? "Enterprise CA present" : "No enterprise CA" },
            { tone: Number.isFinite(quota) && quota > 0 ? "red" : "green", icon: "quota", label: "Machine quota", main: value(data.machine_account_quota), sub: "MachineAccountQuota" },
            { tone: data.smb_signing_required ? "green" : "red", icon: "shield", label: "SMB signing", main: data.smb_signing_required ? "Required" : "Not required", sub: data.smb_signing_enabled ? "Enabled" : "Disabled" }
        ];

        root.innerHTML = `
            <div class="domain-hero domain-hero-${esc(severity)}">
                <div class="domain-hero-main">
                    <div class="domain-eyebrow">DOMAIN OVERVIEW</div>
                    <h1>${value(data.netbios_name || data.fqdn, "Unknown domain")}</h1>
                    <div class="domain-hero-tags">
                        <span class="domain-hero-tag">${icon("globe")}${value(data.fqdn)}</span>
                        <span class="domain-hero-tag domain-hero-tag-mono">${value(data.domain_sid)}</span>
                    </div>
                </div>
                <div class="domain-risk domain-risk-${esc(severity)}" style="--risk-pct:${score}">
                    <div class="domain-risk-ring"><strong>${value(data.risk_score, "0")}</strong></div>
                    <span>Risk score</span>
                    <small>${esc(severity)}</small>
                </div>
            </div>
            <div class="domain-stat-grid">
                ${stats.map((stat, index) => `
                <div class="domain-stat domain-stat-${stat.tone}" style="--stat-index:${index}">
                    <div class="domain-stat-icon">${icon(stat.icon)}</div>
                    <div class="domain-stat-body">
                        <span>${stat.label}</span>
                        <strong>${stat.main}</strong>
                        <small>${stat.sub}</small>
                    </div>
                </div>`).join("")}
            </div>
            <div class="domain-summary-grid">
                <section class="domain-panel domain-panel-wide domain-panel-blue">
                    <div class="domain-panel-title">Domain controllers</div>
                    ${controllers.length ? `<div class="domain-controller-list">${controllers.map(controller => `
                        <div class="domain-controller">
                            <div class="domain-controller-icon">DC</div>
                            <div><strong>${value(controller.name)}</strong><span>${value(controller.dns_hostname)}</span><span>${value(controller.ip_address)}</span></div>
                            <small>${value(controller.operating_system)}</small>
                        </div>`).join("")}</div>` : '<div class="domain-muted">No domain controllers reported</div>'}
                </section>
                <section class="domain-panel domain-panel-purple">
                    <div class="domain-panel-title">FSMO roles</div>
                    <div class="domain-fsmo-list">${fsmoRows(data.fsmo)}</div>
                </section>
                <section class="domain-panel domain-panel-amber">
                    <div class="domain-panel-title">Password policy</div>
                    <div class="domain-kv-list">${rows([
                        ["Minimum length", `<span class="domain-state domain-state-${minLength >= 12 ? "good" : minLength >= 8 ? "warn" : "bad"}">${value(policy.min_length)}</span>`],
                        ["Complexity", stateValue(policy.complexity_enabled, "Enabled", "Disabled")],
                        ["History count", `<span class="domain-state domain-state-info">${value(policy.history_count)}</span>`],
                        ["Lockout threshold", `<span class="domain-state domain-state-${lockout > 0 ? "good" : "bad"}">${value(policy.lockout_threshold)}</span>`]
                    ])}</div>
                </section>
                <section class="domain-panel domain-panel-green">
                    <div class="domain-panel-title">Authentication security</div>
                    <div class="domain-kv-list">${rows([
                        ["NTLM supported", `<span class="domain-state domain-state-${ntlm ? "warn" : "good"}">${value(ntlm)}</span>`],
                        ["LDAP signing", stateValue(ldap.required, "Required", "Not required")],
                        ["Anonymous bind", stateValue(!anonymous, "Restricted", "Allowed")],
                        ["Smart card", stateValue(data.smart_card_required, "Required", "Not required")]
                    ])}</div>
                </section>
                <section class="domain-panel domain-panel-teal">
                    <div class="domain-panel-title">DNS zones</div>
                    <div class="domain-chip-list">${list(data.dns_zones)}</div>
                </section>
            </div>`;
    }

    Api.getDomainResults("domain", { page: 1, page_size: 1 }).then(result => {
        if (!result.ok || !result.items.length) {
            render({});
            return;
        }
        render(result.items[0].data);
    });
}