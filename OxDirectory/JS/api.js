const Api = {
    async parse(response) {
        const contentType = response.headers.get("content-type") || "";
        if (!contentType.includes("application/json")) {
            const preview = (await response.text()).trim().slice(0, 120);
            throw new Error(
                `API returned ${response.status} ${response.statusText || "error"} instead of JSON` +
                (preview ? `: ${preview}` : "")
            );
        }
        return response.json();
    },
    async getMeta() {
        const res = await fetch("/api/meta");
        return Api.parse(res);
    },
    async getFiles() {
        const res = await fetch("/api/files");
        return Api.parse(res);
    },
    async getDashboardSummary() {
        const res = await fetch("/api/dashboard-summary");
        if (res.status === 404) return Api.getLegacyDashboardSummary();
        return Api.parse(res);
    },
    async getLegacyDashboardSummary() {
        const kinds = ["domain", "users", "groups", "computers", "ous", "gpos", "trusts", "certificates"];
        const responses = await Promise.all([
            ...kinds.map(kind => fetch(`/api/domain-results/${kind}?page=1&page_size=200`).then(Api.parse)),
            fetch("/api/files").then(Api.parse)
        ]);
        const records = {};
        kinds.forEach((kind, index) => {
            records[kind] = responses[index].items || [];
        });
        const count = (items, field) => items.filter(item => item[field] === true).length;
        const summary = items => ({
            total: items.length,
            admins: count(items, "is_admin"),
            disabled: count(items, "disabled"),
            locked: count(items, "locked_out"),
            kerberoastable: count(items, "kerberoastable"),
            asrep: count(items, "asrep"),
            dcsync: count(items, "dcsync"),
            privileged: count(items, "is_privileged"),
            empty: count(items, "is_empty"),
            nested: count(items, "is_nested"),
            protected: count(items, "is_protected"),
            servers: count(items, "is_server"),
            workstations: count(items, "is_workstation"),
            domain_controllers: count(items, "is_domain_controller"),
            stale: count(items, "is_stale"),
            delegation: count(items, "unconstrained_delegation"),
            linked: items.filter(item => (item.linked_count || 0) > 0).length,
            enforced: count(items, "enforced"),
            high_value: count(items, "highvalue"),
            gpo_links: count(items, "has_gpo_links")
        });
        const domain = records.domain[0] || {};
        const filesResult = responses[kinds.length];
        return {
            ok: true,
            summary: {
                domain: {
                    name: domain.fqdn || domain.domain_name || domain.netbios_name,
                    risk_score: domain.risk_score || 0,
                    highest_severity: domain.highest_severity || "info",
                    domain_controllers: (domain.domain_controllers || []).length,
                    dns_zones: (domain.dns_zones || []).length,
                    anonymous_bind: !!(domain.null_anonymous_access || {}).allowed,
                    ldap_signing: !!(domain.ldap_signing || {}).required,
                    enterprise_ca: !!domain.has_enterprise_ca
                },
                sections: {
                    users: summary(records.users),
                    groups: summary(records.groups),
                    computers: summary(records.computers),
                    ous: summary(records.ous),
                    gpos: summary(records.gpos),
                    trusts: summary(records.trusts),
                    certificates: summary(records.certificates)
                },
                files: (filesResult.files || []).map(file => ({
                    name: file.name,
                    kind: file.kind,
                    records: file.record_count || 0
                })),
                aces: filesResult.summary || { total: 0, dangerous: 0, extended: 0 }
            }
        };
    },
    async getDomainAces(params = {}) {
        const query = new URLSearchParams(params);
        const res = await fetch(`/api/files/domain-aces?${query}`);
        return Api.parse(res);
    },
    async getAceExceptions() {
        const res = await fetch("/api/ace-exceptions");
        return Api.parse(res);
    },
    async addAceException(principalName) {
        const res = await fetch("/api/ace-exceptions", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ principal_name: principalName })
        });
        return Api.parse(res);
    },
    async deleteAceException(principalName) {
        const res = await fetch(`/api/ace-exceptions/${encodeURIComponent(principalName)}`, { method: "DELETE" });
        return Api.parse(res);
    },
    async optimizeAceExceptions() {
        const res = await fetch("/api/ace-exceptions/optimize", { method: "POST" });
        return Api.parse(res);
    },
    async getDomainResults(kind, params = {}) {
        const query = new URLSearchParams(params);
        const res = await fetch(`/api/domain-results/${kind}?${query}`);
        return Api.parse(res);
    },
    async getDomainOuObjects(dn) {
        const query = new URLSearchParams({ dn });
        const res = await fetch(`/api/domain-ou-objects?${query}`);
        return Api.parse(res);
    },
    async upload(files) {
        const body = new FormData();
        files.forEach(file => body.append("file", file));
        const res = await fetch("/api/files/upload", { method: "POST", body });
        return Api.parse(res);
    }
};