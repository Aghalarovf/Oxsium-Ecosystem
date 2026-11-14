const Api = {
    query() {
        const params = new URLSearchParams();
        const f = AppState.filters;
        if (AppState.selectedSubnet) params.set("subnet", AppState.selectedSubnet);
        if (AppState.selectedSubnetGroup) params.set("subnet_group", AppState.selectedSubnetGroup);
        if (f.q) params.set("q", f.q);
        if (f.os.length) params.set("os", f.os.join(","));
        if (f.role.length) params.set("role", f.role.join(","));
        if (f.port) params.set("port", f.port);
        if (f.service) params.set("service", f.service);
        if (f.min_ports) params.set("min_ports", f.min_ports);
        if (f.sort) {
            params.set("sort", f.sort);
            params.set("dir", f.dir);
        }
        const text = params.toString();
        return text ? `?${text}` : "";
    },
    async upload(files) {
        const fd = new FormData();
        (Array.isArray(files) ? files : [files]).forEach(file => fd.append("file", file));
        try {
            const res = await fetch("/api/upload", { method: "POST", body: fd });
            if (res.status === 413) return { ok: false, error: "Upload exceeds the server size limit" };
            return await res.json();
        } catch (error) {
            return { ok: false, error: "Upload failed" };
        }
    },
    async deleteSubnet(subnets) {
        const params = new URLSearchParams();
        (Array.isArray(subnets) ? subnets : [subnets]).forEach(subnet => params.append("subnet", subnet));
        try {
            const res = await fetch(`/api/subnets?${params.toString()}`, { method: "DELETE" });
            return await res.json();
        } catch (error) {
            return { ok: false, error: "Request failed" };
        }
    },
    async updateSubnetName(subnet, specialName) {
        try {
            const res = await fetch("/api/subnets/special-name", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ subnet, special_name: specialName })
            });
            return await res.json();
        } catch (error) {
            return { ok: false, error: "Request failed" };
        }
    },
    async updateSubnetGroup(subnet, groupName) {
        try {
            const res = await fetch("/api/subnets/group", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ subnet, group_name: groupName })
            });
            return await res.json();
        } catch (error) {
            return { ok: false, error: "Request failed" };
        }
    },
    async createSubnetGroup(groupName) {
        try {
            const res = await fetch("/api/subnets/group-name", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ group_name: groupName })
            });
            return await res.json();
        } catch (error) {
            return { ok: false, error: "Request failed" };
        }
    },
    async getMeta() {
        const res = await fetch(`/api/meta${this.query()}`);
        return res.json();
    },
    async getHosts() {
        const res = await fetch(`/api/hosts${this.query()}`);
        return res.json();
    },
    async getAllHosts() {
        const res = await fetch("/api/hosts");
        return res.json();
    },
    async getHostsForSubnet(subnet) {
        const params = new URLSearchParams({ subnet });
        const res = await fetch(`/api/hosts?${params.toString()}`);
        return res.json();
    },
    async getPorts() {
        const res = await fetch(`/api/ports${this.query()}`);
        return res.json();
    },
    async getGraph() {
        const res = await fetch(`/api/graph${this.query()}`);
        return res.json();
    },
    async updateHostNote(host, note) {
        const res = await fetch(`/api/hosts/${encodeURIComponent(host)}/note`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ note })
        });
        return res.json();
    },
    async updateHostRoles(host, roles) {
        const res = await fetch(`/api/hosts/${encodeURIComponent(host)}/roles`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ roles })
        });
        return res.json();
    },
    async updateHostDetails(host, details) {
        const res = await fetch(`/api/hosts/${encodeURIComponent(host)}/details`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify(details)
        });
        return res.json();
    },
    async getVulnerabilities(host) {
        const res = await fetch(`/api/hosts/${encodeURIComponent(host)}/vulnerabilities`);
        return res.json();
    },
    async addVulnerability(host, fields) {
        const res = await fetch(`/api/hosts/${encodeURIComponent(host)}/vulnerabilities`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify(fields)
        });
        return res.json();
    },
    async updateVulnerability(host, vulnId, fields) {
        const res = await fetch(`/api/hosts/${encodeURIComponent(host)}/vulnerabilities/${encodeURIComponent(vulnId)}`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify(fields)
        });
        return res.json();
    },
    async deleteVulnerability(host, vulnId) {
        const res = await fetch(`/api/hosts/${encodeURIComponent(host)}/vulnerabilities/${encodeURIComponent(vulnId)}`, {
            method: "DELETE"
        });
        return res.json();
    },
    async getAllVulnerabilities() {
        const res = await fetch("/api/vulnerabilities/all");
        return res.json();
    },
        async searchCwe(query) {
        const params = new URLSearchParams({ q: query || "" });
        const res = await fetch(`/api/cwe/search?${params.toString()}`);
        return res.json();
    },
    async reset(password) {
        try {
            const res = await fetch("/api/reset", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ password })
            });
            return await res.json();
        } catch (error) {
            return { ok: false, error: "Request failed" };
        }
    }
};