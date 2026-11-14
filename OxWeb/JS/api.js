const Api = {
    async request(url, options) {
        try {
            const res = await fetch(url, options);
            return await res.json();
        } catch (error) {
            return { ok: false, error: "Request failed" };
        }
    },
    json(method, body) {
        return {
            method,
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify(body)
        };
    },
    getMeta() {
        return this.request("/api/meta");
    },
    listTargets() {
        return this.request("/api/targets");
    },
    addTarget(fields) {
        return this.request("/api/targets", this.json("POST", fields));
    },
    deleteTarget(id) {
        return this.request(`/api/targets/${id}`, { method: "DELETE" });
    },
    listWhoisDnsResults() {
        return this.request("/api/whois-dns/results");
    },
    uploadWhoisDns(file) {
        const body = new FormData();
        body.append("file", file);
        return this.request("/api/whois-dns/upload", { method: "POST", body });
    },
    resetWhoisDns() {
        return this.request("/api/whois-dns/reset", { method: "POST" });
    }
};
