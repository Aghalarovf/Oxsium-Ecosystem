const SEVERITIES = ["critical", "high", "medium", "low", "info"];
const SEVERITY_WEIGHT = { critical: 25, high: 15, medium: 8, low: 3, info: 0 };
const PAGE_SIZE = 5;

const ICONS = {
    globe: '<circle cx="12" cy="12" r="9"/><path d="M3 12h18"/><path d="M12 3a14 14 0 0 1 0 18a14 14 0 0 1 0-18"/>',
    shield: '<path d="M12 3l8 3v6c0 4.5-3.2 8-8 9-4.8-1-8-4.5-8-9V6z"/><path d="M9 12l2 2 4-4"/>',
    alert: '<path d="M12 3l10 18H2z"/><path d="M12 10v5"/><path d="M12 18h.01"/>',
    layers: '<path d="M12 3l9 5-9 5-9-5z"/><path d="M3 13l9 5 9-5"/>',
    clock: '<circle cx="12" cy="12" r="9"/><path d="M12 7v5l3 2"/>',
    server: '<rect x="3" y="4" width="18" height="7" rx="2"/><rect x="3" y="13" width="18" height="7" rx="2"/><path d="M7 7.5h.01M7 16.5h.01"/>',
    inbox: '<path d="M4 13l2-8h12l2 8"/><path d="M4 13v6h16v-6h-5l-1 2h-4l-1-2z"/>',
    chevron: '<path d="m6 9 6 6 6-6"/>',
    id: '<rect x="3" y="5" width="18" height="14" rx="2"/><circle cx="9" cy="11" r="2"/><path d="M6 16c.5-1.5 5.5-1.5 6 0"/><path d="M14 10h4M14 14h4"/>',
    mail: '<rect x="3" y="5" width="18" height="14" rx="2"/><path d="m3 7 9 6 9-6"/>',
    lock: '<rect x="5" y="11" width="14" height="9" rx="2"/><path d="M8 11V8a4 4 0 0 1 8 0v3"/>',
    database: '<ellipse cx="12" cy="6" rx="8" ry="3"/><path d="M4 6v12c0 1.7 3.6 3 8 3s8-1.3 8-3V6"/><path d="M4 12c0 1.7 3.6 3 8 3s8-1.3 8-3"/>',
    network: '<circle cx="12" cy="5" r="2"/><circle cx="5" cy="19" r="2"/><circle cx="19" cy="19" r="2"/><path d="M12 7v5M12 12l-6 5M12 12l6 5"/>',
    copy: '<rect x="9" y="9" width="11" height="11" rx="2"/><path d="M5 15V6a2 2 0 0 1 2-2h9"/>',
    check: '<path d="m5 12 5 5 9-9"/>'
};

const state = { reports: [], query: "", severity: "all", page: 1 };
let panelKeyHandler = null;

function icon(name, size = 18) {
    return `<svg viewBox="0 0 24 24" width="${size}" height="${size}" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">${ICONS[name]}</svg>`;
}

function formatValue(value) {
    if (value === null || value === undefined || value === "") return "—";
    if (typeof value === "object") return JSON.stringify(value, null, 2);
    return String(value);
}

function severityKey(value) {
    const key = String(value || "info").toLowerCase();
    return SEVERITIES.includes(key) ? key : "info";
}

function severityLabel(key) {
    return key.charAt(0).toUpperCase() + key.slice(1);
}

function fmtDate(value) {
    if (!value) return "";
    const date = new Date(value);
    if (Number.isNaN(date.getTime())) return String(value);
    return date.toLocaleString("en-US", { year: "numeric", month: "short", day: "2-digit", hour: "2-digit", minute: "2-digit" });
}

function fmtNumber(value) {
    const number = Number(value);
    return Number.isFinite(number) ? number.toLocaleString("en-US") : "0";
}

function badge(text, tone = "muted") {
    return `<span class="whois-badge tone-${tone}">${Util.esc(text)}</span>`;
}

function muted(text = "—") {
    return `<span class="whois-muted">${Util.esc(text)}</span>`;
}

function riskScore(counts) {
    const raw = SEVERITIES.reduce((sum, key) => sum + (counts[key] || 0) * SEVERITY_WEIGHT[key], 0);
    return Math.min(100, raw);
}

function topSeverity(counts) {
    return SEVERITIES.find(key => counts[key] > 0) || null;
}

function normalizeReport(report, index) {
    const findings = Object.entries(report)
        .filter(([name]) => name.startsWith("finding_"))
        .flatMap(([, value]) => Array.isArray(value) ? value : [value])
        .filter(item => item !== null && item !== undefined && item !== "")
        .map(item => item && typeof item === "object" ? item : { title: String(item) })
        .sort((a, b) => SEVERITIES.indexOf(severityKey(a.severity)) - SEVERITIES.indexOf(severityKey(b.severity)));

    const checks = [];
    const cdn = [];
    const records = [];
    const seen = new Set();
    Object.entries(report)
        .filter(([name]) => name.startsWith("check_"))
        .forEach(([name, value]) => {
            const split = splitRecords(value);
            if (normKey(name) === "checkrecords") {
                split.records.forEach(record => {
                    const id = `${record.type}|${record.name}|${record.value}`;
                    if (seen.has(id)) return;
                    seen.add(id);
                    records.push({ ...record, source: name });
                });
                return;
            }
            if (!split.records.length) {
                (isCdnCheck(name) ? cdn : checks).push({ name, value });
                return;
            }
            split.records.forEach(record => {
                const id = `${record.type}|${record.name}|${record.value}`;
                if (seen.has(id)) return;
                seen.add(id);
                records.push({ ...record, source: name });
            });
            if (!isEmpty(split.rest)) (isCdnCheck(name) ? cdn : checks).push({ name, value: split.rest });
        });

    const counts = {};
    SEVERITIES.forEach(key => {
        const stored = report[`${key}_count`];
        counts[key] = stored === null || stored === undefined || Number.isNaN(Number(stored))
            ? findings.filter(item => severityKey(item.severity) === key).length
            : Number(stored);
    });

    const top = topSeverity(counts);
    const searchText = [
        report.target, report.source_name, report.profile, report.status,
        ...findings.map(item => `${item.title || ""} ${item.id || ""} ${item.check || ""}`),
        ...records.map(item => `${item.type} ${item.value}`),
        ...cdn.map(item => `${item.name} ${formatValue(item.value)}`)
    ].join(" ").toLowerCase();

    return {
        index,
        raw: report,
        target: report.target || "Unknown target",
        source: report.source_name || "unknown source",
        profile: report.profile || "unknown",
        status: report.status || "unknown",
        time: report.finished_at || report.started_at || "",
        total: report.findings_total ?? findings.length,
        findings,
        checks,
        cdn,
        records,
        counts,
        top,
        score: riskScore(counts),
        searchText
    };
}

function renderSummary(reports) {
    const totals = {};
    SEVERITIES.forEach(key => { totals[key] = reports.reduce((sum, report) => sum + report.counts[key], 0); });
    const totalFindings = reports.reduce((sum, report) => sum + Number(report.total || 0), 0);
    const targets = new Set(reports.map(report => report.target)).size;
    const sources = new Set(reports.map(report => report.source)).size;
    const top = topSeverity(totals);
    const tone = top || "info";
    const score = riskScore(totals);
    const urgent = totals.critical + totals.high;
    const riskiest = [...reports].sort((a, b) => b.score - a.score);
    const latest = [...reports].sort((a, b) => String(b.time).localeCompare(String(a.time)))[0];

    const checkCounts = {};
    reports.forEach(report => report.findings.forEach(item => {
        const name = item.check || "whois_dns";
        checkCounts[name] = (checkCounts[name] || 0) + 1;
    }));
    const checkEntries = Object.entries(checkCounts).sort((a, b) => b[1] - a[1]);

    const stats = [
        { tone: "blue", icon: "layers", label: "Reports", main: fmtNumber(reports.length), sub: `${sources} source${sources === 1 ? "" : "s"}` },
        { tone: totalFindings ? "red" : "green", icon: "shield", label: "Findings", main: fmtNumber(totalFindings), sub: `${totals.medium + totals.low} medium or low` },
        { tone: urgent ? "red" : "green", icon: "alert", label: "Critical and high", main: fmtNumber(urgent), sub: urgent ? "Needs review" : "Nothing urgent" },
        { tone: "amber", icon: "globe", label: "Targets", main: fmtNumber(targets), sub: `${fmtNumber(totals.info)} informational` }
    ];

    return `
        <div class="whois-hero tone-${tone}">
            <div class="whois-hero-main">
                <div class="whois-eyebrow">WHOIS / DNS OVERVIEW</div>
                <h1>${fmtNumber(targets)} target${targets === 1 ? "" : "s"} analysed</h1>
                <div class="whois-hero-tags">
                    <span class="whois-hero-tag">${icon("globe", 13)}${Util.esc(riskiest[0].target)}</span>
                    ${latest && latest.time ? `<span class="whois-hero-tag whois-hero-tag-mono">${icon("clock", 13)}${Util.esc(fmtDate(latest.time))}</span>` : ""}
                </div>
            </div>
            <div class="whois-risk tone-${tone}" style="--risk-pct:${score}">
                <div class="whois-ring"><strong>${fmtNumber(totalFindings)}</strong></div>
                <span>Findings</span>
                <small>${top ? severityLabel(top) : "Clean"}</small>
            </div>
        </div>
        <div class="whois-stat-grid">
            ${stats.map((stat, index) => `
            <div class="whois-stat whois-stat-${stat.tone}" style="--i:${index}">
                <div class="whois-stat-icon">${icon(stat.icon)}</div>
                <div class="whois-stat-body">
                    <span>${Util.esc(stat.label)}</span>
                    <strong>${stat.main}</strong>
                    <small>${Util.esc(stat.sub)}</small>
                </div>
            </div>`).join("")}
        </div>
        <div class="whois-summary-grid">
            <section class="whois-panel-card whois-panel-amber">
                <div class="whois-panel-title">Severity breakdown</div>
                <div class="whois-kv-list">
                    ${SEVERITIES.map(key => `
                    <div class="whois-kv tone-${key}"><span>${severityLabel(key)}</span>${totals[key] ? badge(String(totals[key]), key) : muted("0")}</div>`).join("")}
                </div>
            </section>
            <section class="whois-panel-card whois-panel-purple">
                <div class="whois-panel-title">Finding checks</div>
                <div class="whois-chip-list">
                    ${checkEntries.length
                        ? checkEntries.map(([name, count], i) => `<span class="whois-chip chip-tone-${i % 5}">${Util.esc(name)} · ${count}</span>`).join("")
                        : muted("No findings recorded")}
                </div>
            </section>
            <section class="whois-panel-card whois-panel-wide whois-panel-blue">
                <div class="whois-panel-title">Targets by risk</div>
                <div class="whois-target-list">
                    ${riskiest.slice(0, 6).map(report => `
                    <button type="button" class="whois-target-row" data-target="${Util.esc(report.target)}">
                        <span class="whois-target-icon">DNS</span>
                        <span class="whois-target-text">
                            <strong>${Util.esc(report.target)}</strong>
                            <small>${Util.esc(report.source)} · ${Util.esc(report.profile)}</small>
                        </span>
                        ${report.top ? badge(`${fmtNumber(report.total)} · ${severityLabel(report.top)}`, report.top) : badge("No findings", "ok")}
                    </button>`).join("")}
                </div>
            </section>
        </div>`;
}

const DNS_TYPES = /^(A|AAAA|MX|NS|TXT|CNAME|SOA|SRV|CAA|PTR|DNSKEY|DS|RRSIG|NSEC3?|SPF)$/i;
const BAD_KEYS = /(expired|vulnerable|missing|error|fail|insecure|exposed|takeover|misconfig|weak|invalid|dangling)/i;
const STATUS_KEYS = /(status|state|result|verdict|policy|valid|enabled)$/i;
const GOOD_WORDS = /(pass|ok|valid|enabled|secure|signed|active|found|success|reject|quarantine)/i;
const BAD_WORDS = /(fail|invalid|missing|none|disabled|insecure|expired|vulnerable|error|unsigned|not found)/i;
const DATE_RE = /^\d{4}-\d{2}-\d{2}([T ]\d{2}:\d{2}(:\d{2})?(\.\d+)?(Z|[+-]\d{2}:?\d{2})?)?$/;
const IP_RE = /^(\d{1,3}\.){3}\d{1,3}$|^[0-9a-f]*:[0-9a-f:]+$/i;
const HOST_RE = /^[\w-]+(\.[\w-]+)+\.?$/;
const ACRONYMS = /\b(dns|dnssec|spf|dkim|dmarc|mx|ns|ssl|tls|ip|asn|whois|ttl|soa|txt|caa|ptr|cname|axfr|smtp|http|https|id)\b/gi;

const CDN_RE = /cdn/i;

function isCdnCheck(name) {
    return CDN_RE.test(String(name).replace(/^check_/, ""));
}

const CHECK_HINTS = [
    [/cdn/, "network", "teal"],
    [/whois|registr|domain_?info/, "id", "amber"],
    [/dnssec/, "lock", "green"],
    [/(^|_)(mx|spf|dkim|dmarc|mail|email|smtp)($|_)/, "mail", "blue"],
    [/zone|axfr|transfer/, "network", "purple"],
    [/takeover|dangling/, "alert", "red"],
    [/(^|_)(ns|nameservers?|name_servers?)($|_)/, "server", "teal"],
    [/dns|record|resolv/, "database", "blue"],
    [/ssl|tls|cert/, "lock", "teal"],
    [/(^|_)(ip|asn|geo|network|host)($|_)/, "network", "blue"]
];

const TONE_COLORS = {
    amber: "var(--accent)",
    blue: "var(--blue)",
    green: "var(--green)",
    teal: "#2cb5b0",
    purple: "#a07be8",
    red: "#e8694a"
};

function labelize(key) {
    return String(key).replace(/^check_/, "").replace(/([a-z])([A-Z])/g, "$1 $2").replace(/[_-]+/g, " ").trim();
}

function prettyTitle(key) {
    return labelize(key).replace(/\b\w/g, c => c.toUpperCase()).replace(ACRONYMS, m => m.toUpperCase());
}

function isPrimitive(value) {
    return value === null || typeof value !== "object";
}

function isEmpty(value) {
    if (value === null || value === undefined || value === "") return true;
    if (Array.isArray(value)) return value.length === 0;
    if (typeof value === "object") return Object.keys(value).length === 0;
    return false;
}

function fmtDay(value) {
    if (String(value).length === 10) {
        const date = new Date(value);
        return Number.isNaN(date.getTime()) ? String(value)
            : date.toLocaleDateString("en-US", { year: "numeric", month: "short", day: "2-digit", timeZone: "UTC" });
    }
    return fmtDate(value);
}

function checkHint(name) {
    const base = name.replace(/^check_/, "").toLowerCase();
    const hit = CHECK_HINTS.find(([re]) => re.test(base));
    return hit ? { icon: hit[1], tone: hit[2] } : { icon: "layers", tone: "amber" };
}

function checkMeta(value) {
    if (Array.isArray(value)) return `${value.length} item${value.length === 1 ? "" : "s"}`;
    if (value && typeof value === "object") {
        const size = Object.keys(value).length;
        return `${size} field${size === 1 ? "" : "s"}`;
    }
    return value === null || value === undefined || value === "" ? "empty" : "single value";
}

function renderScalar(key, value, ctx, inline = false) {
    if (value === null || value === undefined || value === "") return muted();
    if (typeof value === "boolean") {
        const bad = BAD_KEYS.test(key || "");
        const tone = value ? (bad ? "critical" : "ok") : (bad ? "ok" : "muted");
        return badge(value ? "Yes" : "No", tone);
    }
    if (typeof value === "number") return `<span class="whois-num">${Util.esc(String(value))}</span>`;
    const text = String(value);
    if (DATE_RE.test(text)) return `<span class="whois-date">${Util.esc(fmtDay(text))}</span>`;
    if (!inline && (text.length > 180 || text.includes("\n"))) {
        ctx.wide = true;
        return `<pre class="whois-text">${Util.esc(text)}</pre>`;
    }
    if (inline && text.length > 90) return `<span class="whois-trunc" title="${Util.esc(text)}">${Util.esc(text.slice(0, 88))}…</span>`;
    if (text.length <= 40 && STATUS_KEYS.test(key || "")) {
        const tone = BAD_WORDS.test(text) ? "high" : GOOD_WORDS.test(text) ? "ok" : "info";
        return badge(text, tone);
    }
    if (IP_RE.test(text) || HOST_RE.test(text)) return `<code class="whois-code">${Util.esc(text)}</code>`;
    return Util.esc(text);
}

function renderInline(key, value) {
    if (Array.isArray(value)) {
        if (!value.length) return muted();
        const head = value.slice(0, 3).map(item => {
            const text = isPrimitive(item) ? String(item) : JSON.stringify(item).slice(0, 60);
            return `<code class="whois-code">${Util.esc(text)}</code>`;
        }).join(" ");
        return head + (value.length > 3 ? ` <span class="whois-muted">+${value.length - 3}</span>` : "");
    }
    if (value && typeof value === "object") return `<code class="whois-code">${Util.esc(JSON.stringify(value).slice(0, 90))}</code>`;
    return renderScalar(key, value, {}, true);
}

function renderChips(items, ctx) {
    if (items.some(item => String(item).length > 50)) {
        ctx.wide = true;
        return `<ul class="whois-list">${items.slice(0, 40).map(item => `<li><code class="whois-code">${Util.esc(String(item))}</code></li>`).join("")}</ul>${items.length > 40 ? `<div class="whois-more">Showing 40 of ${items.length}</div>` : ""}`;
    }
    const max = 30;
    return `<div class="whois-chips">${items.slice(0, max).map(item => `<span class="whois-chip">${Util.esc(String(item))}</span>`).join("")}${items.length > max ? `<span class="whois-chip whois-chip-more">+${items.length - max} more</span>` : ""}</div>`;
}

function renderTable(rows, ctx) {
    ctx.wide = true;
    const columns = [];
    rows.slice(0, 25).forEach(row => Object.keys(row).forEach(name => { if (!columns.includes(name)) columns.push(name); }));
    const shown = columns.slice(0, 6);
    const slice = rows.slice(0, 50);
    return `
        <div class="whois-mini-wrap">
            <table class="whois-mini-table">
                <thead><tr>${shown.map(name => `<th>${Util.esc(prettyTitle(name))}</th>`).join("")}</tr></thead>
                <tbody>${slice.map(row => `<tr>${shown.map(name => `<td>${renderInline(name, row[name])}</td>`).join("")}</tr>`).join("")}</tbody>
            </table>
        </div>
        ${rows.length > slice.length ? `<div class="whois-more">Showing ${slice.length} of ${rows.length} rows</div>` : ""}
        ${columns.length > shown.length ? `<div class="whois-more">${columns.length - shown.length} more column${columns.length - shown.length === 1 ? "" : "s"} in Raw JSON</div>` : ""}`;
}

function renderRecordGroups(obj, ctx) {
    ctx.wide = true;
    const rows = Object.entries(obj)
        .filter(([, value]) => !isEmpty(value))
        .map(([type, value]) => {
            const list = Array.isArray(value) ? value : [value];
            const values = list.map(item => item && typeof item === "object"
                ? Object.values(item).map(part => formatValue(part)).join("  ")
                : String(item));
            return `
                <div class="whois-record">
                    <span class="whois-rtype rt-${Util.esc(type.toLowerCase())}">${Util.esc(type.toUpperCase())}</span>
                    <div class="whois-rvals">${values.map(item => `<code class="whois-code">${Util.esc(item)}</code>`).join("")}</div>
                    <span class="whois-rcount">${list.length}</span>
                </div>`;
        });
    return rows.length ? `<div class="whois-records">${rows.join("")}</div>` : muted("No records");
}

function renderObject(obj, ctx, depth) {
    const entries = Object.entries(obj);
    if (!entries.length) return muted("No data returned");
    const recordish = entries.filter(([name]) => DNS_TYPES.test(name)).length >= Math.max(1, Math.ceil(entries.length / 2));
    if (recordish) return renderRecordGroups(obj, ctx);

    const scalars = entries.filter(([, value]) => isPrimitive(value));
    const nested = entries.filter(([, value]) => !isPrimitive(value));
    let html = "";
    if (scalars.length) {
        html += `<div class="whois-fields">${scalars.map(([name, value]) => {
            const cell = renderScalar(name, value, ctx);
            const full = cell.startsWith("<pre");
            return `<div class="whois-field${full ? " whois-field-full" : ""}"><span>${Util.esc(prettyTitle(name))}</span><div>${cell}</div></div>`;
        }).join("")}</div>`;
    }
    nested.forEach(([name, value]) => {
        html += `<div class="whois-sub"><div class="whois-sub-title">${Util.esc(prettyTitle(name))}</div>${renderAny(value, name, ctx, depth + 1)}</div>`;
    });
    return html;
}

function renderAny(value, key, ctx, depth) {
    if (isPrimitive(value)) return renderScalar(key, value, ctx);
    if (Array.isArray(value)) {
        if (!value.length) return muted("None");
        if (value.every(isPrimitive)) return renderChips(value, ctx);
        return renderTable(value.map(item => item && typeof item === "object" && !Array.isArray(item) ? item : { value: item }), ctx);
    }
    if (depth > 3) {
        ctx.wide = true;
        return `<pre class="whois-text">${Util.esc(formatValue(value))}</pre>`;
    }
    return renderObject(value, ctx, depth);
}

function normKey(value) {
    return String(value || "").toLowerCase().replace(/[^a-z0-9]/g, "");
}

function findingsForCheck(report, name) {
    const base = normKey(name.replace(/^check_/, ""));
    return report.findings.filter(finding => {
        const other = normKey(finding.check);
        if (!other || other === "whoisdns") return false;
        return other === base || (base.length >= 3 && other.length >= 3 && (other.includes(base) || base.includes(other)));
    });
}

const RECORD_ORDER = ["A", "AAAA", "CNAME", "MX", "NS", "TXT", "SPF", "SOA", "CAA", "SRV", "PTR", "DNSKEY", "DS", "RRSIG", "NSEC", "NSEC3"];
const RECORD_LABELS = {
    A: "IPv4 addresses",
    AAAA: "IPv6 addresses",
    CNAME: "Canonical names",
    MX: "Mail exchangers",
    NS: "Name servers",
    TXT: "Text records",
    SPF: "SPF policy",
    SOA: "Start of authority",
    CAA: "Certificate authorities",
    SRV: "Service locators",
    PTR: "Reverse pointers",
    DNSKEY: "DNSSEC keys",
    DS: "Delegation signers",
    RRSIG: "Signatures",
    NSEC: "Authenticated denial",
    NSEC3: "Hashed denial"
};
const MAIN_KEYS = ["value", "data", "address", "ip", "exchange", "target", "host", "hostname", "nameserver", "content", "record", "text", "answer"];
const META_KEYS = /^(ttl|priority|preference|pref|weight|port|class|flags|tag)$/i;
const TYPE_KEYS = ["type", "record_type", "rtype"];

function rowType(row) {
    const key = TYPE_KEYS.find(name => typeof row[name] === "string");
    return key ? row[key] : "";
}

function isTypedRow(item) {
    return Boolean(item) && typeof item === "object" && !Array.isArray(item) && DNS_TYPES.test(rowType(item));
}

function isRecordRows(value) {
    return Array.isArray(value) && value.length > 0 && value.every(isTypedRow);
}

function isRecordMap(value) {
    if (!value || typeof value !== "object" || Array.isArray(value)) return false;
    const entries = Object.entries(value);
    if (!entries.length) return false;
    return entries.filter(([name]) => DNS_TYPES.test(name)).length >= Math.max(1, Math.ceil(entries.length / 2));
}

function toRecord(type, item) {
    const base = { type: String(type).toUpperCase(), value: "", name: "", meta: [] };
    if (isPrimitive(item)) return { ...base, value: formatValue(item) };
    if (Array.isArray(item)) return { ...base, value: item.map(formatValue).join("  ") };
    const keys = Object.keys(item).filter(name => !TYPE_KEYS.includes(name));
    const mainKey = MAIN_KEYS.find(name => keys.includes(name) && !isEmpty(item[name]));
    const meta = keys
        .filter(name => META_KEYS.test(name) && isPrimitive(item[name]) && !isEmpty(item[name]))
        .map(name => [name.toUpperCase(), String(item[name])]);
    const owner = mainKey && typeof item.name === "string" ? item.name : "";
    const value = mainKey
        ? formatValue(item[mainKey])
        : keys.filter(name => !META_KEYS.test(name) && !isEmpty(item[name])).map(name => formatValue(item[name])).join("  ");
    return { ...base, value, name: owner, meta };
}

function rowsToRecords(rows) {
    return rows.map(row => toRecord(rowType(row), row)).filter(record => record.value);
}

function mapToRecords(type, items) {
    const list = Array.isArray(items) ? items : [items];
    const records = [];
    list.filter(item => !isEmpty(item)).forEach(item => {
        if (item && typeof item === "object" && !Array.isArray(item) && Array.isArray(item.records)) {
            item.records
                .filter(record => !isEmpty(record))
                .forEach(record => records.push(toRecord(type, record)));
            return;
        }
        records.push(toRecord(type, item));
    });
    return records.filter(record => record.value);
}

function splitRecords(value) {
    if (isRecordRows(value)) return { records: rowsToRecords(value), rest: undefined };
    if (!value || typeof value !== "object" || Array.isArray(value)) return { records: [], rest: value };
    if (isRecordMap(value)) {
        const records = [];
        const rest = {};
        Object.entries(value).forEach(([name, items]) => {
            if (DNS_TYPES.test(name)) records.push(...mapToRecords(name, items));
            else rest[name] = items;
        });
        return { records, rest: Object.keys(rest).length ? rest : undefined };
    }
    const records = [];
    const rest = {};
    Object.entries(value).forEach(([name, inner]) => {
        if (/^(dns_?)?records?$/i.test(name) && (isRecordMap(inner) || isRecordRows(inner))) {
            records.push(...splitRecords(inner).records);
        } else {
            rest[name] = inner;
        }
    });
    if (!records.length) return { records: [], rest: value };
    return { records, rest: Object.keys(rest).length ? rest : undefined };
}

function recordKey(type) {
    return String(type).toLowerCase().replace(/[^a-z0-9]/g, "");
}

function groupRecords(records) {
    const map = new Map();
    records.forEach(record => {
        if (!map.has(record.type)) map.set(record.type, []);
        map.get(record.type).push(record);
    });
    const rank = type => {
        const position = RECORD_ORDER.indexOf(type);
        return position === -1 ? RECORD_ORDER.length : position;
    };
    return [...map.entries()]
        .map(([type, items]) => ({ type, items }))
        .sort((a, b) => rank(a.type) - rank(b.type) || a.type.localeCompare(b.type));
}

function renderRecordItem(record) {
    const sub = [
        record.name ? `<span class="whois-rec-name">${Util.esc(record.name)}</span>` : "",
        ...record.meta.map(([key, value]) => `<span class="whois-rec-pill">${Util.esc(key)} ${Util.esc(value)}</span>`)
    ].join("");
    return `
        <li class="whois-rec-item">
            <div class="whois-rec-body">
                <span class="whois-rec-value">${Util.esc(record.value)}</span>
                ${sub ? `<div class="whois-rec-sub">${sub}</div>` : ""}
            </div>
            <button type="button" class="whois-rec-copy" data-copy="${Util.esc(record.value)}" aria-label="Copy value" title="Copy">${icon("copy", 14)}</button>
        </li>`;
}

function renderRecordGroup(group, position) {
    const key = recordKey(group.type);
    const count = group.items.length;
    const wide = group.items.some(item => item.value.length > 70);
    return `
        <section class="whois-rec-group rt-${key}${wide ? " whois-rec-group-wide" : ""}" data-rec-group="${key}" style="--i:${position}">
            <header class="whois-rec-head">
                <span class="whois-rtype rt-${key}">${Util.esc(group.type)}</span>
                <div class="whois-rec-title">
                    <h4>${Util.esc(RECORD_LABELS[group.type] || "DNS records")}</h4>
                    <small>${count} record${count === 1 ? "" : "s"}</small>
                </div>
                <span class="whois-rec-count">${fmtNumber(count)}</span>
            </header>
            <ul class="whois-rec-list">${group.items.map(renderRecordItem).join("")}</ul>
        </section>`;
}

function renderRecords(report) {
    const title = `<div class="whois-section-title">Records · ${fmtNumber(report.records.length)}</div>`;
    if (!report.records.length) return `${title}<div class="whois-empty whois-empty-sm">No records stored</div>`;
    const groups = groupRecords(report.records);
    return `
        ${title}
        <div class="whois-rec">
            <div class="whois-rec-bar">
                <div class="whois-rec-tabs" role="group" aria-label="Filter records by type">
                    <button type="button" class="whois-rec-tab active" data-rec-type="all">All<b>${fmtNumber(report.records.length)}</b></button>
                    ${groups.map(group => `<button type="button" class="whois-rec-tab rt-${recordKey(group.type)}" data-rec-type="${recordKey(group.type)}">${Util.esc(group.type)}<b>${fmtNumber(group.items.length)}</b></button>`).join("")}
                </div>
            </div>
            <div class="whois-rec-grid">${groups.map(renderRecordGroup).join("")}</div>
        </div>`;
}

function cdnFieldRows(value, ctx) {
    if (!value || typeof value !== "object" || Array.isArray(value)) return "";
    const entries = Object.entries(value).filter(([, v]) => !isEmpty(v));
    const scalars = entries.filter(([, v]) => isPrimitive(v));
    const nested = entries.filter(([, v]) => !isPrimitive(v));
    let html = scalars.length ? `
        <div class="whois-fields">${scalars.map(([name, v]) => {
            const cell = renderScalar(name, v, ctx);
            const full = cell.startsWith("<pre");
            return `<div class="whois-field${full ? " whois-field-full" : ""}"><span>${Util.esc(prettyTitle(name))}</span><div>${cell}</div></div>`;
        }).join("")}</div>` : "";
    nested.forEach(([name, v]) => {
        if (Array.isArray(v) && v.every(isPrimitive)) {
            html += `<div class="whois-sub"><div class="whois-sub-title">${Util.esc(prettyTitle(name))}</div>${renderChips(v, ctx)}</div>`;
        } else {
            html += `<div class="whois-sub"><div class="whois-sub-title">${Util.esc(prettyTitle(name))}</div>${renderAny(v, name, ctx, 1)}</div>`;
        }
    });
    return html;
}

function cdnEntryMeta(value) {
    if (Array.isArray(value)) return `${value.length} item${value.length === 1 ? "" : "s"}`;
    if (value && typeof value === "object") {
        const size = Object.keys(value).length;
        return `${size} field${size === 1 ? "" : "s"}`;
    }
    return isEmpty(value) ? "empty" : "single value";
}

function renderCdnEntry(entry, position) {
    const ctx = { wide: false };
    const empty = isEmpty(entry.value);
    const body = empty
        ? '<div class="whois-block-empty">No data returned</div>'
        : (Array.isArray(entry.value)
            ? (entry.value.every(isPrimitive) ? renderChips(entry.value, ctx) : renderTable(entry.value.map(item => item && typeof item === "object" ? item : { value: item }), ctx))
            : (cdnFieldRows(entry.value, ctx) || renderScalar(entry.name, entry.value, ctx)));
    return `
        <section class="whois-rec-group rt-cdn${ctx.wide ? " whois-rec-group-wide" : ""}" style="--i:${position}">
            <header class="whois-rec-head">
                <span class="whois-rtype rt-cdn">${icon("network", 15)}</span>
                <div class="whois-rec-title">
                    <h4>${Util.esc(prettyTitle(entry.name))}</h4>
                    <small>${Util.esc(cdnEntryMeta(entry.value))}</small>
                </div>
            </header>
            <div class="whois-cdn-body">${body}</div>
        </section>`;
}

function renderCdnSection(report) {
    if (!report.cdn.length) return "";
    const title = `<div class="whois-section-title">CDN · ${fmtNumber(report.cdn.length)}</div>`;
    return `
        ${title}
        <div class="whois-rec whois-cdn">
            <div class="whois-rec-grid">${report.cdn.map(renderCdnEntry).join("")}</div>
        </div>`;
}

function copyText(text) {
    if (navigator.clipboard && navigator.clipboard.writeText) return navigator.clipboard.writeText(text);
    return new Promise((resolve, reject) => {
        const area = document.createElement("textarea");
        area.value = text;
        area.style.position = "fixed";
        area.style.opacity = "0";
        document.body.appendChild(area);
        area.select();
        const done = document.execCommand("copy");
        area.remove();
        if (done) resolve();
        else reject(new Error("copy failed"));
    });
}

function renderCheckSection(check, report, position) {
    const hint = checkHint(check.name);
    const tone = TONE_COLORS[hint.tone] || "var(--accent)";
    const ctx = { wide: false };
    const empty = isEmpty(check.value);
    const body = empty
        ? '<div class="whois-block-empty">No data returned</div>'
        : (Array.isArray(check.value)
            ? (check.value.every(isPrimitive) ? renderChips(check.value, ctx) : renderTable(check.value.map(item => item && typeof item === "object" ? item : { value: item }), ctx))
            : (cdnFieldRows(check.value, ctx) || renderScalar(check.name, check.value, ctx)));
    const linked = findingsForCheck(report, check.name);
    const linkedTop = SEVERITIES.find(key => linked.some(finding => severityKey(finding.severity) === key));
    const raw = empty ? "" : `
        <details class="whois-raw">
            <summary><span class="whois-chevron">${icon("chevron", 12)}</span>Raw JSON</summary>
            <pre>${Util.esc(formatValue(check.value))}</pre>
        </details>`;
    const title = `<div class="whois-section-title">${Util.esc(prettyTitle(check.name))} · ${Util.esc(checkMeta(check.value))}</div>`;
    return `
        ${title}
        <div class="whois-rec">
            <div class="whois-rec-grid">
                <section class="whois-rec-group${ctx.wide ? " whois-rec-group-wide" : ""}" style="--tone:${tone};--i:${position}">
                    <header class="whois-rec-head">
                        <span class="whois-rtype" style="--tone:${tone}">${icon(hint.icon, 15)}</span>
                        <div class="whois-rec-title">
                            <h4>${Util.esc(prettyTitle(check.name))}</h4>
                            <small>${Util.esc(checkMeta(check.value))}</small>
                        </div>
                        ${linkedTop ? badge(`${linked.length} finding${linked.length === 1 ? "" : "s"}`, linkedTop) : ""}
                    </header>
                    <div class="whois-cdn-body">${body}${raw}</div>
                </section>
            </div>
        </div>`;
}

function orderedChecks(checks) {
    const priority = ["checkipintel", "checkreversedns", "checkwhois", "checkzonetransfer"];
    const selected = [];
    const remaining = [];

    priority.forEach(name => {
        const check = checks.find(item => normKey(item.name) === name);
        if (check) selected.push(check);
    });
    checks.forEach(check => {
        if (!selected.includes(check)) remaining.push(check);
    });

    return [...selected, ...remaining];
}

function renderFindingRow(finding, report, findingIndex) {
    const key = severityKey(finding.severity);
    return `
        <tr class="whois-row tone-${key} whois-row-clickable" data-report="${report.index}" data-finding="${findingIndex}" tabindex="0">
            <td>${badge(severityLabel(key), key)}</td>
            <td><strong>${Util.esc(finding.title || finding.id || "Finding")}</strong>${finding.id ? `<small>${Util.esc(finding.id)}</small>` : ""}</td>
            <td><span>${Util.esc(finding.check || "whois_dns")}</span><small>${Util.esc(finding.confidence || "unrated")} confidence</small></td>
            <td class="whois-desc-cell"><span class="whois-desc">${Util.esc(finding.description || "No description provided.")}</span></td>
        </tr>`;
}

function renderReport(report, position) {
    const tone = report.top || "info";
    const clean = !report.top;
    return `
        <article class="whois-report tone-${tone}" style="--i:${position}">
            <div class="whois-report-head">
                <div class="whois-mini-risk tone-${tone}" style="--risk-pct:${report.score}">
                    <div class="whois-ring whois-ring-sm"><strong>${fmtNumber(report.total)}</strong></div>
                </div>
                <div class="whois-report-title">
                    <div class="whois-target">${Util.esc(report.target)}</div>
                    <div class="whois-badge-row">
                        ${badge(report.source, "info")}
                        ${badge(report.profile, "muted")}
                        ${badge(report.status, String(report.status).toLowerCase() === "completed" || String(report.status).toLowerCase() === "success" ? "ok" : "muted")}
                    </div>
                </div>
                <div class="whois-report-side">
                    ${clean ? badge("No findings", "ok") : badge(severityLabel(tone), tone)}
                    <div class="whois-report-time">${Util.esc(fmtDate(report.time))}</div>
                </div>
            </div>
            <div class="whois-sev-row">
                ${SEVERITIES.map(key => `
                <div class="whois-sev tone-${key}${report.counts[key] ? " is-active" : ""}"><b>${fmtNumber(report.counts[key])}</b><span>${key}</span></div>`).join("")}
            </div>
            <div class="whois-section-title">Findings · ${fmtNumber(report.total)}</div>
            ${report.findings.length ? `
            <div class="whois-table-wrap">
                <table class="whois-table">
                    <thead><tr><th>Severity</th><th>Finding</th><th>Check</th><th>Description</th></tr></thead>
                    <tbody>${report.findings.map((finding, i) => renderFindingRow(finding, report, i)).join("")}</tbody>
                </table>
            </div>` : '<div class="whois-empty whois-empty-sm">No findings stored</div>'}
            ${renderRecords(report)}
            ${renderCdnSection(report)}
            ${orderedChecks(report.checks).map((check, i) => renderCheckSection(check, report, i)).join("")}
        </article>`;
}

function closePanel(immediate = false) {
    const overlay = document.querySelector(".whois-overlay");
    if (panelKeyHandler) {
        document.removeEventListener("keydown", panelKeyHandler);
        panelKeyHandler = null;
    }
    if (!overlay) return;
    if (immediate) {
        overlay.remove();
        return;
    }
    overlay.classList.add("closing");
    setTimeout(() => overlay.remove(), 180);
}

function openFindingPanel(finding, report) {
    closePanel(true);
    const key = severityKey(finding.severity);
    const known = new Set(["severity", "title", "id", "check", "confidence", "description", "evidence"]);
    const extra = Object.entries(finding).filter(([name]) => !known.has(name));
    const hasEvidence = finding.evidence !== null && finding.evidence !== undefined
        && !(typeof finding.evidence === "object" && Object.keys(finding.evidence).length === 0)
        && finding.evidence !== "";
    const val = value => value === null || value === undefined || value === ""
        ? muted()
        : Util.esc(typeof value === "object" ? JSON.stringify(value) : String(value));
    const kv = (label, html) => `<div class="whois-detail-kv"><span>${Util.esc(label)}</span><strong>${html}</strong></div>`;
    const title = finding.title || finding.id || "Finding";
    const initials = String(finding.id || key).slice(0, 3).toUpperCase();

    const overlay = document.createElement("div");
    overlay.className = "whois-overlay";
    overlay.innerHTML = `
        <aside class="whois-panel tone-${key}" role="dialog" aria-modal="true" aria-label="Finding details">
            <div class="whois-panel-header">
                <div class="whois-panel-avatar">${Util.esc(initials)}</div>
                <div class="whois-panel-heading">
                    <h2>${Util.esc(title)}</h2>
                    <span class="whois-panel-sub">${Util.esc(report.target)}</span>
                </div>
                <button class="whois-panel-close" type="button" aria-label="Close">&times;</button>
            </div>
            <div class="whois-panel-status">
                ${badge(severityLabel(key), key)}
                ${badge(finding.check || "whois_dns", "info")}
                ${badge(finding.confidence || "unrated", "muted")}
            </div>
            <div class="whois-panel-body">
                <section class="whois-detail-section">
                    <div class="whois-detail-title">Overview</div>
                    <div class="whois-detail-grid">
                        ${kv("Finding ID", val(finding.id))}
                        ${kv("Severity", val(severityLabel(key)))}
                        ${kv("Check", val(finding.check || "whois_dns"))}
                        ${kv("Confidence", val(finding.confidence))}
                        ${kv("Target", val(report.target))}
                        ${kv("Source", val(report.source))}
                    </div>
                </section>
                <section class="whois-detail-section">
                    <div class="whois-detail-title">Description</div>
                    <p>${Util.esc(finding.description || "No description provided.")}</p>
                </section>
                <section class="whois-detail-section">
                    <div class="whois-detail-title">Evidence</div>
                    ${hasEvidence ? `<pre>${Util.esc(formatValue(finding.evidence))}</pre>` : muted("No evidence recorded")}
                </section>
                ${extra.length ? `
                <section class="whois-detail-section">
                    <div class="whois-detail-title">Additional fields</div>
                    <div class="whois-detail-grid">${extra.map(([name, value]) => kv(name.replace(/[-_]+/g, " "), val(value))).join("")}</div>
                </section>` : ""}
            </div>
        </aside>`;

    overlay.addEventListener("mousedown", event => { if (event.target === overlay) closePanel(); });
    overlay.querySelector(".whois-panel-close").addEventListener("click", () => closePanel());
    document.body.appendChild(overlay);
    panelKeyHandler = event => { if (event.key === "Escape") closePanel(); };
    document.addEventListener("keydown", panelKeyHandler);
}

function filteredReports() {
    const query = state.query.trim().toLowerCase();
    return state.reports.filter(report => {
        if (state.severity !== "all" && !(report.counts[state.severity] > 0)) return false;
        return !query || report.searchText.includes(query);
    });
}

function paintList(root) {
    const list = root.querySelector(".whois-report-list");
    const filtered = filteredReports();
    const pages = Math.max(1, Math.ceil(filtered.length / PAGE_SIZE));
    if (state.page > pages) state.page = pages;
    const slice = filtered.slice((state.page - 1) * PAGE_SIZE, state.page * PAGE_SIZE);

    list.innerHTML = slice.length
        ? slice.map((report, i) => renderReport(report, i)).join("")
        : `<div class="whois-empty">${icon("inbox", 26)}<strong>No matching reports</strong><span>Try a different search or severity filter.</span></div>`;

    root.querySelector(".whois-page").textContent = `Page ${state.page} of ${pages}`;
    root.querySelector(".whois-prev").disabled = state.page <= 1;
    root.querySelector(".whois-next").disabled = state.page >= pages;

    const pill = document.getElementById("whois-count");
    if (pill) {
        pill.textContent = filtered.length !== state.reports.length
            ? `${fmtNumber(filtered.length)} of ${fmtNumber(state.reports.length)} reports`
            : `${fmtNumber(state.reports.length)} report${state.reports.length === 1 ? "" : "s"}`;
    }
}

function buildView(root) {
    root.innerHTML = `
        <div class="whois-summary">${renderSummary(state.reports)}</div>
        <div class="whois-filterbar">
            <input class="whois-search" type="search" placeholder="Search targets, sources or findings" aria-label="Search reports">
            <div class="whois-seg" role="group" aria-label="Filter by severity">
                <button type="button" class="whois-seg-btn active" data-severity="all">All</button>
                ${SEVERITIES.map(key => `<button type="button" class="whois-seg-btn tone-${key}" data-severity="${key}">${severityLabel(key)}</button>`).join("")}
            </div>
        </div>
        <div class="whois-report-list"></div>
        <div class="whois-pagination">
            <button type="button" class="whois-prev">Previous</button>
            <span class="whois-page">-</span>
            <button type="button" class="whois-next">Next</button>
        </div>`;

    const search = root.querySelector(".whois-search");
    let timer = null;
    search.addEventListener("input", () => {
        clearTimeout(timer);
        timer = setTimeout(() => { state.query = search.value; state.page = 1; paintList(root); }, 200);
    });
    search.addEventListener("keydown", event => {
        if (event.key !== "Enter") return;
        event.preventDefault();
        clearTimeout(timer);
        state.query = search.value;
        state.page = 1;
        paintList(root);
    });
    root.querySelectorAll(".whois-seg-btn").forEach(button => {
        button.addEventListener("click", () => {
            state.severity = button.dataset.severity;
            state.page = 1;
            root.querySelectorAll(".whois-seg-btn").forEach(item => item.classList.toggle("active", item === button));
            paintList(root);
        });
    });
    root.querySelector(".whois-prev").addEventListener("click", () => { state.page -= 1; paintList(root); });
    root.querySelector(".whois-next").addEventListener("click", () => { state.page += 1; paintList(root); });
    paintList(root);
}

function bindDelegates(root) {
    if (root.dataset.bound) return;
    root.dataset.bound = "true";

    const openRow = row => {
        const report = state.reports[Number(row.dataset.report)];
        const finding = report && report.findings[Number(row.dataset.finding)];
        if (report && finding) openFindingPanel(finding, report);
    };

    root.addEventListener("click", event => {
        const copy = event.target.closest(".whois-rec-copy");
        if (copy) {
            copyText(copy.dataset.copy || "").then(() => {
                copy.classList.add("copied");
                copy.innerHTML = icon("check", 14);
                setTimeout(() => {
                    copy.classList.remove("copied");
                    copy.innerHTML = icon("copy", 14);
                }, 1200);
            }).catch(() => {});
            return;
        }
        const tab = event.target.closest(".whois-rec-tab");
        if (tab) {
            const box = tab.closest(".whois-rec");
            const type = tab.dataset.recType;
            box.querySelectorAll(".whois-rec-tab").forEach(item => item.classList.toggle("active", item === tab));
            box.querySelectorAll(".whois-rec-group").forEach(group => {
                group.hidden = type !== "all" && group.dataset.recGroup !== type;
            });
            return;
        }
        const row = event.target.closest("tr[data-finding]");
        if (row) {
            openRow(row);
            return;
        }
        const target = event.target.closest("[data-target]");
        if (target) {
            const search = root.querySelector(".whois-search");
            if (!search) return;
            search.value = target.dataset.target;
            state.query = search.value;
            state.page = 1;
            paintList(root);
            search.scrollIntoView({ behavior: "smooth", block: "center" });
        }
    });
    root.addEventListener("keydown", event => {
        if (event.key !== "Enter") return;
        const row = event.target.closest && event.target.closest("tr[data-finding]");
        if (row) openRow(row);
    });
}

window.initWhoisDnsInformation = async function () {
    const root = document.getElementById("whois-dns-results");
    const resetButton = document.getElementById("whois-dns-reset");
    const pill = document.getElementById("whois-count");
    if (resetButton && !AppState.canDelete) resetButton.hidden = true;
    if (resetButton && !resetButton.dataset.bound) {
        resetButton.dataset.bound = "true";
        resetButton.addEventListener("click", async () => {
            if (!confirm("Reset all Whois/DNS results? This only clears the whois_dns table.")) return;
            resetButton.disabled = true;
            const result = await Api.resetWhoisDns();
            resetButton.disabled = false;
            if (!result.ok) {
                alert(result.error || "Unable to reset Whois/DNS results");
                return;
            }
            await window.initWhoisDnsInformation();
        });
    }

    closePanel(true);
    bindDelegates(root);
    if (pill) pill.textContent = "";
    root.innerHTML = `
        <div class="view-loading whois-loading" role="status" aria-live="polite">
            <div class="whois-spinner" aria-hidden="true"></div>
            <span>Loading Whois/DNS results</span>
            <div class="whois-dots" aria-hidden="true"><span></span><span></span><span></span></div>
        </div>`;

    let response;
    try {
        response = await Api.listWhoisDnsResults();
    } catch (error) {
        response = { ok: false, error: error && error.message };
    }
    if (!response.ok) {
        root.innerHTML = `<div class="view-loading view-loading-error">${Util.esc(response.error || "Unable to load results")}</div>`;
        return;
    }

    state.reports = (response.results || []).map(normalizeReport);
    state.query = "";
    state.severity = "all";
    state.page = 1;

    if (!state.reports.length) {
        root.innerHTML = `<div class="whois-empty">${icon("inbox", 26)}<strong>No Whois/DNS reports yet</strong><span>Upload an OxWebx Whois/DNS JSON report to begin.</span></div>`;
        return;
    }
    buildView(root);
};