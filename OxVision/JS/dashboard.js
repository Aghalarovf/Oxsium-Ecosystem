(function () {
    const { esc, countUp } = Util;

    const OS_COLORS = { Linux: "#2fa36b", Windows: "#3b82d6", Network: "#c9b98a", Unknown: "#7a7261" };
    const OS_ICONS = { Linux: "linux", Windows: "windows", Network: "network" };
    const SEVERITY = { high: 0, med: 1, info: 2 };
    const SEVERITY_LABEL = { high: "HIGH", med: "MED", info: "INFO" };
    const RISK_WEIGHT = { high: 3, med: 2, info: 1 };
    const RISK_TABS = [
        { key: "all", label: "All" },
        { key: "high", label: "High" },
        { key: "med", label: "Med" },
        { key: "info", label: "Info" }
    ];
    const RISKY = [
        { name: "Telnet", ports: [23], sev: "high", why: "Cleartext remote shell; credentials travel unencrypted" },
        { name: "rexec / rlogin / rsh", ports: [512, 513, 514], sev: "high", why: "Legacy remote execution with host-based trust" },
        { name: "RDP", ports: [3389], sev: "high", why: "Frequent brute-force and exploit target when exposed" },
        { name: "VNC", ports: [5900, 5901, 5902, 5903], sev: "high", why: "Remote desktop with weak or no authentication" },
        { name: "Radmin", ports: [4899], sev: "high", why: "Remote admin tool with weak authentication history" },
        { name: "Dameware", ports: [6129], sev: "high", why: "Remote control agent with a history of critical flaws" },
        { name: "Winbox", ports: [8291], sev: "high", why: "Router management port with past credential-leak flaws" },
        { name: "IPMI", ports: [623], sev: "high", why: "BMC interface with known authentication bypasses" },
        { name: "MSSQL", ports: [1433, 1434], sev: "high", why: "Database service reachable over the network" },
        { name: "MySQL", ports: [3306, 3307], sev: "high", why: "Database service reachable over the network" },
        { name: "PostgreSQL", ports: [5432, 5433], sev: "high", why: "Database service reachable over the network" },
        { name: "Oracle DB", ports: [1521, 1522], sev: "high", why: "Database listener reachable over the network" },
        { name: "MongoDB", ports: [27017, 27018, 27019, 28017], sev: "high", why: "Often deployed without authentication" },
        { name: "Redis", ports: [6379, 6380, 16379], sev: "high", why: "Often unauthenticated; can lead to remote code execution" },
        { name: "Memcached", ports: [11211], sev: "high", why: "Unauthenticated cache; data leak and amplification abuse" },
        { name: "Elasticsearch", ports: [9200, 9300], sev: "high", why: "Open API frequently exposes full indices" },
        { name: "CouchDB", ports: [5984, 6984], sev: "high", why: "HTTP database API often left open or with default admin" },
        { name: "Cassandra", ports: [9042, 9160, 7199], sev: "high", why: "Cluster database and JMX endpoint without authentication" },
        { name: "ZooKeeper", ports: [2181, 2182], sev: "high", why: "Coordination service that exposes cluster data" },
        { name: "Hadoop", ports: [8020, 50070, 50075, 50090], sev: "high", why: "HDFS endpoints expose files and cluster control" },
        { name: "Docker API", ports: [2375], sev: "high", why: "Unencrypted daemon API grants root-equivalent control" },
        { name: "etcd", ports: [2379, 2380], sev: "high", why: "Cluster key store may expose secrets and configuration" },
        { name: "Kubelet", ports: [10250, 10255], sev: "high", why: "Node API can allow command execution in containers" },
        { name: "Beanstalkd", ports: [11300], sev: "high", why: "Unauthenticated job queue" },
        { name: "PHP-FPM", ports: [9000], sev: "high", why: "FastCGI port allows code execution when reachable" },
        { name: "AJP13", ports: [8009], sev: "high", why: "Tomcat connector vulnerable to file read and inclusion" },
        { name: "JMX", ports: [8686], sev: "high", why: "Management interface that can allow remote code execution" },
        { name: "Webmin", ports: [10000, 10001], sev: "high", why: "Root-level web administration panel" },
        { name: "GlassFish Admin", ports: [4848, 4849], sev: "high", why: "Application server admin console" },
        { name: "WebLogic", ports: [7001, 7002], sev: "high", why: "Application server with frequent critical vulnerabilities" },
        { name: "Modbus", ports: [502, 503], sev: "high", why: "Industrial protocol with no authentication" },
        { name: "IEC-104", ports: [2404], sev: "high", why: "Industrial telecontrol protocol with no authentication" },
        { name: "Siemens S7 / ISO-TSAP", ports: [102], sev: "high", why: "PLC communication port" },
        { name: "PROFINET", ports: [34962, 34963], sev: "high", why: "Industrial automation protocol" },
        { name: "EtherNet/IP", ports: [44818], sev: "high", why: "Industrial control protocol with no authentication" },
        { name: "BACnet", ports: [47808], sev: "high", why: "Building automation protocol with no authentication" },
        { name: "ProConOS", ports: [20547], sev: "high", why: "PLC runtime with unauthenticated access" },
        { name: "FTP", ports: [20, 21], sev: "med", why: "Cleartext file transfer; anonymous access is common" },
        { name: "TFTP", ports: [69], sev: "med", why: "No authentication; used to read or write device files" },
        { name: "Finger", ports: [79], sev: "med", why: "Discloses user account information" },
        { name: "SMB", ports: [139, 445], sev: "med", why: "File sharing; lateral movement and relay attacks" },
        { name: "NetBIOS", ports: [137, 138], sev: "med", why: "Name service discloses host and domain information" },
        { name: "WINS", ports: [42], sev: "med", why: "Legacy name service that can be poisoned" },
        { name: "MS RPC", ports: [135, 593, 1025, 1026, 49152], sev: "med", why: "Endpoint mapper aids enumeration of Windows services" },
        { name: "WinRM", ports: [5985, 5986, 47001], sev: "med", why: "Remote management channel for Windows hosts" },
        { name: "SNMP", ports: [161], sev: "med", why: "Default community strings leak device configuration" },
        { name: "NFS", ports: [2049], sev: "med", why: "Network shares may be exported without restriction" },
        { name: "rpcbind", ports: [111], sev: "med", why: "Lists RPC services and assists NFS enumeration" },
        { name: "SMTP", ports: [25, 26, 2525], sev: "med", why: "Mail relay; user enumeration and open relay risk" },
        { name: "POP3", ports: [106, 110], sev: "med", why: "Cleartext mailbox access" },
        { name: "IMAP", ports: [143], sev: "med", why: "Cleartext mailbox access unless upgraded to TLS" },
        { name: "NNTP", ports: [119], sev: "med", why: "Legacy news service, rarely needed" },
        { name: "Simple FTP", ports: [115], sev: "med", why: "Legacy file transfer with weak authentication" },
        { name: "X11", ports: [6000], sev: "med", why: "Remote display access can allow screen and input capture" },
        { name: "XDMCP", ports: [177], sev: "med", why: "Remote display login with weak controls" },
        { name: "TACACS", ports: [49], sev: "med", why: "Legacy device authentication in cleartext" },
        { name: "Docker TLS / Swarm", ports: [2376, 2377], sev: "med", why: "Container management ports" },
        { name: "Kubernetes API", ports: [6443], sev: "high", why: "Cluster control plane endpoint" },
        { name: "Kubernetes components", ports: [10256, 10257, 10259], sev: "med", why: "Internal control plane ports" },
        { name: "Kibana", ports: [5601], sev: "med", why: "Dashboard UI that often lacks authentication" },
        { name: "Spark", ports: [7077], sev: "med", why: "Cluster master that accepts job submission" },
        { name: "Splunk Management", ports: [8089], sev: "med", why: "Management API with default credentials risk" },
        { name: "Kafka", ports: [9092, 9093, 9094], sev: "med", why: "Message broker reachable over the network" },
        { name: "Hive Metastore", ports: [9083], sev: "med", why: "Data warehouse metadata service" },
        { name: "Solr", ports: [8983, 8984], sev: "med", why: "Search platform with a history of remote code execution" },
        { name: "Neo4j", ports: [7473, 7474, 7687], sev: "med", why: "Graph database interfaces" },
        { name: "CockroachDB", ports: [4000, 26257], sev: "med", why: "Database and admin UI" },
        { name: "RethinkDB", ports: [28015], sev: "med", why: "Database driver port" },
        { name: "Firebird", ports: [3050], sev: "med", why: "Database service reachable over the network" },
        { name: "InfluxDB", ports: [5086, 8086, 8087], sev: "med", why: "Time-series database API" },
        { name: "Oracle TLS / XDB", ports: [2100, 2483, 2484], sev: "med", why: "Additional Oracle database listeners" },
        { name: "Consul", ports: [8300, 8301, 8302, 8500, 8600], sev: "high", why: "Service mesh API can expose configuration and execute checks" },
        { name: "Nomad", ports: [4646, 4647, 4648], sev: "high", why: "Scheduler API can run arbitrary jobs" },
        { name: "Eureka", ports: [8761], sev: "med", why: "Service registry with no authentication by default" },
        { name: "ActiveMQ", ports: [8161, 61616], sev: "med", why: "Broker console and transport with past critical flaws" },
        { name: "STOMP", ports: [61613, 61614], sev: "med", why: "Messaging protocol endpoint" },
        { name: "RabbitMQ Management", ports: [15671, 15672], sev: "med", why: "Broker admin UI with default credentials risk" },
        { name: "MQTT", ports: [1883, 8883, 9001], sev: "med", why: "IoT messaging broker often open without authentication" },
        { name: "cPanel / WHM", ports: [2082, 2083, 2086, 2087], sev: "med", why: "Hosting control panel" },
        { name: "Webmail", ports: [2095, 2096], sev: "med", why: "Mail web interface exposed to brute force" },
        { name: "Git", ports: [9418], sev: "med", why: "Unauthenticated repository access" },
        { name: "SVN", ports: [3690], sev: "med", why: "Source repository access" },
        { name: "Rsync", ports: [873], sev: "med", why: "Modules may allow unauthenticated file access" },
        { name: "Squid Proxy", ports: [3128], sev: "med", why: "Open proxy can be abused to pivot" },
        { name: "SOCKS", ports: [1080, 1081], sev: "med", why: "Open proxy can be abused to pivot" },
        { name: "Privoxy", ports: [8118], sev: "med", why: "Open proxy can be abused to pivot" },
        { name: "Dev HTTP", ports: [3000, 3001, 4200], sev: "med", why: "Development servers should not be exposed" },
        { name: "UPnP", ports: [1900, 5000], sev: "med", why: "Device discovery that exposes control interfaces" },
        { name: "WS-Discovery", ports: [3702], sev: "med", why: "Discovery protocol abused for amplification" },
        { name: "LLMNR", ports: [5355], sev: "med", why: "Name resolution that enables credential capture" },
        { name: "BGP", ports: [179], sev: "med", why: "Routing protocol; session hijack and leak risk" },
        { name: "RIP", ports: [520, 521], sev: "med", why: "Routing protocol with weak authentication" },
        { name: "Legacy diagnostics", ports: [7, 9, 13, 17, 19], sev: "med", why: "Echo, discard, daytime, QOTD and chargen enable amplification" },
        { name: "IRC", ports: [6660, 6666, 6697], sev: "med", why: "Chat service frequently used for botnet control" },
        { name: "Bitcoin", ports: [8333], sev: "info", why: "Cryptocurrency node traffic" },
        { name: "Minecraft RCON", ports: [25575], sev: "high", why: "Remote console with a shared password" },
        { name: "OPC UA", ports: [4840], sev: "med", why: "Industrial interoperability protocol" },
        { name: "Usermin", ports: [20000], sev: "med", why: "User web panel for account self-management" },
        { name: "DNP3", ports: [20000], sev: "high", why: "Industrial telecontrol protocol with no authentication" },
        { name: "SAP", ports: [50000, 50013, 50014], sev: "high", why: "Enterprise system management ports" },
        { name: "WBEM", ports: [5988, 5989], sev: "med", why: "Management interface exposed over HTTP" },
        { name: "Cisco SCCP", ports: [2000], sev: "med", why: "IP phone signaling" },
        { name: "RTSP", ports: [554], sev: "med", why: "Camera and media streams are often unauthenticated" },
        { name: "LPD", ports: [515], sev: "med", why: "Legacy print service" },
        { name: "SLP", ports: [427], sev: "med", why: "Service location protocol abused for amplification" },
        { name: "PPTP", ports: [1723], sev: "med", why: "VPN protocol with weak encryption" },
        { name: "Varnish Admin", ports: [6082], sev: "high", why: "Cache control interface" },
        { name: "SSH", ports: [22, 2022, 2222, 22222], sev: "info", why: "Remote administration entry point" },
        { name: "DNS", ports: [53], sev: "info", why: "Name resolution service" },
        { name: "DHCP", ports: [67, 68], sev: "info", why: "Address assignment service" },
        { name: "NTP", ports: [123], sev: "info", why: "Time service; can be abused for amplification" },
        { name: "HTTP", ports: [80, 81], sev: "high", why: "Cleartext web service" },
        { name: "HTTP alternate", ports: [8000, 8008, 8080, 8081, 8082, 8083, 8088, 8090, 8888, 9080, 9090, 7080], sev: "info", why: "Alternate web service ports" },
        { name: "HTTPS", ports: [443, 4443, 7443, 8443, 8444], sev: "high", why: "Encrypted web service" },
        { name: "LDAP", ports: [389, 636, 3268, 3269], sev: "info", why: "Directory service; useful for account enumeration" },
        { name: "Kerberos", ports: [88, 464], sev: "info", why: "Authentication service of a domain controller" },
        { name: "SMTP secure", ports: [465, 587], sev: "info", why: "Mail submission and encrypted relay" },
        { name: "POP3S", ports: [995], sev: "info", why: "Encrypted mailbox access" },
        { name: "IMAPS", ports: [993], sev: "info", why: "Encrypted mailbox access" },
        { name: "FTPS", ports: [989, 990], sev: "info", why: "Encrypted file transfer" },
        { name: "Telnet TLS", ports: [992], sev: "info", why: "Encrypted telnet" },
        { name: "SIP", ports: [5060, 5061], sev: "info", why: "VoIP signaling; exposed to scanning and toll fraud" },
        { name: "IPP", ports: [631], sev: "info", why: "Network printing protocol" },
        { name: "JetDirect", ports: [9100], sev: "info", why: "Raw printing port on network printers" },
        { name: "AFP", ports: [548], sev: "info", why: "Apple file sharing" },
        { name: "Gopher", ports: [70], sev: "info", why: "Obsolete protocol" },
        { name: "WHOIS", ports: [43], sev: "info", why: "Domain information service" },
        { name: "Time", ports: [37], sev: "info", why: "Obsolete time protocol" },
        { name: "Ident", ports: [113], sev: "info", why: "Discloses account names for connections" },
        { name: "SNMP Trap", ports: [162], sev: "info", why: "Device event notifications" },
        { name: "IPsec / ISAKMP", ports: [500, 4500], sev: "info", why: "VPN key exchange" },
        { name: "OpenVPN", ports: [1194], sev: "info", why: "VPN endpoint" },
        { name: "L2TP", ports: [1701], sev: "info", why: "VPN tunneling protocol" },
        { name: "AppleTalk / IPX", ports: [201, 213], sev: "info", why: "Obsolete network protocols" },
        { name: "VMware", ports: [902, 8182, 8222], sev: "info", why: "Virtualization management and agents" },
        { name: "WSDAPI", ports: [5357, 5358], sev: "info", why: "Windows device discovery" },
        { name: "mDNS", ports: [5353], sev: "info", why: "Local service discovery" },
        { name: "RADIUS", ports: [1645, 1646, 1812, 1813], sev: "info", why: "Network access authentication" },
        { name: "Network telemetry", ports: [2055, 4739, 6343], sev: "info", why: "NetFlow, IPFIX and sFlow collectors" },
        { name: "PTP", ports: [319, 320], sev: "info", why: "Precision time protocol" },
        { name: "Routing support", ports: [264, 646, 3784], sev: "info", why: "BGMP, LDP and BFD sessions" },
        { name: "VXLAN", ports: [4789], sev: "info", why: "Network virtualization overlay" },
        { name: "CAPWAP", ports: [5246, 5247], sev: "info", why: "Wireless controller tunnel" },
        { name: "CoAP", ports: [5683, 5684], sev: "info", why: "Constrained device protocol" },
        { name: "STUN", ports: [3478, 3479], sev: "info", why: "NAT traversal service" },
        { name: "Traceroute", ports: [33434], sev: "info", why: "Network path probing" },
        { name: "BitTorrent DHT", ports: [6881], sev: "info", why: "Peer-to-peer file sharing" },
        { name: "HA Cluster", ports: [694], sev: "info", why: "High availability heartbeat" },
        { name: "AMQP", ports: [5671, 5672], sev: "info", why: "Message broker protocol" },
        { name: "Vault", ports: [8200, 8201], sev: "high", why: "Secrets management API" },
        { name: "Puppet", ports: [8140], sev: "info", why: "Configuration management server" },
        { name: "Jaeger", ports: [14250, 14268, 16686], sev: "info", why: "Tracing collector and UI" },
        { name: "Zipkin", ports: [9411], sev: "info", why: "Tracing collector and UI" },
        { name: "Prometheus", ports: [9091, 9182], sev: "info", why: "Metrics endpoints" },
        { name: "StatsD", ports: [8125], sev: "info", why: "Metrics collector" },
        { name: "Logstash", ports: [5044, 9600], sev: "info", why: "Log pipeline endpoints" },
        { name: "Nessus", ports: [8834], sev: "med", why: "Vulnerability scanner console" },
        { name: "OpenVAS", ports: [9390, 9391], sev: "med", why: "Vulnerability scanner interfaces" },
        { name: "WSUS", ports: [8530, 8531], sev: "high", why: "Windows update server" },
        { name: "AD Web Services", ports: [9389], sev: "info", why: "Active Directory management endpoint" },
        { name: "Syslog TLS", ports: [6514], sev: "info", why: "Encrypted log collection" },
        { name: "Splunk Forwarder", ports: [9997], sev: "info", why: "Log forwarding receiver" },
        { name: "Lotus Notes", ports: [1352], sev: "info", why: "Collaboration server" },
        { name: "RealServer", ports: [7070], sev: "info", why: "Media streaming server" },
        { name: "Commplex", ports: [5001], sev: "med", why: "Generic application link port" },
        { name: "Game server", ports: [7777, 19132, 25565, 27015, 27016, 28960, 61000], sev: "info", why: "Game service ports" },
        { name: "Abyss", ports: [9999], sev: "med", why: "Web server administration port" },
        { name: "SMUX", ports: [199], sev: "med", why: "SNMP multiplexer tied to agent exposure" },
        { name: "UUCP", ports: [540], sev: "med", why: "Obsolete Unix file and mail copy service" },
        { name: "EPMD", ports: [4369], sev: "high", why: "Erlang port mapper; exposes distributed nodes to takeover" },
        { name: "SNPP", ports: [444], sev: "info", why: "Pager protocol, rarely used" }
    ];
    const riskView = { sev: "all", sort: "severity", open: new Set() };
    let riskMenu = null;

    function hideRiskMenu() {
        if (riskMenu) {
            riskMenu.remove();
            riskMenu = null;
        }
    }

    function exportRiskHosts(service, hosts) {
        const safeService = service.toLowerCase().replace(/[^a-z0-9]+/g, "_").replace(/^_+|_+$/g, "") || "service";
        const filename = `${safeService}_hosts.txt`;
        const content = `${hosts.join("\r\n")}\r\n`;

        (async () => {
            try {
                if (typeof window.showDirectoryPicker === "function") {
                    const directory = await window.showDirectoryPicker({ mode: "readwrite" });
                    const file = await directory.getFileHandle(filename, { create: true });
                    const writable = await file.createWritable();
                    await writable.write(content);
                    await writable.close();
                    return;
                }

                const link = document.createElement("a");
                link.href = URL.createObjectURL(new Blob([content], { type: "text/plain;charset=utf-8" }));
                link.download = filename;
                link.click();
                URL.revokeObjectURL(link.href);
            } catch (error) {
                if (error.name === "AbortError") return;
                console.error("Could not export service hosts", error);
                window.alert("Export failed. The host list could not be saved.");
            }
        })();
    }

    function showRiskMenu(event, risk) {
        hideRiskMenu();
        const menu = document.createElement("div");
        menu.className = "risk-menu";
        menu.setAttribute("role", "menu");
        const exportButton = document.createElement("button");
        exportButton.type = "button";
        exportButton.textContent = `Export ${risk.name} hosts`;
        exportButton.addEventListener("click", () => {
            hideRiskMenu();
            exportRiskHosts(risk.name, risk.hosts);
        });
        menu.appendChild(exportButton);
        document.body.appendChild(menu);

        const box = menu.getBoundingClientRect();
        menu.style.left = `${Math.max(8, Math.min(event.clientX, window.innerWidth - box.width - 8))}px`;
        menu.style.top = `${Math.max(8, Math.min(event.clientY, window.innerHeight - box.height - 8))}px`;
        riskMenu = menu;
        exportButton.focus();
    }

    document.addEventListener("mousedown", event => {
        if (riskMenu && !riskMenu.contains(event.target)) hideRiskMenu();
    });

    function tipEl() {
        return document.getElementById("chart-tip");
    }

    function moveTip(event) {
        const tip = tipEl();
        if (!tip || tip.hidden) return;
        const pad = 14;
        const box = tip.getBoundingClientRect();
        let x = event.clientX + pad;
        let y = event.clientY + pad;
        if (x + box.width > window.innerWidth - 8) x = event.clientX - box.width - pad;
        if (y + box.height > window.innerHeight - 8) y = event.clientY - box.height - pad;
        tip.style.left = `${Math.max(8, x)}px`;
        tip.style.top = `${Math.max(8, y)}px`;
    }

    function showTip(event, html) {
        const tip = tipEl();
        if (!tip) return;
        tip.innerHTML = html;
        tip.hidden = false;
        moveTip(event);
    }

    function hideTip() {
        const tip = tipEl();
        if (tip) tip.hidden = true;
    }

    function emptyState(el, text) {
        el.innerHTML = `<div class="chart-empty">${text}</div>`;
    }

    function donut(el, data, { centerValue, centerLabel, onClick, isActive }) {
        const items = data.filter(d => d.value > 0);
        if (!items.length) {
            emptyState(el, "No data");
            return;
        }
        const total = d3.sum(items, d => d.value);
        el.innerHTML = '<div class="donut-wrap"><div class="donut-svg-box"></div><div class="donut-legend"></div></div>';
        const size = 190;
        const radius = 84;
        const inner = 56;

        const svg = d3.select(el.querySelector(".donut-svg-box"))
            .append("svg")
            .attr("viewBox", `0 0 ${size} ${size}`)
            .attr("class", "donut-svg");
        const g = svg.append("g").attr("transform", `translate(${size / 2},${size / 2})`);

        const arc = d3.arc().innerRadius(inner).outerRadius(radius).cornerRadius(3);
        const arcHover = d3.arc().innerRadius(inner - 2).outerRadius(radius + 6).cornerRadius(3);
        const slices = d3.pie().sort(null).value(d => d.value).padAngle(items.length > 1 ? 0.025 : 0)(items);

        const legend = d3.select(el.querySelector(".donut-legend"));
        const legendItems = legend.selectAll("div")
            .data(items)
            .join("div")
            .attr("class", d => `donut-legend-item${isActive && isActive(d) ? " active" : ""}`)
            .style("animation-delay", (d, i) => `${300 + i * 70}ms`)
            .html(d => `
                <span class="legend-swatch" style="background:${d.color}"></span>
                <span class="legend-name">${esc(d.label)}</span>
                <span class="legend-val">${d.value}</span>
                <span class="legend-pct">${Math.round(d.value / total * 100)}%</span>`);

        function highlight(index) {
            paths.style("opacity", (d, i) => index === null || i === index ? 1 : 0.3);
            legendItems.style("opacity", (d, i) => index === null || i === index ? 1 : 0.45);
            paths.each(function (d, i) {
                d3.select(this).transition("hover").duration(140)
                    .attr("d", i === index ? arcHover(d) : arc(d));
            });
        }

        const paths = g.selectAll("path")
            .data(slices)
            .join("path")
            .attr("class", "donut-arc")
            .attr("fill", d => d.data.color)
            .style("cursor", onClick ? "pointer" : "default")
            .on("mouseenter", (event, d) => highlight(slices.indexOf(d)))
            .on("mousemove", (event, d) => showTip(event,
                `<b>${esc(d.data.label)}</b><br>${d.data.value} of ${total} (${Math.round(d.data.value / total * 100)}%)`))
            .on("mouseleave", () => {
                highlight(null);
                hideTip();
            })
            .on("click", (event, d) => onClick && onClick(d.data));

        if (Util.reducedMotion()) {
            paths.attr("d", arc);
        } else {
            paths.transition("enter").duration(1000).delay((d, i) => i * 110)
                .ease(d3.easeCubicOut)
                .attrTween("d", d => {
                    const interpolate = d3.interpolate(
                        { startAngle: d.startAngle, endAngle: d.startAngle, padAngle: d.padAngle },
                        d
                    );
                    return t => arc(interpolate(t));
                });
        }

        const value = g.append("text").attr("class", "donut-total").attr("text-anchor", "middle").attr("dy", "0.05em");
        g.append("text").attr("class", "donut-caption").attr("text-anchor", "middle").attr("dy", "1.9em").text(centerLabel);
        countUp(value.node(), centerValue === undefined ? total : centerValue, { duration: 1000 });

        legendItems
            .style("cursor", onClick ? "pointer" : "default")
            .on("mouseenter", (event, d) => highlight(items.indexOf(d)))
            .on("mouseleave", () => highlight(null))
            .on("click", (event, d) => onClick && onClick(d));
    }

    function hbars(el, rows, { onClick, isActive, scroll = false, empty = "No data" } = {}) {
        if (!rows.length) {
            emptyState(el, empty);
            return;
        }
        const max = d3.max(rows, r => r.max !== undefined ? r.max : r.value) || 1;
        el.innerHTML = `<div class="hbar-list${scroll ? " scroll" : ""}">${rows.map((r, i) => {
            const width = Math.max(2, Math.round(r.value / max * 100));
            return `
            <div class="hbar-row${isActive && isActive(r) ? " active" : ""}${onClick ? " clickable" : ""}" data-i="${i}" style="--d:${Math.min(i, 12) * 55}ms">
                <div class="hbar-label">${r.labelHtml || esc(r.label)}${r.sub ? `<span class="hbar-sub">${esc(r.sub)}</span>` : ""}</div>
                <div class="hbar-track"><div class="hbar-fill" style="--w:${width}%;--c:${r.color}"></div></div>
                <div class="hbar-val">${esc(r.valueText !== undefined ? r.valueText : r.value)}</div>
            </div>`;
        }).join("")}</div>`;

        el.querySelectorAll(".hbar-row").forEach(row => {
            const r = rows[Number(row.dataset.i)];
            row.addEventListener("mousemove", event => r.tip && showTip(event, r.tip));
            row.addEventListener("mouseleave", hideTip);
            if (onClick) row.addEventListener("click", () => onClick(r));
        });
    }

    function histogram(el, hosts) {
        const buckets = [
            { label: "0", test: n => n === 0 },
            { label: "1-2", test: n => n >= 1 && n <= 2 },
            { label: "3-5", test: n => n >= 3 && n <= 5 },
            { label: "6-10", test: n => n >= 6 && n <= 10 },
            { label: "11-20", test: n => n >= 11 && n <= 20 },
            { label: "21+", test: n => n >= 21 }
        ].map(b => ({ label: b.label, count: hosts.filter(h => b.test(h.port_count)).length }));

        if (!hosts.length) {
            emptyState(el, "No data");
            return;
        }

        const width = 440;
        const height = 220;
        const margin = { top: 26, right: 8, bottom: 28, left: 8 };
        const x = d3.scaleBand().domain(buckets.map(b => b.label)).range([margin.left, width - margin.right]).padding(0.28);
        const maxCount = d3.max(buckets, b => b.count) || 1;
        const y = d3.scaleLinear().domain([0, maxCount]).range([height - margin.bottom, margin.top]);

        el.innerHTML = "";
        const svg = d3.select(el).append("svg").attr("viewBox", `0 0 ${width} ${height}`).attr("class", "hist-svg");

        const defs = svg.append("defs");
        const gradient = defs.append("linearGradient").attr("id", "hist-grad").attr("x1", 0).attr("x2", 0).attr("y1", 0).attr("y2", 1);
        gradient.append("stop").attr("offset", "0%").attr("stop-color", "#f0c030");
        gradient.append("stop").attr("offset", "100%").attr("stop-color", "#a07820");

        svg.append("g").selectAll("line")
            .data(y.ticks(4))
            .join("line")
            .attr("class", "hist-grid")
            .attr("x1", margin.left).attr("x2", width - margin.right)
            .attr("y1", d => y(d)).attr("y2", d => y(d));

        const bars = svg.append("g").selectAll("rect")
            .data(buckets)
            .join("rect")
            .attr("class", "hist-bar")
            .attr("x", d => x(d.label))
            .attr("width", x.bandwidth())
            .attr("rx", 3)
            .attr("y", y(0))
            .attr("height", 0)
            .on("mousemove", (event, d) => showTip(event, `<b>${d.label} open ports</b><br>${d.count} host${d.count === 1 ? "" : "s"}`))
            .on("mouseleave", hideTip);

        const labels = svg.append("g").selectAll("text")
            .data(buckets)
            .join("text")
            .attr("class", "hist-value")
            .attr("x", d => x(d.label) + x.bandwidth() / 2)
            .attr("y", y(0) - 6)
            .attr("text-anchor", "middle")
            .style("opacity", 0)
            .text(d => d.count);

        svg.append("g").selectAll("text")
            .data(buckets)
            .join("text")
            .attr("class", "hist-axis")
            .attr("x", d => x(d.label) + x.bandwidth() / 2)
            .attr("y", height - 8)
            .attr("text-anchor", "middle")
            .text(d => d.label);

        if (Util.reducedMotion()) {
            bars.attr("y", d => y(d.count)).attr("height", d => y(0) - y(d.count));
            labels.attr("y", d => y(d.count) - 6).style("opacity", 1);
            return;
        }
        bars.transition().duration(900).delay((d, i) => i * 90).ease(d3.easeBackOut.overshoot(0.8))
            .attr("y", d => y(d.count))
            .attr("height", d => y(0) - y(d.count));
        labels.transition().duration(900).delay((d, i) => i * 90)
            .attr("y", d => y(d.count) - 6)
            .style("opacity", 1);
    }

    function riskList(el, hosts) {
        hideRiskMenu();
        const filters = AppState.filters;
        const all = RISKY.map(r => {
            const matched = hosts.filter(h => h.ports.some(p => r.ports.includes(Number(p.port))));
            return {
                ...r,
                key: r.ports.join(","),
                count: matched.length,
                hosts: matched.map(h => h.host),
                pct: hosts.length ? matched.length / hosts.length * 100 : 0
            };
        }).filter(r => r.count > 0);

        if (!all.length) {
            emptyState(el, "No commonly targeted services found");
            return;
        }

        const counts = { all: all.length, high: 0, med: 0, info: 0 };
        all.forEach(r => { counts[r.sev] += 1; });
        if (riskView.sev !== "all" && !counts[riskView.sev]) riskView.sev = "all";

        const hostScores = new Map();
        all.forEach(r => r.hosts.forEach(name => {
            const entry = hostScores.get(name) || { score: 0, names: [] };
            entry.score += RISK_WEIGHT[r.sev];
            entry.names.push(r.name);
            hostScores.set(name, entry);
        }));
        const topHosts = [...hostScores.entries()]
            .sort((a, b) => b[1].score - a[1].score || a[0].localeCompare(b[0]))
            .slice(0, 3);

        let animate = !riskView.seen;
        riskView.seen = true;

        function render() {
            const items = all
                .filter(r => riskView.sev === "all" || r.sev === riskView.sev)
                .sort(riskView.sort === "count"
                    ? (a, b) => b.count - a.count || SEVERITY[a.sev] - SEVERITY[b.sev]
                    : (a, b) => SEVERITY[a.sev] - SEVERITY[b.sev] || b.count - a.count);
            const affected = new Set(items.flatMap(r => r.hosts)).size;

            const tabs = RISK_TABS.map(t => `
                <button type="button" class="risk-tab${riskView.sev === t.key ? " active" : ""}${t.key === "all" ? "" : ` ${t.key}`}" data-sev="${t.key}"${counts[t.key] ? "" : " disabled"}>
                    ${t.label}<span>${counts[t.key]}</span>
                </button>`).join("");

            const rows = items.map((r, i) => {
                const open = riskView.open.has(r.key);
                const shown = r.hosts.slice(0, 40);
                return `
                <div class="risk-row${open ? " open" : ""}">
                    <div class="risk-item${filters.port === r.key ? " active" : ""}" data-key="${esc(r.key)}" style="--d:${i * 40}ms">
                        <button type="button" class="risk-toggle" data-key="${esc(r.key)}" aria-expanded="${open}" aria-label="Show affected hosts for ${esc(r.name)}">&#9656;</button>
                        <span class="risk-dot ${r.sev}"></span>
                        <span class="risk-name">${esc(r.name)}</span>
                        <span class="risk-ports">${r.ports.join(", ")}</span>
                        <span class="risk-sev ${r.sev}">${SEVERITY_LABEL[r.sev]}</span>
                        <span class="risk-count">${r.count}<small> host${r.count === 1 ? "" : "s"}</small></span>
                        <span class="risk-bar"><i class="${r.sev}" style="--w:${Math.max(3, Math.round(r.pct))}%"></i></span>
                    </div>
                    ${open ? `<div class="risk-hosts">${shown.map(name => `<button type="button" class="risk-host" data-host="${esc(name)}">${esc(name)}</button>`).join("")}${r.hosts.length > shown.length ? `<span class="risk-more">+${r.hosts.length - shown.length} more</span>` : ""}</div>` : ""}
                </div>`;
            }).join("");

            const top = topHosts.map(([name, info]) => `
                <button type="button" class="risk-top-host" data-host="${esc(name)}" data-score="${info.score}">
                    ${esc(name)}<span>${info.score}</span>
                </button>`).join("");

            el.innerHTML = `
                <div class="risk-head">
                    <div class="risk-tabs">${tabs}</div>
                    <button type="button" class="risk-sort">Sort: ${riskView.sort === "count" ? "Hosts" : "Severity"}</button>
                </div>
                <div class="risk-summary"><b>${affected}</b> of <b>${hosts.length}</b> hosts affected &middot; <b>${items.length}</b> service${items.length === 1 ? "" : "s"}</div>
                <div class="risk-list${animate ? "" : " static"}">${rows}</div>
                <div class="risk-top"><span class="risk-top-label">Top risky hosts</span>${top}</div>`;
            animate = false;

            el.querySelectorAll(".risk-tab").forEach(btn => btn.addEventListener("click", () => {
                riskView.sev = btn.dataset.sev;
                hideTip();
                render();
            }));

            el.querySelector(".risk-sort").addEventListener("click", () => {
                riskView.sort = riskView.sort === "count" ? "severity" : "count";
                render();
            });

            el.querySelectorAll(".risk-toggle").forEach(btn => btn.addEventListener("click", event => {
                event.stopPropagation();
                const key = btn.dataset.key;
                if (riskView.open.has(key)) riskView.open.delete(key);
                else riskView.open.add(key);
                hideTip();
                render();
            }));

            el.querySelectorAll(".risk-item").forEach(row => {
                const r = all.find(x => x.key === row.dataset.key);
                row.addEventListener("mousemove", event => showTip(event,
                    `<b>${esc(r.name)}</b> &middot; ${r.ports.join(", ")}<br>${esc(r.why)}<br>${esc(r.hosts.slice(0, 8).join(", "))}${r.hosts.length > 8 ? ` +${r.hosts.length - 8} more` : ""}`));
                row.addEventListener("mouseleave", hideTip);
                row.addEventListener("click", () => {
                    hideTip();
                    Filters.setValue("port", filters.port === r.key ? "" : r.key);
                });
                row.addEventListener("contextmenu", event => {
                    event.preventDefault();
                    event.stopPropagation();
                    showRiskMenu(event, r);
                });
            });

            el.querySelectorAll(".risk-host").forEach(btn => btn.addEventListener("click", () => {
                hideTip();
                Filters.setValue("q", btn.dataset.host);
            }));

            el.querySelectorAll(".risk-top-host").forEach(btn => {
                const info = hostScores.get(btn.dataset.host);
                btn.addEventListener("mousemove", event => showTip(event,
                    `<b>${esc(btn.dataset.host)}</b> &middot; risk score ${info.score}<br>${esc(info.names.slice(0, 8).join(", "))}${info.names.length > 8 ? ` +${info.names.length - 8} more` : ""}`));
                btn.addEventListener("mouseleave", hideTip);
                btn.addEventListener("click", () => {
                    hideTip();
                    Filters.setValue("q", btn.dataset.host);
                });
            });
        }

        render();
    }

    function openResetDialog() {
        return new Promise(resolve => {
            const overlay = document.createElement("div");
            overlay.className = "reset-overlay";
            overlay.innerHTML = `
                <form class="reset-dialog" role="dialog" aria-modal="true" aria-labelledby="reset-title">
                    <div class="reset-title" id="reset-title">Reset data</div>
                    <p>The current scan results will be archived as <code>portscan_{id}.db.bak</code> and an empty database will be created. Archived files are never deleted.</p>
                    <label for="reset-password">Administrator password</label>
                    <input id="reset-password" type="password" autocomplete="current-password">
                    <div class="reset-error" hidden></div>
                    <div class="reset-actions">
                        <button type="button" data-cancel>Cancel</button>
                        <button type="submit" class="danger">Reset</button>
                    </div>
                </form>`;
            const form = overlay.querySelector("form");
            const input = overlay.querySelector("input");
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
            form.addEventListener("submit", async event => {
                event.preventDefault();
                if (!input.value) {
                    errorBox.textContent = "Enter your administrator password";
                    errorBox.hidden = false;
                    return;
                }
                submit.disabled = true;
                errorBox.hidden = true;
                const result = await Api.reset(input.value);
                submit.disabled = false;
                if (!result.ok) {
                    errorBox.textContent = result.error || "Could not reset data";
                    errorBox.hidden = false;
                    input.select();
                    return;
                }
                close(result);
            });

            document.addEventListener("keydown", onKey, true);
            document.body.appendChild(overlay);
            input.focus();
        });
    }

    window.initDashboard = async function () {
        const statGrid = document.getElementById("dashboard-stats");
        const grid = document.getElementById("dash-grid");
        const resetButton = document.getElementById("dashboard-reset");
        const filterNote = document.getElementById("dash-filter-note");
        const groupFilter = document.getElementById("dashboard-group-filter");

        const actions = resetButton.closest(".dashboard-actions");
        if (actions) actions.hidden = !AppState.canReset;
        resetButton.addEventListener("click", async () => {
            resetButton.disabled = true;
            const result = await openResetDialog();
            resetButton.disabled = false;
            if (!result) return;

            AppState.selectedSubnet = null;
            AppState.selectedSubnetGroup = null;
            Filters.reset();
        });

        const [meta, hostsRes, portsRes] = await Promise.all([Api.getMeta(), Api.getHosts(), Api.getPorts()]);

        const hasDataset = meta.ok && hostsRes.ok;
        const datasetMeta = hasDataset ? meta : {
            mode: null,
            subnets: [],
        };
        const hosts = hasDataset ? hostsRes.hosts : [];
        const datasetHostCount = hasDataset ? hostsRes.unfiltered_total : 0;
        const groupNames = hasDataset
            ? [...new Set([...(meta.subnet_group_names || []), ...Object.values(meta.subnet_groups || {})])]
                .sort((a, b) => a.localeCompare(b))
            : [];
        groupFilter.innerHTML = '<option value="">All subnets</option>' +
            groupNames.map(group => `<option value="${esc(group)}">${esc(group)}</option>`).join("");
        groupFilter.value = AppState.selectedSubnetGroup || "";
        groupFilter.addEventListener("change", () => {
            AppState.selectedSubnetGroup = groupFilter.value || null;
            AppState.selectedSubnet = null;
            loadView("dashboard");
            refreshPanel();
        });
        const selectedGroupLabel = AppState.selectedSubnetGroup
            ? ` \u00b7 group: ${AppState.selectedSubnetGroup}`
            : "";
        document.getElementById("dashboard-sub").textContent =
            hasDataset
                ? `Overview of the loaded port-scan dataset${datasetMeta.mode ? ` \u00b7 mode: ${datasetMeta.mode}` : ""}${selectedGroupLabel}`
                : "No dataset loaded · upload a JSON scan to populate the dashboard";

        if (Filters.isActive()) {
            filterNote.hidden = false;
            filterNote.innerHTML = `<span class="dash-filter-dot"></span>Filters active &mdash; showing <b>${hosts.length}</b> of <b>${datasetHostCount}</b> hosts <button type="button" id="dash-clear-filters">Clear</button>`;
            document.getElementById("dash-clear-filters").addEventListener("click", Filters.reset);
        } else {
            filterNote.hidden = true;
        }

        const totalOpen = d3.sum(hosts, h => h.port_count);
        const withRoles = hosts.filter(h => h.roles.length).length;
        const visibleSubnets = new Set(hosts.map(host => host.subnet).filter(Boolean)).size;
        const kpis = [
            { label: "Hosts", value: hosts.length, color: "#f0c030", sub: datasetHostCount !== hosts.length ? `of ${datasetHostCount}` : "scanned" },
            { label: "Subnets", value: AppState.selectedSubnetGroup ? visibleSubnets : (AppState.selectedSubnet ? 1 : datasetMeta.subnets.length), color: "#3b82d6", sub: "networks" },
            { label: "Unique Ports", value: portsRes.ok ? portsRes.total : 0, color: "#2fa36b", sub: "distinct" },
            { label: "Open Ports", value: totalOpen, color: "#e8a33c", sub: "total findings" },
            { label: "Avg Ports / Host", value: hosts.length ? totalOpen / hosts.length : 0, decimals: 1, color: "#a77be0", sub: "exposure" },
            { label: "Roles Assigned", value: withRoles, color: "#e0659a", sub: `${hosts.length ? Math.round(withRoles / hosts.length * 100) : 0}% coverage` }
        ];

        statGrid.innerHTML = kpis.map((k, i) => `
            <div class="kpi-card" style="--i:${i};--kc:${k.color}">
                <div class="kpi-label">${k.label}</div>
                <div class="kpi-value" data-i="${i}">0</div>
                <div class="kpi-sub">${esc(k.sub)}</div>
            </div>`).join("");
        kpis.forEach((k, i) => countUp(statGrid.querySelector(`.kpi-value[data-i="${i}"]`), k.value, {
            duration: 1000, decimals: k.decimals || 0, delay: i * 70
        }));

        grid.hidden = false;
        const f = AppState.filters;

        const osCounts = d3.rollups(hosts, v => v.length, h => h.os || "Unknown").sort((a, b) => b[1] - a[1]);
        donut(document.getElementById("chart-os"),
            osCounts.map(([label, value]) => ({ label, value, color: OS_COLORS[label] || OS_COLORS.Unknown })),
            {
                centerLabel: "hosts",
                centerValue: hosts.length,
                isActive: d => f.os.includes(d.label),
                onClick: d => Filters.toggleValue("os", d.label)
            });

        const roleMap = new Map();
        hosts.forEach(h => h.roles.forEach(r => roleMap.set(r, (roleMap.get(r) || 0) + 1)));
        const roleData = [...roleMap.entries()].sort((a, b) => b[1] - a[1])
            .map(([label, value]) => ({ label, value, color: Roles.color(label) }));
        const rolesEl = document.getElementById("chart-roles");
        if (roleData.length) {
            donut(rolesEl, roleData, {
                centerLabel: "with roles",
                centerValue: withRoles,
                isActive: d => f.role.includes(d.label),
                onClick: d => Filters.toggleValue("role", d.label)
            });
            const unassigned = hosts.length - withRoles;
            if (unassigned > 0) {
                const note = document.createElement("div");
                note.className = "chart-footnote";
                note.innerHTML = `<b>${unassigned}</b> host${unassigned === 1 ? "" : "s"} without a role <button type="button">Show</button>`;
                note.querySelector("button").addEventListener("click", () => Filters.toggleValue("role", "__none__"));
                rolesEl.appendChild(note);
            }
        } else {
            emptyState(rolesEl, "No roles assigned yet.<br>Right-click a host in the Network Graph or click a Roles cell in Hosts.");
        }

        const topPorts = (portsRes.ok ? [...portsRes.ports] : [])
            .sort((a, b) => b.count - a.count || Number(a.port) - Number(b.port))
            .map(p => ({
            key: String(p.port),
            label: `${p.port}/${p.protocol}`,
            sub: p.service || "",
            value: p.count,
            max: hosts.length,
            color: String(p.protocol).toLowerCase() === "udp" ? "#e8a33c" : "#2fa36b",
            valueText: `${p.count} \u00b7 ${Math.round(p.count / hosts.length * 100)}%`,
            tip: `<b>${esc(p.port)}/${esc(p.protocol)}</b> ${esc(p.service || "")}<br>${esc(p.hosts.slice(0, 8).join(", "))}${p.hosts.length > 8 ? ` +${p.hosts.length - 8} more` : ""}`
        }));
        hbars(document.getElementById("chart-ports"), topPorts, {
            scroll: true,
            empty: "No open ports",
            isActive: r => f.port === r.key,
            onClick: r => Filters.setValue("port", f.port === r.key ? "" : r.key)
        });

        histogram(document.getElementById("chart-hist"), hosts);
        riskList(document.getElementById("chart-risk"), hosts);

        const exposed = [...hosts].sort((a, b) => b.port_count - a.port_count).slice(0, 8)
            .filter(h => h.port_count > 0)
            .map(h => ({
                label: h.host,
                labelHtml: `<img class="hbar-icon" src="/assets/${OS_ICONS[h.os] || "unknown"}.png" alt="">${esc(h.host)}`,
                value: h.port_count,
                color: OS_COLORS[h.os || "Unknown"] || OS_COLORS.Unknown,
                tip: `<b>${esc(h.host)}</b> (${esc(h.os || "Unknown")})<br>${esc(h.ports.map(p => p.port).slice(0, 12).join(", "))}`
            }));
        hbars(document.getElementById("chart-exposed"), exposed, {
            empty: "No open ports",
            onClick: r => Filters.setValue("q", r.label)
        });

        const subnetCounts = d3.rollups(hosts, v => v.length, h => h.subnet || "Unassigned")
            .sort((a, b) => b[1] - a[1]).slice(0, 8)
            .map(([label, value]) => ({
                label,
                value,
                color: "#f0c030",
                active: AppState.selectedSubnet === label
            }));
        hbars(document.getElementById("chart-subnets"), subnetCounts, {
            isActive: r => r.active
        });
    };
})();