const AppState = {
    user: null,
    canEditHosts: false,
    canEditHostDetails: false,
    canUpload: false,
    canReset: false,
    canManageSubnets: false,
    dataset: null,
    currentView: "dashboard",
    connected: false,
    selectedSubnet: null,
    selectedSubnetGroup: null,
    selectedHost: null,
    defaultRoles: [],
    roleNames: [],
    filters: {
        q: "",
        os: [],
        role: [],
        port: "",
        service: "",
        min_ports: "",
        sort: "",
        dir: "asc"
    }
};