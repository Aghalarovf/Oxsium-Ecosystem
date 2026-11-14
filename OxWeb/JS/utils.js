const Util = {
    esc(value) {
        if (value === null || value === undefined) return "";
        return String(value)
            .replace(/&/g, "&amp;")
            .replace(/</g, "&lt;")
            .replace(/>/g, "&gt;")
            .replace(/"/g, "&quot;")
            .replace(/'/g, "&#39;");
    },
    reducedMotion() {
        return !!(window.matchMedia && window.matchMedia("(prefers-reduced-motion: reduce)").matches);
    },
    countUp(el, to, { duration = 900, decimals = 0, delay = 0 } = {}) {
        if (!el) return;
        const target = Number(to);
        const format = value => decimals ? value.toFixed(decimals) : Math.round(value).toLocaleString("en-US");
        if (!Number.isFinite(target)) {
            el.textContent = String(to);
            return;
        }
        if (Util.reducedMotion()) {
            el.textContent = format(target);
            return;
        }
        el.textContent = format(0);
        const start = performance.now() + delay;
        const tick = now => {
            if (!el.isConnected) return;
            const t = Math.min(1, Math.max(0, (now - start) / duration));
            el.textContent = format(target * (1 - Math.pow(1 - t, 3)));
            if (t < 1) requestAnimationFrame(tick);
        };
        requestAnimationFrame(tick);
    }
};