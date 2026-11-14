/**
 * CVSS v3.1 calculation engine (FIRST.org specification 3.1).
 * Pure functions: given a metric selection, returns the vector string,
 * base score, and severity rating. No DOM dependency, so it can be
 * reused anywhere (forms, reports, API payloads).
 */
const Cvss31 = (() => {
    const METRICS = {
        AV: { label: "Attack Vector", values: { N: "Network", A: "Adjacent", L: "Local", P: "Physical" } },
        AC: { label: "Attack Complexity", values: { L: "Low", H: "High" } },
        PR: { label: "Privileges Required", values: { N: "None", L: "Low", H: "High" } },
        UI: { label: "User Interaction", values: { N: "None", R: "Required" } },
        S:  { label: "Scope", values: { U: "Unchanged", C: "Changed" } },
        C:  { label: "Confidentiality", values: { N: "None", L: "Low", H: "High" } },
        I:  { label: "Integrity", values: { N: "None", L: "Low", H: "High" } },
        A:  { label: "Availability", values: { N: "None", L: "Low", H: "High" } },
    };

    const METRIC_ORDER = ["AV", "AC", "PR", "UI", "S", "C", "I", "A"];

    // Numeric weights per the CVSS v3.1 spec (Table 7-14 / equations in section 8.1)
    const WEIGHTS = {
        AV: { N: 0.85, A: 0.62, L: 0.55, P: 0.2 },
        AC: { L: 0.77, H: 0.44 },
        PR: {
            unchanged: { N: 0.85, L: 0.62, H: 0.27 },
            changed:   { N: 0.85, L: 0.68, H: 0.5 },
        },
        UI: { N: 0.85, R: 0.62 },
        CIA: { N: 0, L: 0.22, H: 0.56 },
    };

    function roundUp(value) {
        // CVSS spec "Roundup" function: round to 1 decimal, always upward.
        const intInput = Math.round(value * 100000);
        if (intInput % 10000 === 0) {
            return intInput / 100000;
        }
        return (Math.floor(intInput / 10000) + 1) / 10;
    }

    function severityFor(score) {
        if (score === 0) return "Info";
        if (score < 4.0) return "Low";
        if (score < 7.0) return "Medium";
        if (score < 9.0) return "High";
        return "Critical";
    }

    function isComplete(metrics) {
        return METRIC_ORDER.every(key => metrics[key] && METRICS[key].values[metrics[key]]);
    }

    function vectorString(metrics) {
        if (!isComplete(metrics)) return "";
        return "CVSS:3.1/" + METRIC_ORDER.map(key => `${key}:${metrics[key]}`).join("/");
    }

    function parseVector(vector) {
        if (!vector || typeof vector !== "string") return null;
        const parts = vector.trim().split("/");
        if (parts[0] !== "CVSS:3.1") return null;
        const metrics = {};
        for (let i = 1; i < parts.length; i++) {
            const [key, value] = parts[i].split(":");
            if (key && value) metrics[key] = value;
        }
        if (!isComplete(metrics)) return null;
        return metrics;
    }

    function calculate(metrics) {
        if (!isComplete(metrics)) {
            return { valid: false, vector: "", baseScore: null, severity: null };
        }

        const changed = metrics.S === "C";
        const iss = 1 - (1 - WEIGHTS.CIA[metrics.C]) * (1 - WEIGHTS.CIA[metrics.I]) * (1 - WEIGHTS.CIA[metrics.A]);

        let impact;
        if (!changed) {
            impact = 6.42 * iss;
        } else {
            impact = 7.52 * (iss - 0.029) - 3.25 * Math.pow(iss - 0.02, 15);
        }

        const avW = WEIGHTS.AV[metrics.AV];
        const acW = WEIGHTS.AC[metrics.AC];
        const prW = (changed ? WEIGHTS.PR.changed : WEIGHTS.PR.unchanged)[metrics.PR];
        const uiW = WEIGHTS.UI[metrics.UI];

        const exploitability = 8.22 * avW * acW * prW * uiW;

        let baseScore;
        if (impact <= 0) {
            baseScore = 0;
        } else if (!changed) {
            baseScore = roundUp(Math.min(impact + exploitability, 10));
        } else {
            baseScore = roundUp(Math.min(1.08 * (impact + exploitability), 10));
        }

        return {
            valid: true,
            vector: vectorString(metrics),
            baseScore,
            impactSubscore: Math.round(impact * 10) / 10,
            exploitabilitySubscore: Math.round(exploitability * 10) / 10,
            severity: severityFor(baseScore),
        };
    }

    return { METRICS, METRIC_ORDER, calculate, vectorString, parseVector, severityFor, isComplete };
})();

if (typeof module !== "undefined" && module.exports) {
    module.exports = Cvss31;
}
