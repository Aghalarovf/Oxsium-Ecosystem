window.initUpload = function() {
    const dropZone = document.getElementById("drop-zone");
    const fileInput = document.getElementById("file-input");
    const status = document.getElementById("upload-status");
    const esc = Util.esc;
    let busy = false;

    function renderResult(result, total) {
        if (!result.ok && !result.results) {
            status.innerHTML = `<div class="upload-summary err">Error: ${esc(result.error || "Upload failed")}</div>`;
            return;
        }
        const rows = (result.results || []).map(r => `
            <div class="upload-file ${r.ok ? "ok" : "err"}">
                <span class="upload-file-mark">${r.ok ? "&#10003;" : "&#10005;"}</span>
                <span class="upload-file-name">${esc(r.name)}</span>
                <span class="upload-file-info">${r.ok ? `${r.host_count} host${r.host_count === 1 ? "" : "s"}` : esc(r.error)}</span>
            </div>`).join("");

        let summary;
        if (!result.ok) {
            summary = `<div class="upload-summary err">Error: ${esc(result.error)}</div>`;
        } else {
            const failed = result.failed_count || 0;
            const modeText = result.mode ? ` (mode: ${esc(result.mode)})` : "";
            summary = `<div class="upload-summary ${failed ? "warn" : "ok"}">Loaded ${result.loaded_count} of ${total} file${total === 1 ? "" : "s"}: ${result.host_count || 0} hosts, ${result.subnet_count} subnets in the dataset${modeText}.</div>`;
        }
        status.innerHTML = summary + (total > 1 || !result.ok ? `<div class="upload-file-list">${rows}</div>` : "");
    }

    async function handleFiles(fileList) {
        const files = Array.from(fileList || []);
        if (!files.length || busy) return;
        busy = true;
        dropZone.classList.add("busy");
        status.innerHTML = `<div class="output-placeholder">Uploading ${files.length} file${files.length === 1 ? "" : "s"}...</div>`;
        const result = await Api.upload(files);
        renderResult(result, files.length);
        if (result.ok) refreshPanel();
        busy = false;
        dropZone.classList.remove("busy");
        fileInput.value = "";
    }

    dropZone.addEventListener("click", () => fileInput.click());
    fileInput.addEventListener("change", e => handleFiles(e.target.files));

    dropZone.addEventListener("dragover", e => {
        e.preventDefault();
        dropZone.classList.add("drag-over");
    });
    dropZone.addEventListener("dragleave", () => dropZone.classList.remove("drag-over"));
    dropZone.addEventListener("drop", e => {
        e.preventDefault();
        dropZone.classList.remove("drag-over");
        handleFiles(e.dataTransfer.files);
    });
};