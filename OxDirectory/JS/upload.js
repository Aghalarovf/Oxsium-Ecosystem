window.initUpload = function() {
    const dropZone = document.getElementById("drop-zone");
    const fileInput = document.getElementById("file-input");
    const status = document.getElementById("upload-status");
    if (!dropZone || dropZone.dataset.initialized) return;
    dropZone.dataset.initialized = "true";
    let busy = false;

    function renderResult(result, total) {
        if (!result.ok && !result.results) {
            status.innerHTML = `<div class="upload-summary err">Error: ${Util.esc(result.error || "Upload failed")}</div>`;
            return;
        }
        const rows = (result.results || []).map(item => `
            <div class="upload-file ${item.ok ? "ok" : "err"}">
                <span class="upload-file-mark">${item.ok ? "&#10003;" : "&#10005;"}</span>
                <span class="upload-file-name">${Util.esc(item.name)}</span>
                <span class="upload-file-info">${item.ok ? `${item.host_count || 0} records` : Util.esc(item.error)}</span>
            </div>`).join("");
        const failed = result.failed_count || 0;
        const summary = result.ok
            ? `<div class="upload-summary ${failed ? "warn" : "ok"}">Loaded ${result.loaded_count || 0} of ${total} file${total === 1 ? "" : "s"}.</div>`
            : `<div class="upload-summary err">Error: ${Util.esc(result.error || "Some files failed")}</div>`;
        status.innerHTML = summary + (total > 1 || !result.ok ? `<div class="upload-file-list">${rows}</div>` : "");
    }

    async function handleFiles(files) {
        const selected = Array.from(files || []);
        if (!selected.length || busy) return;
        busy = true;
        dropZone.classList.add("busy");
        status.innerHTML = `<div class="output-placeholder">Uploading ${selected.length} file${selected.length === 1 ? "" : "s"}...</div>`;
        try {
            const result = await Api.upload(selected);
            renderResult(result, selected.length);
            if (result.ok) {
                if (window.invalidateDomainViews) window.invalidateDomainViews();
                if (window.refreshPanel) window.refreshPanel();
            }
        } catch (error) {
            status.innerHTML = `<div class="upload-summary err">Error: ${Util.esc(error.message)}</div>`;
        } finally {
            busy = false;
            dropZone.classList.remove("busy");
            fileInput.value = "";
        }
    }

    dropZone.addEventListener("click", () => fileInput.click());
    fileInput.addEventListener("change", event => handleFiles(event.target.files));
    dropZone.addEventListener("dragover", event => {
        event.preventDefault();
        dropZone.classList.add("drag-over");
    });
    dropZone.addEventListener("dragleave", () => dropZone.classList.remove("drag-over"));
    dropZone.addEventListener("drop", event => {
        event.preventDefault();
        dropZone.classList.remove("drag-over");
        handleFiles(event.dataTransfer.files);
    });
};
