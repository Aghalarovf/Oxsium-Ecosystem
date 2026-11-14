function bindResultsUpload() {
    const zone = document.querySelector(".drop-zone");
    const input = document.getElementById("whois-dns-upload-input");
    const output = document.querySelector(".output-wrap");
    if (!zone || !input || zone.dataset.bound) return;
    zone.dataset.bound = "true";
    const upload = async file => {
        output.innerHTML = `<div>Importing ${Util.esc(file.name)}...</div>`;
        const result = await Api.uploadWhoisDns(file);
        output.innerHTML = result.ok
            ? `<div class="upload-success">Imported ${Util.esc(file.name)} for ${Util.esc(result.result.target)}</div>`
            : `<div class="upload-error">${Util.esc(result.error || "Import failed")}</div>`;
    };
    zone.addEventListener("click", () => input.click());
    input.addEventListener("change", () => {
        if (input.files[0]) upload(input.files[0]);
    });
    zone.addEventListener("dragover", event => {
        event.preventDefault();
        zone.classList.add("drag-over");
    });
    zone.addEventListener("dragleave", () => zone.classList.remove("drag-over"));
    zone.addEventListener("drop", event => {
        event.preventDefault();
        zone.classList.remove("drag-over");
        if (event.dataTransfer.files[0]) upload(event.dataTransfer.files[0]);
    });
}

document.addEventListener("DOMContentLoaded", bindResultsUpload);
