const state = {
    uploads: [],
    primaryInputId: "",
    tmatsId: "",
    rulePack: null,
    rulePackName: "",
    running: false,
};

const elements = {
    dropZone: document.getElementById("drop-zone"),
    fileInput: document.getElementById("file-input"),
    uploadedList: document.getElementById("uploaded-files"),
    profileSelect: document.getElementById("profile-select"),
    inputSelect: document.getElementById("input-select"),
    tmatsSelect: document.getElementById("tmats-select"),
    rulepackInput: document.getElementById("rulepack-input"),
    rulepackStatus: document.getElementById("rulepack-status"),
    validateButton: document.getElementById("start-validate"),
    autoFixButton: document.getElementById("start-autofix"),
    clearButton: document.getElementById("clear-diagnostics"),
    diagnosticBody: document.getElementById("diagnostic-body"),
    streamStatus: document.getElementById("stream-status"),
    acceptanceSummary: document.getElementById("acceptance-summary"),
    artifactLinks: document.getElementById("artifact-links"),
    autoFixLinks: document.getElementById("autofix-links"),
    logOutput: document.getElementById("log-output"),
    runStatus: document.getElementById("run-status"),
};

init();

function init() {
    wireEvents();
    fetchProfiles();
    setRunStatus("Ready.");
    logMessage("UI initialized.");
}

function wireEvents() {
    elements.dropZone.addEventListener("click", () => elements.fileInput.click());
    elements.dropZone.addEventListener("keydown", (event) => {
        if (event.key === "Enter" || event.key === " ") {
            event.preventDefault();
            elements.fileInput.click();
        }
    });
    elements.dropZone.addEventListener("dragover", (event) => {
        event.preventDefault();
        elements.dropZone.classList.add("dragover");
    });
    elements.dropZone.addEventListener("dragleave", () => {
        elements.dropZone.classList.remove("dragover");
    });
    elements.dropZone.addEventListener("drop", (event) => {
        event.preventDefault();
        elements.dropZone.classList.remove("dragover");
        if (event.dataTransfer?.files?.length) {
            uploadFiles(event.dataTransfer.files);
        }
    });
    elements.fileInput.addEventListener("change", (event) => {
        if (event.target.files?.length) {
            uploadFiles(event.target.files);
        }
    });
    elements.inputSelect.addEventListener("change", (event) => {
        state.primaryInputId = event.target.value;
    });
    elements.tmatsSelect.addEventListener("change", (event) => {
        state.tmatsId = event.target.value;
    });
    elements.rulepackInput.addEventListener("change", handleRulePackSelection);
    elements.validateButton.addEventListener("click", startValidate);
    elements.autoFixButton.addEventListener("click", startAutoFix);
    elements.clearButton.addEventListener("click", clearDiagnostics);
}

async function fetchProfiles() {
    try {
        const response = await fetch("/profiles");
        if (!response.ok) {
            throw new Error(`failed (${response.status})`);
        }
        const profiles = await response.json();
        renderProfiles(Array.isArray(profiles) ? profiles : []);
    } catch (error) {
        renderProfiles([]);
        setRunStatus(`Unable to load profiles: ${error.message}`, "error");
    }
}

function renderProfiles(profiles) {
    elements.profileSelect.innerHTML = "";
    if (profiles.length === 0) {
        const opt = document.createElement("option");
        opt.value = "";
        opt.textContent = "No profiles available";
        opt.disabled = true;
        opt.selected = true;
        elements.profileSelect.appendChild(opt);
        return;
    }
    const placeholder = document.createElement("option");
    placeholder.value = "";
    placeholder.textContent = "Select a profile";
    placeholder.disabled = true;
    placeholder.selected = true;
    elements.profileSelect.appendChild(placeholder);
    profiles.sort().forEach((profile) => {
        const opt = document.createElement("option");
        opt.value = profile;
        opt.textContent = profile;
        elements.profileSelect.appendChild(opt);
    });
}

async function uploadFiles(fileList) {
    const files = Array.from(fileList).filter((file) => file.size > 0);
    if (!files.length) {
        return;
    }
    setRunStatus(`Uploading ${files.length} file(s)…`);
    const formData = new FormData();
    files.forEach((file) => formData.append("file", file, file.name));
    try {
        const response = await fetch("/upload", {
            method: "POST",
            body: formData,
        });
        if (!response.ok) {
            const text = await response.text();
            throw new Error(text || `upload failed (${response.status})`);
        }
        const payload = await response.json();
        if (!payload.files || !Array.isArray(payload.files)) {
            throw new Error("unexpected upload response");
        }
        payload.files.forEach((ref) => {
            state.uploads.push({
                id: ref.id,
                name: ref.name,
                size: ref.size,
                contentType: ref.contentType,
                kind: ref.kind,
            });
        });
        renderUploads();
        setRunStatus(`Uploaded ${payload.files.length} file(s).`, "success");
        logMessage(`Uploaded ${payload.files.length} file(s).`, "success");
    } catch (error) {
        setRunStatus(`Upload error: ${error.message}`, "error");
        logMessage(`Upload error: ${error.message}`, "error");
    } finally {
        elements.fileInput.value = "";
    }
}

function renderUploads() {
    elements.uploadedList.innerHTML = "";
    if (state.uploads.length === 0) {
        elements.uploadedList.classList.add("empty");
        const li = document.createElement("li");
        li.textContent = "No files uploaded yet.";
        elements.uploadedList.appendChild(li);
    } else {
        elements.uploadedList.classList.remove("empty");
        state.uploads.forEach((file) => {
            const li = document.createElement("li");
            const name = document.createElement("strong");
            name.textContent = file.name || file.id;
            const meta = document.createElement("span");
            meta.textContent = `${formatBytes(file.size)} · ${file.kind || file.contentType || "upload"}`;
            li.append(name, meta);
            elements.uploadedList.appendChild(li);
        });
    }
    renderInputOptions();
    renderTMATSOptions();
}

function renderInputOptions() {
    elements.inputSelect.innerHTML = "";
    if (state.uploads.length === 0) {
        const opt = document.createElement("option");
        opt.value = "";
        opt.textContent = "No uploads yet";
        opt.disabled = true;
        opt.selected = true;
        elements.inputSelect.appendChild(opt);
        state.primaryInputId = "";
        return;
    }
    state.uploads.forEach((file, index) => {
        const opt = document.createElement("option");
        opt.value = file.id;
        opt.textContent = file.name || file.id;
        if (!state.primaryInputId && index === 0) {
            opt.selected = true;
            state.primaryInputId = file.id;
        }
        if (state.primaryInputId === file.id) {
            opt.selected = true;
        }
        elements.inputSelect.appendChild(opt);
    });
}

function renderTMATSOptions() {
    elements.tmatsSelect.innerHTML = "";
    const none = document.createElement("option");
    none.value = "";
    none.textContent = "None";
    elements.tmatsSelect.appendChild(none);
    if (!state.tmatsId) {
        none.selected = true;
    }
    state.uploads.forEach((file) => {
        const opt = document.createElement("option");
        opt.value = file.id;
        opt.textContent = file.name || file.id;
        if (state.tmatsId === file.id) {
            opt.selected = true;
        }
        elements.tmatsSelect.appendChild(opt);
    });
}

async function handleRulePackSelection(event) {
    const file = event.target.files?.[0];
    if (!file) {
        state.rulePack = null;
        state.rulePackName = "";
        elements.rulepackStatus.textContent = "Using default rule pack.";
        elements.rulepackStatus.classList.remove("error");
        return;
    }
    try {
        const text = await file.text();
        const parsed = JSON.parse(text);
        state.rulePack = parsed;
        state.rulePackName = file.name;
        elements.rulepackStatus.textContent = `Loaded ${file.name}`;
        elements.rulepackStatus.classList.remove("error");
        logMessage(`Loaded rule pack override from ${file.name}.`);
    } catch (error) {
        state.rulePack = null;
        state.rulePackName = "";
        elements.rulepackStatus.textContent = `Invalid rule pack: ${error.message}`;
        elements.rulepackStatus.classList.add("error");
        logMessage(`Rule pack error: ${error.message}`, "error");
    }
}

function setRunStatus(message, level = "info") {
    elements.runStatus.textContent = message;
    elements.runStatus.classList.remove("error", "success");
    if (level === "error") {
        elements.runStatus.classList.add("error");
    } else if (level === "success") {
        elements.runStatus.classList.add("success");
    }
}

function setRunning(running) {
    state.running = running;
    elements.validateButton.disabled = running;
    elements.autoFixButton.disabled = running;
    elements.dropZone.setAttribute("aria-disabled", running ? "true" : "false");
}

async function startValidate() {
    if (state.running) {
        return;
    }
    if (!state.primaryInputId) {
        setRunStatus("Select a primary input to validate.", "error");
        return;
    }
    const profile = elements.profileSelect.value;
    if (!profile) {
        setRunStatus("Select a profile before running validation.", "error");
        return;
    }
    clearDiagnostics();
    renderArtifacts([]);
    elements.acceptanceSummary.hidden = true;
    setRunStatus("Starting validation…");
    setRunning(true);
    elements.streamStatus.textContent = "Waiting for server…";
    logMessage(`Validation started for profile ${profile}.`);
    const payload = {
        inputs: [state.primaryInputId],
        profile,
        includeTimestamps: true,
    };
    if (state.tmatsId) {
        payload.tmats = state.tmatsId;
    }
    if (state.rulePack) {
        payload.rulePack = state.rulePack;
    }
    let summary = null;
    try {
        const response = await fetch("/validate?stream=true", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify(payload),
        });
        if (!response.ok || !response.body) {
            const text = await response.text();
            throw new Error(text || `validate failed (${response.status})`);
        }
        await readNDJSONStream(response.body, (item) => {
            if (item.type === "error") {
                elements.streamStatus.textContent = item.error || "Server reported an error.";
                logMessage(`Validation error: ${item.error}`, "error");
                return;
            }
            if (item.type === "acceptance") {
                summary = item;
                renderAcceptance(item);
            } else {
                appendDiagnostic(item);
            }
        });
        if (!summary) {
            throw new Error("validation ended without summary");
        }
        const manifest = await requestManifest();
        renderArtifacts(collectArtifacts(summary, manifest));
        elements.streamStatus.textContent = "Validation finished.";
        setRunStatus("Validation completed.", summary.acceptance?.summary?.pass ? "success" : "info");
        logMessage("Validation completed.", summary.acceptance?.summary?.pass ? "success" : "info");
    } catch (error) {
        elements.streamStatus.textContent = `Validation failed: ${error.message}`;
        setRunStatus(`Validation failed: ${error.message}`, "error");
        logMessage(`Validation failed: ${error.message}`, "error");
    } finally {
        setRunning(false);
    }
}

async function readNDJSONStream(stream, onItem) {
    const reader = stream.getReader();
    const decoder = new TextDecoder();
    let buffer = "";
    while (true) {
        const { value, done } = await reader.read();
        if (done) {
            break;
        }
        buffer += decoder.decode(value, { stream: true });
        buffer = processBuffer(buffer, onItem);
    }
    buffer += decoder.decode();
    processBuffer(buffer, onItem);
    reader.releaseLock();
}

function processBuffer(buffer, onItem) {
    const lines = buffer.split(/\r?\n/);
    const trailing = lines.pop();
    for (const line of lines) {
        const trimmed = line.trim();
        if (!trimmed) {
            continue;
        }
        try {
            const item = JSON.parse(trimmed);
            onItem(item);
        } catch (error) {
            logMessage(`Failed to parse stream chunk: ${error.message}`, "error");
        }
    }
    return trailing ?? "";
}

function appendDiagnostic(diag) {
    if (!diag || typeof diag !== "object") {
        return;
    }
    if (elements.diagnosticBody.querySelector(".placeholder")) {
        elements.diagnosticBody.innerHTML = "";
    }
    const row = document.createElement("tr");
    const severityCell = document.createElement("td");
    const severity = String(diag.severity || "").toLowerCase();
    severityCell.textContent = diag.severity ?? "";
    severityCell.classList.add(`severity-${severity || "info"}`);
    const ruleCell = document.createElement("td");
    ruleCell.textContent = diag.ruleId || "";
    const messageCell = document.createElement("td");
    messageCell.textContent = diag.message || "";
    const fileCell = document.createElement("td");
    fileCell.textContent = diag.file || "";
    const tsCell = document.createElement("td");
    tsCell.textContent = formatTimestamp(diag.ts, diag.timestamp_us);
    row.append(severityCell, ruleCell, messageCell, fileCell, tsCell);
    elements.diagnosticBody.appendChild(row);
}

function formatTimestamp(ts, micro) {
    if (micro != null) {
        return `${micro} μs`;
    }
    if (!ts) {
        return "";
    }
    const dt = new Date(ts);
    if (Number.isNaN(dt.getTime())) {
        return String(ts);
    }
    return dt.toLocaleString();
}

function clearDiagnostics() {
    elements.diagnosticBody.innerHTML = "";
    const row = document.createElement("tr");
    row.classList.add("placeholder");
    const cell = document.createElement("td");
    cell.colSpan = 5;
    cell.textContent = "Waiting for validation to start…";
    row.appendChild(cell);
    elements.diagnosticBody.appendChild(row);
    elements.streamStatus.textContent = "";
    elements.acceptanceSummary.hidden = true;
}

function renderAcceptance(summary) {
    if (!summary || !summary.acceptance) {
        return;
    }
    const rep = summary.acceptance;
    const summaryBox = elements.acceptanceSummary;
    summaryBox.hidden = false;
    summaryBox.classList.toggle("fail", !rep.summary?.pass);
    summaryBox.innerHTML = "";
    const heading = document.createElement("h3");
    heading.textContent = rep.summary?.pass ? "Acceptance: PASS" : "Acceptance: FAIL";
    const list = document.createElement("dl");
    const addPair = (label, value) => {
        const dt = document.createElement("dt");
        dt.textContent = label;
        const dd = document.createElement("dd");
        dd.textContent = value;
        list.append(dt, dd);
    };
    addPair("Total Diagnostics", String(rep.summary?.total ?? "0"));
    addPair("Errors", String(rep.summary?.errors ?? "0"));
    addPair("Warnings", String(rep.summary?.warnings ?? "0"));
    addPair("Pass", rep.summary?.pass ? "Yes" : "No");
    summaryBox.append(heading, list);
}

function collectArtifacts(summary, manifestArtifacts) {
    const artifacts = Array.isArray(summary?.artifacts) ? [...summary.artifacts] : [];
    if (Array.isArray(manifestArtifacts)) {
        artifacts.push(...manifestArtifacts);
    } else if (manifestArtifacts) {
        artifacts.push(manifestArtifacts);
    }
    return artifacts;
}

function renderArtifacts(artifacts) {
    elements.artifactLinks.innerHTML = "";
    if (!artifacts || artifacts.length === 0) {
        elements.artifactLinks.classList.add("empty");
        const li = document.createElement("li");
        li.textContent = "Run validation to produce artifacts.";
        elements.artifactLinks.appendChild(li);
        return;
    }
    elements.artifactLinks.classList.remove("empty");
    artifacts.forEach((artifact) => {
        const li = document.createElement("li");
        const link = document.createElement("a");
        link.href = `/artifacts/${encodeURIComponent(artifact.id)}`;
        link.download = artifact.name || "artifact";
        const label = artifact.name || artifact.id;
        const size = artifact.size ? ` (${formatBytes(artifact.size)})` : "";
        link.textContent = `${label}${size}`;
        li.appendChild(link);
        elements.artifactLinks.appendChild(li);
    });
}

async function requestManifest() {
    if (state.uploads.length === 0) {
        return null;
    }
    try {
        const response = await fetch("/manifest", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
                inputs: state.uploads.map((f) => f.id),
                shaAlgo: "sha256",
            }),
        });
        if (!response.ok) {
            const text = await response.text();
            throw new Error(text || `manifest failed (${response.status})`);
        }
        const payload = await response.json();
        const manifestArtifact = payload?.manifestArtifact ?? payload?.artifact ?? null;
        const signatureArtifact = payload?.signatureArtifact ?? null;
        const artifacts = [];
        if (manifestArtifact) {
            artifacts.push(manifestArtifact);
        }
        if (signatureArtifact) {
            artifacts.push(signatureArtifact);
        }
        return artifacts;
    } catch (error) {
        logMessage(`Manifest build failed: ${error.message}`, "error");
        return null;
    }
}

async function startAutoFix() {
    if (state.running) {
        return;
    }
    if (!state.primaryInputId) {
        setRunStatus("Select a primary input before auto-fix.", "error");
        return;
    }
    const profile = elements.profileSelect.value;
    if (!profile) {
        setRunStatus("Select a profile before auto-fix.", "error");
        return;
    }
    setRunning(true);
    setRunStatus("Running auto-fix…");
    logMessage(`Auto-fix started for profile ${profile}.`);
    const payload = {
        input: state.primaryInputId,
        profile,
        dryRun: false,
    };
    if (state.tmatsId) {
        payload.tmats = state.tmatsId;
    }
    if (state.rulePack) {
        payload.rulePack = state.rulePack;
    }
    try {
        const response = await fetch("/auto-fix", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify(payload),
        });
        if (!response.ok) {
            const text = await response.text();
            throw new Error(text || `auto-fix failed (${response.status})`);
        }
        const result = await response.json();
        renderAutoFixOutputs(result?.outputs || []);
        setRunStatus(`Auto-fix completed with ${result?.outputs?.length || 0} artifact(s).`, "success");
        logMessage("Auto-fix completed.", "success");
    } catch (error) {
        setRunStatus(`Auto-fix failed: ${error.message}`, "error");
        logMessage(`Auto-fix failed: ${error.message}`, "error");
    } finally {
        setRunning(false);
    }
}

function renderAutoFixOutputs(outputs) {
    elements.autoFixLinks.innerHTML = "";
    if (!outputs || outputs.length === 0) {
        elements.autoFixLinks.classList.add("empty");
        const li = document.createElement("li");
        li.textContent = "No auto-fix artifacts.";
        elements.autoFixLinks.appendChild(li);
        return;
    }
    elements.autoFixLinks.classList.remove("empty");
    outputs.forEach((artifact) => {
        const li = document.createElement("li");
        const link = document.createElement("a");
        link.href = `/artifacts/${encodeURIComponent(artifact.id)}`;
        link.download = artifact.name || "artifact";
        const label = artifact.name || artifact.id;
        const size = artifact.size ? ` (${formatBytes(artifact.size)})` : "";
        link.textContent = `${label}${size}`;
        li.appendChild(link);
        elements.autoFixLinks.appendChild(li);
    });
}

function formatBytes(size) {
    if (!size || Number.isNaN(Number(size))) {
        return "";
    }
    const units = ["B", "KB", "MB", "GB", "TB"];
    let value = Number(size);
    let unitIndex = 0;
    while (value >= 1024 && unitIndex < units.length - 1) {
        value /= 1024;
        unitIndex += 1;
    }
    return `${value.toFixed(value >= 10 || unitIndex === 0 ? 0 : 1)} ${units[unitIndex]}`;
}

function logMessage(message, level = "info") {
    const entry = document.createElement("div");
    entry.textContent = `[${new Date().toLocaleTimeString()}] ${message}`;
    entry.classList.add(level);
    if (level === "success") {
        entry.classList.add("success");
    } else if (level === "error") {
        entry.classList.add("error");
    }
    elements.logOutput.appendChild(entry);
    elements.logOutput.scrollTop = elements.logOutput.scrollHeight;
}
