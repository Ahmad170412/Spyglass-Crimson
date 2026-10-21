(() => {
  const viewNames = ["overview", "website", "ip", "settings", "results"];
  const views = Array.from(document.querySelectorAll("[data-view-panel]"));
  const navItems = Array.from(document.querySelectorAll("[data-view]"));
  const sourceCount = document.getElementById("sourceCount");
  const readinessBar = document.getElementById("readinessBar");
  const meterSegments = Array.from(document.querySelectorAll("#readinessBar .meter-seg"));

  const focusAfterNavTargets = {};

  const viewTitles = {
    overview: "Overview",
    website: "Website",
    ip: "IP address",
    settings: "Settings",
    results: "Results",
  };

  /* API layer ------------------------------------------------------- */

  const API_BASE = "/api";

  async function apiGet(path) {
    const response = await fetch(`${API_BASE}${path}`, {
      headers: { Accept: "application/json" },
    });
    const payload = await response.json().catch(() => ({}));
    if (!response.ok) {
      const message = payload && payload.error ? payload.error : `Request failed (${response.status})`;
      throw new Error(message);
    }
    return payload;
  }

  async function apiSend(path, method, body) {
    const response = await fetch(`${API_BASE}${path}`, {
      method,
      headers: { Accept: "application/json", "Content-Type": "application/json" },
      body: body === undefined ? undefined : JSON.stringify(body),
    });
    const payload = await response.json().catch(() => ({}));
    if (!response.ok) {
      const message = payload && payload.error ? payload.error : `Request failed (${response.status})`;
      throw new Error(message);
    }
    return payload;
  }

  /* Source inventory ------------------------------------------------ */

  let sourceInventory = { sources: [], summary: {} };

  async function loadSources() {
    try {
      sourceInventory = await apiGet("/sources");
    } catch (_error) {
      sourceInventory = { sources: [], summary: {} };
    }
    renderOverviewSources();
    syncActiveAvailability();
  }

  function sourceById(id) {
    return sourceInventory.sources.find((item) => item.id === id) || null;
  }

  function aggressiveIds() {
    const ids = sourceInventory.sources
      .filter((item) => item.layer === "aggressive")
      .map((item) => item.id);
    return new Set(ids.length ? ids : ["http", "nmap", "nuclei"]);
  }

  function syncActiveAvailability() {
    document.querySelectorAll("[data-active-source]").forEach((row) => {
      const id = row.dataset.activeSource;
      const item = sourceById(id);
      const available = !item || item.available !== false;
      const input = row.querySelector("input");
      const tag = row.querySelector("[data-active-tag]");

      if (input) {
        input.dataset.available = available ? "1" : "0";
        if (!available) input.checked = false;
      }
      row.classList.toggle("is-unavailable", !available);

      if (tag && item && item.requires_binary) {
        tag.textContent = available ? item.requires_binary : "not installed";
      }
      if (!available && item) {
        row.title = `Install ${item.missing || item.requires_binary} to enable this module.`;
      } else {
        row.removeAttribute("title");
      }
    });

    formRefreshers.forEach((refresh) => refresh());
  }

  function renderOverviewSources() {
    const container = document.querySelector("[data-source-list]");
    if (!container) return;

    const core = sourceInventory.sources.filter((item) => item.layer === "core");
    const enrichment = sourceInventory.sources.filter((item) => item.layer === "enrichment");
    const aggressive = sourceInventory.sources.filter((item) => item.layer === "aggressive");

    container.innerHTML = [
      groupMarkup("Core sources", "Keyless", core),
      groupMarkup("Enrichment", "Optional keys", enrichment),
      groupMarkup("Aggressive", "Authorization required", aggressive),
    ].join("");

    const summary = sourceInventory.summary || {};
    const coreTotal = summary.core || 0;
    const coreReady = summary.core_implemented || 0;
    const enrTotal = summary.enrichment || 0;
    const enrReady = summary.enrichment_implemented || 0;
    const aggTotal = summary.aggressive || 0;
    const aggReady = summary.aggressive_available || 0;

    if (sourceCount) {
      sourceCount.textContent =
        `${coreReady}/${coreTotal} core · ${enrReady}/${enrTotal} enrichment` +
        (aggTotal ? ` · ${aggReady}/${aggTotal} aggressive` : "");
    }

    const onCount = Math.max(0, Math.min(meterSegments.length, coreReady));
    meterSegments.forEach((segment, index) => {
      segment.classList.toggle("is-on", index < onCount);
    });

    if (readinessBar) {
      readinessBar.setAttribute("aria-label", `${coreReady} of ${coreTotal} core sources implemented`);
    }
  }

  function groupMarkup(title, meta, items) {
    if (!items.length) return "";
    return [
      `<div class="source-group">`,
      `<div class="group-head"><h3>${title}</h3><span>${meta}</span></div>`,
      `<div class="source-list">`,
      items.map(rowMarkup).join(""),
      `</div></div>`,
    ].join("");
  }

  function rowMarkup(item) {
    const health = item.health || { status: "unknown" };
    let state;
    if (item.requires_key && !keyConfigured(item.id)) {
      state =
        '<span class="status status--missing"><span class="status-dot"></span>Key needed</span>' +
        `<a class="text-link" href="#settings" data-focus="${item.id}Key">Add key</a>`;
    } else if (item.requires_binary && item.available === false) {
      state = `<span class="status status--missing" title="Install ${escapeHtml(item.missing || item.requires_binary)}"><span class="status-dot"></span>Not installed</span>`;
    } else if (health.status === "error") {
      state = '<span class="status status--error" title="Last run failed"><span class="status-dot"></span>Error</span>';
    } else if (health.status === "ok") {
      state = '<span class="status status--active"><span class="status-dot"></span>Active</span>';
    } else {
      state = '<span class="status status--warn" title="Implemented, not run yet"><span class="status-dot"></span>Ready</span>';
    }

    return [
      `<div class="source-row" data-source="${item.id}">`,
      `<div class="source-main">`,
      `<span class="source-name">${item.label}</span>`,
      `<span class="source-detail">${item.description}</span>`,
      `</div>`,
      `<span class="source-state">${state}</span>`,
      `</div>`,
    ].join("");
  }

  /* Key state ------------------------------------------------------- */

  let credentials = { credentials: [], backend: "file" };

  async function loadCredentials() {
    try {
      credentials = await apiGet("/credentials");
    } catch (_error) {
      credentials = { credentials: [], backend: "file" };
    }
    renderKeyStates();
    // Key state changes what the overview may claim about keyed sources.
    renderOverviewSources();
  }

  function credFor(provider) {
    return credentials.credentials.find((item) => item.provider === provider) || null;
  }

  function keyConfigured(provider) {
    const item = credFor(provider);
    return Boolean(item && item.configured);
  }

  function renderKeyStates() {
    credentials.credentials.forEach((item) => {
      const state = document.querySelector(`[data-key-state="${item.provider}"]`);
      const button = document.querySelector(`[data-save-key="${item.provider}"]`);
      if (state) {
        state.className = item.configured ? "key-state is-set" : "key-state";
        state.innerHTML = item.configured
          ? '<span class="status-dot"></span>Key set'
          : '<span class="status-dot"></span>Not configured';
      }
      if (button) button.textContent = item.configured ? "Replace" : "Save key";
    });
  }

  document.querySelectorAll("[data-save-key]").forEach((button) => {
    button.addEventListener("click", async () => {
      const provider = button.dataset.saveKey;
      const input = document.getElementById(`${provider}Key`);
      const state = document.querySelector(`[data-key-state="${provider}"]`);
      const value = input.value.trim();

      if (!value) {
        if (state) {
          state.className = "key-state is-error";
          state.innerHTML = '<span class="status-dot"></span>Enter a key';
        }
        input.focus();
        return;
      }

      button.disabled = true;
      const original = button.textContent;
      button.textContent = "Saving…";
      try {
        await apiSend(`/credentials/${provider}`, "PUT", { secret: value });
        input.value = "";
        input.placeholder = "Key set — paste a new key to replace";
        await loadCredentials();
      } catch (error) {
        if (state) {
          state.className = "key-state is-error";
          state.innerHTML = '<span class="status-dot"></span>Could not save';
        }
      } finally {
        button.disabled = false;
        button.textContent = original;
      }
    });
  });

  document.querySelectorAll("[data-test-key]").forEach((button) => {
    button.addEventListener("click", async () => {
      const provider = button.dataset.testKey;
      const out = document.querySelector(`[data-key-result="${provider}"]`);
      button.disabled = true;
      if (out) {
        out.textContent = "Testing…";
        out.className = "key-result";
      }
      try {
        const payload = await apiSend(`/credentials/${provider}/test`, "POST", {});
        if (out) {
          out.textContent = payload.message || (payload.ok ? "Key valid" : "Key rejected");
          out.className = payload.ok ? "key-result is-ok" : "key-result is-error";
        }
      } catch (error) {
        if (out) {
          out.textContent = error.message;
          out.className = "key-result is-error";
        }
      } finally {
        button.disabled = false;
      }
    });
  });

  document.querySelectorAll("[data-remove-key]").forEach((button) => {
    button.addEventListener("click", async () => {
      const provider = button.dataset.removeKey;
      const out = document.querySelector(`[data-key-result="${provider}"]`);
      button.disabled = true;
      if (out) {
        out.textContent = "Removing…";
        out.className = "key-result";
      }
      try {
        await apiSend(`/credentials/${provider}`, "DELETE");
        await loadCredentials();
        if (out) {
          out.textContent = "Key removed";
          out.className = "key-result";
        }
        const input = document.getElementById(`${provider}Key`);
        if (input) {
          input.value = "";
          input.placeholder = "Paste API key";
        }
      } catch (error) {
        if (out) {
          out.textContent = error.message;
          out.className = "key-result is-error";
        }
      } finally {
        button.disabled = false;
      }
    });
  });

  /* Views ----------------------------------------------------------- */

  function currentViewFromHash() {
    return (location.hash || "").replace("#", "");
  }

  function showView(name) {
    const targetName = viewNames.includes(name) ? name : "overview";

    views.forEach((view) => {
      const active = view.dataset.viewPanel === targetName;
      view.hidden = !active;
      view.classList.toggle("is-active", active);
    });

    navItems.forEach((item) => {
      const active = item.dataset.view === targetName;
      item.classList.toggle("is-active", active);
      if (active) {
        item.setAttribute("aria-current", "page");
      } else {
        item.removeAttribute("aria-current");
      }
    });

    document.title = `Spyglass-Crimson — ${viewTitles[targetName]}`;
    window.scrollTo({ top: 0, left: 0, behavior: "auto" });

    if (targetName === "results") {
      renderResults();
    }
  }

  if (!location.hash) {
    history.replaceState(null, "", "#overview");
  }

  showView(viewNames.includes(currentViewFromHash()) ? currentViewFromHash() : "overview");

  window.addEventListener("hashchange", () => {
    const name = currentViewFromHash();
    if (viewNames.includes(name)) {
      showView(name);
    }
  });

  document.addEventListener("click", (event) => {
    const trigger = event.target.closest("[data-focus]");
    if (trigger) {
      focusAfterNavTargets.field = trigger.dataset.focus;
      const field = document.getElementById(trigger.dataset.focus);
      if (field) requestAnimationFrame(() => field.focus());
    }
  });

  /* Run orchestration ---------------------------------------------- */

  async function startRun({ target, mode, layer, sources, aggressive, activeSources }) {
    const payload = await apiSend("/runs", "POST", {
      target,
      mode,
      layer: layer || null,
      sources: Array.isArray(sources) && sources.length ? sources : null,
      aggressive: Boolean(aggressive),
      active_sources:
        Array.isArray(activeSources) && activeSources.length ? activeSources : null,
    });
    return payload.id;
  }

  async function pollRun(runId, { onUpdate, interval = 800, timeoutMs = 180000 } = {}) {
    const deadline = Date.now() + timeoutMs;
    while (Date.now() < deadline) {
      let payload;
      try {
        payload = await apiGet(`/runs/${runId}`);
      } catch (error) {
        await sleep(interval);
        continue;
      }
      if (onUpdate) onUpdate(payload);
      if (payload.status === "complete" || payload.status === "error") {
        return payload;
      }
      await sleep(interval);
    }
    throw new Error("Timed out waiting for the run to finish");
  }

  function sleep(ms) {
    return new Promise((resolve) => setTimeout(resolve, ms));
  }

  async function runAndFollow(form, { target, mode, layer, sources, aggressive, activeSources }) {
    const runButton = form.querySelector("[data-run]");
    const note = form.querySelector("[data-form-note]");
    const originalLabel = runButton ? runButton.textContent : "";

    if (runButton) {
      runButton.disabled = true;
      runButton.textContent = "Starting…";
    }
    if (note) {
      note.textContent = "Creating run…";
      note.classList.remove("is-error");
      note.hidden = false;
    }

    try {
      const runId = await startRun({ target, mode, layer, sources, aggressive, activeSources });
      location.hash = "#results";
      activeRunId = runId;

      if (note) note.textContent = `Run ${runId} queued.`;
      if (runButton) runButton.textContent = "Running…";

      await pollRun(runId, {
        onUpdate: () => renderResults(),
      });
      await renderResults();
    } catch (error) {
      if (note) {
        note.textContent = error.message;
        note.classList.add("is-error");
        note.hidden = false;
      }
      if (runButton) runButton.disabled = false;
      return;
    }

    if (runButton) {
      runButton.disabled = false;
      runButton.textContent = originalLabel;
    }
    if (note) note.hidden = true;
  }

  /* Results view ---------------------------------------------------- */

  let activeRunId = null;
  let lastResults = null;

  function setResultsPlaceholder(message) {
    const host = document.querySelector("[data-results-host]");
    if (host) host.innerHTML = `<p class="form-note">${escapeHtml(message)}</p>`;
  }

  async function renderResults() {
    const host = document.querySelector("[data-results-host]");
    if (!host) return;

    if (!activeRunId) {
      const latest = await apiGet("/runs?limit=1").catch(() => ({ runs: [] }));
      if (latest.runs && latest.runs.length) {
        activeRunId = latest.runs[0].id;
      }
    }

    if (!activeRunId) {
      setResultsPlaceholder("No runs yet. Start one from the Website or IP view.");
      return;
    }

    let payload;
    try {
      payload = await apiGet(`/runs/${activeRunId}/results`);
    } catch (error) {
      setResultsPlaceholder(`Could not load run: ${error.message}`);
      return;
    }
    lastResults = payload;
    host.innerHTML = resultsMarkup(payload);
  }

  function resultsMarkup(payload) {
    const run = payload.run || {};
    const summary = payload.summary || {};
    const sourceRuns = payload.source_runs || [];
    const entities = payload.entities || [];
    const observations = payload.observations || [];

    const head = [
      `<div class="block-head">`,
      `<h2>${escapeHtml(run.target || "—")}</h2>`,
      `<span class="block-meta">${escapeHtml(run.status || "")}</span>`,
      `</div>`,
      `<p class="form-note">${summary.complete || 0} complete · ${summary.skipped || 0} skipped · ${summary.failed || 0} failed · ${summary.records || 0} record${(summary.records || 0) === 1 ? "" : "s"}</p>`,
    ].join("");

    const sourceRows = sourceRuns.map((item) => {
      const detail = item.error
        ? escapeHtml(item.error)
        : `${item.record_count || 0} record${(item.record_count || 0) === 1 ? "" : "s"}`;
      return [
        `<div class="source-row">`,
        `<div class="source-main">`,
        `<span class="source-name">${escapeHtml(item.source)}</span>`,
        `<span class="source-detail">${detail}</span>`,
        `</div>`,
        `<span class="source-state">${statusBadge(item.status)}</span>`,
        `</div>`,
      ].join("");
    }).join("");

    const grouped = groupEntities(entities);
    const entityBlocks = Object.keys(grouped).map((kind) => {
      const rows = grouped[kind].map((item) =>
        `<div class="source-row"><div class="source-main"><span class="source-name">${escapeHtml(item.key)}</span></div></div>`
      ).join("");
      return [
        `<div class="tool-group">`,
        `<div class="group-head"><h3>${escapeHtml(kindLabel(kind))}</h3><span>${grouped[kind].length}</span></div>`,
        `<div class="source-list">${rows}</div>`,
        `</div>`,
      ].join("");
    }).join("");

    const obsMarkup = observations.length
      ? [
          `<div class="tool-group">`,
          `<div class="group-head"><h3>Observations</h3><span>${observations.length}</span></div>`,
          `<div class="source-list">`,
          observations.map((item) =>
            `<div class="source-row"><div class="source-main"><span class="source-name">${escapeHtml(item.title)}</span>` +
            `<span class="source-detail">${escapeHtml(item.detail || "")}</span></div></div>`
          ).join(""),
          `</div></div>`,
        ].join("")
      : "";

    return [
      `<section class="block">${head}</section>`,
      `<section class="block"><div class="source-list">${sourceRows}</div></section>`,
      entityBlocks ? `<section class="block">${entityBlocks}</section>` : "",
      obsMarkup ? `<section class="block">${obsMarkup}</section>` : "",
    ].join("");
  }

  function groupEntities(entities) {
    const groups = {};
    entities.forEach((item) => {
      const kind = item.kind || "other";
      if (!groups[kind]) groups[kind] = [];
      groups[kind].push(item);
    });
    return groups;
  }

  function kindLabel(kind) {
    const labels = {
      hostname: "Hostnames",
      ip: "IP addresses",
      dns: "DNS records",
      registration: "Registration",
      certificate: "Certificates",
      asn: "ASN & routing",
      host: "Exposed services",
      enrichment: "Enrichment",
    };
    return labels[kind] || kind;
  }

  const STATUS_LABELS = {
    ok: ["Active", "status--active"],
    complete: ["Complete", "status--active"],
    partial: ["Partial", "status--warn"],
    empty: ["Empty", "status--warn"],
    not_found: ["Not found", "status--idle"],
    skipped: ["Skipped", "status--idle"],
    error: ["Error", "status--error"],
  };

  function statusBadge(status) {
    const [label, className] = STATUS_LABELS[status] || [
      status || "—",
      "status--missing",
    ];
    return `<span class="status ${className}"><span class="status-dot"></span>${escapeHtml(label)}</span>`;
  }

  function escapeHtml(value) {
    return String(value == null ? "" : value)
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;");
  }

  /* Scan forms ------------------------------------------------------ */

  const formRefreshers = [];

  function setupScan(form) {
    const modeButtons = Array.from(form.querySelectorAll("[data-mode]"));
    const modeNote = form.querySelector("[data-mode-note]");
    const authStrip = form.querySelector("[data-auth-strip]");
    const authCheck = form.querySelector("[data-auth-check]");
    const runButton = form.querySelector("[data-run]");
    const summary = form.querySelector("[data-scan-summary]");
    const note = form.querySelector("[data-form-note]");
    const target = form.querySelector(".target-input");
    const toolInputs = Array.from(form.querySelectorAll('input[name$="-tool"]'));
    const aggressiveRows = Array.from(form.querySelectorAll("[data-aggressive]"));
    const kind = form.dataset.scan;

    let mode = "passive";
    let authorized = false;

    function aggressiveSelected() {
      return aggressiveRows.some((row) => row.querySelector("input").checked);
    }

    function selectedTools() {
      return toolInputs.filter((input) => input.checked);
    }

    function updateSummary() {
      const count = selectedTools().length;
      summary.textContent = `${count} tool${count === 1 ? "" : "s"} selected`;
    }

    function showNote(message, isError = false) {
      note.textContent = message;
      note.classList.toggle("is-error", isError);
      note.hidden = false;
    }

    function refresh() {
      modeButtons.forEach((button) => {
        const active = button.dataset.mode === mode;
        button.classList.toggle("is-selected", active);
        button.setAttribute("aria-pressed", String(active));
      });

      const aggressive = mode === "aggressive";
      mirrorNote(aggressive);

      if (!aggressive) {
        authorized = false;
        authCheck.checked = false;
      }

      authStrip.hidden = !aggressive;

      aggressiveRows.forEach((row) => {
        const input = row.querySelector("input");
        const available = input.dataset.available !== "0";
        const unlocked = aggressive && authorized && available;
        input.disabled = !unlocked;
        row.classList.toggle("is-locked", !unlocked);
        if (unlocked) {
          input.checked = true;
        } else {
          input.checked = false;
        }
      });

      if (aggressive && !authorized) {
        runButton.disabled = true;
        runButton.textContent = "Confirm authorization";
      } else {
        runButton.disabled = false;
        runButton.textContent = aggressive ? "Run aggressive recon" : "Run passive recon";
      }

      updateSummary();
      note.hidden = true;
    }

    function mirrorNote(aggressive) {
      modeNote.textContent = aggressive
        ? "Active modules send traffic from this machine: HTTPS probe, top-100 TCP port scan, and rate-limited templates. Authorization is required."
        : "Public records only. No packets are sent to the target.";
    }

    modeButtons.forEach((button) => {
      button.addEventListener("click", () => {
        mode = button.dataset.mode;
        refresh();
      });
    });

    authCheck.addEventListener("change", () => {
      authorized = authCheck.checked;
      refresh();
    });

    toolInputs.forEach((input) => {
      input.addEventListener("change", () => {
        updateSummary();
        note.hidden = true;
      });
    });

    target.addEventListener("input", () => {
      note.hidden = true;
    });

    form.addEventListener("submit", async (event) => {
      event.preventDefault();

      const value = target.value.trim();
      const valid = kind === "website" ? isValidWebsite(value) : isValidIpTarget(value);

      if (!valid) {
        showNote(
          kind === "website"
            ? "Enter a domain or public URL, such as example.com."
            : "Enter an IP, CIDR, or ASN, such as 8.8.8.8 or AS15169.",
          true
        );
        target.focus();
        return;
      }

      if (mode === "aggressive" && !authorized) {
        showNote("Confirm authorization before running aggressive checks.", true);
        authCheck.focus();
        return;
      }

      const selected = selectedTools();
      if (!selected.length) {
        showNote("Select at least one tool to run.", true);
        return;
      }

      if (mode === "aggressive" && !selected.some((input) => aggressiveIds().has(input.value))) {
        showNote(
          "Select at least one active module, or switch to passive mode.",
          true
        );
        return;
      }

      if (mode === "aggressive") {
        // The gate is server-side: record the authorization before asking for
        // an active run, otherwise the API answers 403.
        try {
          await apiSend("/authorizations", "POST", {
            target: value,
            note: "confirmed in dashboard",
          });
        } catch (error) {
          showNote(error.message, true);
          return;
        }
      }

      // Aggressive ids never travel in `sources`; the `aggressive` flag adds the
      // module after the server checks the gate.
      const activeIds = aggressiveIds();
      const selectedActive = selected
        .map((input) => input.value)
        .filter((source) => activeIds.has(source));
      const passiveSources = selected
        .map((input) => input.value)
        .filter((source) => !activeIds.has(source));

      await runAndFollow(form, {
        target: value,
        mode: kind === "website" ? "website" : "passive",
        layer: null,
        sources: passiveSources.length ? passiveSources : null,
        aggressive: mode === "aggressive",
        activeSources: selectedActive,
      });
    });

    refresh();
    formRefreshers.push(refresh);
  }

  function isValidWebsite(value) {
    const candidate = value
      .replace(/^https?:\/\//i, "")
      .split("/")[0]
      .split("?")[0]
      .trim();
    return /^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/i.test(candidate);
  }

  function isValidIpTarget(value) {
    const ipv4 = /^(?:\d{1,3}\.){3}\d{1,3}(?:\/\d{1,2})?$/;
    const asn = /^as\d+$/i;
    const ipv6 = /^[0-9a-f:]+(?:\/\d{1,3})?$/i;
    return ipv4.test(value) || asn.test(value) || (value.includes(":") && ipv6.test(value));
  }

  document.querySelectorAll("[data-scan]").forEach(setupScan);

  const refreshButton = document.querySelector("[data-refresh-results]");
  if (refreshButton) {
    refreshButton.addEventListener("click", () => renderResults());
  }

  loadSources();
  loadCredentials();
  renderResults();
})();
