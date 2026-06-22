/* vulnscan dashboard — single-page client.
 *
 * Talks to the FastAPI backend: POST /api/scan -> EventSource /api/scan/{id}/events,
 * rendering findings live, grouped by severity. All finding data is inserted via
 * textContent / createElement (never innerHTML) because findings contain
 * attacker-influenced strings and must not be able to execute in this page.
 */
(() => {
  "use strict";

  const SEV_ORDER = ["Critical", "High", "Medium", "Low", "Info"];
  const SEV_COLOR = {
    Critical: "#b00020",
    High: "#d9534f",
    Medium: "#f0ad4e",
    Low: "#5bc0de",
    Info: "#777777",
  };

  const $ = (id) => document.getElementById(id);
  const el = (tag, cls, text) => {
    const n = document.createElement(tag);
    if (cls) n.className = cls;
    if (text != null) n.textContent = text;
    return n;
  };

  // ---- State ------------------------------------------------------------------
  const state = {
    kind: "auto", // user-selected: auto | url | repo
    modulesByKind: { live: [], static: [] },
    selected: new Set(),
    passive: false,
    authorized: false,
    findings: new Map(), // id -> finding
    counts: { Critical: 0, High: 0, Medium: 0, Low: 0, Info: 0 },
    sevVisible: new Set(SEV_ORDER),
    source: null, // EventSource
    jobId: null,
    planned: 0,
    done: 0,
  };

  // ---- Target kind detection (mirrors server detect_kind) ---------------------
  function detectKind(target) {
    const t = (target || "").trim();
    if (!t) return "url";
    if (t.endsWith(".git") || t.startsWith("git@")) return "repo";
    if (/(github\.com|gitlab\.com|bitbucket\.org)/i.test(t)) return "repo";
    if (/^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/.test(t) && !/^https?:\/\//.test(t)) return "repo";
    return "url";
  }
  function resolvedKind() {
    return state.kind === "auto" ? detectKind($("target").value) : state.kind;
  }
  function isRepo() {
    return resolvedKind() === "repo";
  }

  // ---- Initial load -----------------------------------------------------------
  async function init() {
    wireKindControl();
    wireAdvanced();
    wirePassive();
    wireAuthorized();
    wireForm();
    $("target").addEventListener("input", onTargetChange);
    $("modules-clear").addEventListener("click", () => {
      state.selected.clear();
      renderModules();
      updateScanButton();
    });

    try {
      const h = await fetch("/api/health").then((r) => r.json());
      $("health-pill").textContent = `${h.service} v${h.version}`;
    } catch (_) {
      $("health-pill").textContent = "offline";
    }
    try {
      state.modulesByKind = await fetch("/api/modules").then((r) => r.json());
    } catch (_) {
      state.modulesByKind = { live: [], static: [] };
    }
    refreshForKind();
  }

  function wireKindControl() {
    document.querySelectorAll(".kind-btn").forEach((btn) => {
      btn.addEventListener("click", () => {
        state.kind = btn.dataset.kind;
        document.querySelectorAll(".kind-btn").forEach((b) =>
          b.setAttribute("aria-pressed", String(b === btn))
        );
        state.selected.clear();
        refreshForKind();
      });
    });
  }

  function wireAdvanced() {
    const toggle = $("adv-toggle");
    toggle.addEventListener("click", () => {
      const panel = $("adv-panel");
      const open = panel.classList.toggle("hidden") === false;
      toggle.setAttribute("aria-expanded", String(open));
      $("adv-chevron").style.transform = open ? "rotate(180deg)" : "";
    });
  }

  function wirePassive() {
    const sw = $("passive");
    sw.addEventListener("click", () => {
      state.passive = !state.passive;
      sw.setAttribute("aria-checked", String(state.passive));
    });
  }

  function wireAuthorized() {
    $("authorized").addEventListener("change", (e) => {
      state.authorized = e.target.checked;
      updateScanButton();
    });
  }

  function onTargetChange() {
    if (state.kind === "auto") refreshForKind();
    else updateScanButton();
  }

  // Adjust the form to the resolved kind (URL vs repo).
  function refreshForKind() {
    const repo = isRepo();
    const rk = resolvedKind();
    $("kind-resolved").textContent = state.kind === "auto" ? `→ ${rk}` : "";

    $("token-row").classList.toggle("hidden", !repo);
    $("ref-row").classList.toggle("hidden", !repo);
    $("passive-row").classList.toggle("hidden", repo);
    // Repo scans are read-only static analysis: the authorization gate is for URL scans.
    $("auth-gate").classList.toggle("hidden", repo);
    $("modules-mode").textContent = repo ? "static modules" : "live modules";

    renderModules();
    updateScanButton();
  }

  function currentModuleList() {
    return isRepo() ? state.modulesByKind.static : state.modulesByKind.live;
  }

  function renderModules() {
    const list = $("modules-list");
    list.replaceChildren();
    const mods = currentModuleList();
    if (!mods || !mods.length) {
      list.appendChild(el("div", "text-xs text-slate-500 py-2", "No modules available."));
      return;
    }
    mods.forEach((m) => {
      const label = el("label", "flex items-start gap-2.5 rounded-lg border border-white/5 bg-ink-850/50 px-3 py-2 cursor-pointer hover:border-white/10 transition");
      const cb = el("input");
      cb.type = "checkbox";
      cb.className = "mt-0.5 h-3.5 w-3.5 rounded border-white/20 bg-ink-750 text-cyan-500";
      cb.checked = state.selected.has(m.name);
      cb.addEventListener("change", () => {
        if (cb.checked) state.selected.add(m.name);
        else state.selected.delete(m.name);
        updateModulesMode();
      });
      const box = el("div", "min-w-0");
      const top = el("div", "flex items-center gap-1.5");
      top.appendChild(el("span", "text-sm font-medium text-slate-200 font-mono", m.name));
      if (m.intrusive) top.appendChild(el("span", "chip", "intrusive"));
      box.appendChild(top);
      box.appendChild(el("div", "text-xs text-slate-500 leading-snug", m.description || ""));
      label.appendChild(cb);
      label.appendChild(box);
      list.appendChild(label);
    });
    updateModulesMode();
  }

  function updateModulesMode() {
    const n = state.selected.size;
    const base = isRepo() ? "static modules" : "live modules";
    $("modules-mode").textContent = n === 0 ? `all ${base}` : `${n} selected`;
  }

  function updateScanButton() {
    const hasTarget = $("target").value.trim().length > 0;
    const needAuth = !isRepo();
    const ok = hasTarget && (!needAuth || $("authorized").checked);
    $("scan-btn").disabled = !ok;
  }

  // ---- Submit -----------------------------------------------------------------
  function wireForm() {
    $("scan-form").addEventListener("submit", onSubmit);
    $("reset-btn").addEventListener("click", resetForNewScan);
  }

  async function onSubmit(e) {
    e.preventDefault();
    const target = $("target").value.trim();
    if (!target) return;
    hide("form-error");
    resetResults();

    const payload = {
      target,
      kind: state.kind,
      modules: state.selected.size ? [...state.selected] : null,
      passive: state.passive,
      authorized: $("authorized").checked,
      token: ($("token").value || "").trim() || null,
      ref: ($("ref").value || "").trim() || null,
    };

    setScanning(true);
    let resp;
    try {
      resp = await fetch("/api/scan", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload),
      });
    } catch (err) {
      return formError("Could not reach the server. Is the dashboard still running?");
    }
    if (!resp.ok) {
      const detail = await resp.json().then((j) => j.detail).catch(() => resp.statusText);
      setScanning(false);
      return formError(detail || `Request failed (${resp.status}).`);
    }
    const data = await resp.json();
    state.jobId = data.job_id;
    show("status-card");
    $("status-line").textContent = `Starting ${data.kind} scan…`;
    $("status-sub").textContent = data.target;
    stream(data.job_id);
  }

  function stream(jobId) {
    const src = new EventSource(`/api/scan/${jobId}/events`);
    state.source = src;
    src.onmessage = (ev) => {
      let event;
      try { event = JSON.parse(ev.data); } catch (_) { return; }
      handleEvent(event);
    };
    src.onerror = () => {
      // Stream dropped — fall back to a final status poll.
      src.close();
      pollOnce(jobId);
    };
  }

  async function pollOnce(jobId) {
    try {
      const job = await fetch(`/api/scan/${jobId}`).then((r) => r.json());
      if (job.status === "done" && job.result) onComplete({ status: "done", result: job.result });
      else if (job.status === "error") onComplete({ status: "error", error: job.error });
    } catch (_) {
      formError("Lost connection to the scan.");
      setScanning(false);
    }
  }

  function handleEvent(event) {
    switch (event.type) {
      case "plan":
        state.planned = (event.modules ? event.modules.length : 0) * (event.targets || 1);
        $("status-line").textContent = `Scanning with ${event.modules ? event.modules.length : 0} module(s)…`;
        updateProgress();
        break;
      case "item_start":
        $("status-line").textContent = `Scanning: ${event.module}`;
        $("status-sub").textContent = event.target || "";
        break;
      case "item_done":
        (event.findings || []).forEach(addFinding);
        state.done += 1;
        updateProgress();
        renderFindings();
        break;
      case "item_error":
        state.done += 1;
        updateProgress();
        break;
      case "done":
        $("status-line").textContent = "Finalising…";
        break;
      case "complete":
        if (state.source) state.source.close();
        onComplete(event);
        break;
    }
  }

  function addFinding(f) {
    if (!f || !f.id || state.findings.has(f.id)) return;
    state.findings.set(f.id, f);
    if (state.counts[f.severity] != null) state.counts[f.severity] += 1;
    $("status-count").textContent = String(state.findings.size);
  }

  function updateProgress() {
    const bar = $("progress-bar");
    if (state.planned > 0) {
      bar.classList.remove("progress-indeterminate");
      bar.classList.add("progress-determinate");
      const pct = Math.min(100, Math.round((state.done / state.planned) * 100));
      bar.style.width = `${Math.max(6, pct)}%`;
      $("progress-text").textContent = `${state.done}/${state.planned} checks · ${state.findings.size} findings`;
    } else {
      $("progress-text").textContent = `${state.findings.size} findings`;
    }
  }

  // ---- Findings rendering -----------------------------------------------------
  function renderFindings() {
    show("findings-section");
    renderSevBar();
    const groups = $("findings-groups");
    groups.replaceChildren();

    const bySev = {};
    SEV_ORDER.forEach((s) => (bySev[s] = []));
    state.findings.forEach((f) => {
      if (bySev[f.severity]) bySev[f.severity].push(f);
    });

    let any = false;
    SEV_ORDER.forEach((sev) => {
      const items = bySev[sev];
      if (!items.length || !state.sevVisible.has(sev)) return;
      any = true;
      const wrap = el("div", "space-y-2");
      const head = el("div", "flex items-center gap-2 px-0.5");
      const badge = el("span", "sev-badge", sev);
      badge.style.background = SEV_COLOR[sev];
      head.appendChild(badge);
      head.appendChild(el("span", "text-sm font-medium text-slate-300", `${items.length}`));
      wrap.appendChild(head);
      items
        .sort((a, b) => (a.module + a.target).localeCompare(b.module + b.target))
        .forEach((f) => wrap.appendChild(findingCard(f)));
      groups.appendChild(wrap);
    });
    $("findings-empty").classList.toggle("hidden", any);
  }

  function renderSevBar() {
    const bar = $("sev-bar");
    bar.replaceChildren();
    SEV_ORDER.forEach((sev) => {
      const count = state.counts[sev] || 0;
      const chip = el("button", "sev-chip");
      chip.type = "button";
      chip.setAttribute("aria-pressed", String(state.sevVisible.has(sev)));
      const dot = el("span", "dot");
      dot.style.background = SEV_COLOR[sev];
      chip.appendChild(dot);
      chip.appendChild(el("span", null, `${sev} ${count}`));
      chip.addEventListener("click", () => {
        if (state.sevVisible.has(sev)) state.sevVisible.delete(sev);
        else state.sevVisible.add(sev);
        renderFindings();
      });
      bar.appendChild(chip);
    });
  }

  function findingCard(f) {
    const card = el("details", "finding");
    card.style.borderLeftColor = SEV_COLOR[f.severity] || "#777";

    const sum = el("summary");
    const badge = el("span", "sev-badge");
    badge.textContent = f.severity;
    badge.style.background = SEV_COLOR[f.severity];
    sum.appendChild(badge);

    const titleWrap = el("div", "min-w-0 flex-1");
    titleWrap.appendChild(el("div", "text-sm font-medium text-slate-100 truncate", f.title));
    const meta = el("div", "flex items-center gap-1.5 mt-0.5 flex-wrap");
    meta.appendChild(el("span", "text-xs text-slate-500 font-mono truncate", f.target));
    titleWrap.appendChild(meta);
    sum.appendChild(titleWrap);

    const chips = el("div", "flex items-center gap-1.5 shrink-0");
    chips.appendChild(el("span", "chip", f.module));
    if (f.confidence) chips.appendChild(el("span", "chip", f.confidence));
    sum.appendChild(chips);
    card.appendChild(sum);

    const body = el("div", "px-4 py-3 space-y-3 text-sm");
    if (f.description) body.appendChild(el("p", "text-slate-300 leading-relaxed", f.description));

    if (f.evidence && Object.keys(f.evidence).length) {
      const ev = el("div", "space-y-1");
      ev.appendChild(el("div", "text-xs uppercase tracking-wide text-slate-500", "Evidence"));
      const pre = el("pre", "evidence");
      pre.textContent = safeStringify(f.evidence);
      ev.appendChild(pre);
      body.appendChild(ev);
    }
    if (f.remediation) {
      const rem = el("div", "space-y-1");
      rem.appendChild(el("div", "text-xs uppercase tracking-wide text-slate-500", "Remediation"));
      rem.appendChild(el("p", "text-slate-300 leading-relaxed", f.remediation));
      body.appendChild(rem);
    }
    if (f.references && f.references.length) {
      const refs = el("div", "flex flex-wrap gap-x-3 gap-y-1");
      f.references.forEach((r) => refs.appendChild(referenceLink(r)));
      body.appendChild(refs);
    }
    card.appendChild(body);
    return card;
  }

  function referenceLink(ref) {
    const a = el("a", "text-xs");
    a.textContent = ref;
    a.target = "_blank";
    a.rel = "noopener noreferrer";
    const cve = /^CVE-\d{4}-\d+$/.exec(ref);
    const cwe = /^CWE-(\d+)$/.exec(ref);
    if (cve) a.href = `https://nvd.nist.gov/vuln/detail/${ref}`;
    else if (cwe) a.href = `https://cwe.mitre.org/data/definitions/${cwe[1]}.html`;
    else if (/^https?:\/\//.test(ref)) a.href = ref;
    else { const s = el("span", "text-xs text-slate-500"); s.textContent = ref; return s; }
    return a;
  }

  function safeStringify(obj) {
    try { return JSON.stringify(obj, null, 2); } catch (_) { return String(obj); }
  }

  // ---- Completion / summary ---------------------------------------------------
  function onComplete(event) {
    setScanning(false);
    hide("status-card");
    show("reset-btn");
    if (event.status === "error") {
      $("error-message").textContent = event.error || "The scan failed.";
      show("error-card");
      return;
    }
    const result = event.result;
    if (result && result.findings) {
      result.findings.forEach(addFinding);
      renderFindings();
    }
    renderSummary(result);
  }

  function renderSummary(result) {
    if (!result) return;
    show("summary-card");
    const s = result.summary || {};
    const counts = s.counts || state.counts;
    const highest = s.highest_severity || "Info";

    const badge = $("summary-badge");
    badge.textContent = highest;
    badge.style.background = SEV_COLOR[highest] || "#777";

    const meta = [];
    if (result.targets_scanned != null) meta.push(`${result.targets_scanned} target(s)`);
    if (result.modules_run) meta.push(`${result.modules_run.length} module(s)`);
    if (result.duration_seconds != null) meta.push(`${result.duration_seconds.toFixed(2)}s`);
    meta.push(`exit ${s.exit_code != null ? s.exit_code : "-"}`);
    $("summary-meta").textContent = meta.join("  ·  ");

    const grid = $("summary-counts");
    grid.replaceChildren();
    SEV_ORDER.forEach((sev) => {
      const cell = el("div", "rounded-lg border border-white/5 bg-ink-850/60 px-3 py-2.5 text-center");
      const n = el("div", "text-lg font-semibold tabular-nums", String(counts[sev] || 0));
      n.style.color = (counts[sev] || 0) > 0 ? SEV_COLOR[sev] : "#64748b";
      cell.appendChild(n);
      cell.appendChild(el("div", "text-[10px] uppercase tracking-wide text-slate-500 mt-0.5", sev));
      grid.appendChild(cell);
    });

    const errBox = $("summary-errors");
    if (result.errors && result.errors.length) {
      errBox.replaceChildren();
      errBox.appendChild(el("div", "font-semibold text-sev-high mb-1", `${result.errors.length} module error(s)`));
      result.errors.slice(0, 8).forEach((e) =>
        errBox.appendChild(el("div", "text-slate-400 font-mono", `${e.module}: ${e.error}`))
      );
      show("summary-errors");
    } else {
      hide("summary-errors");
    }

    if (state.jobId) {
      $("dl-json").href = `/api/scan/${state.jobId}/report.json`;
      $("dl-html").href = `/api/scan/${state.jobId}/report.html`;
      $("dl-json").setAttribute("target", "_blank");
      $("dl-html").setAttribute("target", "_blank");
    }
  }

  // ---- UI helpers -------------------------------------------------------------
  function setScanning(on) {
    $("scan-btn").disabled = on || $("scan-btn").disabled;
    $("scan-btn-label").textContent = on ? "Scanning…" : "Start scan";
    if (!on) updateScanButton();
  }
  function resetResults() {
    state.findings.clear();
    state.counts = { Critical: 0, High: 0, Medium: 0, Low: 0, Info: 0 };
    state.sevVisible = new Set(SEV_ORDER);
    state.planned = 0;
    state.done = 0;
    $("status-count").textContent = "0";
    const bar = $("progress-bar");
    bar.classList.add("progress-indeterminate");
    bar.classList.remove("progress-determinate");
    bar.style.width = "33%";
    ["summary-card", "error-card", "findings-section", "reset-btn"].forEach(hide);
  }
  function resetForNewScan() {
    if (state.source) state.source.close();
    resetResults();
    hide("status-card");
    updateScanButton();
    window.scrollTo({ top: 0, behavior: "smooth" });
  }
  function show(id) { $(id).classList.remove("hidden"); }
  function hide(id) { $(id).classList.add("hidden"); }
  function formError(msg) {
    const e = $("form-error");
    e.textContent = msg;
    show("form-error");
  }

  document.addEventListener("DOMContentLoaded", init);
})();
