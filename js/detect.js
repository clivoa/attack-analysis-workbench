/* Detection Designer — prioritized detection-engineering worklist.
 *
 * Answers "what should we detect and why":
 *   score  = threat (profile usage, 0–50)
 *          + prevalence (global group usage, log-scaled, 0–30)
 *          + exposure (no mitigation mapped, +20)
 *   visibility = analytics' required log sources vs the user's telemetry
 *                (full / partial / blind)
 * Per-technique detection cards come from ATT&CK v18+ detection strategies:
 * analytics with descriptions, platforms, log sources (channel-level) and
 * tuning knobs (mutable elements). */

const Detect = (() => {
  const TEL_KEY = "attack-workbench-telemetry";
  const BACKLOG_KEY = "attack-workbench-backlog";
  const PAGE = 100;

  const STATUS_LABELS = { review: "To review", planned: "Planned", done: "Implemented", na: "N/A" };

  const PRESETS = {
    Windows: ["wineventlog"],
    Linux: ["auditd", "linux"],
    macOS: ["macos", "fs"],
    Cloud: ["aws", "azure", "gcp", "m365", "o365", "saas", "kubernetes", "docker", "identity"],
    Network: ["nsm", "networkdevice", "network", "pcap", "zeek", "dns", "internet"],
  };

  let telemetry = new Set();   // log source names
  let backlog = {};            // techId -> status
  let limit = PAGE;
  let expanded = new Set();    // techIds with open cards
  let focusTid = null;

  /* ---------- Persistence ---------- */

  function load() {
    try { telemetry = new Set(JSON.parse(localStorage.getItem(TEL_KEY) || "[]")); } catch { telemetry = new Set(); }
    try { backlog = JSON.parse(localStorage.getItem(BACKLOG_KEY) || "{}"); } catch { backlog = {}; }
  }

  function saveTel() { localStorage.setItem(TEL_KEY, JSON.stringify([...telemetry])); }
  function saveBacklog() { localStorage.setItem(BACKLOG_KEY, JSON.stringify(backlog)); }

  /* ---------- Scoring & visibility ---------- */

  function hasMitigation(tid) {
    if (S.idx.techMitigations.has(tid)) return true;
    const parent = S.idx.parentOf.get(tid);
    return parent ? S.idx.techMitigations.has(parent) : false;
  }

  /* full: some analytic has all of its log sources in telemetry
   * partial: some analytic has at least one matched log source
   * blind: analytics exist but nothing matches
   * unknown: telemetry not configured yet */
  function visibilityOf(tid) {
    if (!telemetry.size) return "unknown";
    const det = S.data.detections[tid];
    if (!det || !det.analytics.length) return "blind";
    let partial = false;
    for (const an of det.analytics) {
      if (!an.logs.length) continue;
      let matched = 0;
      for (const [ls] of an.logs) if (telemetry.has(S.data.logsources[ls])) matched++;
      if (matched === an.logs.length) return "full";
      if (matched > 0) partial = true;
    }
    return partial ? "partial" : "blind";
  }

  function buildScope() {
    const heat = profileHeat(); // exact technique granularity
    const maxThreat = Math.max(1, ...[...heat.exact.values()].map((r) => r.count));
    const maxGroups = Math.max(1, ...[...S.idx.techGroups.values()].map((g) => g.length));

    const rows = [];
    for (const [tid, rec] of heat.exact) {
      const t = S.data.techniques[tid];
      if (!t) continue;
      const gcount = (S.idx.techGroups.get(tid) || []).length;
      const threat = 50 * (rec.count / maxThreat);
      const prevalence = 30 * (Math.log1p(gcount) / Math.log1p(maxGroups));
      const exposure = hasMitigation(tid) ? 0 : 20;
      rows.push({
        tid, t,
        who: rec.who, whoCount: rec.count,
        gcount,
        threat, prevalence, exposure,
        score: threat + prevalence + exposure,
        vis: visibilityOf(tid),
        status: backlog[tid] || "review",
      });
    }
    rows.sort((a, b) => b.score - a.score || a.tid.localeCompare(b.tid));
    return { rows, isFallback: heat.isFallback, size: heat.size };
  }

  function applyFilters(rows) {
    const q = document.getElementById("dt-search").value.trim().toLowerCase();
    const plat = document.getElementById("dt-platform").value;
    const vis = document.getElementById("dt-visibility").value;
    const status = document.getElementById("dt-status").value;

    return rows.filter((r) => {
      if (q && !(`${r.tid} ${r.t.name}`.toLowerCase().includes(q))) return false;
      if (vis && r.vis !== vis) return false;
      if (status && r.status !== status) return false;
      if (plat) {
        const det = S.data.detections[r.tid];
        const plats = new Set((det ? det.analytics : []).flatMap((a) => a.platforms));
        if (!plats.has(plat)) return false;
      }
      return true;
    });
  }

  /* ---------- Rendering ---------- */

  function render() {
    S.dirty.detect = false;
    renderTelemetryRail();

    const scope = buildScope();
    const rows = applyFilters(scope.rows);

    renderSummary(scope, rows);

    document.getElementById("dt-scoring-note").innerHTML =
      `Score = <b>threat</b> (usage by ${scope.isFallback ? "any group — build a threat profile to focus this" : "your threat profile"}, 0–50)
       + <b>prevalence</b> (how many of all ${Object.keys(S.data.groups).length} groups use it, 0–30)
       + <b>exposure</b> (+20 when ATT&CK maps no mitigation — detection is the only control).`;

    const list = document.getElementById("dt-worklist");
    list.innerHTML = rows.slice(0, limit).map((r, i) => rowHtml(r, i)).join("");

    const moreWrap = document.getElementById("dt-more-wrap");
    moreWrap.innerHTML = rows.length > limit
      ? `<button id="dt-more" class="btn subtle">Show ${Math.min(PAGE, rows.length - limit)} more (${rows.length - limit} remaining)</button>`
      : "";
    const moreBtn = document.getElementById("dt-more");
    if (moreBtn) moreBtn.addEventListener("click", () => { limit += PAGE; render(); });

    wireRows(list);

    if (focusTid) {
      const el = list.querySelector(`[data-tid="${CSS.escape(focusTid)}"]`);
      if (el) el.scrollIntoView({ block: "center" });
      focusTid = null;
    }
  }

  function renderSummary(scope, rows) {
    const vis = { full: 0, partial: 0, blind: 0, unknown: 0 };
    let noMit = 0, planned = 0, done = 0;
    for (const r of scope.rows) {
      vis[r.vis]++;
      if (r.exposure) noMit++;
      if (r.status === "planned") planned++;
      if (r.status === "done") done++;
    }
    const denom = scope.rows.length || 1;
    const covPct = telemetry.size
      ? Math.round(((vis.full + 0.5 * vis.partial) / denom) * 100)
      : null;

    document.getElementById("dt-summary").innerHTML = `
      <div class="sum-card">
        <div class="sum-num">${scope.rows.length}</div>
        <div class="sum-lbl">techniques in scope${scope.isFallback ? " (all groups)" : ""}</div>
      </div>
      <div class="sum-card ${covPct === null ? "" : covPct < 40 ? "bad" : covPct < 70 ? "mid" : "good"}">
        <div class="sum-num">${covPct === null ? "—" : covPct + "%"}</div>
        <div class="sum-lbl">${covPct === null ? "telemetry not configured" : `visibility (${vis.full} full · ${vis.partial} partial · ${vis.blind} blind)`}</div>
      </div>
      <div class="sum-card warn">
        <div class="sum-num">${noMit}</div>
        <div class="sum-lbl">no mitigation mapped — detection-only</div>
      </div>
      <div class="sum-card">
        <div class="sum-num">${done}<span class="sum-sub">/${done + planned}</span></div>
        <div class="sum-lbl">rules implemented / in backlog</div>
      </div>
      ${rows.length !== scope.rows.length ? `<div class="sum-note">${rows.length} shown after filters</div>` : ""}`;
  }

  function rowHtml(r, i) {
    const visMeta = {
      full: ["Full", "vis-full", "At least one analytic fully served by your telemetry"],
      partial: ["Partial", "vis-partial", "Some required log sources present, none of the analytics fully served"],
      blind: ["Blind", "vis-blind", "None of the required log sources are in your telemetry"],
      unknown: ["?", "vis-unknown", "Configure your telemetry on the left"],
    }[r.vis];
    const whoPreview = r.who.slice(0, 3).join(", ");
    const open = expanded.has(r.tid);

    return `
      <li class="wl-item ${open ? "open" : ""}" data-tid="${r.tid}">
        <div class="wl-row">
          <span class="wl-rank">${i + 1}</span>
          <span class="wl-score" title="threat ${r.threat.toFixed(0)} + prevalence ${r.prevalence.toFixed(0)} + exposure ${r.exposure}">
            ${Math.round(r.score)}
            <span class="wl-scorebar"><i style="width:${r.score}%"></i></span>
          </span>
          <span class="wl-name">
            <span class="tid">${r.tid}</span>${esc(r.t.name)}
            ${r.t.sub ? `<span class="wl-sub">sub</span>` : ""}
            <span class="wl-tactic">${(r.t.tactics[0] || "").replace(/-/g, " ")}</span>
          </span>
          <span class="wl-who" title="${esc(whoPreview)}${r.whoCount > 3 ? "…" : ""}">${r.whoCount}× actors</span>
          ${r.exposure ? `<span class="wl-flag" title="No mitigation mapped in ATT&CK — detection is the only control">⚠ no mitigation</span>` : `<span class="wl-flag ok">mitigable</span>`}
          <span class="wl-vis ${visMeta[1]}" title="${visMeta[2]}">${visMeta[0]}</span>
          <select class="wl-status" data-tid="${r.tid}">
            ${Object.entries(STATUS_LABELS).map(([v, l]) =>
              `<option value="${v}" ${r.status === v ? "selected" : ""}>${l}</option>`).join("")}
          </select>
          <button class="wl-toggle" title="Detection card">${open ? "▴" : "▾"}</button>
        </div>
        ${open ? cardHtml(r) : ""}
      </li>`;
  }

  /* The detection card: WHY → COLLECT → DETECT. */
  function cardHtml(r) {
    const det = S.data.detections[r.tid];
    const groups = (S.idx.techGroups.get(r.tid) || []).slice(0, 10);
    const campaigns = (S.idx.techCampaigns.get(r.tid) || []).slice(0, 6);
    const profileWho = r.who.join(", ");

    const analytics = det ? det.analytics : [];
    const neededSources = new Map(); // name -> {channels:Set, have:bool}
    for (const an of analytics) {
      for (const [ls, ch] of an.logs) {
        const name = S.data.logsources[ls];
        if (!neededSources.has(name)) neededSources.set(name, { channels: new Set(), have: telemetry.has(name) });
        if (ch) neededSources.get(name).channels.add(ch);
      }
    }

    return `
      <div class="dcard">
        <div class="dcard-col">
          <div class="dcard-h">Why detect this</div>
          <p class="dcard-p">${esc(r.t.desc || "")}</p>
          <p class="dcard-p">
            ${S.profile.size ? `<b>${r.whoCount}</b> profile ${r.whoCount === 1 ? "entity uses" : "entities use"} it${profileWho ? ` (${esc(profileWho)})` : ""}. ` : ""}
            Used by <b>${r.gcount}</b> of ${Object.keys(S.data.groups).length} tracked groups.
            ${r.exposure ? `<b class="warn-text">No mitigation is mapped — detection is your only control here.</b>` : ""}
          </p>
          ${groups.length ? `<div class="chips">${groups.map((g) =>
            `<span class="chip clickable" data-nav="${g}"><span class="tid">${g}</span>${esc(S.data.groups[g].name)}</span>`).join("")}</div>` : ""}
          ${campaigns.length ? `<div class="dcard-h" style="margin-top:10px">Seen in campaigns</div><div class="chips">${campaigns.map((c) =>
            `<span class="chip clickable" data-nav="${c}"><span class="tid">${c}</span>${esc(S.data.campaigns[c].name)}</span>`).join("")}</div>` : ""}
        </div>

        <div class="dcard-col">
          <div class="dcard-h">What to collect</div>
          ${neededSources.size ? `<ul class="ls-list">${[...neededSources.entries()].map(([name, info]) => `
            <li class="${info.have ? "have" : "miss"}">
              <span class="ls-mark">${info.have ? "✓" : "✗"}</span>
              <span class="ls-name">${esc(name)}</span>
              <span class="ls-ch">${esc([...info.channels].slice(0, 3).join(" · "))}</span>
            </li>`).join("")}</ul>`
          : `<p class="dcard-p">No log source mapping available for this technique.</p>`}
        </div>

        <div class="dcard-col wide">
          <div class="dcard-h">Detection use-cases ${det ? `<span class="count">${det.detName ? esc(det.det) : ""} · ${analytics.length} analytics</span>` : ""}</div>
          ${analytics.length ? analytics.map((an) => {
            const anCov = an.logs.length && an.logs.every(([ls]) => telemetry.has(S.data.logsources[ls]));
            return `
            <div class="an-item ${anCov ? "covered" : ""}">
              <div class="an-head">
                <span class="tid">${an.id}</span>
                <span class="an-plat">${an.platforms.join(", ")}</span>
                ${anCov ? `<span class="an-ok">✓ telemetry ready</span>` : ""}
              </div>
              <div class="an-desc">${esc(an.desc)}</div>
              ${an.logs.length ? `<div class="an-logs">${an.logs.map(([ls, ch]) =>
                `<span class="an-log ${telemetry.has(S.data.logsources[ls]) ? "have" : ""}">${esc(S.data.logsources[ls])}${ch ? ` <i>${esc(ch)}</i>` : ""}</span>`).join("")}</div>` : ""}
              ${an.tuning.length ? `<div class="an-tuning">Tuning knobs: ${an.tuning.map((f) => `<code>${esc(f)}</code>`).join(", ")}</div>` : ""}
            </div>`;
          }).join("") : `<p class="dcard-p">No analytics defined.</p>`}
          <div class="dcard-actions">
            <button class="btn mini dcard-copy" data-tid="${r.tid}">Copy card (Markdown)</button>
            <a class="btn mini" href="${attackUrl(r.tid)}" target="_blank" rel="noopener">ATT&CK ↗</a>
            <button class="btn mini dcard-panel" data-tid="${r.tid}">Full relationships →</button>
          </div>
        </div>
      </div>`;
  }

  function wireRows(list) {
    list.querySelectorAll(".wl-row").forEach((row) => {
      row.addEventListener("click", (ev) => {
        if (ev.target.closest("select, a, button.dcard-copy")) return;
        const tid = row.parentElement.dataset.tid;
        if (expanded.has(tid)) expanded.delete(tid);
        else expanded.add(tid);
        render();
      });
    });
    list.querySelectorAll(".wl-status").forEach((sel) => {
      sel.addEventListener("click", (ev) => ev.stopPropagation());
      sel.addEventListener("change", () => {
        if (sel.value === "review") delete backlog[sel.dataset.tid];
        else backlog[sel.dataset.tid] = sel.value;
        saveBacklog();
        render();
      });
    });
    list.querySelectorAll("[data-nav]").forEach((n) =>
      n.addEventListener("click", (ev) => { ev.stopPropagation(); Panel.show(n.dataset.nav); }));
    list.querySelectorAll(".dcard-panel").forEach((b) =>
      b.addEventListener("click", () => Panel.show(b.dataset.tid)));
    list.querySelectorAll(".dcard-copy").forEach((b) =>
      b.addEventListener("click", async () => {
        const r = buildScope().rows.find((x) => x.tid === b.dataset.tid);
        await navigator.clipboard.writeText(cardMarkdown(r));
        b.textContent = "Copied ✓";
        setTimeout(() => { b.textContent = "Copy card (Markdown)"; }, 1600);
      }));
  }

  /* ---------- Telemetry rail ---------- */

  function telGroups() {
    const groups = new Map(); // prefix -> [names]
    for (const name of S.data.logsources) {
      const prefix = name.includes(":") ? name.split(":")[0] : name.split(" ")[0];
      if (!groups.has(prefix)) groups.set(prefix, []);
      groups.get(prefix).push(name);
    }
    return [...groups.entries()].sort((a, b) => b[1].length - a[1].length || a[0].localeCompare(b[0]));
  }

  function renderTelemetryRail() {
    document.getElementById("tel-presets").innerHTML =
      Object.keys(PRESETS).map((p) => `<button class="btn subtle mini" data-preset="${p}">＋ ${p}</button>`).join("");

    document.getElementById("tel-groups").innerHTML = telGroups().map(([prefix, names]) => {
      const haveCount = names.filter((n) => telemetry.has(n)).length;
      const open = haveCount > 0;
      return `
      <details class="tel-group" ${open ? "open" : ""}>
        <summary>
          <span>${esc(prefix)}</span>
          <span class="tel-count ${haveCount ? "on" : ""}">${haveCount}/${names.length}</span>
        </summary>
        <div class="tel-items">
          <button class="tel-all" data-prefix="${esc(prefix)}">toggle all</button>
          ${names.sort().map((n) => `
            <label class="tel-item">
              <input type="checkbox" data-ls="${esc(n)}" ${telemetry.has(n) ? "checked" : ""} />
              <span>${esc(n.includes(":") ? n.slice(n.indexOf(":") + 1) : n)}</span>
            </label>`).join("")}
        </div>
      </details>`;
    }).join("");

    const rail = document.getElementById("tel-groups");
    rail.querySelectorAll("input[data-ls]").forEach((cb) =>
      cb.addEventListener("change", () => {
        if (cb.checked) telemetry.add(cb.dataset.ls);
        else telemetry.delete(cb.dataset.ls);
        saveTel();
        renderMainOnly();
      }));
    rail.querySelectorAll(".tel-all").forEach((btn) =>
      btn.addEventListener("click", (ev) => {
        ev.preventDefault();
        const names = S.data.logsources.filter((n) =>
          (n.includes(":") ? n.split(":")[0] : n.split(" ")[0]) === btn.dataset.prefix);
        const allOn = names.every((n) => telemetry.has(n));
        names.forEach((n) => allOn ? telemetry.delete(n) : telemetry.add(n));
        saveTel();
        render();
      }));

    document.querySelectorAll("[data-preset]").forEach((btn) =>
      btn.addEventListener("click", () => {
        const prefixes = PRESETS[btn.dataset.preset];
        for (const n of S.data.logsources) {
          const p = (n.includes(":") ? n.split(":")[0] : n.split(" ")[0]).toLowerCase();
          if (prefixes.includes(p)) telemetry.add(n);
        }
        saveTel();
        render();
      }));
  }

  /* Re-render summary + worklist without rebuilding the rail (checkbox focus). */
  function renderMainOnly() {
    const scope = buildScope();
    const rows = applyFilters(scope.rows);
    renderSummary(scope, rows);
    const list = document.getElementById("dt-worklist");
    list.innerHTML = rows.slice(0, limit).map((r, i) => rowHtml(r, i)).join("");
    wireRows(list);
    // refresh group counters in place
    document.querySelectorAll(".tel-group").forEach((g) => {
      const prefix = g.querySelector("summary span").textContent;
      const names = S.data.logsources.filter((n) =>
        (n.includes(":") ? n.split(":")[0] : n.split(" ")[0]) === prefix);
      const c = names.filter((n) => telemetry.has(n)).length;
      const el = g.querySelector(".tel-count");
      el.textContent = `${c}/${names.length}`;
      el.classList.toggle("on", c > 0);
    });
  }

  /* ---------- Exports ---------- */

  function planRows() {
    return applyFilters(buildScope().rows);
  }

  function cardMarkdown(r) {
    const det = S.data.detections[r.tid];
    const analytics = det ? det.analytics : [];
    const groups = (S.idx.techGroups.get(r.tid) || []).map((g) => S.data.groups[g].name);
    const lines = [
      `## ${r.tid} — ${r.t.name}`,
      ``,
      `- **Priority score:** ${Math.round(r.score)} (threat ${r.threat.toFixed(0)} / prevalence ${r.prevalence.toFixed(0)} / exposure ${r.exposure})`,
      `- **Tactic:** ${r.t.tactics.join(", ")}`,
      `- **Status:** ${STATUS_LABELS[r.status]}`,
      `- **Visibility:** ${r.vis}`,
      `- **Mitigation mapped:** ${r.exposure ? "NO — detection-only" : "yes"}`,
      `- **Known actors (${r.gcount}):** ${groups.slice(0, 12).join(", ")}${groups.length > 12 ? "…" : ""}`,
      ``,
      `> ${r.t.desc || ""}`,
      ``,
    ];
    if (analytics.length) {
      lines.push(`### Detection use-cases (${det.det})`, ``);
      for (const an of analytics) {
        lines.push(`**${an.id}** _(${an.platforms.join(", ")})_ — ${an.desc}`);
        for (const [ls, ch] of an.logs) {
          lines.push(`  - \`${S.data.logsources[ls]}\`${ch ? ` — ${ch}` : ""}${telemetry.has(S.data.logsources[ls]) ? " ✓" : " ✗ missing"}`);
        }
        if (an.tuning.length) lines.push(`  - Tuning: ${an.tuning.map((f) => `\`${f}\``).join(", ")}`);
        lines.push(``);
      }
    }
    lines.push(`[ATT&CK reference](${attackUrl(r.tid)})`, ``);
    return lines.join("\n");
  }

  function exportMarkdown() {
    const rows = planRows();
    const profileNames = S.profile.size
      ? [...S.profile].map((id) => getEnt(id).name).join(", ")
      : "none (global scope: all ATT&CK groups)";
    const head = [
      `# Detection Plan`,
      ``,
      `Generated by ATT&CK Analysis Workbench — ATT&CK v${S.data.attackVersion}, ${new Date().toISOString().slice(0, 10)}`,
      ``,
      `- **Threat profile:** ${profileNames}`,
      `- **Telemetry:** ${telemetry.size ? [...telemetry].sort().join(", ") : "not configured"}`,
      `- **Techniques in plan:** ${rows.length}`,
      ``,
      `---`,
      ``,
    ].join("\n");
    download("detection-plan.md", head + rows.map(cardMarkdown).join("\n---\n\n"), "text/markdown");
  }

  function exportJson() {
    const rows = planRows();
    const out = {
      generated: new Date().toISOString(),
      attackVersion: S.data.attackVersion,
      threatProfile: [...S.profile],
      telemetry: [...telemetry].sort(),
      techniques: rows.map((r) => ({
        techniqueID: r.tid,
        name: r.t.name,
        score: Math.round(r.score),
        components: { threat: +r.threat.toFixed(1), prevalence: +r.prevalence.toFixed(1), exposure: r.exposure },
        visibility: r.vis,
        status: r.status,
        mitigationMapped: !r.exposure,
        actorCount: r.gcount,
        detectionStrategy: S.data.detections[r.tid]?.det || null,
        analytics: (S.data.detections[r.tid]?.analytics || []).map((a) => a.id),
        requiredLogSources: [...new Set((S.data.detections[r.tid]?.analytics || [])
          .flatMap((a) => a.logs.map(([ls]) => S.data.logsources[ls])))],
      })),
    };
    download("detection-plan.json", JSON.stringify(out, null, 2), "application/json");
  }

  function download(filename, content, mime) {
    const blob = new Blob([content], { type: mime });
    const a = document.createElement("a");
    a.href = URL.createObjectURL(blob);
    a.download = filename;
    a.click();
    URL.revokeObjectURL(a.href);
  }

  /* ---------- API ---------- */

  /* Jump from anywhere ("Design detection" button) straight to a technique's card. */
  function focus(tid) {
    switchView("detect");
    document.getElementById("dt-search").value = tid;
    expanded.add(tid);
    focusTid = tid;
    render();
  }

  /* Used by the guided tour to stage/restore example telemetry. */
  function getTelemetry() { return [...telemetry]; }

  function setTelemetry(names) {
    telemetry = new Set(names);
    saveTel();
    if (S.view === "detect") render();
    else S.dirty.detect = true;
  }

  function applyPreset(name) {
    const prefixes = PRESETS[name] || [];
    for (const n of S.data.logsources) {
      const p = (n.includes(":") ? n.split(":")[0] : n.split(" ")[0]).toLowerCase();
      if (prefixes.includes(p)) telemetry.add(n);
    }
    saveTel();
    if (S.view === "detect") render();
    else S.dirty.detect = true;
  }

  function clearFilter() {
    document.getElementById("dt-search").value = "";
    if (S.view === "detect") render();
  }

  function init() {
    load();

    // Platform filter options from the analytics corpus.
    const plats = new Set();
    for (const det of Object.values(S.data.detections)) {
      for (const an of det.analytics) an.platforms.forEach((p) => plats.add(p));
    }
    document.getElementById("dt-platform").innerHTML =
      `<option value="">All platforms</option>` +
      [...plats].sort().map((p) => `<option value="${esc(p)}">${esc(p)}</option>`).join("");

    for (const id of ["dt-search", "dt-platform", "dt-visibility", "dt-status"]) {
      document.getElementById(id).addEventListener(id === "dt-search" ? "input" : "change",
        () => { limit = PAGE; renderMainOnly(); });
    }
    document.getElementById("dt-export-md").addEventListener("click", exportMarkdown);
    document.getElementById("dt-export-json").addEventListener("click", exportJson);
    document.getElementById("tel-clear").addEventListener("click", () => {
      telemetry.clear();
      saveTel();
      render();
    });
  }

  return { init, render, focus, getTelemetry, setTelemetry, applyPreset, clearFilter };
})();
