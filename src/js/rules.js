/* Detection rule inventory — import deployed rules (Sigma YAML, CSV, JSON,
 * Navigator layer), map them to ATT&CK techniques and expose the coverage
 * layer used by the Matrix overlay and the Detection Designer gap analysis.
 * Also serves SigmaHQ rule suggestions from the prebuilt sigma-index.json. */

import { S, esc } from './app.js'

export const Rules = (() => {
  const RULES_KEY = "attack-workbench-rules";
  const INACTIVE = new Set(["disabled", "deprecated", "unsupported", "inactive", "off", "false", "0"]);
  const TID = /T\d{4}(?:\.\d{3})?/g;

  let rules = [];          // {n: name, t: [techIds], s: status, src: filename}
  let exact = new Map();   // techId -> [rule index] (active rules only)
  let sigma = null;        // sigma-index.json payload, lazily fetched
  let sigmaPromise = null;

  /* ---------- Persistence & coverage index ---------- */

  function load() {
    try { rules = JSON.parse(localStorage.getItem(RULES_KEY) || "[]"); } catch { rules = []; }
    rebuild();
  }

  function save() { localStorage.setItem(RULES_KEY, JSON.stringify(rules)); }

  function isActive(r) { return !INACTIVE.has(String(r.s || "").toLowerCase()); }

  function rebuild() {
    exact = new Map();
    rules.forEach((r, i) => {
      if (!isActive(r)) return;
      for (const t of r.t) {
        if (!exact.has(t)) exact.set(t, []);
        exact.get(t).push(i);
      }
    });
  }

  function activeCount() { return rules.filter(isActive).length; }

  /* Active rules covering a technique. Sub-techniques inherit rules tagged
   * on their parent (generic rules) and parents count rules on any of their
   * subs — `via` says which related technique the rule actually targets. */
  function coverageFor(tid) {
    const out = new Map();
    for (const i of exact.get(tid) || []) out.set(i, null);
    const parent = S.idx.parentOf.get(tid);
    if (parent) for (const i of exact.get(parent) || []) if (!out.has(i)) out.set(i, parent);
    for (const sub of S.idx.subsOf.get(tid) || [])
      for (const i of exact.get(sub) || []) if (!out.has(i)) out.set(i, sub);
    return [...out].map(([i, via]) => ({ ...rules[i], via }));
  }

  function covered(tid) {
    if (exact.has(tid)) return true;
    const parent = S.idx.parentOf.get(tid);
    if (parent && exact.has(parent)) return true;
    return (S.idx.subsOf.get(tid) || []).some((sub) => exact.has(sub));
  }

  function coveredTechniques() {
    const set = new Set();
    for (const tid of exact.keys()) if (S.data.techniques[tid]) set.add(tid);
    return set;
  }

  /* ---------- Parsers ---------- */

  function parseSigma(text, filename) {
    const out = [];
    for (const doc of text.split(/^---\s*$/m)) {
      let title = null, status = null, inTags = false;
      const tids = new Set();
      for (const line of doc.split(/\r?\n/)) {
        if (!/^\s/.test(line)) {
          inTags = /^tags\s*:/.test(line);
          let m = line.match(/^title\s*:\s*(.+?)\s*$/);
          if (m && title === null) { title = m[1].replace(/^['"]|['"]$/g, ""); continue; }
          m = line.match(/^status\s*:\s*(.+?)\s*$/);
          if (m && status === null) status = m[1].replace(/^['"]|['"]$/g, "");
        } else if (inTags) {
          const m = line.match(/^\s*-\s+attack\.(t\d{4}(?:\.\d{3})?)\s*$/i);
          if (m) tids.add(m[1].toUpperCase());
        }
      }
      if (title && tids.size) out.push({ n: title, t: [...tids], s: status || "active", src: filename });
    }
    return out;
  }

  function parseCsvText(text) {
    const rows = [];
    let row = [], cell = "", q = false;
    for (let i = 0; i < text.length; i++) {
      const c = text[i];
      if (q) {
        if (c === '"') { if (text[i + 1] === '"') { cell += '"'; i++; } else q = false; }
        else cell += c;
      } else if (c === '"') q = true;
      else if (c === ",") { row.push(cell); cell = ""; }
      else if (c === "\n" || c === "\r") {
        if (c === "\r" && text[i + 1] === "\n") i++;
        row.push(cell);
        if (row.some((x) => x.trim() !== "")) rows.push(row);
        row = []; cell = "";
      } else cell += c;
    }
    row.push(cell);
    if (row.some((x) => x.trim() !== "")) rows.push(row);
    return rows;
  }

  function parseCsvRules(text, filename) {
    const rows = parseCsvText(text);
    if (rows.length < 2) return [];
    const heads = rows[0].map((h) => h.trim().toLowerCase());
    const col = (...names) => heads.findIndex((h) => names.some((n) => h.includes(n)));
    const nameCol = col("name", "title", "rule");
    const techCol = col("technique", "attack", "mitre", "tid", "ttp");
    const statCol = col("status", "state", "enabled");
    if (techCol < 0) return [];

    const out = [];
    rows.slice(1).forEach((row, i) => {
      const tids = [...new Set((row[techCol] || "").toUpperCase().match(TID) || [])];
      if (!tids.length) return;
      out.push({
        n: (nameCol >= 0 && row[nameCol] && row[nameCol].trim()) || `${filename} #${i + 1}`,
        t: tids,
        s: statCol >= 0 ? (row[statCol] || "active").trim() : "active",
        src: filename,
      });
    });
    return out;
  }

  function objToRule(o, filename) {
    if (!o || typeof o !== "object") return null;
    const name = o.name || o.title || o.rule || o.rule_name || o.id;
    const raw = [].concat(o.techniques ?? o.technique ?? o.attack ?? o.mitre ?? o.tags ?? []).join(" ");
    const tids = [...new Set(String(raw).toUpperCase().match(TID) || [])];
    if (!name || !tids.length) return null;
    const status = o.enabled === false ? "disabled" : String(o.status ?? o.state ?? "active");
    return { n: String(name), t: tids, s: status, src: filename };
  }

  function parseJsonRules(text, filename) {
    const data = JSON.parse(text);
    if (Array.isArray(data)) return data.map((o) => objToRule(o, filename)).filter(Boolean);
    if (data && Array.isArray(data.rules)) return data.rules.map((o) => objToRule(o, filename)).filter(Boolean);
    if (data && Array.isArray(data.techniques)) {
      // ATT&CK Navigator layer (or any techniqueID-list coverage export):
      // imported as a single inventory entry marking those techniques covered.
      const tids = [...new Set(data.techniques
        .filter((t) => t && t.techniqueID && t.enabled !== false && !(typeof t.score === "number" && t.score <= 0))
        .map((t) => String(t.techniqueID).toUpperCase())
        .filter((t) => /^T\d{4}(\.\d{3})?$/.test(t)))];
      if (tids.length) return [{ n: data.name || filename, t: tids, s: "active", src: filename }];
    }
    return [];
  }

  function parseFile(text, filename) {
    const ext = (filename.split(".").pop() || "").toLowerCase();
    if (ext === "yml" || ext === "yaml") return parseSigma(text, filename);
    if (ext === "csv") return parseCsvRules(text, filename);
    if (ext === "json") return parseJsonRules(text, filename);
    // Sniff: JSON, then Sigma, then CSV.
    const head = text.trimStart();
    if (head.startsWith("{") || head.startsWith("[")) return parseJsonRules(text, filename);
    if (/^title\s*:/m.test(text) && /attack\./i.test(text)) return parseSigma(text, filename);
    return parseCsvRules(text, filename);
  }

  /* ---------- Import ---------- */

  async function importFiles(fileList) {
    let added = 0, failed = 0;
    for (const file of fileList) {
      try {
        const parsed = parseFile(await file.text(), file.name);
        rules.push(...parsed);
        added += parsed.length;
        if (!parsed.length) failed++;
      } catch { failed++; }
    }
    if (added) {
      // Same rule re-imported (same name + source) replaces the older copy.
      const seen = new Map();
      for (const r of rules) seen.set(`${r.src}\u0000${r.n}`, r);
      rules = [...seen.values()];
      save();
      rebuild();
    }
    changed();
    return { added, failed };
  }

  function clearAll() {
    rules = [];
    save();
    rebuild();
    changed();
  }

  function changed() {
    renderRail();
    S.dirty.matrix = S.dirty.detect = true;
    if (S.view === "matrix") window.Matrix.render();
    if (S.view === "detect") window.Detect.render();
  }

  /* ---------- SigmaHQ suggestions ---------- */

  function loadSigma() {
    if (!sigmaPromise) {
      sigmaPromise = fetch(`${import.meta.env.BASE_URL}data/sigma-index.json`)
        .then((res) => (res.ok ? res.json() : null))
        .then((data) => {
          sigma = data;
          if (sigma && S.view === "detect") window.Detect.render();
        })
        .catch(() => { sigma = null; });
    }
    return sigmaPromise;
  }

  /* Public SigmaHQ rules for a technique; falls back to the parent
   * technique when a sub-technique has no rules of its own. */
  function suggest(tid, n = 5) {
    if (!sigma) return null;
    let entries = sigma.techniques[tid] || [];
    let via = null;
    if (!entries.length) {
      const parent = S.idx.parentOf.get(tid);
      if (parent && sigma.techniques[parent]) { entries = sigma.techniques[parent]; via = parent; }
    }
    return { entries: entries.slice(0, n), total: entries.length, via };
  }

  function sigmaUrl(path) { return `https://github.com/SigmaHQ/sigma/blob/master/${path}`; }

  /* ---------- Rail UI (Detection Designer sidebar) ---------- */

  function renderRail(note) {
    const el = document.getElementById("rules-summary");
    if (!el) return;
    if (!rules.length) {
      el.innerHTML = `<span class="rules-empty">${note ? esc(note) : "no rules imported yet"}</span>`;
      return;
    }
    const active = activeCount();
    const known = coveredTechniques().size;
    el.innerHTML = `<b>${active}</b> active rule${active === 1 ? "" : "s"}` +
      `${rules.length - active ? ` <span class="rules-off">(+${rules.length - active} disabled)</span>` : ""}` +
      ` covering <b>${known}</b> technique${known === 1 ? "" : "s"}` +
      (note ? `<div class="rules-note">${esc(note)}</div>` : "");
  }

  function init() {
    load();

    const input = document.getElementById("rules-file");
    document.getElementById("rules-import").addEventListener("click", () => input.click());
    input.addEventListener("change", async () => {
      const files = [...input.files];
      input.value = "";
      if (!files.length) return;
      const { added, failed } = await importFiles(files);
      renderRail(failed
        ? `imported ${added} rule${added === 1 ? "" : "s"} — ${failed} file${failed === 1 ? "" : "s"} had no ATT&CK-mapped rules`
        : `imported ${added} rule${added === 1 ? "" : "s"}`);
    });
    document.getElementById("rules-clear").addEventListener("click", clearAll);

    renderRail();
    loadSigma();
  }

  return {
    init, importFiles, clearAll,
    activeCount, covered, coverageFor, coveredTechniques,
    suggest, sigmaUrl,
    count: () => rules.length,
  };
})();
