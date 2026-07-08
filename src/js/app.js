/* ATT&CK Analysis Workbench — core state, data loading, search, threat profile. */

export const S = {
  data: null,
  idx: null,
  profile: new Set(),   // entity ids (G/S/C) driving Matrix + Defense
  view: "explore",
  selected: null,
  dirty: { matrix: true, defense: true, detect: true },
};

export const TYPE_META = {
  group:      { label: "Group",      color: "#5eead4", letter: "G" },
  software:   { label: "Software",   color: "#818cf8", letter: "S" },
  technique:  { label: "Technique",  color: "#fbbf24", letter: "T" },
  campaign:   { label: "Campaign",   color: "#f472b6", letter: "C" },
  mitigation: { label: "Mitigation", color: "#4ade80", letter: "M" },
  tactic:     { label: "Tactic",     color: "#94a3b8", letter: "TA" },
};

export function typeOf(id) {
  if (id.startsWith("TA")) return "tactic";
  if (id.startsWith("T")) return "technique";
  if (id.startsWith("G")) return "group";
  if (id.startsWith("S")) return "software";
  if (id.startsWith("C")) return "campaign";
  if (id.startsWith("M")) return "mitigation";
  return null;
}

export function getEnt(id) {
  const t = typeOf(id);
  const bucket = {
    technique: S.data.techniques,
    group: S.data.groups,
    software: S.data.software,
    campaign: S.data.campaigns,
    mitigation: S.data.mitigations,
  }[t];
  if (t === "tactic") return S.data.tactics.find((x) => x.id === id);
  return bucket && bucket[id];
}

export function attackUrl(id) {
  const t = typeOf(id);
  const path = {
    group: "groups", software: "software", campaign: "campaigns",
    mitigation: "mitigations", tactic: "tactics",
  }[t];
  if (t === "technique") return `https://attack.mitre.org/techniques/${id.replace(".", "/")}/`;
  return `https://attack.mitre.org/${path}/${id}/`;
}

export function esc(s) {
  return String(s).replace(/[&<>"']/g, (c) =>
    ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
}

/* ---------- Indexes ---------- */

export function buildIndexes() {
  const d = S.data;
  const idx = {
    techGroups: new Map(), techSoftware: new Map(), techCampaigns: new Map(),
    techMitigations: new Map(), softwareGroups: new Map(), groupCampaigns: new Map(),
    subsOf: new Map(), parentOf: new Map(), techByTactic: new Map(),
    searchList: [],
  };

  const push = (map, key, val) => {
    if (!map.has(key)) map.set(key, []);
    map.get(key).push(val);
  };

  for (const [tid, t] of Object.entries(d.techniques)) {
    if (t.sub) {
      const parent = tid.split(".")[0];
      idx.parentOf.set(tid, parent);
      push(idx.subsOf, parent, tid);
    } else {
      for (const tactic of t.tactics) push(idx.techByTactic, tactic, tid);
    }
  }
  for (const list of idx.techByTactic.values()) {
    list.sort((a, b) => d.techniques[a].name.localeCompare(d.techniques[b].name));
  }

  for (const [gid, g] of Object.entries(d.groups)) {
    for (const t of g.techniques) push(idx.techGroups, t, gid);
    for (const s of g.software) push(idx.softwareGroups, s, gid);
  }
  for (const [sid, s] of Object.entries(d.software)) {
    for (const t of s.techniques) push(idx.techSoftware, t, sid);
  }
  for (const [cid, c] of Object.entries(d.campaigns)) {
    for (const t of c.techniques) push(idx.techCampaigns, t, cid);
    for (const g of c.groups) push(idx.groupCampaigns, g, cid);
  }
  for (const [mid, m] of Object.entries(d.mitigations)) {
    for (const t of m.techniques) push(idx.techMitigations, t, mid);
  }

  for (const [bucket, type] of [
    [d.groups, "group"], [d.software, "software"], [d.campaigns, "campaign"],
    [d.mitigations, "mitigation"], [d.techniques, "technique"],
  ]) {
    for (const [id, e] of Object.entries(bucket)) {
      idx.searchList.push({ id, type, name: e.name, aliases: e.aliases || [] });
    }
  }

  S.idx = idx;
}

/* Set of parent-level technique ids used by an entity (subs rolled up). */
export function rolledTechs(entity) {
  const set = new Set();
  for (const t of entity.techniques || []) set.add(S.idx.parentOf.get(t) || t);
  return set;
}

/* ---------- Threat profile ---------- */

const PROFILE_KEY = "attack-workbench-profile";

export function profileHas(id) { return S.profile.has(id); }

export function profileToggle(id) {
  if (S.profile.has(id)) S.profile.delete(id);
  else S.profile.add(id);
  profileChanged();
}

export function profileClear() {
  S.profile.clear();
  profileChanged();
}

export function profileChanged() {
  localStorage.setItem(PROFILE_KEY, JSON.stringify([...S.profile]));
  renderProfileChips();
  S.dirty.matrix = S.dirty.defense = S.dirty.detect = true;
  if (S.view === "matrix") window.Matrix.render();
  if (S.view === "defense") window.Defense.render();
  if (S.view === "detect") window.Detect.render();
  if (S.selected) window.Panel.refreshActions();
}

/* Heat for matrix / defense:
 * exact  — Map techId -> {count, who[]} at exact technique granularity
 * rolled — Map parentId -> {count, who[]} (each entity counted once per parent)
 * Falls back to "all groups" when the profile is empty. */
export function profileHeat() {
  const entities = S.profile.size
    ? [...S.profile].map((id) => ({ id, e: getEnt(id) }))
    : Object.entries(S.data.groups).map(([id, e]) => ({ id, e }));

  const exact = new Map(), rolled = new Map();
  const bump = (map, key, name) => {
    if (!map.has(key)) map.set(key, { count: 0, who: [] });
    const rec = map.get(key);
    rec.count++;
    if (rec.who.length < 8) rec.who.push(name);
  };

  for (const { e } of entities) {
    if (!e || !e.techniques) continue;
    for (const t of e.techniques) bump(exact, t, e.name);
    for (const p of rolledTechs(e)) bump(rolled, p, e.name);
  }
  return { exact, rolled, isFallback: S.profile.size === 0, size: entities.length };
}

function renderProfileChips() {
  const wrap = document.getElementById("profile-chips");
  if (!S.profile.size) {
    wrap.innerHTML = `<span class="profile-empty">empty — add groups, software or campaigns to drive the Matrix heatmap and Defense Planner</span>`;
    return;
  }
  wrap.innerHTML = [...S.profile].map((id) => {
    const e = getEnt(id);
    const meta = TYPE_META[typeOf(id)];
    return `<span class="chip profile-chip" data-id="${id}" style="--c:${meta.color}">
      <b class="dot"></b>${esc(e.name)}<button class="chip-x" data-remove="${id}" title="Remove">×</button>
    </span>`;
  }).join("");

  wrap.querySelectorAll(".chip-x").forEach((b) =>
    b.addEventListener("click", (ev) => { ev.stopPropagation(); profileToggle(b.dataset.remove); }));
  wrap.querySelectorAll(".profile-chip").forEach((c) =>
    c.addEventListener("click", () => window.Panel.show(c.dataset.id)));
}

/* ---------- Tabs ---------- */

export function switchView(view) {
  S.view = view;
  if (location.hash.replace("#", "") !== view) history.replaceState(null, "", `#${view}`);
  document.querySelectorAll(".tab").forEach((t) =>
    t.classList.toggle("active", t.dataset.view === view));
  document.querySelectorAll(".view").forEach((v) =>
    v.classList.toggle("active", v.id === `view-${view}`));
  if (view === "matrix" && S.dirty.matrix) window.Matrix.render();
  if (view === "defense" && S.dirty.defense) window.Defense.render();
  if (view === "detect" && S.dirty.detect) window.Detect.render();
  if (view === "explore") window.Graph.onShow();
}

/* ---------- Search ---------- */

function setupSearch() {
  const input = document.getElementById("search");
  const results = document.getElementById("search-results");
  let activeIdx = -1;

  function run() {
    const q = input.value.trim().toLowerCase();
    activeIdx = -1;
    if (q.length < 2) { results.hidden = true; return; }

    const scored = [];
    for (const item of S.idx.searchList) {
      const name = item.name.toLowerCase();
      let score = -1, via = null;
      if (name.startsWith(q)) score = 0;
      else if (name.includes(q)) score = 1;
      else if (item.id.toLowerCase() === q) score = 0;
      else {
        const alias = item.aliases.find((a) => a.toLowerCase().includes(q));
        if (alias) { score = 2; via = alias; }
      }
      if (score >= 0) scored.push({ ...item, score, via });
    }
    scored.sort((a, b) => a.score - b.score || a.name.localeCompare(b.name));
    const hits = scored.slice(0, 12);

    if (!hits.length) { results.hidden = true; return; }
    results.innerHTML = hits.map((h) => {
      const meta = TYPE_META[h.type];
      return `<li data-id="${h.id}">
        <span class="badge-type" style="--c:${meta.color}">${meta.label}</span>
        <span class="s-name">${esc(h.name)}${h.via ? ` <span class="alias-hit">(${esc(h.via)})</span>` : ""}</span>
        <span class="gid">${h.id}</span>
      </li>`;
    }).join("");
    results.hidden = false;

    results.querySelectorAll("li").forEach((li) =>
      li.addEventListener("mousedown", (ev) => { ev.preventDefault(); pick(li.dataset.id); }));
  }

  function pick(id) {
    results.hidden = true;
    input.value = "";
    input.blur();
    window.Panel.show(id);
    if (S.view === "explore") window.Graph.addEntity(id, { focus: true });
  }

  input.addEventListener("input", run);
  input.addEventListener("focus", run);
  input.addEventListener("blur", () => setTimeout(() => { results.hidden = true; }, 150));
  input.addEventListener("keydown", (ev) => {
    const items = results.querySelectorAll("li");
    if (ev.key === "Escape") { results.hidden = true; input.blur(); return; }
    if (!items.length) return;
    if (ev.key === "ArrowDown") { ev.preventDefault(); activeIdx = Math.min(activeIdx + 1, items.length - 1); }
    else if (ev.key === "ArrowUp") { ev.preventDefault(); activeIdx = Math.max(activeIdx - 1, 0); }
    else if (ev.key === "Enter") { ev.preventDefault(); pick(items[Math.max(activeIdx, 0)].dataset.id); return; }
    else return;
    items.forEach((li, i) => li.classList.toggle("active", i === activeIdx));
  });

  document.addEventListener("keydown", (ev) => {
    if (ev.key === "/" && document.activeElement !== input) {
      ev.preventDefault();
      input.focus();
    }
  });
}

/* ---------- Init ---------- */

export async function initApp() {
  const res = await fetch(`${import.meta.env.BASE_URL}data/attack-data.json`);
  S.data = await res.json();
  buildIndexes();

  document.getElementById("attack-version").textContent =
    S.data.attackVersion ? `v${S.data.attackVersion}` : "";

  try {
    const saved = JSON.parse(localStorage.getItem(PROFILE_KEY) || "[]");
    saved.filter((id) => getEnt(id)).forEach((id) => S.profile.add(id));
  } catch { /* corrupt storage — start fresh */ }

  renderProfileChips();
  setupSearch();

  document.querySelectorAll(".tab").forEach((t) =>
    t.addEventListener("click", () => switchView(t.dataset.view)));
  document.getElementById("profile-clear").addEventListener("click", profileClear);
  document.getElementById("profile-graph").addEventListener("click", () => {
    switchView("explore");
    [...S.profile].forEach((id) => window.Graph.addEntity(id));
  });

  window.Graph.init();
  window.Matrix.init();
  window.Rules.init();
  window.Detect.init();
  window.Defense.init();
  window.Tour.init();

  // Deep links: #matrix / #detect / #defense / #explore switch views;
  // #G0016 / #T1055.001 opens the entity panel (and seeds the graph).
  const hash = decodeURIComponent(location.hash.replace("#", ""));
  if (["explore", "matrix", "detect", "defense"].includes(hash)) {
    switchView(hash);
  } else if (hash.startsWith("tour=")) {
    // e.g. #tour=cti / #tour=engineer / #tour=soc (optionally #tour=engineer:4)
    const [key, at] = hash.slice(5).split(":");
    window.Tour.start(key, parseInt(at) || 0);
  } else if (hash.startsWith("detect=") && getEnt(hash.slice(7))) {
    window.Detect.focus(hash.slice(7)); // e.g. #detect=T1059.001 → detection card
  } else if (hash && getEnt(hash)) {
    window.Panel.show(hash);
    if (typeOf(hash) !== "tactic") window.Graph.addEntity(hash, { focus: true });
  }
}

export { Graph } from './graph.js'
export { Matrix } from './matrix.js'
export { Detect } from './detect.js'
export { Defense } from './defense.js'
export { Panel } from './panel.js'
export { Tour } from './tour.js'
export { Rules } from './rules.js'
