/* Side panel — detail view for any entity type, with cross-navigation. */

const Panel = (() => {
  const TACTIC_ORDER = [
    "reconnaissance", "resource-development", "initial-access", "execution",
    "persistence", "privilege-escalation", "defense-evasion", "credential-access",
    "discovery", "lateral-movement", "collection", "command-and-control",
    "exfiltration", "impact",
  ];

  function show(id) {
    const e = getEnt(id);
    if (!e) return;
    S.selected = id;
    const type = typeOf(id);
    const meta = TYPE_META[type];

    const sections = {
      group: groupSections, software: softwareSections, technique: techniqueSections,
      campaign: campaignSections, mitigation: mitigationSections, tactic: tacticSections,
    }[type](id, e);

    const el = document.getElementById("panel-content");
    el.innerHTML = `
      <div class="panel-type" style="--c:${meta.color}">${meta.label}</div>
      <h2>${esc(e.name)} <span class="badge">${id}</span>${e.type ? ` <span class="badge alt">${e.type}</span>` : ""}</h2>
      ${e.aliases && e.aliases.length ? `<div class="aliases"><b>Also known as:</b> ${esc(e.aliases.join(", "))}</div>` : ""}
      ${e.first_seen ? `<div class="aliases"><b>Active:</b> ${e.first_seen}${e.last_seen ? ` → ${e.last_seen}` : ""}</div>` : ""}
      ${e.desc ? `<p class="desc">${esc(e.desc)}</p>` : ""}
      <div class="panel-actions">
        <a class="btn" href="${attackUrl(id)}" target="_blank" rel="noopener">ATT&CK ↗</a>
        ${type !== "tactic" ? `<button class="btn" id="act-graph">Add to graph</button>` : ""}
        ${["group", "software", "campaign"].includes(type)
          ? `<button class="btn profile-btn" id="act-profile"></button>` : ""}
      </div>
      ${sections}`;

    document.getElementById("panel-empty").hidden = true;
    el.hidden = false;
    document.getElementById("panel").scrollTop = 0;

    const gBtn = el.querySelector("#act-graph");
    if (gBtn) gBtn.addEventListener("click", () => {
      Graph.addEntity(id, { focus: S.view === "explore" });
      if (S.view !== "explore") switchView("explore");
    });

    const pBtn = el.querySelector("#act-profile");
    if (pBtn) {
      refreshActions();
      pBtn.addEventListener("click", () => profileToggle(id));
    }

    el.querySelectorAll("[data-nav]").forEach((n) =>
      n.addEventListener("click", () => show(n.dataset.nav)));

    const dBtn = el.querySelector("#act-detect");
    if (dBtn) dBtn.addEventListener("click", () => Detect.focus(id));
  }

  function refreshActions() {
    const pBtn = document.querySelector("#act-profile");
    if (!pBtn || !S.selected) return;
    const inProfile = profileHas(S.selected);
    pBtn.textContent = inProfile ? "✓ In profile — remove" : "＋ Threat profile";
    pBtn.classList.toggle("in-profile", inProfile);
  }

  /* ---------- Shared builders ---------- */

  function section(title, count, body) {
    if (!body) return "";
    return `<div class="section-title">${title} <span class="count">${count}</span></div>${body}`;
  }

  function chips(ids, { shared = false } = {}) {
    if (!ids.length) return "";
    return `<div class="chips">${ids.map((id) => {
      const e = getEnt(id);
      const meta = TYPE_META[typeOf(id)];
      return `<span class="chip clickable${shared ? " shared" : ""}" data-nav="${id}" style="--c:${meta.color}">
        <span class="tid">${id}</span>${esc(e.name)}</span>`;
    }).join("")}</div>`;
  }

  function techBlocks(techIds) {
    if (!techIds.length) return "";
    const byTactic = new Map();
    for (const tid of techIds) {
      const t = S.data.techniques[tid];
      if (!t) continue;
      const tactic = t.tactics[0] || "other";
      if (!byTactic.has(tactic)) byTactic.set(tactic, []);
      byTactic.get(tactic).push(tid);
    }
    const tactics = [...byTactic.keys()].sort(
      (x, y) => (TACTIC_ORDER.indexOf(x) + 99) % 100 - (TACTIC_ORDER.indexOf(y) + 99) % 100
    );
    return tactics.map((tactic) => `
      <div class="tactic-block">
        <div class="tactic-name">${tactic.replace(/-/g, " ")}</div>
        ${chips(byTactic.get(tactic).sort())}
      </div>`).join("");
  }

  /* ---------- Per-type sections ---------- */

  function groupSections(id, g) {
    // Closest peers by technique overlap.
    const mySet = new Set(g.techniques);
    const peers = Object.entries(S.data.groups)
      .filter(([gid]) => gid !== id)
      .map(([gid, other]) => {
        let shared = 0;
        for (const t of other.techniques) if (mySet.has(t)) shared++;
        const union = mySet.size + other.techniques.length - shared;
        return { gid, shared, jaccard: union ? shared / union : 0 };
      })
      .filter((p) => p.shared > 0)
      .sort((a, b) => b.shared - a.shared)
      .slice(0, 8);
    const maxShared = peers.length ? peers[0].shared : 1;

    const campaigns = S.idx.groupCampaigns.get(id) || [];

    return [
      section("Campaigns", campaigns.length, chips(campaigns)),
      section("Software used", g.software.length, chips(g.software)),
      peers.length ? section("Closest peers by technique overlap", peers.length, `
        <ul class="overlap-list">${peers.map((p) => `
          <li class="overlap-item" data-nav="${p.gid}">
            <span class="o-name">${esc(S.data.groups[p.gid].name)}</span>
            <span class="overlap-bar"><div style="width:${(p.shared / maxShared) * 100}%"></div></span>
            <span class="o-stat">${p.shared} · ${(p.jaccard * 100).toFixed(0)}%</span>
          </li>`).join("")}
        </ul>`) : "",
      section("Techniques", g.techniques.length, techBlocks(g.techniques)),
    ].join("");
  }

  function softwareSections(id, s) {
    const groups = S.idx.softwareGroups.get(id) || [];
    const campaigns = Object.entries(S.data.campaigns)
      .filter(([, c]) => c.software.includes(id)).map(([cid]) => cid);
    return [
      section("Used by groups", groups.length, chips(groups)),
      section("Deployed in campaigns", campaigns.length, chips(campaigns)),
      section("Techniques", s.techniques.length, techBlocks(s.techniques)),
    ].join("");
  }

  function techniqueSections(id, t) {
    const groups = S.idx.techGroups.get(id) || [];
    const software = S.idx.techSoftware.get(id) || [];
    const campaigns = S.idx.techCampaigns.get(id) || [];
    const mitigations = S.idx.techMitigations.get(id) || [];
    const parent = S.idx.parentOf.get(id);
    const subs = S.idx.subsOf.get(id) || [];

    const det = S.data.detections[id];
    const detSection = det ? section("Detection engineering", `${det.analytics.length} analytics`, `
      <p class="desc" style="margin-top:0">${esc(det.detName)} <span class="tid">(${det.det})</span></p>
      <div class="chips">${[...new Set(det.analytics.flatMap((a) => a.logs.map(([ls]) => S.data.logsources[ls])))]
        .map((n) => `<span class="chip"><span class="tid">log</span>${esc(n)}</span>`).join("")}</div>
      <div class="panel-actions" style="margin-top:10px">
        <button class="btn" id="act-detect">Design detection →</button>
      </div>`) : "";

    return [
      detSection,
      `<div class="aliases"><b>Tactics:</b> ${t.tactics.map((x) => x.replace(/-/g, " ")).join(", ")}</div>`,
      parent ? section("Parent technique", 1, chips([parent])) : "",
      section("Sub-techniques", subs.length, chips(subs)),
      section("Mitigations", mitigations.length, chips(mitigations, { shared: true })),
      section("Groups using it", groups.length, chips(groups)),
      section("Software implementing it", software.length, chips(software)),
      section("Seen in campaigns", campaigns.length, chips(campaigns)),
    ].join("");
  }

  function campaignSections(id, c) {
    return [
      section("Attributed to", c.groups.length, chips(c.groups)),
      section("Software deployed", c.software.length, chips(c.software)),
      section("Techniques", c.techniques.length, techBlocks(c.techniques)),
    ].join("");
  }

  function mitigationSections(id, m) {
    return section("Mitigates techniques", m.techniques.length, techBlocks(m.techniques));
  }

  function tacticSections(id, tactic) {
    const techs = S.idx.techByTactic.get(tactic.shortname) || [];
    return section("Techniques in this tactic", techs.length, chips(techs));
  }

  return { show, refreshActions };
})();
