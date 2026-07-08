/* Defense Planner — mitigations ranked by coverage of the threat profile's techniques. */

const Defense = (() => {

  function render() {
    S.dirty.defense = false;
    const heat = profileHeat();
    const el = document.getElementById("defense");

    // Techniques in scope, weighted by how many profile entities use them.
    const scope = heat.exact; // Map techId -> {count, who}
    const totalTechs = scope.size;
    const totalWeight = [...scope.values()].reduce((a, r) => a + r.count, 0);

    // Rank mitigations by weighted coverage.
    const ranked = Object.entries(S.data.mitigations).map(([mid, m]) => {
      const covered = m.techniques.filter((t) => scope.has(t));
      const weight = covered.reduce((a, t) => a + scope.get(t).count, 0);
      return { mid, m, covered, weight };
    }).filter((r) => r.covered.length)
      .sort((a, b) => b.weight - a.weight || b.covered.length - a.covered.length);

    // Techniques with no mitigation mapping at all.
    const unmitigated = [...scope.keys()]
      .filter((t) => !S.idx.techMitigations.has(t))
      .sort((a, b) => scope.get(b).count - scope.get(a).count);

    // Top techniques in the profile.
    const topTechs = [...scope.entries()]
      .sort((a, b) => b[1].count - a[1].count)
      .slice(0, 15);
    const maxFreq = topTechs.length ? topTechs[0][1].count : 1;

    const banner = heat.isFallback
      ? `<div class="def-banner">Showing the <b>global view across all ${heat.size} ATT&CK groups</b>. Build a threat profile (add groups, software or campaigns) to get a prioritization tailored to the actors you care about.</div>`
      : `<div class="def-banner focus">Prioritization for your threat profile: <b>${heat.size} ${heat.size === 1 ? "entity" : "entities"}</b>, ${totalTechs} distinct techniques in scope.</div>`;

    el.innerHTML = `
      ${banner}
      <div class="def-grid">
        <div class="def-main">
          <div class="section-title">Mitigations ranked by coverage <span class="count">${ranked.length}</span></div>
          <p class="def-explain">Score = sum of usage frequency over the techniques each mitigation addresses. Higher = one control that blunts more of what these actors actually do.</p>
          <ol class="mit-list">
            ${ranked.map((r, i) => mitigationRow(r, i, totalWeight)).join("")}
          </ol>
        </div>

        <div class="def-side">
          <div class="section-title">Most-used techniques <span class="count">top ${topTechs.length}</span></div>
          <ul class="freq-list">
            ${topTechs.map(([tid, rec]) => {
              const t = S.data.techniques[tid];
              return `<li class="freq-item" data-id="${tid}">
                <span class="f-name"><span class="tid">${tid}</span>${esc(t.name)}</span>
                <span class="overlap-bar"><div style="width:${(rec.count / maxFreq) * 100}%"></div></span>
                <span class="f-count">${rec.count}</span>
              </li>`;
            }).join("")}
          </ul>

          <div class="section-title">Blind spots <span class="count">${unmitigated.length}</span></div>
          <p class="def-explain">Techniques in scope with <b>no mapped mitigation</b> in ATT&CK — detection &amp; response are your main options here.</p>
          <div class="chips">
            ${unmitigated.slice(0, 30).map((tid) =>
              `<span class="chip clickable warn" data-id="${tid}"><span class="tid">${tid}</span>${esc(S.data.techniques[tid].name)}</span>`
            ).join("")}
            ${unmitigated.length > 30 ? `<span class="chip">+${unmitigated.length - 30} more</span>` : ""}
          </div>
        </div>
      </div>`;

    el.querySelectorAll("[data-id]").forEach((n) =>
      n.addEventListener("click", (ev) => {
        ev.stopPropagation();
        Panel.show(n.dataset.id);
      }));

    el.querySelectorAll(".mit-toggle").forEach((btn) =>
      btn.addEventListener("click", (ev) => {
        ev.stopPropagation();
        const row = btn.closest(".mit-item");
        row.classList.toggle("open");
        btn.textContent = row.classList.contains("open") ? "Hide techniques ▴" : "Show techniques ▾";
      }));
  }

  function mitigationRow(r, i, totalWeight) {
    const pct = totalWeight ? (r.weight / totalWeight) * 100 : 0;
    const coveredSorted = [...r.covered].sort((a, b) => a.localeCompare(b));
    return `
      <li class="mit-item">
        <div class="mit-row">
          <span class="mit-rank">${i + 1}</span>
          <div class="mit-body">
            <div class="mit-head">
              <span class="mit-name" data-id="${r.mid}">${esc(r.m.name)} <span class="tid">${r.mid}</span></span>
              <span class="mit-stat">${r.covered.length} techniques · ${pct.toFixed(1)}% weight</span>
            </div>
            <div class="mit-bar"><div style="width:${pct}%"></div></div>
            <div class="mit-desc">${esc(r.m.desc)}</div>
            <button class="mit-toggle">Show techniques ▾</button>
            <div class="mit-techs chips">
              ${coveredSorted.map((tid) =>
                `<span class="chip clickable" data-id="${tid}"><span class="tid">${tid}</span>${esc(S.data.techniques[tid].name)}</span>`
              ).join("")}
            </div>
          </div>
        </div>
      </li>`;
  }

  function init() { /* rendered lazily on first view switch */ }

  return { init, render };
})();
