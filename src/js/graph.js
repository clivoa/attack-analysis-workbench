/* Explore view — expandable relationship graph. */

import { S, TYPE_META, typeOf, getEnt, esc } from './app.js'

export const Graph = (() => {
  const NODE_R = { group: 10, software: 7, campaign: 9, mitigation: 8, technique: 5.5, tactic: 8 };
  const EXPAND_CAP = 12;

  let svg, root, linkLayer, nodeLayer, sim, zoomBehavior;
  let nodes = [], links = [];
  const present = new Set();
  const relCache = new Map(); // id -> Set of related ids (membership sets)

  /* ---------- Relationship helpers ---------- */

  function memberSet(id) {
    if (relCache.has(id)) return relCache.get(id);
    const e = getEnt(id);
    const t = typeOf(id);
    const set = new Set();
    if (e.techniques) e.techniques.forEach((x) => set.add(x));
    if (e.software) e.software.forEach((x) => set.add(x));
    if (e.groups) e.groups.forEach((x) => set.add(x));
    if (t === "technique") {
      const p = S.idx.parentOf.get(id);
      if (p) set.add(p);
      (S.idx.subsOf.get(id) || []).forEach((x) => set.add(x));
    }
    relCache.set(id, set);
    return set;
  }

  function hasRel(a, b) {
    return memberSet(a).has(b) || memberSet(b).has(a);
  }

  /* All related ids of an entity, bucketed by type. */
  function relatedOf(id) {
    const e = getEnt(id);
    const t = typeOf(id);
    const out = { group: [], software: [], campaign: [], technique: [], mitigation: [] };

    if (t === "group") {
      out.software = e.software;
      out.technique = e.techniques;
      out.campaign = S.idx.groupCampaigns.get(id) || [];
    } else if (t === "software") {
      out.group = S.idx.softwareGroups.get(id) || [];
      out.technique = e.techniques;
      out.campaign = Object.entries(S.data.campaigns)
        .filter(([, c]) => c.software.includes(id)).map(([cid]) => cid);
    } else if (t === "technique") {
      out.group = S.idx.techGroups.get(id) || [];
      out.software = S.idx.techSoftware.get(id) || [];
      out.campaign = S.idx.techCampaigns.get(id) || [];
      out.mitigation = S.idx.techMitigations.get(id) || [];
      const p = S.idx.parentOf.get(id);
      out.technique = p ? [p] : (S.idx.subsOf.get(id) || []);
    } else if (t === "campaign") {
      out.group = e.groups;
      out.software = e.software;
      out.technique = e.techniques;
    } else if (t === "mitigation") {
      out.technique = e.techniques;
    }
    return out;
  }

  /* ---------- Graph mutation ---------- */

  function addEntity(id, { focus = false } = {}) {
    if (typeOf(id) === "tactic") return;
    document.getElementById("graph-empty").hidden = true;
    if (!present.has(id)) {
      present.add(id);
      const { width, height } = svg.node().getBoundingClientRect();
      nodes.push({ id, x: width / 2 + (Math.random() - 0.5) * 60, y: height / 2 + (Math.random() - 0.5) * 60 });
      for (const other of present) {
        if (other !== id && hasRel(id, other)) links.push({ source: id, target: other });
      }
      rebuild();
    }
    if (focus) setTimeout(() => zoomToNode(id), 350);
  }

  function expand(id) {
    const wanted = new Set(
      [...document.querySelectorAll("[data-expand]")]
        .filter((c) => c.checked).map((c) => c.dataset.expand)
    );
    const rel = relatedOf(id);
    let added = 0, skipped = 0;
    for (const [type, ids] of Object.entries(rel)) {
      if (!wanted.has(type) && type !== "technique") continue;
      // techniques only when explicitly enabled (they explode the graph)
      if (type === "technique" && !wanted.has("technique")) continue;
      const fresh = ids.filter((x) => !present.has(x));
      fresh.slice(0, EXPAND_CAP).forEach((x) => addEntity(x));
      added += Math.min(fresh.length, EXPAND_CAP);
      skipped += Math.max(0, fresh.length - EXPAND_CAP);
    }
    if (skipped > 0) toast(`Added ${added} nodes — ${skipped} more omitted (open the side panel for full lists)`);
    else if (added === 0) toast("Nothing new to expand (check the \"On expand\" filters)");
  }

  function clear() {
    nodes = []; links = []; present.clear();
    rebuild();
    document.getElementById("graph-empty").hidden = false;
  }

  /* ---------- Rendering ---------- */

  function rebuild() {
    const linkSel = linkLayer.selectAll("line")
      .data(links, (l) => `${l.source.id || l.source}|${l.target.id || l.target}`)
      .join("line")
      .attr("class", "link");

    const nodeSel = nodeLayer.selectAll("g.node")
      .data(nodes, (d) => d.id)
      .join(
        (enter) => {
          const g = enter.append("g").attr("class", "node");
          g.append("circle")
            .attr("r", (d) => NODE_R[typeOf(d.id)])
            .attr("fill", (d) => TYPE_META[typeOf(d.id)].color);
          g.append("text")
            .attr("dy", (d) => -NODE_R[typeOf(d.id)] - 4)
            .text((d) => {
              const n = getEnt(d.id).name;
              return n.length > 22 ? n.slice(0, 21) + "…" : n;
            });
          g.call(window.d3.drag()
            .on("start", (ev, d) => { if (!ev.active) sim.alphaTarget(0.25).restart(); d.fx = d.x; d.fy = d.y; })
            .on("drag", (ev, d) => { d.fx = ev.x; d.fy = ev.y; })
            .on("end", (ev, d) => { if (!ev.active) sim.alphaTarget(0); d.fx = null; d.fy = null; }));
          g.on("click", (ev, d) => {
            ev.stopPropagation();
            if (ev.altKey) { removeNode(d.id); return; }
            highlight(d.id);
            window.Panel.show(d.id);
          });
          g.on("dblclick", (ev, d) => { ev.stopPropagation(); expand(d.id); });
          g.on("mouseenter", (ev, d) => showTip(ev, d))
            .on("mousemove", moveTip)
            .on("mouseleave", hideTip);
          return g;
        }
      );

    sim.nodes(nodes);
    sim.force("link", window.d3.forceLink(links).id((d) => d.id).distance(70).strength(0.4));
    sim.alpha(0.7).restart();

    sim.on("tick", () => {
      linkSel
        .attr("x1", (l) => l.source.x).attr("y1", (l) => l.source.y)
        .attr("x2", (l) => l.target.x).attr("y2", (l) => l.target.y);
      nodeSel.attr("transform", (d) => `translate(${d.x},${d.y})`);
    });
  }

  function removeNode(id) {
    nodes = nodes.filter((n) => n.id !== id);
    links = links.filter((l) => (l.source.id || l.source) !== id && (l.target.id || l.target) !== id);
    present.delete(id);
    rebuild();
    if (!nodes.length) document.getElementById("graph-empty").hidden = false;
  }

  function highlight(id) {
    const neighbors = new Set([id]);
    for (const l of links) {
      const s = l.source.id || l.source, t = l.target.id || l.target;
      if (s === id) neighbors.add(t);
      if (t === id) neighbors.add(s);
    }
    nodeLayer.selectAll("g.node")
      .classed("selected", (d) => d.id === id)
      .classed("faded", (d) => !neighbors.has(d.id));
    linkLayer.selectAll("line")
      .classed("highlighted", (l) => (l.source.id || l.source) === id || (l.target.id || l.target) === id)
      .classed("faded", (l) => (l.source.id || l.source) !== id && (l.target.id || l.target) !== id);
  }

  function clearHighlight() {
    nodeLayer.selectAll("g.node").classed("selected", false).classed("faded", false);
    linkLayer.selectAll("line").classed("highlighted", false).classed("faded", false);
  }

  function zoomToNode(id) {
    const n = nodes.find((x) => x.id === id);
    if (!n || n.x == null) return;
    const { width, height } = svg.node().getBoundingClientRect();
    const k = 1.4;
    svg.transition().duration(600).call(
      zoomBehavior.transform,
      window.d3.zoomIdentity.translate(width / 2 - n.x * k, height / 2 - n.y * k).scale(k)
    );
  }

  /* ---------- Tooltip / toast ---------- */

  const tipEl = () => document.getElementById("tooltip");

  function showTip(ev, d) {
    const e = getEnt(d.id);
    const meta = TYPE_META[typeOf(d.id)];
    tipEl().innerHTML = `
      <span class="t-name">${esc(e.name)}</span><span class="t-id">${d.id}</span>
      <div class="t-meta" style="color:${meta.color}">${meta.label}${e.type ? ` · ${e.type}` : ""}</div>
      <div class="t-meta">double-click to expand · alt-click to remove</div>`;
    tipEl().hidden = false;
    moveTip(ev);
  }

  function moveTip(ev) {
    const wrap = document.querySelector(".graph-wrap").getBoundingClientRect();
    let x = ev.clientX - wrap.left + 14, y = ev.clientY - wrap.top + 10;
    if (x + 280 > wrap.width) x -= 300;
    if (y + 100 > wrap.height) y -= 110;
    tipEl().style.left = `${x}px`;
    tipEl().style.top = `${y}px`;
  }

  function hideTip() { tipEl().hidden = true; }

  let toastTimer;
  function toast(msg) {
    let el = document.getElementById("graph-toast");
    if (!el) {
      el = document.createElement("div");
      el.id = "graph-toast";
      el.className = "toast";
      document.querySelector(".graph-wrap").appendChild(el);
    }
    el.textContent = msg;
    el.classList.add("show");
    clearTimeout(toastTimer);
    toastTimer = setTimeout(() => el.classList.remove("show"), 3200);
  }

  /* ---------- Setup ---------- */

  function init() {
    svg = window.d3.select("#graph");
    root = svg.append("g");
    linkLayer = root.append("g");
    nodeLayer = root.append("g");

    onShow();

    zoomBehavior = window.d3.zoom()
      .scaleExtent([0.1, 6])
      .on("zoom", (ev) => root.attr("transform", ev.transform));
    svg.call(zoomBehavior).on("dblclick.zoom", null);
    svg.on("click", () => clearHighlight());

    sim = window.d3.forceSimulation()
      .force("charge", window.d3.forceManyBody().strength(-160))
      .force("collide", window.d3.forceCollide((d) => NODE_R[typeOf(d.id)] + 8))
      .force("x", window.d3.forceX().strength(0.03))
      .force("y", window.d3.forceY().strength(0.04));

    const { width, height } = svg.node().getBoundingClientRect();
    sim.force("x").x(width / 2);
    sim.force("y").y(height / 2);

    document.getElementById("graph-clear").addEventListener("click", clear);
    document.getElementById("graph-example").addEventListener("click", () => {
      addEntity("G0016"); // APT29
      setTimeout(() => { expand("G0016"); window.Panel.show("G0016"); }, 100);
    });

    document.getElementById("graph-legend").innerHTML =
      Object.entries(TYPE_META)
        .filter(([k]) => k !== "tactic")
        .map(([, m]) => `<span class="legend-item"><i style="background:${m.color}"></i>${m.label}</span>`)
        .join("") +
      `<span class="hint">click = details · double-click = expand · alt-click = remove · scroll = zoom</span>`;

    window.addEventListener("resize", onShow);
  }

  function onShow() {
    const { width, height } = document.querySelector(".graph-wrap").getBoundingClientRect();
    svg.attr("viewBox", [0, 0, width, height]);
  }

  return { init, onShow, addEntity, expand, clear };
})();
