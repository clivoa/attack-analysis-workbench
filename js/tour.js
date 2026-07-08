/* Guided tours — persona-based interactive walkthroughs.
 * Each tour stages a real example (profile, telemetry, views) with a
 * spotlight overlay, and offers to restore the user's own state at the end. */

const Tour = (() => {
  const TOURED_KEY = "attack-workbench-toured";
  const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

  const setProfile = (ids) => { S.profile = new Set(ids); profileChanged(); };

  /* ---------- Tour definitions ---------- */

  const EXAMPLE_PROFILE = ["G0016", "G0032"]; // APT29 + Lazarus Group

  const TOURS = {
    overview: {
      title: "Platform overview",
      icon: "◉",
      color: "#5eead4",
      minutes: 2,
      desc: "The layout in two minutes: views, search, threat profile, detail panel.",
      steps: [
        {
          title: "Welcome to the Workbench",
          body: "Four analysis views built on the full MITRE ATT&CK dataset — groups, software, techniques, campaigns, mitigations and detection analytics. Everything runs in your browser; nothing leaves it. This quick tour shows the layout.",
        },
        {
          target: ".tabs",
          title: "Four views, one dataset",
          body: "<b>Explore</b> — relationship graph. <b>Matrix</b> — the ATT&CK heatmap. <b>Detection Designer</b> — a prioritized detection-engineering worklist. <b>Defense Planner</b> — mitigations ranked by impact.",
        },
        {
          target: ".search-wrap",
          title: "Search everything",
          body: "1,700+ entities searchable by name, ATT&CK ID or alias — typing <i>Cozy Bear</i> finds APT29. Press <b>/</b> anywhere to jump here.",
        },
        {
          target: ".profile-bar",
          title: "The threat profile drives everything",
          before: async () => setProfile(EXAMPLE_PROFILE),
          body: "We just staged an example: <b>APT29 + Lazarus Group</b>. The profile is your set of adversaries of concern — the Matrix heatmap, Detection Designer and Defense Planner all recalculate from it. It persists in your browser.",
        },
        {
          target: "#panel",
          title: "The detail panel",
          before: async () => Panel.show("G0016"),
          body: "Click anything, anywhere, and its dossier opens here — with clickable cross-links, so you can walk from a group to its malware to a technique to its mitigations.",
        },
        {
          title: "Pick your path",
          body: "That's the layout. For a workflow tailored to your role, run one of the persona tours from the <b>✦ Tour</b> button: <b>CTI Analyst</b>, <b>Detection Engineer</b> or <b>SOC Lead</b>.",
          final: true,
        },
      ],
    },

    cti: {
      title: "CTI Analyst",
      icon: "◎",
      color: "#f472b6",
      minutes: 4,
      desc: "Profile actors, map their ecosystem and overlap, export a Navigator layer.",
      steps: [
        {
          title: "CTI workflow",
          body: "Goal: turn <i>“we are worried about these actors”</i> into evidence you can share — actor dossiers, ecosystem maps, combined technique footprints and a Navigator layer for your report.",
        },
        {
          target: ".search-wrap",
          title: "1 · Find your actors",
          body: "Search by any name your sources use — ATT&CK aliases are indexed, so <i>NOBELIUM</i>, <i>Cozy Bear</i> and <i>Midnight Blizzard</i> all resolve to APT29.",
        },
        {
          target: "#panel",
          title: "2 · Read the dossier",
          before: async () => Panel.show("G0016"),
          body: "APT29's profile: aliases, attributed campaigns, its malware/tool arsenal and techniques grouped by tactic. Note <b>Closest peers by technique overlap</b> — shared tradecraft ranked by Jaccard similarity, useful when reasoning about attribution.",
        },
        {
          target: ".profile-chips",
          title: "3 · Build the threat profile",
          before: async () => setProfile(EXAMPLE_PROFILE),
          body: "Staged for you: <b>APT29 + Lazarus Group</b>. In real use, click <b>＋ Threat profile</b> on any group, software or campaign panel to build your own set.",
        },
        {
          view: "explore",
          target: ".graph-wrap",
          title: "4 · Map the ecosystem",
          before: async () => {
            Graph.clear();
            Graph.addEntity("G0016");
            Graph.addEntity("G0032");
            await sleep(120);
            Graph.expand("G0016");
            await sleep(400);
          },
          body: "APT29's ecosystem expanded: its software and campaigns pulled into the graph. <b>Double-click</b> any node to keep expanding, <b>alt-click</b> to prune. This is how you walk from one IOC-adjacent entity to the next.",
        },
        {
          view: "matrix",
          target: "#matrix",
          title: "5 · The combined footprint",
          body: "The heatmap now shows the union of your profiled actors — hotter cells are techniques <b>both</b> use. That intersection is where hunting pays off across the whole profile.",
        },
        {
          target: "#export-layer",
          title: "6 · Ship it",
          body: "One click exports this exact heatmap as an <b>ATT&CK Navigator layer</b> (JSON) — drop it into the official Navigator, attach it to your report, or diff it against another team's layer.",
        },
        {
          title: "You're set",
          body: "Everything is deep-linkable for sharing: <code>#G0016</code> opens a dossier, <code>#matrix</code> the heatmap. Your profile stays saved in this browser.",
          final: true,
        },
      ],
    },

    engineer: {
      title: "Detection Engineer",
      icon: "◈",
      color: "#fbbf24",
      minutes: 5,
      desc: "Declare telemetry, work a prioritized backlog, export a detection plan.",
      steps: [
        {
          title: "Detection engineering workflow",
          body: "Goal: go from threat intel to a <b>prioritized, evidence-backed detection backlog</b> — knowing for each technique why it matters, what telemetry it needs, and which analytic to build.",
        },
        {
          target: ".profile-bar",
          title: "1 · Scope from intel",
          before: async () => setProfile(EXAMPLE_PROFILE),
          body: "Example profile staged: <b>APT29 + Lazarus Group</b>. Your CTI team's profile becomes your engineering scope — no more guessing which techniques matter.",
        },
        {
          view: "detect",
          target: "#dt-scoring-note",
          title: "2 · A transparent priority score",
          body: "Every technique in scope is ranked by <b>threat</b> (profile usage, 0–50) + <b>prevalence</b> (global actor usage, 0–30) + <b>exposure</b> (+20 when ATT&CK maps no mitigation — detection is the only control). Hover any score to see the breakdown. No black boxes.",
        },
        {
          target: ".telemetry-rail",
          title: "3 · Declare your telemetry",
          before: async () => { Detect.applyPreset("Windows"); await sleep(100); },
          body: "We just applied the <b>Windows preset</b> (WinEventLog:* sources). Tick exactly what your SOC ingests — 266 log sources from ATT&CK's analytics corpus, grouped by product. Every verdict downstream is computed against this list.",
        },
        {
          target: "#dt-summary",
          title: "4 · Your reality check",
          body: "Instant answers: visibility percentage over the scope (<b>Full / Partial / Blind</b> per technique), how many techniques are detection-only, and backlog progress. Blind + high score = your next data-onboarding conversation.",
        },
        {
          target: ".wl-item .wl-row",
          title: "5 · Read a worklist row",
          body: "Left to right: rank, score (hover for the breakdown), technique, how many actors use it, mitigation flag, your visibility verdict, and a status selector. Click the row to open its detection card.",
        },
        {
          target: ".dcard",
          title: "6 · The detection card",
          before: async () => { Detect.focus("T1053.005"); await sleep(150); },
          body: "Scheduled Task as an example. <b>Why</b> — which profiled actors use it, campaigns, mitigation status. <b>What to collect</b> — channel-level log sources, ✓/✗ against your telemetry. <b>Detection use-cases</b> — MITRE's analytics with the behavior to look for and the <b>tuning knobs</b> you'll need in your SIEM.",
        },
        {
          target: ".wl-status",
          title: "7 · Track the backlog",
          body: "Mark techniques <b>Planned</b> or <b>Implemented</b> as you build rules — states persist in your browser and feed the summary metrics.",
        },
        {
          target: "#dt-export-md",
          title: "8 · Export the plan",
          before: async () => { Detect.clearFilter(); await sleep(100); },
          body: "Ship the filtered worklist as <b>Markdown</b> (wiki/ticket-ready detection cards) or <b>JSON</b> (scores, visibility, required log sources, analytic IDs — pipe it into your backlog tooling).",
        },
        {
          title: "You're set",
          body: "Daily loop: profile updates from CTI → re-check the summary → work the top Blind/Partial items → export. Deep-link a card to a teammate with <code>#detect=T1053.005</code>.",
          final: true,
        },
      ],
    },

    soc: {
      title: "SOC Lead",
      icon: "◍",
      color: "#818cf8",
      minutes: 3,
      desc: "Coverage KPIs, mitigation ROI, blind spots, exec-ready exports.",
      steps: [
        {
          title: "SOC leadership workflow",
          body: "Goal: defensible answers to <i>“are we covered against the actors that matter?”</i> and <i>“what's the next best investment?”</i> — from the same data your analysts work with.",
        },
        {
          target: ".profile-bar",
          title: "1 · The scope is the threat landscape",
          before: async () => setProfile(EXAMPLE_PROFILE),
          body: "Example staged: <b>APT29 + Lazarus Group</b>. Have your CTI function maintain this profile — every metric below recalculates from it automatically.",
        },
        {
          view: "detect",
          target: "#dt-summary",
          title: "2 · Coverage KPIs",
          before: async () => { Detect.applyPreset("Windows"); await sleep(100); },
          body: "Techniques in scope, <b>visibility %</b> against your actual telemetry, techniques where <b>no mitigation exists</b> (detection is the only control), and rules implemented vs. backlog. Screenshot-ready status.",
        },
        {
          view: "defense",
          target: ".mit-list",
          title: "3 · Mitigation ROI",
          body: "Mitigations ranked by <b>weighted coverage</b>: how much of what your profiled actors actually do each control blunts. The top entries are your highest-leverage hardening investments — with the exact technique list as evidence.",
        },
        {
          target: ".def-side",
          title: "4 · Blind spots",
          body: "Two lists your budget conversation needs: the profile's <b>most-used techniques</b>, and techniques with <b>no mapped mitigation at all</b> — where detection & response capacity is the only option.",
        },
        {
          view: "matrix",
          target: ".matrix-toolbar",
          title: "5 · Exec reporting",
          body: "The heatmap gives the one-slide view of adversary pressure; <b>Export Navigator layer</b> produces the artifact for decks, audits and cross-team alignment.",
        },
        {
          title: "You're set",
          body: "Monthly rhythm: refresh the profile with CTI → check visibility % trend → pick the next mitigation and the next detection items → export the evidence.",
          final: true,
        },
      ],
    },
  };

  /* ---------- Engine ---------- */

  let active = null;   // { key, tour, idx, snapshot }
  let ui = null;       // { block, spot, pop }

  function snapshot() {
    return { profile: [...S.profile], telemetry: Detect.getTelemetry() };
  }

  function restore(snap) {
    S.profile = new Set(snap.profile);
    profileChanged();
    Detect.setTelemetry(snap.telemetry);
    Detect.clearFilter();
    Graph.clear();
  }

  function buildUi() {
    const block = document.createElement("div");
    block.className = "tour-block";
    const spot = document.createElement("div");
    spot.className = "tour-spotlight";
    const pop = document.createElement("div");
    pop.className = "tour-pop";
    document.body.append(block, spot, pop);
    ui = { block, spot, pop };
  }

  function destroyUi() {
    if (!ui) return;
    ui.block.remove(); ui.spot.remove(); ui.pop.remove();
    ui = null;
  }

  async function start(key, at = 0) {
    if (!TOURS[key]) return;
    closeLauncher();
    if (active) endTour(false);
    active = { key, tour: TOURS[key], idx: -1, snapshot: snapshot() };
    buildUi();
    document.addEventListener("keydown", onKey);
    // Steps stage state cumulatively; replay the preceding ones when jumping in.
    for (let i = 0; i < at && i < TOURS[key].steps.length; i++) {
      const s = TOURS[key].steps[i];
      if (s.view && S.view !== s.view) switchView(s.view);
      if (s.before) await s.before();
    }
    await goto(Math.min(at, TOURS[key].steps.length - 1));
  }

  async function goto(i) {
    const { tour } = active;
    if (i < 0 || i >= tour.steps.length) return;
    active.idx = i;
    const step = tour.steps[i];

    if (step.view && S.view !== step.view) switchView(step.view);
    if (step.before) await step.before();
    await sleep(80);

    renderPop(step, i, tour);
    position(step);
  }

  function position(step) {
    const { spot, pop } = ui;
    const target = step.target ? document.querySelector(step.target) : null;

    if (!target) {
      spot.style.opacity = "0";
      pop.style.left = `${(window.innerWidth - pop.offsetWidth) / 2}px`;
      pop.style.top = `${(window.innerHeight - pop.offsetHeight) / 2}px`;
      return;
    }

    target.scrollIntoView({ block: "nearest" });
    const r = target.getBoundingClientRect();
    const pad = 6;
    spot.style.opacity = "1";
    spot.style.left = `${r.left - pad}px`;
    spot.style.top = `${r.top - pad}px`;
    spot.style.width = `${r.width + pad * 2}px`;
    spot.style.height = `${r.height + pad * 2}px`;

    const pw = pop.offsetWidth, ph = pop.offsetHeight, gap = 14;
    let top = r.bottom + gap;
    if (top + ph > window.innerHeight - 10) top = r.top - ph - gap;
    if (top < 10) top = Math.max(10, (window.innerHeight - ph) / 2);
    let left = r.left + r.width / 2 - pw / 2;
    left = Math.max(10, Math.min(left, window.innerWidth - pw - 10));
    pop.style.left = `${left}px`;
    pop.style.top = `${top}px`;
  }

  function renderPop(step, i, tour) {
    const last = i === tour.steps.length - 1;
    ui.pop.style.setProperty("--tc", tour.color);
    ui.pop.innerHTML = `
      <div class="tour-pop-head">
        <span class="tour-pop-tag">${tour.icon} ${esc(tour.title)}</span>
        <span class="tour-pop-count">${i + 1}/${tour.steps.length}</span>
        <button class="tour-x" title="End tour (restores your data)">×</button>
      </div>
      <h3>${step.title}</h3>
      <p>${step.body}</p>
      <div class="tour-pop-actions">
        ${i > 0 ? `<button class="btn subtle mini tour-back">← Back</button>` : ""}
        ${last
          ? `<button class="btn subtle mini tour-restore">Restore my data & finish</button>
             <button class="btn mini tour-keep">Keep example setup ✓</button>`
          : `<button class="btn mini tour-next">Next →</button>`}
      </div>`;

    ui.pop.querySelector(".tour-x").addEventListener("click", () => endTour(true));
    const back = ui.pop.querySelector(".tour-back");
    if (back) back.addEventListener("click", () => goto(active.idx - 1));
    const next = ui.pop.querySelector(".tour-next");
    if (next) next.addEventListener("click", () => goto(active.idx + 1));
    const keep = ui.pop.querySelector(".tour-keep");
    if (keep) keep.addEventListener("click", () => endTour(false));
    const rest = ui.pop.querySelector(".tour-restore");
    if (rest) rest.addEventListener("click", () => endTour(true));
  }

  function onKey(ev) {
    if (!active) return;
    if (ev.key === "Escape") endTour(true);
    else if (ev.key === "ArrowRight") goto(active.idx + 1);
    else if (ev.key === "ArrowLeft") goto(active.idx - 1);
  }

  function endTour(restoreState) {
    document.removeEventListener("keydown", onKey);
    if (restoreState && active) restore(active.snapshot);
    active = null;
    destroyUi();
  }

  /* ---------- Launcher ---------- */

  function openLauncher() {
    closeLauncher();
    const el = document.createElement("div");
    el.className = "tour-modal-backdrop";
    el.id = "tour-launcher";
    el.innerHTML = `
      <div class="tour-modal">
        <button class="tour-x tour-modal-x">×</button>
        <h2>✦ Take a tour</h2>
        <p class="tour-modal-sub">Interactive walkthroughs that stage a real example (APT29 + Lazarus Group) inside the app. Your own data is snapshotted and can be restored at the end.</p>
        <div class="tour-cards">
          ${Object.entries(TOURS).map(([key, t]) => `
            <button class="tour-card" data-tour="${key}" style="--tc:${t.color}">
              <span class="tour-card-icon">${t.icon}</span>
              <span class="tour-card-body">
                <b>${esc(t.title)}</b>
                <span>${esc(t.desc)}</span>
              </span>
              <span class="tour-card-min">~${t.minutes} min</span>
            </button>`).join("")}
        </div>
      </div>`;
    document.body.appendChild(el);

    el.addEventListener("click", (ev) => { if (ev.target === el) closeLauncher(); });
    el.querySelector(".tour-modal-x").addEventListener("click", closeLauncher);
    el.querySelectorAll("[data-tour]").forEach((b) =>
      b.addEventListener("click", () => start(b.dataset.tour)));
  }

  function closeLauncher() {
    const el = document.getElementById("tour-launcher");
    if (el) el.remove();
  }

  function init() {
    document.getElementById("tour-btn").addEventListener("click", openLauncher);
    window.addEventListener("resize", () => {
      if (active) position(active.tour.steps[active.idx]);
    });
    if (!localStorage.getItem(TOURED_KEY) && !location.hash) {
      localStorage.setItem(TOURED_KEY, "1");
      setTimeout(openLauncher, 600);
    }
  }

  return { init, open: openLauncher, start };
})();
