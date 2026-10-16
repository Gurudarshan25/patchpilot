"""PatchPilot dashboard: reads every results file and builds one interactive page (dashboard.html)."""
import json
import os
from datetime import datetime


def read(path):
    if not os.path.exists(path):
        print(f"Note: {path} not found, that section will be empty")
        return None
    with open(path, "r", encoding="utf-8") as f:
        if path.endswith(".md"):
            return f.read()
        return json.load(f)


assets = read("assets.json") or []
priorities = read("priorities.json") or []
plan = read("plan.json")
backtest = read("backtest_results.json")
sbom = read("sbom_report.json")
compliance = read("compliance_report.json")
whatif = read("whatif.json") or []
tickets = read("reports/tickets.json") or []
summary = read("reports/executive_summary.md") or ""

# ---------- Attack map: where each system is drawn ----------
POS = {
    "internet": (70, 280),
    "fw-edge": (300, 50), "vpn-gw": (300, 140), "web-shop": (300, 230),
    "mail-01": (300, 320), "mft-01": (300, 410), "laptop-fleet": (300, 500),
    "dev-server": (580, 60), "app-01": (580, 170), "mq-01": (580, 280),
    "wiki": (580, 390), "legacy-scan": (580, 490),
    "dc-01": (880, 140), "db-customers": (880, 290), "backup-01": (880, 440),
}
for n, a in enumerate(a for a in assets if a["id"] not in POS):   # any new system gets a free spot
    POS[a["id"]] = (440 + (n % 3) * 140, 540 + (n // 3) * 70)

# ---------- Attack map: replay the Hybrid plan week by week ----------
graph_states = []
try:
    from attack_graph import load, build_graph, breakable, open_paths
    a_dict, findings, intel = load()
    G = build_graph(a_dict)
    weeks = plan["strategies"]["Hybrid"]["weeks"] if plan else []
    fixed = set()
    for w in range(len(weeks) + 1):
        if w > 0:
            fixed |= set(weeks[w - 1])
        broken = breakable(a_dict, findings, intel, fixed)
        paths = open_paths(G, a_dict, broken)
        edges = sorted({(p[i], p[i + 1]) for p in paths for i in range(len(p) - 1)})
        per_target = {t: sum(1 for p in paths if p[-1] == t) for t, a in a_dict.items() if a["crown_jewel"]}
        graph_states.append({"week": w, "open": len(paths), "broken": sorted(broken),
                             "edges": [list(e) for e in edges], "per_target": per_target, "fixed": len(fixed)})
    graph_edges = [list(e) for e in G.edges()]
except Exception as e:
    print(f"Note: attack map skipped ({e})")
    graph_edges = []

assets_by_id = {a["id"]: a for a in assets}
findings_table = [{
    "rank": r["rank"], "asset": r["asset"], "asset_name": assets_by_id.get(r["asset"], {}).get("name", r["asset"]),
    "cve": r["cve"], "score": r["score"], "priority": r["priority"], "in_kev": r["in_kev"],
    "ransomware": r["ransomware"], "cvss": r["cvss"], "epss": r["epss"], "fix": r["fix"],
    "fix_hours": r["fix_hours"], "breakdown": r["breakdown"], "source": r.get("source", ""),
} for r in priorities]

DATA = {
    "generated": datetime.now().strftime("%d %B %Y, %H:%M"),
    "assets": assets, "pos": POS, "graph_edges": graph_edges, "graph_states": graph_states,
    "findings": findings_table, "plan": plan, "backtest": backtest, "sbom": sbom,
    "compliance": {k: v for k, v in (compliance or {}).items() if k != "forecast"},
    "sla": [{"priority": x["priority"], "in_kev": x["in_kev"], "late": x["late"]}
            for x in ((compliance or {}).get("forecast", {}).get("Hybrid", []))],
    "sla_cvss": [{"priority": x["priority"], "in_kev": x["in_kev"], "late": x["late"]}
                 for x in ((compliance or {}).get("forecast", {}).get("Sort by CVSS", []))],
    "whatif": whatif, "tickets": tickets, "summary": summary,
}

# ---------- The page ----------
TEMPLATE = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>PatchPilot - vulnerability prioritization</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=Bricolage+Grotesque:opsz,wght@12..96,600;12..96,700;12..96,800&family=JetBrains+Mono:wght@400;600&family=Public+Sans:wght@400;500;600;700&display=swap" rel="stylesheet">
<script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.1/dist/chart.umd.min.js"></script>
<style>
  :root {
    --paper: #F5F3EE; --card: #FFFFFF; --ink: #16191D; --muted: #5F6670; --faint: #9AA1AA;
    --line: #E3DFD6; --orange: #E8590C; --red: #C62F3B; --green: #2B8A3E; --amber: #B97100; --blue: #2F5D8A;
    --head: "Bricolage Grotesque", "Segoe UI", Arial, sans-serif;
    --body: "Public Sans", "Segoe UI", Arial, sans-serif;
    --mono: "JetBrains Mono", Consolas, "Courier New", monospace;
  }
  * { box-sizing: border-box; }
  html { scroll-behavior: smooth; scroll-padding-top: 64px; }
  body { margin: 0; background: var(--paper); color: var(--ink); font-family: var(--body); font-size: 15px; line-height: 1.55; }
  :focus-visible { outline: 2px solid var(--orange); outline-offset: 2px; border-radius: 4px; }
  .mono { font-family: var(--mono); font-size: .92em; }

  nav { position: sticky; top: 0; z-index: 20; background: rgba(245, 243, 238, .94); backdrop-filter: blur(6px); border-bottom: 1px solid var(--line); }
  nav .in { max-width: 1180px; margin: 0 auto; padding: 0 24px; display: flex; align-items: center; gap: 4px; overflow-x: auto; }
  .mark { font-family: var(--head); font-weight: 800; font-size: 17px; margin-right: 18px; white-space: nowrap; display: flex; align-items: center; gap: 8px; }
  .mark i { width: 12px; height: 12px; background: var(--orange); border-radius: 3px; display: inline-block; transform: rotate(45deg); }
  nav a { color: var(--muted); text-decoration: none; padding: 14px 9px; font-size: 14px; white-space: nowrap; border-bottom: 2px solid transparent; }
    nav .in { scrollbar-width: none; }
  nav .in::-webkit-scrollbar { display: none; }
  nav a:hover { color: var(--ink); border-bottom-color: var(--orange); }

  main { max-width: 1180px; margin: 0 auto; padding: 0 24px 80px; }
  header.top { padding: 52px 0 36px; }
  .kicker { color: var(--orange); font-weight: 600; font-size: 14px; margin: 0 0 10px; }
  h1 { font-family: var(--head); font-weight: 800; font-size: clamp(36px, 5.6vw, 62px); line-height: 1.02; letter-spacing: -.02em; margin: 0 0 18px; max-width: 18ch; }
  h1 em { font-style: normal; color: var(--orange); }
  .lede { font-size: 18px; color: var(--muted); max-width: 66ch; margin: 0 0 30px; }
  .lede b { color: var(--ink); }
  .stats { display: grid; grid-template-columns: repeat(auto-fit, minmax(170px, 1fr)); gap: 0; border-top: 2px solid var(--ink); }
  .stat { padding: 16px 18px 16px 0; border-right: 1px solid var(--line); margin-right: 18px; }
  .stat:last-child { border-right: 0; }
  .stat .v { font-family: var(--head); font-weight: 800; font-size: 40px; line-height: 1; }
  .stat .v small { font-size: 18px; color: var(--muted); font-weight: 600; }
  .stat .l { color: var(--muted); font-size: 14px; margin-top: 6px; }

  section { padding: 56px 0 4px; }
  h2 { font-family: var(--head); font-weight: 700; font-size: 32px; line-height: 1.1; letter-spacing: -.01em; margin: 0 0 8px; }
  h3 { font-size: 16px; font-weight: 700; margin: 0 0 4px; }
  .note { color: var(--muted); max-width: 72ch; margin: 0 0 22px; }
  .card { background: var(--card); border: 1px solid var(--line); border-radius: 10px; padding: 20px; }
  .grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(360px, 1fr)); gap: 16px; margin-bottom: 16px; }
  .chart { position: relative; height: 300px; }
  .scroll { overflow-x: auto; }
  .empty { color: var(--faint); font-style: italic; }

  /* attack map */
  .map-wrap { display: grid; grid-template-columns: 1fr 260px; gap: 16px; }
  .map svg { width: 100%; height: auto; display: block; }
  .edge { fill: none; stroke: #D4CFC4; stroke-width: 1.5; transition: stroke .5s, stroke-width .5s, opacity .5s; }
  .edge.on { stroke: var(--red); stroke-width: 2.6; }
  .node rect { stroke-width: 2; transition: fill .5s, stroke .5s; }
  .node text { font-family: var(--mono); font-size: 12px; fill: var(--ink); }
  .node.broken rect { fill: #FBE3E5; stroke: var(--red); }
  .node.safe rect { fill: #E3F2E6; stroke: var(--green); }
  .node.jewel rect { stroke: var(--orange); stroke-width: 3; }
  .node.internet rect { fill: var(--ink); stroke: var(--ink); }
  .node.internet text { fill: #fff; }
  .side .big { font-family: var(--head); font-size: 56px; font-weight: 800; line-height: 1; transition: color .4s; }
  .side .row { display: flex; justify-content: space-between; border-bottom: 1px solid var(--line); padding: 8px 0; font-size: 14px; }
  .controls { display: flex; align-items: center; gap: 12px; margin-top: 14px; flex-wrap: wrap; }
  .controls input[type=range] { flex: 1; min-width: 200px; accent-color: var(--orange); }
  button { font: inherit; font-weight: 600; font-size: 14px; background: var(--ink); color: #fff; border: 0; border-radius: 8px; padding: 9px 16px; cursor: pointer; }
  button.ghost { background: transparent; color: var(--ink); border: 1px solid var(--line); }
  .legend { display: flex; gap: 16px; flex-wrap: wrap; font-size: 13px; color: var(--muted); margin-top: 10px; }
  .legend span::before { content: ""; display: inline-block; width: 12px; height: 12px; border-radius: 3px; margin-right: 6px; vertical-align: -1px; border: 2px solid; }
  .lg-b::before { background: #FBE3E5; border-color: var(--red) !important; }
  .lg-s::before { background: #E3F2E6; border-color: var(--green) !important; }
  .lg-j::before { background: #fff; border-color: var(--orange) !important; }
  .lg-e::before { height: 3px !important; border: 0 !important; background: var(--red); vertical-align: 3px !important; }

  table { width: 100%; border-collapse: collapse; font-size: 14px; }
  th { text-align: left; color: var(--muted); font-weight: 600; font-size: 13px; padding: 10px 10px; border-bottom: 2px solid var(--ink); white-space: nowrap; }
  td { padding: 10px 10px; border-bottom: 1px solid var(--line); vertical-align: top; }
  td.num, th.num { text-align: center; }
  tr.best td { background: #FFF3EA; }
  .wk { font-family: var(--head); font-weight: 700; font-size: 18px; }
  .good { color: var(--green); } .bad { color: var(--red); } .mid { color: var(--amber); }
  .pill { display: inline-block; padding: 2px 9px; border-radius: 999px; font-size: 12px; font-weight: 600; white-space: nowrap; }
  .p-P1 { background: #FBE3E5; color: var(--red); } .p-P2 { background: #FFF0D9; color: var(--amber); }
  .p-P3 { background: #E6EEF6; color: var(--blue); } .p-P4 { background: #EEF0F2; color: var(--muted); }
  .tag { display: inline-block; font-size: 11px; font-weight: 700; padding: 2px 7px; border-radius: 4px; margin: 2px 4px 2px 0; }
  .t-kev { background: var(--red); color: #fff; } .t-ran { background: #6B1C23; color: #fff; } .t-path { background: var(--orange); color: #fff; }

  .tickets { display: grid; grid-template-columns: repeat(auto-fit, minmax(340px, 1fr)); gap: 16px; }
  .ticket h3 { font-size: 15px; margin: 6px 0 10px; }
  .ticket .facts { display: flex; flex-wrap: wrap; gap: 6px 14px; font-size: 13px; color: var(--muted); margin-bottom: 12px; }
  .ticket .facts b { color: var(--ink); }
  .ticket p { margin: 0 0 10px; font-size: 14px; }
  .ticket ol { margin: 0 0 10px; padding-left: 20px; font-size: 14px; }
  .ai { font-size: 12px; color: var(--muted); border-top: 1px dashed var(--line); padding-top: 10px; margin-top: 6px; }
  .ai.warn { color: var(--amber); }
  .ai::before { content: "AI-written text, facts filled in by code. "; font-weight: 600; }

  .summary p { font-size: 16px; max-width: 72ch; margin: 0 0 14px; }
  .bars { display: flex; height: 10px; width: 140px; border-radius: 3px; overflow: hidden; background: #EEF0F2; }
  .bars span { height: 100%; }
  .tools { display: flex; gap: 8px; flex-wrap: wrap; margin-bottom: 12px; }
  .tools input, .tools select { font: inherit; font-size: 14px; padding: 8px 12px; border: 1px solid var(--line); border-radius: 8px; background: #fff; color: var(--ink); }
  .tools input { flex: 1; min-width: 200px; }
  .count { color: var(--muted); font-size: 13px; margin-bottom: 8px; }
  details summary { cursor: pointer; font-weight: 600; color: var(--orange); padding: 6px 0; }
  ul.limits li { margin-bottom: 8px; color: var(--muted); }
  footer { border-top: 1px solid var(--line); margin-top: 56px; padding-top: 18px; color: var(--muted); font-size: 13px; }

  @media (max-width: 860px) { .map-wrap { grid-template-columns: 1fr; } .stat { border-right: 0; } }
  @media (prefers-reduced-motion: reduce) { html { scroll-behavior: auto; } .edge, .node rect { transition: none; } }
</style>
</head>
<body>
<nav aria-label="Sections"><div class="in">
  <span class="mark"><i></i>PatchPilot</span>
  <a href="#map">Attack map</a>
  <a href="#strategies">Strategies</a>
  <a href="#backtest">Backtest</a>
  <a href="#week1">This week</a>
  <a href="#capacity">Capacity</a>
  <a href="#supply">Software supply chain</a>
  <a href="#findings">All findings</a>
  <a href="#method">Method</a>
</div></nav>

<main>
  <header class="top">
    <p class="kicker">Vulnerability prioritization for Waalstad Logistics</p>
    <h1 id="headline"></h1>
    <p class="lede" id="lede"></p>
    <div class="stats" id="stats"></div>
  </header>

  <section id="map">
    <h2>Watch the attack paths close</h2>
    <p class="note">Every route an attacker could take from the internet to the crown jewels, where each system along the way has a bug that is reachable and likely to be exploited. Move the slider to replay the Hybrid plan week by week.</p>
    <div class="map-wrap">
      <div class="card map">
        <svg id="graph" viewBox="0 0 1000 560" role="img" aria-label="Network attack graph"></svg>
        <div class="controls">
          <button id="play">Play</button>
          <input type="range" id="week" min="0" value="0" aria-label="Week of the plan">
          <span id="weekLabel" class="wk"></span>
        </div>
        <div class="legend"><span class="lg-b">breakable system</span><span class="lg-s">no usable bug left</span><span class="lg-j">crown jewel</span><span class="lg-e">open attack route</span></div>
      </div>
      <div class="card side">
        <div class="note" style="margin:0 0 6px">Open attack paths</div>
        <div class="big" id="openCount"></div>
        <div style="margin-top:16px" id="perTarget"></div>
        <p class="note" style="margin-top:16px;font-size:13px" id="mapNote"></p>
      </div>
    </div>
  </section>

  <section id="strategies">
    <h2>Same team, different order</h2>
    <p class="note">Five ways to work through the same findings with 20 hours a week. The order alone decides how long the company stays exposed.</p>
    <div class="card scroll" style="margin-bottom:16px"><table id="stratTable"></table></div>
    <div class="card"><h3>Risk burn-down</h3><p class="note" style="margin-bottom:8px">Share of total risk removed by the end of each week</p><div class="chart"><canvas id="burnChart"></canvas></div></div>
  </section>

  <section id="backtest">
    <h2>Would it have predicted real attacks?</h2>
    <p class="note" id="btNote"></p>
    <div class="grid">
      <div class="card"><h3>Fixes needed to catch half of the later-exploited bugs</h3><p class="note" style="margin-bottom:8px">Fewer is better</p><div class="chart"><canvas id="btChart"></canvas></div></div>
      <div class="card scroll"><h3>Caught in the top of the list</h3><p class="note" style="margin-bottom:8px">Share of later-exploited bugs ranked in the top 1%, 5% and 10%</p><table id="btTable"></table></div>
    </div>
  </section>

  <section id="week1">
    <h2>This week's fixes</h2>
    <p class="note">Tickets for week 1 of the Hybrid plan. Every fact (CVE, system, hours, exploitation status) is filled in by code. The explanations are written by a local AI model and checked by guardrails for invented numbers, CVE IDs and false claims.</p>
    <div class="card summary" style="margin-bottom:16px"><h3>Executive summary for the CISO</h3><div id="summary"></div></div>
    <div class="tickets" id="tickets"></div>
  </section>

  <section id="capacity">
    <h2>Deadlines and capacity</h2>
    <p class="note" id="capNote"></p>
    <div class="grid">
      <div class="card"><h3>Late findings by team size</h3><p class="note" style="margin-bottom:8px">Hybrid plan, deadline policy P1 2 days, P2 7, P3 30, P4 90, exploited max 14</p><div class="chart"><canvas id="whatifChart"></canvas></div></div>
      <div class="card scroll"><h3>Who misses the deadline at 20 hours a week</h3><table id="slaTable"></table></div>
    </div>
  </section>

  <section id="supply">
    <h2>Software supply chain</h2>
    <p class="note" id="sbomNote"></p>
    <div class="grid">
      <div class="card scroll"><h3>Upgrade advisor</h3><p class="note" style="margin-bottom:8px">One upgrade per library that fixes all its known vulnerabilities</p><table id="sbomTable"></table></div>
      <div class="card"><h3>Cyber Resilience Act and VEX</h3><div id="cra"></div></div>
    </div>
  </section>

  <section id="findings">
    <h2>All findings</h2>
    <p class="note">Every finding with its explainable score. The bar shows where the points come from.</p>
    <div class="tools">
      <select id="fPri" aria-label="Priority"><option value="">All priorities</option><option>P1</option><option>P2</option><option>P3</option><option>P4</option></select>
      <select id="fKev" aria-label="Exploited"><option value="">Exploited or not</option><option value="1">Exploited only</option></select>
      <input id="fSearch" type="search" placeholder="Search CVE, system or fix" aria-label="Search">
    </div>
    <div class="count" id="fCount"></div>
    <div class="card scroll"><table id="fTable"></table></div>
  </section>

  <section id="method">
    <h2>How it works, and its limits</h2>
    <div class="grid">
      <div class="card">
        <h3>Score (0 to 100)</h3>
        <p class="note" style="margin:0">Exploitation (max 45: 40 if in CISA KEV, +5 for ransomware, otherwise EPSS percentile x 35) + severity (CVSS x 2) + asset value (criticality x 3, +5 for a crown jewel) + exposure (internet 15, network 7, local 3) + attack-path bonus (up to 15 for bugs that open routes to the crown jewels). P1 means exploited and reachable.</p>
      </div>
      <div class="card">
        <h3>Limitations</h3>
        <ul class="limits" style="margin:0;padding-left:18px">
          <li>The company and its scan are fictional. The CVEs and threat data are real, and the scan is enriched with well-known exploited bugs.</li>
          <li>Fix effort numbers are estimates. Strategies that optimise risk per hour depend on them.</li>
          <li>The backtest covers 12 later-exploited bugs in its test window, so results can move a few percent with other data.</li>
          <li>AI explanations are checked for invented numbers and claims, but a human should still review anything sent to management.</li>
        </ul>
      </div>
    </div>
  </section>

  <footer id="footer"></footer>
</main>

<script>
(() => {
  const D = __DATA__;
  const $ = id => document.getElementById(id);
  const C = { red: "#C62F3B", green: "#2B8A3E", orange: "#E8590C", amber: "#B97100", blue: "#2F5D8A", ink: "#16191D", muted: "#5F6670", slate: "#9AA1AA" };
  function el(tag, text, cls) {
    const e = document.createElement(tag);
    if (text !== undefined && text !== null) e.textContent = text;
    if (cls) e.className = cls;
    return e;
  }
  function empty(target, msg) { const t = $(target); if (t) t.replaceWith(el("p", msg, "empty")); }
  const P = D.plan ? D.plan.strategies : null;
  const hyb = P ? P["Hybrid"] : null;
  const cvss = P ? P["Sort by CVSS"] : null;
  const assetName = id => (D.assets.find(a => a.id === id) || { name: id }).name;

  // ---------- header ----------
  const h1 = $("headline");
  if (hyb && cvss) {
    h1.append("Crown jewels safe in ", el("em", "week " + hyb.week_unreachable), ", not week " + cvss.week_unreachable + ".");
  } else {
    h1.textContent = "Fix what attackers actually use, first.";
  }
  const nF = D.findings.length, nK = D.findings.filter(f => f.in_kev).length;
  const lede = $("lede");
  lede.append("PatchPilot combines live threat intelligence (NVD, EPSS, CISA KEV) with the company's network to decide what to fix first. Waalstad Logistics has ",
    el("b", nF + " findings"), ", ", el("b", nK + " of them actively exploited"), ", and a team with ",
    el("b", (D.plan ? D.plan.team_hours : "?") + " hours a week"), ".");
  const stats = [];
  if (hyb && cvss) stats.push([hyb.week_all_kev, "wk", "all exploited bugs fixed (CVSS sorting: week " + cvss.week_all_kev + ")"]);
  if (D.backtest) {
    const t = D.backtest.windows["2024 (test)"].results;
    const ratio = t["CVSS only"].fixes_to_half / t[D.backtest.chosen].fixes_to_half;
    stats.push([ratio.toFixed(1), "x", "fewer fixes than CVSS to catch half of future attacks (2024 backtest)"]);
  }
  if (D.graph_states.length) stats.push([D.graph_states[0].open, "", "open attack paths to the crown jewels before any fix"]);
  if (D.plan) stats.push([Math.round(D.plan.capacity_needed) - D.plan.team_hours, "h", "per week missing to fix exploited bugs within 2 weeks"]);
  stats.forEach(([v, unit, label]) => {
    const s = el("div", null, "stat");
    const val = el("div", String(v), "v");
    if (unit) val.appendChild(el("small", " " + unit));
    s.append(val, el("div", label, "l"));
    $("stats").appendChild(s);
  });

  // ---------- attack map ----------
  const svg = $("graph");
  const NS = "http://www.w3.org/2000/svg";
  const S = (tag, attrs) => { const e = document.createElementNS(NS, tag); for (const k in attrs) e.setAttribute(k, attrs[k]); return e; };
  if (!D.graph_states.length) {
    empty("graph", "Attack map not available (run attack_graph.py and planner.py first).");
  } else {
    const defs = S("defs", {});
    [["arrow", "#D4CFC4"], ["arrowOn", C.red]].forEach(([id, col]) => {
      const m = S("marker", { id, viewBox: "0 0 10 10", refX: "9", refY: "5", markerWidth: "7", markerHeight: "7", orient: "auto-start-reverse" });
      m.appendChild(S("path", { d: "M0,0 L10,5 L0,10 z", fill: col }));
      defs.appendChild(m);
    });
    svg.appendChild(defs);
    const BW = 116, BH = 34;
    const edgeEls = {};
    D.graph_edges.forEach(([a, b]) => {
      const [x1, y1] = D.pos[a], [x2, y2] = D.pos[b];
      let d;
      if (Math.abs(x2 - x1) < 20) {            // same column: bend outwards
        const bend = x1 + 95;
        d = `M${x1 + BW / 2},${y1} C${bend},${y1} ${bend},${y2} ${x2 + BW / 2 + 2},${y2}`;
      } else if (x2 > x1) {                    // left to right
        const sx = x1 + BW / 2, ex = x2 - BW / 2 - 4, mid = (sx + ex) / 2;
        d = `M${sx},${y1} C${mid},${y1} ${mid},${y2} ${ex},${y2}`;
      } else {                                 // right to left (e.g. domain controller back to laptops)
        const sx = x1 - BW / 2, ex = x2 + BW / 2 + 4, mid = (sx + ex) / 2;
        d = `M${sx},${y1} C${mid},${y1} ${mid},${y2} ${ex},${y2}`;
      }
      const p = S("path", { d, class: "edge", "marker-end": "url(#arrow)" });
      svg.appendChild(p);
      edgeEls[a + ">" + b] = p;
    });
    const nodeEls = {};
    Object.entries(D.pos).forEach(([id, [x, y]]) => {
      if (id !== "internet" && !D.assets.find(a => a.id === id)) return;
      const a = D.assets.find(a => a.id === id);
      const g = S("g", { class: "node" + (id === "internet" ? " internet" : "") + (a && a.crown_jewel ? " jewel" : "") });
      g.appendChild(S("rect", { x: x - BW / 2, y: y - BH / 2, width: BW, height: BH, rx: 7, fill: "#fff" }));
      const t = S("text", { x, y: y + 4, "text-anchor": "middle" });
      t.textContent = id;
      g.appendChild(t);
      const title = S("title", {});
      title.textContent = a ? a.name : "The internet (attacker starts here)";
      g.appendChild(title);
      svg.appendChild(g);
      nodeEls[id] = g;
    });

    const slider = $("week");
    slider.max = D.graph_states.length - 1;
    function show(w) {
      const s = D.graph_states[w];
      const broken = new Set(s.broken), on = new Set(s.edges.map(e => e[0] + ">" + e[1]));
      Object.entries(nodeEls).forEach(([id, g]) => {
        if (id === "internet") return;
        g.classList.toggle("broken", broken.has(id));
        g.classList.toggle("safe", !broken.has(id));
      });
      Object.entries(edgeEls).forEach(([k, p]) => {
        const isOn = on.has(k);
        p.classList.toggle("on", isOn);
        p.setAttribute("marker-end", isOn ? "url(#arrowOn)" : "url(#arrow)");
      });
      $("weekLabel").textContent = w === 0 ? "Before any fixes" : "After week " + w;
      const big = $("openCount");
      big.textContent = s.open;
      big.style.color = s.open ? C.red : C.green;
      const pt = $("perTarget");
      pt.innerHTML = "";
      Object.entries(s.per_target).forEach(([t, n]) => {
        const r = el("div", null, "row");
        const v = el("b", n === 0 ? "safe" : n + (n === 1 ? " path" : " paths"));
        v.style.color = n === 0 ? C.green : C.red;
        r.append(el("span", assetName(t)), v);
        pt.appendChild(r);
      });
      $("mapNote").textContent = `${s.fixed} findings fixed so far. ${s.broken.length} systems still have a usable bug.`;
    }
    slider.oninput = () => show(+slider.value);
    let timer = null;
    $("play").onclick = () => {
      if (timer) { clearInterval(timer); timer = null; $("play").textContent = "Play"; return; }
      if (+slider.value >= +slider.max) slider.value = 0;
      $("play").textContent = "Pause";
      show(+slider.value);
      timer = setInterval(() => {
        if (+slider.value >= +slider.max) { clearInterval(timer); timer = null; $("play").textContent = "Play"; return; }
        slider.value = +slider.value + 1;
        show(+slider.value);
      }, 900);
    };
    show(0);
  }

  // ---------- strategies ----------
  if (!P) {
    empty("stratTable", "No plan found (run planner.py).");
  } else {
    const t = $("stratTable");
    const head = el("tr");
    ["Strategy", "Crown jewels safe", "All exploited fixed", "All ransomware fixed", "80% of risk gone", "Exploited bugs fixed late"]
      .forEach((h, i) => head.appendChild(el("th", h, i ? "num" : "")));
    t.appendChild(head);
    const keys = ["week_unreachable", "week_all_kev", "week_all_ransom", "week_80"];
    const best = {}, worst = {};
    keys.forEach(k => {
      best[k] = Math.min(...Object.values(P).map(s => s[k] || 999));
      worst[k] = Math.max(...Object.values(P).map(s => s[k] || 0));
    });
    const DESC = {
      "Sort by CVSS": "highest severity score first",
      "Compliance first": "exploited bugs first",
      "Protect crown jewels": "close attack paths first",
      "Balanced": "most risk per hour first",
      "Hybrid": "close paths, then exploited, then risk per hour",
    };
    Object.entries(P).forEach(([name, s]) => {
      const tr = el("tr", null, name === "Hybrid" ? "best" : "");
      const c = el("td");
      c.append(el("b", name), el("div", DESC[name] || "", "note"));
      c.lastChild.style.margin = "0";
      tr.appendChild(c);
      keys.forEach(k => {
        const td = el("td", s[k] ? "week " + s[k] : "–", "num wk");
        if (s[k] === best[k]) td.classList.add("good");
        else if (s[k] === worst[k]) td.classList.add("bad");
        tr.appendChild(td);
      });
      tr.appendChild(el("td", String(s.kev_late), "num wk"));
      t.appendChild(tr);
    });
  }

  // ---------- backtest ----------
  if (!D.backtest) {
    empty("btTable", "No backtest found (run backtest.py).");
    $("btNote").textContent = "";
  } else {
    const test = D.backtest.windows["2024 (test)"];
    const tune = D.backtest.windows["2023 (tuning)"];
    $("btNote").textContent = `Time machine set to ${test.cutoff}: ${test.candidates.toLocaleString()} vulnerabilities that were not yet known to be exploited, ranked using only data available on that day. ${test.exploited_later} of them were exploited in the following year. The formula was chosen on ${tune ? tune.cutoff.slice(0, 4) : "earlier"} data and tested on ${test.cutoff.slice(0, 4)}.`;
    const bt = $("btTable");
    const hr = el("tr");
    ["Ranking", "Top 1%", "Top 5%", "Top 10%", "Fixes to catch half"].forEach((h, i) => hr.appendChild(el("th", h, i ? "num" : "")));
    bt.appendChild(hr);
    const NAMES = { "CVSS only": "CVSS only", "EPSS only": "EPSS only", [D.backtest.chosen]: "PatchPilot" };
    Object.entries(NAMES).forEach(([k, label]) => {
      const r = test.results[k];
      if (!r) return;
      const tr = el("tr", null, label === "PatchPilot" ? "best" : "");
      tr.appendChild(el("td", label));
      [r.top1, r.top5, r.top10].forEach(v => tr.appendChild(el("td", Math.round(v) + "%", "num")));
      tr.appendChild(el("td", String(r.fixes_to_half), "num wk"));
      bt.appendChild(tr);
    });
    const rnd = el("tr");
    rnd.appendChild(el("td", "Random guess"));
    ["1%", "5%", "10%", Math.round(test.candidates / 2).toLocaleString()].forEach(v => rnd.appendChild(el("td", v, "num")));
    rnd.style.color = C.slate;
    bt.appendChild(rnd);
  }

  // ---------- tickets + summary ----------
  if (D.summary) {
    D.summary.split(/\n\s*\n/).filter(p => p.trim() && !p.trim().startsWith("#")).forEach(p => {
      if (p.trim().startsWith(">")) { const w = el("p", p.replace(/^>\s*/, ""), "ai warn"); $("summary").appendChild(w); }
      else $("summary").appendChild(el("p", p.trim()));
    });
  } else {
    $("summary").appendChild(el("p", "No executive summary found (run reports.py).", "empty"));
  }
  if (!D.tickets.length) {
    empty("tickets", "No tickets found (run reports.py).");
  } else {
    D.tickets.forEach(t => {
      const c = el("article", null, "card ticket");
      const top = el("div");
      top.append(el("span", t.ticket, "mono"), document.createTextNode("  "), el("span", t.priority, "pill p-" + t.priority));
      c.appendChild(top);
      c.appendChild(el("h3", `${t.system}: ${t.cve}`));
      const facts = el("div", null, "facts");
      [["Effort", t.fix_hours + " h"], ["Deadline", t.deadline.replace("fix within ", "")], ["Score", t.risk_score_out_of_100 + "/100"]]
        .forEach(([k, v]) => { const s = el("span"); s.append(k + ": ", el("b", v)); facts.appendChild(s); });
      c.appendChild(facts);
      const tags = el("div");
      if (t.actively_exploited_in_kev) tags.appendChild(el("span", "EXPLOITED", "tag t-kev"));
      if (t.used_by_ransomware) tags.appendChild(el("span", "RANSOMWARE", "tag t-ran"));
      if (t.opens_attack_path_to_crown_jewels) tags.appendChild(el("span", "OPENS ATTACK PATH", "tag t-path"));
      if (tags.childNodes.length) { tags.style.marginBottom = "10px"; c.appendChild(tags); }
      const ai = t.ai_text || {};
      if (ai.risk_summary) { const p = el("p"); p.append(el("b", "Why it matters: "), ai.risk_summary); c.appendChild(p); }
      if (ai.attacker_scenario) { const p = el("p"); p.append(el("b", "Attacker scenario: "), ai.attacker_scenario); c.appendChild(p); }
      if (ai.fix_steps && ai.fix_steps.length) {
        c.appendChild(el("b", "Fix steps"));
        const ol = el("ol");
        ai.fix_steps.forEach(s => ol.appendChild(el("li", String(s))));
        c.appendChild(ol);
      }
      if (ai.verification) { const p = el("p"); p.append(el("b", "Verify: "), ai.verification); c.appendChild(p); }
      const w = t.guardrail_warnings || [];
      c.appendChild(el("div", w.length ? "Guardrail warning: " + w.join("; ") : "Guardrails passed.", "ai" + (w.length ? " warn" : "")));
      $("tickets").appendChild(c);
    });
  }

  // ---------- capacity ----------
  if (D.plan) {
    const kevF = D.findings.filter(f => f.in_kev);
    $("capNote").textContent = `Fixing all ${kevF.length} exploited findings takes ${kevF.reduce((s, f) => s + f.fix_hours, 0)} hours. Meeting a two-week deadline would need about ${Math.round(D.plan.capacity_needed)} hours a week; the team has ${D.plan.team_hours}. No ordering can solve that alone: it needs more capacity, a one-time clean-up project, or a formally accepted risk.`;
  }
  if (D.sla.length) {
    const st = $("slaTable");
    const hr = el("tr");
    ["Group", "Findings", "Late (CVSS order)", "Late (Hybrid)"].forEach((h, i) => hr.appendChild(el("th", h, i ? "num" : "")));
    st.appendChild(hr);
    const groups = [["P1 (2 days)", x => x.priority === "P1"], ["P2 (7 days)", x => x.priority === "P2"],
                    ["P3 (30 days)", x => x.priority === "P3"], ["P4 (90 days)", x => x.priority === "P4"],
                    ["Exploited (max 14 days)", x => x.in_kev]];
    groups.forEach(([label, f]) => {
      const tr = el("tr");
      tr.appendChild(el("td", label));
      tr.appendChild(el("td", String(D.sla.filter(f).length), "num"));
      [D.sla_cvss, D.sla].forEach(list => {
        const n = list.filter(x => f(x) && x.late).length;
        tr.appendChild(el("td", String(n), "num " + (n ? "bad" : "good")));
      });
      st.appendChild(tr);
    });
  } else {
    empty("slaTable", "No deadline forecast found (run compliance.py).");
  }

  // ---------- supply chain ----------
  if (!D.sbom) {
    empty("sbomTable", "No SBOM report found (run sbom_scan.py).");
  } else {
    const app = D.sbom.application;
    $("sbomNote").textContent = `${app.name} ${app.version} runs on ${D.sbom.asset}. Its SBOM lists ${D.sbom.components} libraries in Python, Java and JavaScript; OSV.dev reports ${D.sbom.findings.length} known vulnerabilities in them.`;
    const t = $("sbomTable");
    const hr = el("tr");
    ["Library", "Installed", "Upgrade to", "Fixes", "Exploited"].forEach((h, i) => hr.appendChild(el("th", h, i > 2 ? "num" : "")));
    t.appendChild(hr);
    D.sbom.advice.forEach(a => {
      const tr = el("tr");
      const n = el("td");
      n.append(el("b", a.component), el("div", a.ecosystem, "note"));
      n.lastChild.style.margin = "0";
      tr.append(n, el("td", a.installed, "mono"), el("td", a.upgrade_to, "mono"), el("td", String(a.fixes), "num"));
      const k = el("td", String(a.kev), "num wk " + (a.kev ? "bad" : ""));
      tr.appendChild(k);
      t.appendChild(tr);
    });
    const cra = $("cra");
    const n = (D.compliance && D.compliance.cra_count) || D.sbom.findings.filter(f => f.in_kev).length;
    const big = el("div", String(n), "stat");
    big.innerHTML = "";
    const v = el("div", String(n), "v");
    v.style.color = n ? C.red : C.green;
    big.append(v, el("div", "actively exploited vulnerabilities in the product: each needs a CRA early warning within 24 hours, a notification within 72 hours and a final report within 14 days after the fix", "l"));
    big.style.border = "0";
    cra.appendChild(big);
    const vs = (D.compliance && D.compliance.vex_states) || {};
    if (Object.keys(vs).length) {
      cra.appendChild(el("h3", "VEX statements exported (CycloneDX)"));
      const total = Object.values(vs).reduce((a, b) => a + b, 0);
      const COL = { exploitable: C.red, in_triage: C.slate, not_affected: C.green, resolved: C.blue };
      const bar = el("div", null, "bars");
      bar.style.width = "100%"; bar.style.height = "14px"; bar.style.margin = "8px 0";
      Object.entries(vs).forEach(([k, n]) => { const s = el("span"); s.style.width = (n / total * 100) + "%"; s.style.background = COL[k] || C.blue; s.title = k + ": " + n; bar.appendChild(s); });
      cra.appendChild(bar);
      Object.entries(vs).forEach(([k, n]) => {
        const r = el("div", null);
        r.style.fontSize = "14px";
        const dot = el("span", "■ ");
        dot.style.color = COL[k] || C.blue;
        r.append(dot, k.replace("_", " ") + ": ", el("b", String(n)));
        cra.appendChild(r);
      });
      cra.appendChild(el("p", "Only an analyst can mark a vulnerability as not affected, with a standard justification.", "note"));
    }
  }

  // ---------- findings table ----------
  const PARTS = [["exploitation", C.red], ["severity", C.amber], ["asset_value", C.blue], ["exposure", C.slate], ["attack_path", C.orange]];
  function render() {
    const pri = $("fPri").value, kev = $("fKev").value, q = $("fSearch").value.toLowerCase();
    const t = $("fTable");
    t.innerHTML = "";
    const hr = el("tr");
    ["#", "System", "CVE", "Priority", "Score", "Where the points come from", "CVSS", "Fix", "Hours"].forEach((h, i) =>
      hr.appendChild(el("th", h, [0, 4, 6, 8].includes(i) ? "num" : "")));
    t.appendChild(hr);
    const rows = D.findings.filter(f => (!pri || f.priority === pri) && (!kev || f.in_kev) &&
      (f.cve + " " + f.asset + " " + f.asset_name + " " + f.fix).toLowerCase().includes(q));
    $("fCount").textContent = `Showing ${rows.length} of ${D.findings.length} findings`;
    rows.slice(0, 200).forEach(f => {
      const tr = el("tr");
      tr.appendChild(el("td", String(f.rank), "num"));
      const sys = el("td");
      sys.append(el("b", f.asset), el("div", f.asset_name, "note"));
      sys.lastChild.style.margin = "0";
      tr.appendChild(sys);
      const cv = el("td");
      cv.appendChild(el("span", f.cve, "mono"));
      const tg = el("div");
      if (f.in_kev) tg.appendChild(el("span", "EXPLOITED", "tag t-kev"));
      if (f.ransomware) tg.appendChild(el("span", "RANSOMWARE", "tag t-ran"));
      if (f.breakdown.attack_path) tg.appendChild(el("span", "PATH", "tag t-path"));
      cv.appendChild(tg);
      tr.appendChild(cv);
      const p = el("td"); p.appendChild(el("span", f.priority, "pill p-" + f.priority)); tr.appendChild(p);
      tr.appendChild(el("td", String(f.score), "num wk"));
      const bc = el("td");
      const bars = el("div", null, "bars");
      PARTS.forEach(([k, col]) => {
        const v = f.breakdown[k] || 0;
        if (!v) return;
        const s = el("span");
        s.style.width = v + "%";
        s.style.background = col;
        s.title = k.replace("_", " ") + ": " + v;
        bars.appendChild(s);
      });
      bc.appendChild(bars);
      tr.appendChild(bc);
      tr.appendChild(el("td", f.cvss ? String(f.cvss) : "–", "num"));
      tr.appendChild(el("td", f.fix));
      tr.appendChild(el("td", String(f.fix_hours), "num"));
      t.appendChild(tr);
    });
  }
  if (D.findings.length) {
    ["fPri", "fKev"].forEach(id => { $(id).onchange = render; });
    $("fSearch").oninput = render;
    render();
  } else {
    empty("fTable", "No findings found (run prioritize_paths.py).");
  }

  // ---------- charts ----------
  if (window.Chart) {
    Chart.defaults.font.family = '"Public Sans", "Segoe UI", Arial, sans-serif';
    Chart.defaults.color = C.muted;
    Chart.defaults.borderColor = "#E3DFD6";
    const legend = { position: "bottom", labels: { boxWidth: 12, boxHeight: 12 } };
    if (P) {
      const COL = { "Sort by CVSS": C.slate, "Compliance first": C.blue, "Protect crown jewels": C.amber, "Balanced": "#7A6CC8", "Hybrid": C.orange };
      const maxW = Math.max(...Object.values(P).map(s => s.burn.length));
      new Chart($("burnChart"), {
        type: "line",
        data: {
          labels: Array.from({ length: maxW }, (_, i) => "Week " + (i + 1)),
          datasets: Object.entries(P).map(([name, s]) => ({
            label: name, data: s.burn, borderColor: COL[name] || C.ink, backgroundColor: COL[name] || C.ink,
            borderWidth: name === "Hybrid" ? 3.5 : 2, pointRadius: name === "Hybrid" ? 3 : 0, tension: .25,
          })),
        },
        options: { maintainAspectRatio: false, scales: { y: { min: 0, max: 100, ticks: { callback: v => v + "%" } }, x: { grid: { display: false } } }, plugins: { legend } },
      });
    }
    if (D.backtest) {
      const order = ["CVSS only", "EPSS only", D.backtest.chosen];
      const labels = ["CVSS only", "EPSS only", "PatchPilot"];
      const wins = Object.keys(D.backtest.windows);
      new Chart($("btChart"), {
        type: "bar",
        data: {
          labels,
          datasets: wins.map((w, i) => ({
            label: w, data: order.map(k => (D.backtest.windows[w].results[k] || {}).fixes_to_half),
            backgroundColor: i === wins.length - 1 ? [C.slate, C.blue, C.orange] : ["#D7DADF", "#C9D6E4", "#F6C9AE"],
            borderRadius: 4,
          })),
        },
        options: { maintainAspectRatio: false, scales: { x: { grid: { display: false } }, y: { beginAtZero: true } }, plugins: { legend } },
      });
    }
    if (D.whatif.length) {
      new Chart($("whatifChart"), {
        type: "bar",
        data: {
          labels: D.whatif.map(w => w.hours_per_week + " h/week"),
          datasets: [
            { label: "Exploited bugs late", data: D.whatif.map(w => w.kev_late), backgroundColor: C.red, borderRadius: 3 },
            { label: "P1 late", data: D.whatif.map(w => w.p1_late), backgroundColor: C.orange, borderRadius: 3 },
            { label: "All findings late", data: D.whatif.map(w => w.all_late), backgroundColor: "#D7DADF", borderRadius: 3 },
          ],
        },
        options: { maintainAspectRatio: false, scales: { x: { grid: { display: false } }, y: { beginAtZero: true, ticks: { precision: 0 } } }, plugins: { legend } },
      });
    } else {
      empty("whatifChart", "No what-if data found (run compliance.py).");
    }
  } else {
    document.querySelectorAll("canvas").forEach(c => c.replaceWith(el("p", "Charts need an internet connection. Reopen the page while online.", "empty")));
  }

  $("footer").textContent = `Generated ${D.generated} by make_dashboard.py. Threat data: NVD, FIRST EPSS, CISA KEV, OSV.dev. AI: qwen2.5:3b running locally via Ollama.`;
})();
</script>
</body>
</html>"""


def to_js(value):
    return json.dumps(value).replace("</", "<\\/")


page = TEMPLATE.replace("__DATA__", to_js(DATA))
with open("dashboard.html", "w", encoding="utf-8") as f:
    f.write(page)
print(f"Dashboard saved to dashboard.html ({len(findings_table)} findings, {len(graph_states)} attack-map states, "
      f"{len(tickets)} tickets)")