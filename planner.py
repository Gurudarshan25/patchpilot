import json
from attack_graph import load, build_graph, is_enabling, breakable, open_paths

TEAM_HOURS_PER_WEEK = 20
KEV_DEADLINE_WEEKS = 2          # policy: actively exploited bugs fixed within 2 weeks
SHOW_PLAN_FOR = "Hybrid"       # which strategy's week-by-week plan to print

assets, findings, intel = load()
G = build_graph(assets)
with open("priorities.json", "r", encoding="utf-8") as f:
    rows = json.load(f)
total_risk = sum(r["score"] for r in rows)


def paths_after(fixed):
    return open_paths(G, assets, breakable(assets, findings, intel, fixed))


# ---------- 1. The four strategies (each returns an order of fixes) ----------
def order_cvss():
    return sorted(rows, key=lambda r: -r["cvss"])


def order_compliance():
    kev = sorted([r for r in rows if r["in_kev"]], key=lambda r: (not r["ransomware"], -r["score"]))
    rest = sorted([r for r in rows if not r["in_kev"]], key=lambda r: -r["score"])
    return kev + rest


def order_balanced():
    return sorted(rows, key=lambda r: -(r["score"] / r["fix_hours"]))


def order_crown_jewels():
    """Greedy: repeatedly fix the system whose enabling bugs close the most attack paths per hour."""
    fixed, order = set(), []
    current = paths_after(fixed)
    while current:
        best = None
        for node in {n for p in current for n in p[1:-1]}:
            bundle = [r for r in rows if r["asset"] == node and r["key"] not in fixed
                      and is_enabling(r, assets[node], intel)]
            if not bundle:
                continue
            after = paths_after(fixed | {r["key"] for r in bundle})
            value = (len(current) - len(after)) / sum(r["fix_hours"] for r in bundle)
            if best is None or value > best[0]:
                best = (value, bundle, after)
        if best is None or best[0] == 0:
            break
        for r in sorted(best[1], key=lambda r: -r["score"]):
            order.append(r)
            fixed.add(r["key"])
        current = best[2]
    rest = sorted([r for r in rows if r["key"] not in fixed], key=lambda r: -r["score"])
    return order + rest


def order_hybrid():
    """1) close all attack paths to crown jewels, 2) remaining exploited bugs, 3) the rest by risk per hour."""
    fixed, first = set(), []
    for r in order_crown_jewels():
        first.append(r)
        fixed.add(r["key"])
        if not paths_after(fixed):
            break
    taken = {r["key"] for r in first}
    kev = sorted([r for r in rows if r["in_kev"] and r["key"] not in taken],
                 key=lambda r: (not r["ransomware"], -r["score"]))
    taken |= {r["key"] for r in kev}
    rest = sorted([r for r in rows if r["key"] not in taken], key=lambda r: -(r["score"] / r["fix_hours"]))
    return first + kev + rest


STRATEGIES = {
    "Sort by CVSS": order_cvss,
    "Compliance first": order_compliance,
    "Protect crown jewels": order_crown_jewels,
    "Balanced": order_balanced,
    "Hybrid": order_hybrid,
}


# ---------- 2. Turn an order into weeks of 20 hours ----------
def schedule(order):
    weeks, week, used = [], [], 0
    for r in order:
        if used + r["fix_hours"] > TEAM_HOURS_PER_WEEK and week:
            weeks.append(week)
            week, used = [], 0
        week.append(r)
        used += r["fix_hours"]
    if week:
        weeks.append(week)
    return weeks


# ---------- 3. Measure a plan ----------
def evaluate(order):
    weeks = schedule(order)
    total_kev = sum(r["in_kev"] for r in rows)
    total_ransom = sum(r["ransomware"] for r in rows)
    fixed, removed, kev_done, ransom_done = set(), 0, 0, 0
    result = {"weeks": [[r["key"] for r in w] for w in weeks], "burn": [],
              "week_80": None, "week_all_kev": None, "week_all_ransom": None,
              "week_unreachable": 0 if not paths_after(set()) else None, "kev_late": 0}
    for n, week in enumerate(weeks, start=1):
        for r in week:
            fixed.add(r["key"])
            removed += r["score"]
            kev_done += r["in_kev"]
            ransom_done += r["ransomware"]
            if r["in_kev"] and n > KEV_DEADLINE_WEEKS:
                result["kev_late"] += 1
        pct = removed / total_risk * 100
        result["burn"].append(round(pct, 1))
        if result["week_80"] is None and pct >= 80:
            result["week_80"] = n
        if result["week_all_kev"] is None and kev_done == total_kev:
            result["week_all_kev"] = n
        if result["week_all_ransom"] is None and ransom_done == total_ransom:
            result["week_all_ransom"] = n
        if result["week_unreachable"] is None and not paths_after(fixed):
            result["week_unreachable"] = n
    return result


results = {}
for name, make_order in STRATEGIES.items():
    print(f"Planning: {name}...")
    results[name] = evaluate(make_order())

# ---------- 4. Compare the strategies ----------
print()
print(f"=== STRATEGY COMPARISON (team: {TEAM_HOURS_PER_WEEK} h/week) ===")
print(f"{'Strategy':22} {'80% risk gone':>14} {'all exploited':>14} {'all ransomware':>15} "
      f"{'crown jewels safe':>18} {'KEV fixed late':>15}")
for name, r in results.items():
    print(f"{name:22} {'week ' + str(r['week_80']):>14} {'week ' + str(r['week_all_kev']):>14} "
          f"{'week ' + str(r['week_all_ransom']):>15} {'week ' + str(r['week_unreachable']):>18} {r['kev_late']:>15}")

print()
print("=== RISK BURN-DOWN (% of total risk removed by end of week) ===")
n_weeks = max(len(r["burn"]) for r in results.values())
print(f"{'Strategy':22}" + "".join(f"{'wk ' + str(i):>7}" for i in range(1, min(n_weeks, 8) + 1)))
for name, r in results.items():
    print(f"{name:22}" + "".join(f"{v:6.0f}%" for v in r["burn"][:8]))

kev_hours = sum(r["fix_hours"] for r in rows if r["in_kev"])
needed = kev_hours / KEV_DEADLINE_WEEKS
print()
print("=== CAPACITY CHECK ===")
print(f"Fixing all {sum(r['in_kev'] for r in rows)} exploited findings takes {kev_hours} hours.")
print(f"To meet a {KEV_DEADLINE_WEEKS}-week deadline the team needs {needed:.0f} h/week "
      f"(it has {TEAM_HOURS_PER_WEEK}) -> {'OK' if needed <= TEAM_HOURS_PER_WEEK else 'NOT ENOUGH CAPACITY'}")

# ---------- 5. The week-by-week plan for one strategy ----------
by_key = {r["key"]: r for r in rows}
print()
print(f"=== WEEK-BY-WEEK PLAN: {SHOW_PLAN_FOR} (first 3 weeks) ===")
for n, week in enumerate(results[SHOW_PLAN_FOR]["weeks"][:3], start=1):
    items = [by_key[k] for k in week]
    print(f"Week {n} ({sum(r['fix_hours'] for r in items)} h, risk removed so far: "
          f"{results[SHOW_PLAN_FOR]['burn'][n - 1]:.0f}%)")
    for r in items:
        tags = []
        if r["in_kev"]:
            tags.append("EXPLOITED")
        if r["ransomware"]:
            tags.append("RANSOMWARE")
        if r["breakdown"].get("attack_path"):
            tags.append("OPENS ATTACK PATH")
        print(f"   {r['asset']:13} {r['cve']:16} {r['fix_hours']}h  score {r['score']:5.1f}  {', '.join(tags)}")

with open("plan.json", "w", encoding="utf-8") as f:
    json.dump({"team_hours": TEAM_HOURS_PER_WEEK, "kev_deadline_weeks": KEV_DEADLINE_WEEKS,
               "capacity_needed": needed, "strategies": results}, f, indent=2)
print()
print("Saved to plan.json")