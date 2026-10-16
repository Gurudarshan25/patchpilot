import json
from scoring import score_finding, priority
from attack_graph import load, key, build_graph, is_enabling, breakable, open_paths, chokepoints

TEAM_HOURS_PER_WEEK = 20

assets, findings, intel = load()
G = build_graph(assets)
paths_through = chokepoints(open_paths(G, assets, breakable(assets, findings, intel)))

# ---------- 1. Score every finding (base score + attack path bonus) ----------
rows = []
for f in findings:
    i = intel[f["cve"]]
    a = assets[f["asset"]]
    base, breakdown = score_finding(f, a, i)

    bonus = 0
    if is_enabling(f, a, intel) and f["asset"] in paths_through:
        bonus = min(15, 5 + 2 * paths_through[f["asset"]])
    breakdown["attack_path"] = bonus

    total = min(100, round(base + bonus, 1))
    p, deadline = priority(total, i["in_kev"], a["internet_facing"] or bonus > 0)
    rows.append({**f, "key": key(f), "base_score": base, "score": total, "breakdown": breakdown,
                 "priority": p, "deadline": deadline, "cvss": i["cvss"] or 0, "epss": i["epss"],
                 "in_kev": i["in_kev"], "ransomware": i["ransomware"]})
rows.sort(key=lambda r: -r["score"])
for rank, r in enumerate(rows, start=1):
    r["rank"] = rank

with open("priorities.json", "w", encoding="utf-8") as f:
    json.dump(rows, f, indent=2)

# ---------- 2. Top 15 ----------
print("=== PATCHPILOT TOP 15 ===")
print(f"{'#':>3} {'Score':>5} {'Pri':3} {'Asset':13} {'CVE':16} {'CVSS':>4} {'KEV':3}  Why")
for r in rows[:15]:
    b = r["breakdown"]
    why = (f"exploit {b['exploitation']:.0f} + sev {b['severity']:.0f} + asset {b['asset_value']} "
           f"+ expo {b['exposure']} + path {b['attack_path']}")
    print(f"{r['rank']:>3} {r['score']:5.1f} {r['priority']:3} {r['asset']:13} {r['cve']:16} "
          f"{r['cvss']:4.1f} {'YES' if r['in_kev'] else 'no':3}  {why}")

print()
print("Priority counts:", {p: sum(1 for r in rows if r["priority"] == p) for p in ["P1", "P2", "P3", "P4"]})


# ---------- 3. Compare three ways of working ----------
def hours_until_all(order, condition):
    target = sum(1 for r in order if condition(r))
    hours, done = 0, 0
    for r in order:
        hours += r["fix_hours"]
        if condition(r):
            done += 1
            if done == target:
                return hours
    return hours


def hours_until_paths_closed(order):
    """Fix findings one by one; return the hours when no open path to a crown jewel is left."""
    fixed = set()
    hours = 0
    if not open_paths(G, assets, breakable(assets, findings, intel, fixed)):
        return 0
    for r in order:
        hours += r["fix_hours"]
        fixed.add(r["key"])
        if not open_paths(G, assets, breakable(assets, findings, intel, fixed)):
            return hours
    return hours


orders = {
    "Sort by CVSS": sorted(rows, key=lambda r: -r["cvss"]),
    "PatchPilot (no paths)": sorted(rows, key=lambda r: -r["base_score"]),
    "PatchPilot + paths": rows,
}

checks = [
    ("all exploited bugs", lambda r: r["in_kev"]),
    ("all ransomware bugs", lambda r: r["ransomware"]),
    ("exploited bugs on crown jewels", lambda r: r["in_kev"] and assets[r["asset"]]["crown_jewel"]),
]

total_hours = sum(r["fix_hours"] for r in rows)
print()
print(f"=== WEEKS UNTIL FIXED (total work: {total_hours} h, team: {TEAM_HOURS_PER_WEEK} h/week) ===")
print(f"{'Goal':32}" + "".join(f"{name:>24}" for name in orders))
for label, condition in checks:
    cells = "".join(f"{hours_until_all(order, condition) / TEAM_HOURS_PER_WEEK:23.1f}w" for order in orders.values())
    print(f"{label:32}{cells}")
cells = "".join(f"{hours_until_paths_closed(order) / TEAM_HOURS_PER_WEEK:23.1f}w" for order in orders.values())
print(f"{'crown jewels unreachable':32}{cells}")

print()
print("Saved to priorities.json")