"""PatchPilot compliance: SLA deadline forecast, CRA reporting duties and a CycloneDX VEX export."""
import json
import math
from datetime import date, timedelta

SCAN_DATE = date(2026, 10, 1)          # the day the scan ran
HOURS_PER_WORKDAY = 4                  # 20 hours/week spread over 5 working days
SLA_DAYS = {"P1": 2, "P2": 7, "P3": 30, "P4": 90}
KEV_MAX_DAYS = 14                      # exploited bugs: never more than 14 days


def load(path):
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


PRIORITIES = load("priorities.json")
PLAN = load("plan.json")
SBOM = load("sbom_report.json")
SBOM_FILE = load("sbom.json")
OVERRIDES = load("vex_overrides.json")
BY_KEY = {r["key"]: r for r in PRIORITIES}


def deadline_days(r):
    days = SLA_DAYS[r["priority"]]
    return min(days, KEV_MAX_DAYS) if r["in_kev"] else days


# ---------- 1. SLA forecast: simulate the plan day by day ----------
def forecast(order, hours_per_workday=HOURS_PER_WORKDAY):
    hours, rows = 0, []
    for r in order:
        hours += r["fix_hours"]
        work_days = hours / hours_per_workday
        calendar_days = math.ceil(work_days * 7 / 5)        # weekends don't count as work
        allowed = deadline_days(r)
        rows.append({"key": r["key"], "priority": r["priority"], "in_kev": r["in_kev"],
                     "fixed_on_day": calendar_days, "deadline_day": allowed,
                     "late": calendar_days > allowed,
                     "fix_date": str(SCAN_DATE + timedelta(days=calendar_days)),
                     "deadline_date": str(SCAN_DATE + timedelta(days=allowed))})
    return rows


plans = {}
for name in ["Sort by CVSS", "Hybrid"]:
    order = [BY_KEY[k] for week in PLAN["strategies"][name]["weeks"] for k in week]
    plans[name] = forecast(order)

print(f"=== SLA FORECAST (scan date {SCAN_DATE}, team {PLAN['team_hours']} h/week) ===")
print("Deadlines (company policy): P1 2 days, P2 7, P3 30, P4 90; exploited (KEV) max 14 days")
print(f"{'Group':16} {'Findings':>8} {'Late with CVSS':>16} {'Late with Hybrid':>18}")
groups = [("P1", lambda x: x["priority"] == "P1"), ("P2", lambda x: x["priority"] == "P2"),
          ("P3", lambda x: x["priority"] == "P3"), ("P4", lambda x: x["priority"] == "P4"),
          ("Exploited (KEV)", lambda x: x["in_kev"]), ("ALL", lambda x: True)]
for label, cond in groups:
    total = sum(1 for x in plans["Hybrid"] if cond(x))
    late_c = sum(1 for x in plans["Sort by CVSS"] if cond(x) and x["late"])
    late_h = sum(1 for x in plans["Hybrid"] if cond(x) and x["late"])
    print(f"{label:16} {total:8} {late_c:16} {late_h:18}")

# ---------- 2. CRA: actively exploited vulnerabilities in our PRODUCT ----------
app = SBOM["application"]
cra = [f for f in SBOM["findings"] if f["in_kev"]]
print()
print(f"=== CRA REPORTING DUTIES for product '{app['name']} {app['version']}' ===")
print(f"Actively exploited vulnerabilities in the product: {len(cra)}")
notices = ["# CRA notification drafts", "",
           f"Product: **{app['name']} {app['version']}**  ",
           "Rule (Cyber Resilience Act, from 11 Sept 2026): actively exploited vulnerabilities in a product must be "
           "reported: early warning within 24 hours, notification within 72 hours, final report within 14 days "
           "after a fix is available.", ""]
for f in cra:
    print(f"  {f['id']:18} in {f['component']} {f['installed']} -> fixed in {f['fixed_in'] or 'unknown'}")
    notices += [f"## {f['id']} in {f['component']} {f['installed']}", "",
                f"- **Status:** actively exploited (listed in CISA KEV){' and used by ransomware' if f['ransomware'] else ''}",
                f"- **Affected component:** {f['component']} version {f['installed']} ({f['ecosystem']})",
                f"- **Corrective measure:** upgrade to {f['fixed_in'] or 'a fixed version (not listed)'}",
                f"- **Summary:** {f['summary']}",
                "- **Deadlines:** early warning within 24 h of becoming aware, notification within 72 h, "
                "final report within 14 days after the fix is available", ""]
with open("reports/cra_notifications.md", "w", encoding="utf-8") as fh:
    fh.write("\n".join(notices))

# ---------- 3. VEX export (CycloneDX) ----------
purls = {c["name"]: c["purl"] for c in SBOM_FILE["components"]}
vex_items, states = [], {}
for f in SBOM["findings"]:
    o = OVERRIDES.get(f["id"])
    if o:
        analysis = {"state": o["state"], "justification": o["justification"], "detail": o["detail"]}
    elif f["in_kev"]:
        analysis = {"state": "exploitable", "detail": "Actively exploited in the wild (CISA KEV). Upgrade required."}
    else:
        analysis = {"state": "in_triage", "detail": "Known vulnerability in a used component; reachability not yet analysed."}
    if f["fixed_in"] and analysis["state"] != "not_affected":
        analysis["response"] = ["update"]
    states[analysis["state"]] = states.get(analysis["state"], 0) + 1
    item = {"id": f["id"], "affects": [{"ref": purls.get(f["component"], f["component"])}], "analysis": analysis}
    if f["id"].startswith("CVE-"):
        item["source"] = {"name": "NVD", "url": f"https://nvd.nist.gov/vuln/detail/{f['id']}"}
    if f["cvss"]:
        item["ratings"] = [{"score": f["cvss"], "method": "other"}]
    vex_items.append(item)

vex = {"bomFormat": "CycloneDX", "specVersion": "1.5", "version": 1,
       "metadata": {"timestamp": f"{SCAN_DATE}T00:00:00Z", "component": app},
       "vulnerabilities": vex_items}
with open("reports/vex.cdx.json", "w", encoding="utf-8") as fh:
    json.dump(vex, fh, indent=2)

print()
print(f"=== VEX EXPORT ({len(vex_items)} vulnerabilities) ===")
for s, n in sorted(states.items(), key=lambda x: -x[1]):
    print(f"  {s:14} {n}")

with open("compliance_report.json", "w", encoding="utf-8") as fh:
    json.dump({"scan_date": str(SCAN_DATE), "sla_days": SLA_DAYS, "kev_max_days": KEV_MAX_DAYS,
               "forecast": plans, "cra_count": len(cra), "vex_states": states}, fh, indent=2)
print()
print("Saved: compliance_report.json, reports/cra_notifications.md, reports/vex.cdx.json")



# ---------- 4. WHAT-IF: how much team capacity meets the deadlines? ----------
hybrid_order = [BY_KEY[k] for week in PLAN["strategies"]["Hybrid"]["weeks"] for k in week]
print()
print("=== WHAT-IF: team capacity vs late findings (Hybrid plan) ===")
print(f"{'Hours/week':>10} {'KEV late':>9} {'P1 late':>8} {'All late':>9}")
whatif = []
for team in [20, 30, 40, 60, 80, 120]:
    rows = forecast(hybrid_order, hours_per_workday=team / 5)
    kev_late = sum(1 for x in rows if x["in_kev"] and x["late"])
    p1_late = sum(1 for x in rows if x["priority"] == "P1" and x["late"])
    all_late = sum(1 for x in rows if x["late"])
    whatif.append({"hours_per_week": team, "kev_late": kev_late, "p1_late": p1_late, "all_late": all_late})
    print(f"{team:10} {kev_late:9} {p1_late:8} {all_late:9}")
with open("whatif.json", "w", encoding="utf-8") as fh:
    json.dump(whatif, fh, indent=2)