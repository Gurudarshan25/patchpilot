"""PatchPilot reports: CODE writes the facts, the AI writes only the words, guardrails check the words."""
import json
import os
import re
import ollama

MODEL = "qwen2.5:3b"
CVE_PATTERN = r"CVE-\d{4}-\d{4,7}"
os.makedirs("reports", exist_ok=True)


def load(path):
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


ASSETS = {a["id"]: a for a in load("assets.json")}
PRIORITIES = load("priorities.json")
INTEL = load("threat_intel.json")
PATHS = load("attack_paths.json")
PLAN = load("plan.json")
SBOM = load("sbom_report.json")
BACKTEST = load("backtest_results.json")
BY_KEY = {r["key"]: r for r in PRIORITIES}


# ---------- GUARDRAILS ----------
def numbers_in(text):
    text = re.sub(CVE_PATTERN, "", text)            # numbers inside CVE IDs don't count
    found = set()
    for n in re.findall(r"\d+(?:\.\d+)?", text):
        found.add(n[:-2] if n.endswith(".0") else n)  # "100.0" and "100" are the same
    return found


def allowed_numbers(facts):
    allowed = numbers_in(json.dumps(facts))
    allowed |= {str(round(float(n))) for n in allowed}   # allow rounded versions (e.g. 96.2 -> 96)
    allowed |= {str(i) for i in range(0, 11)}            # small counting numbers are fine
    return allowed


def check_text(text, facts, own_cves=(), kev=None, ransomware=None):
    warnings = []
    invented = numbers_in(text) - allowed_numbers(facts)
    if invented:
        warnings.append(f"numbers not in the facts: {', '.join(sorted(invented))}")
    other_cves = set(re.findall(CVE_PATTERN, text.upper())) - set(own_cves)
    if other_cves:
        warnings.append(f"mentions CVE IDs that were not given: {', '.join(sorted(other_cves))}")
    low = text.lower()
    if ransomware is False and "ransomware" in low:
        warnings.append("says 'ransomware' but this bug is not ransomware-linked")
    if kev is False and re.search(r"actively exploited|known exploited|\bkev\b", low):
        warnings.append("says it is actively exploited but it is NOT in KEV")
    return warnings


def ask_json(prompt, keys):
    for _ in range(2):  # one retry if the AI returns broken JSON
        r = ollama.chat(model=MODEL, messages=[{"role": "user", "content": prompt}],
                        format="json", options={"temperature": 0.2})
        try:
            data = json.loads(r.message.content)
            if all(k in data for k in keys):
                return data
        except json.JSONDecodeError:
            pass
    return None


# ---------- 1. TICKETS for every week-1 fix ----------
REUSE_TICKETS = True   # set to False to write the tickets again
tickets = load("reports/tickets.json") if REUSE_TICKETS and os.path.exists("reports/tickets.json") else []
week1 = PLAN["strategies"]["Hybrid"]["weeks"][0]
todo = [] if tickets else week1
print(f"Writing {len(todo)} tickets (reusing {len(tickets)} existing ones)...")

for n, key in enumerate(todo, start=1):
    r = BY_KEY[key]
    a = ASSETS[r["asset"]]
    i = INTEL[r["cve"]]
    facts = {   # written by CODE, always correct
        "cve": r["cve"], "system": a["name"], "system_id": r["asset"],
        "internet_facing": a["internet_facing"], "crown_jewel": a["crown_jewel"],
        "actively_exploited_in_kev": r["in_kev"], "used_by_ransomware": r["ransomware"],
        "opens_attack_path_to_crown_jewels": r["breakdown"].get("attack_path", 0) > 0,
        "attack_paths_through_system": PATHS["chokepoints"].get(r["asset"], 0),
        "fix": r["fix"], "fix_hours": r["fix_hours"],
        "risk_score_out_of_100": r["score"], "priority": r["priority"], "deadline": r["deadline"],
        "description": i["description"][:500],
    }
    prompt = f"""You are a senior security engineer writing a remediation ticket.

FACTS (correct and complete - do not change them, do not add numbers, versions or CVE IDs that are not here):
{json.dumps(facts, indent=2)}

Return ONLY JSON with exactly these fields:
{{"risk_summary": "2 sentences: why this matters for THIS system",
  "attacker_scenario": "2-3 sentences: what an attacker could realistically do with this bug here",
  "fix_steps": ["3 to 5 short, concrete steps"],
  "verification": "1 sentence: how to check that the fix worked"}}"""

    print(f"  [{n}/{len(week1)}] {r['cve']} on {r['asset']}...")
    ai = ask_json(prompt, ["risk_summary", "attacker_scenario", "fix_steps", "verification"])
    if ai is None:
        warnings = ["AI did not return valid JSON - fill in by hand"]
        ai = {"risk_summary": "", "attacker_scenario": "", "fix_steps": [], "verification": ""}
    else:
        all_text = " ".join([ai["risk_summary"], ai["attacker_scenario"], " ".join(map(str, ai["fix_steps"])),
                             ai["verification"]])
        warnings = check_text(all_text, facts, own_cves=[r["cve"]], kev=r["in_kev"], ransomware=r["ransomware"])

    tickets.append({
        "ticket": f"PP-{n:03d}",
        "title": f"[{r['priority']}] {r['fix']} on {a['name']} ({r['cve']})",
        **{k: facts[k] for k in ["cve", "system", "system_id", "priority", "deadline", "fix_hours",
                                 "actively_exploited_in_kev", "used_by_ransomware",
                                 "opens_attack_path_to_crown_jewels", "risk_score_out_of_100"]},
        "ai_text": ai, "guardrail_warnings": warnings,
    })

with open("reports/tickets.json", "w", encoding="utf-8") as f:
    json.dump(tickets, f, indent=2)

yes = lambda b: "Yes" if b else "No"
lines = ["# PatchPilot tickets - week 1", "",
         "| Ticket | System | CVE | Priority | Hours | Exploited (KEV) | Ransomware | Opens attack path |",
         "|---|---|---|---|---|---|---|---|"]
for t in tickets:
    lines.append(f"| {t['ticket']} | {t['system']} | {t['cve']} | {t['priority']} | {t['fix_hours']} | "
                 f"{yes(t['actively_exploited_in_kev'])} | {yes(t['used_by_ransomware'])} | "
                 f"{yes(t['opens_attack_path_to_crown_jewels'])} |")
for t in tickets:
    ai = t["ai_text"]
    lines += ["", f"## {t['ticket']}: {t['title']}", "",
              f"**Deadline:** {t['deadline']}  |  **Effort:** {t['fix_hours']} h  |  **Risk score:** {t['risk_score_out_of_100']}/100",
              "", f"**Why it matters:** {ai['risk_summary']}", "",
              f"**Attacker scenario:** {ai['attacker_scenario']}", "", "**Fix steps:**"]
    lines += [f"{k}. {s}" for k, s in enumerate(ai["fix_steps"], start=1)]
    lines += ["", f"**Verify:** {ai['verification']}"]
    if t["guardrail_warnings"]:
        lines += ["", "> Guardrail warnings: " + "; ".join(t["guardrail_warnings"])]
with open("reports/tickets.md", "w", encoding="utf-8") as f:
    f.write("\n".join(lines))

# ---------- 2. EXECUTIVE SUMMARY for the CISO ----------
hybrid = PLAN["strategies"]["Hybrid"]
cvss = PLAN["strategies"]["Sort by CVSS"]
test = BACKTEST["windows"]["2024 (test)"]
summary_facts = {   # every number here is calculated by CODE
    "company": "Waalstad Logistics",
    "systems": len(ASSETS), "findings": len(PRIORITIES), "unique_cves": len({r["cve"] for r in PRIORITIES}),
    "actively_exploited_findings": sum(r["in_kev"] for r in PRIORITIES),
    "ransomware_findings": sum(r["ransomware"] for r in PRIORITIES),
    "open_attack_paths_to_crown_jewels": len(PATHS["paths"]),
    "team_hours_per_week": PLAN["team_hours"],
    "hours_per_week_needed_to_fix_all_exploited_within_2_weeks": round(PLAN["capacity_needed"]),
    "weeks_until_crown_jewels_unreachable": {"sorting_by_cvss": cvss["week_unreachable"], "patchpilot": hybrid["week_unreachable"]},
    "weeks_until_all_exploited_fixed": {"sorting_by_cvss": cvss["week_all_kev"], "patchpilot": hybrid["week_all_kev"]},
    "backtest_2024_fixes_needed_to_catch_half_of_later_exploited": {
        "cvss": test["results"]["CVSS only"]["fixes_to_half"],
        "patchpilot": test["results"][BACKTEST["chosen"]]["fixes_to_half"]},
    "top_library_upgrade": {k: SBOM["advice"][0][k] for k in ["component", "installed", "upgrade_to", "fixes"]},
        "week_1_fixes": [f"{t['system']} ({t['cve']})" for t in tickets],
    "comparisons_already_calculated": {
        "crown_jewels_safe_weeks_earlier_than_cvss": cvss["week_unreachable"] - hybrid["week_unreachable"],
        "exploited_bugs_fixed_weeks_earlier_than_cvss": cvss["week_all_kev"] - hybrid["week_all_kev"],
        "backtest_times_fewer_fixes_than_cvss": round(test["results"]["CVSS only"]["fixes_to_half"]
                                                      / test["results"][BACKTEST["chosen"]]["fixes_to_half"], 1),
        "missing_hours_per_week": round(PLAN["capacity_needed"]) - PLAN["team_hours"],
    },

}
summary_prompt = f"""Write an executive summary for the CISO of Waalstad Logistics about vulnerability risk.

FACTS (the only numbers you may use):
{json.dumps(summary_facts, indent=2)}

Write 4 short paragraphs of plain text (no headings, no bullet points):
1. The current situation.
2. What the team will fix this week and why.
3. Why prioritizing by real exploitation and attack paths beats sorting by CVSS (use the comparison numbers).
4. What we need from management (team capacity).
Use ONLY numbers from FACTS. Do not calculate anything yourself: use comparisons_already_calculated.
Do not invent any number, percentage or date."""
print("Writing the executive summary...")
messages = [{"role": "user", "content": summary_prompt}]
summary = ollama.chat(model=MODEL, messages=messages, options={"temperature": 0.2}).message.content
own = re.findall(CVE_PATTERN, json.dumps(summary_facts))
warnings = check_text(summary, summary_facts, own_cves=own)

for attempt in range(3):   # self-correction, up to 3 tries
    if not warnings:
        break
    print(f"  guardrail found problems ({'; '.join(warnings)}), correction attempt {attempt + 1}...")
    messages += [{"role": "assistant", "content": summary},
                 {"role": "user", "content": "Problems: " + "; ".join(warnings)
                  + ". Rewrite the whole summary using ONLY numbers that appear in FACTS. Do not calculate anything."}]
    fixed = ollama.chat(model=MODEL, messages=messages, options={"temperature": 0.2}).message.content
    fixed_warnings = check_text(fixed, summary_facts, own_cves=own)
    if len(fixed_warnings) <= len(warnings):
        summary, warnings = fixed, fixed_warnings

with open("reports/executive_summary.md", "w", encoding="utf-8") as f:
    f.write("# Executive summary - vulnerability risk at Waalstad Logistics\n\n" + summary)
    if warnings:
        f.write("\n\n> Guardrail warnings: " + "; ".join(warnings))

# ---------- 3. Report ----------
print()
print("=== GUARDRAIL RESULTS ===")
for t in tickets:
    status = "OK" if not t["guardrail_warnings"] else "; ".join(t["guardrail_warnings"])
    print(f"{t['ticket']} {t['cve']:16} {status}")
print(f"Executive summary: {'OK' if not warnings else '; '.join(warnings)}")
print()
print("Saved: reports/tickets.json, reports/tickets.md, reports/executive_summary.md")