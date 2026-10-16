"""PatchPilot AI agent: answers questions by calling tools, then gets fact-checked."""
import json
import re
import ollama

MODEL = "qwen2.5:3b"
MAX_STEPS = 6


def load(path):
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


ASSETS = {a["id"]: a for a in load("assets.json")}
PRIORITIES = load("priorities.json")
INTEL = load("threat_intel.json")
PATHS = load("attack_paths.json")
PLAN = load("plan.json")
SBOM = load("sbom_report.json")


# ---------- TOOLS: small functions the AI is allowed to call ----------
def get_company_overview() -> str:
    """Get a summary of the company: systems, crown jewels, number of findings, exploited bugs and team capacity."""
    return json.dumps({
        "systems": len(ASSETS),
        "crown_jewels": [a for a, v in ASSETS.items() if v["crown_jewel"]],
        "internet_facing": [a for a, v in ASSETS.items() if v["internet_facing"]],
        "findings": len(PRIORITIES),
        "actively_exploited_findings": sum(r["in_kev"] for r in PRIORITIES),
        "ransomware_findings": sum(r["ransomware"] for r in PRIORITIES),
        "priority_counts": {p: sum(r["priority"] == p for r in PRIORITIES) for p in ["P1", "P2", "P3", "P4"]},
        "open_attack_paths_to_crown_jewels": len(PATHS["paths"]),
        "team_hours_per_week": PLAN["team_hours"],
        "hours_per_week_needed_for_kev_deadline": round(PLAN["capacity_needed"]),
    })


def get_top_findings(n: int = 5) -> str:
    """Get the highest-risk findings in the company, ranked by PatchPilot score.

    Args:
        n: how many findings to return (1 to 15)
    """
    n = max(1, min(15, int(n)))
    return json.dumps([{"rank": r["rank"], "system": r["asset"], "system_name": ASSETS[r["asset"]]["name"],
                        "cve": r["cve"], "risk_score_out_of_100": r["score"], "priority": r["priority"],
                        "in_kev": r["in_kev"], "ransomware": r["ransomware"],
                        "opens_attack_path": r["breakdown"].get("attack_path", 0) > 0,
                        "fix": r["fix"], "fix_hours": r["fix_hours"]} for r in PRIORITIES[:n]])


def get_finding_details(cve: str) -> str:
    """Get full details about one vulnerability (CVE ID): description, scores, where it was found and how to fix it.

    Args:
        cve: the CVE ID, for example CVE-2021-44228
    """
    cve = cve.strip().upper()
    hits = [r for r in PRIORITIES if r["cve"] == cve]
    if not hits:
        return json.dumps({"error": f"{cve} was not found in this company's scan"})
    i = INTEL.get(cve, {})
    return json.dumps({
        "cve": cve,
        "description": i.get("description", "")[:400],
        "cvss": i.get("cvss"), "epss": i.get("epss"), "in_kev": i.get("in_kev"), "ransomware": i.get("ransomware"),
        "found_on": [{"system": r["asset"], "system_name": ASSETS[r["asset"]]["name"],
                      "internet_facing": ASSETS[r["asset"]]["internet_facing"],
                      "crown_jewel": ASSETS[r["asset"]]["crown_jewel"],
                      "risk_score_out_of_100": r["score"], "priority": r["priority"],
                      "score_breakdown": r["breakdown"], "fix": r["fix"], "fix_hours": r["fix_hours"]} for r in hits],
    })


def get_attack_paths(asset: str) -> str:
    """Get the open attack paths from the internet to the crown jewels that go through or end at a system.

    Args:
        asset: the system id, for example vpn-gw or db-customers
    """
    asset = asset.strip()
    if asset not in ASSETS:
        return json.dumps({"error": f"unknown system '{asset}'", "known_systems": list(ASSETS)})
    mine = [p for p in PATHS["paths"] if asset in p]
    return json.dumps({"system": asset, "open_paths_involving_it": len(mine),
                       "paths_passing_through_it": PATHS["chokepoints"].get(asset, 0),
                       "examples": [" -> ".join(p) for p in sorted(mine, key=len)[:5]]})


def get_fix_plan(week: int = 1) -> str:
    """Get the recommended fixes for a given week from the Hybrid plan (team has limited hours per week).

    Args:
        week: week number, starting at 1
    """
    weeks = PLAN["strategies"]["Hybrid"]["weeks"]
    week = int(week)
    if not 1 <= week <= len(weeks):
        return json.dumps({"error": f"week must be between 1 and {len(weeks)}"})
    by_key = {r["key"]: r for r in PRIORITIES}
    items = [by_key[k] for k in weeks[week - 1]]
    return json.dumps({
        "week": week,
        "total_hours_this_week": sum(r["fix_hours"] for r in items),
        "team_hours_per_week": PLAN["team_hours"],
        "risk_removed_by_end_of_week_percent": PLAN["strategies"]["Hybrid"]["burn"][week - 1],
        "fixes": [{"system": r["asset"], "system_name": ASSETS[r["asset"]]["name"], "cve": r["cve"],
                   "fix": r["fix"], "fix_hours": r["fix_hours"], "risk_score_out_of_100": r["score"],
                   "in_kev": r["in_kev"], "ransomware": r["ransomware"],
                   "opens_attack_path": r["breakdown"].get("attack_path", 0) > 0} for r in items],
    })


def get_library_upgrades() -> str:
    """Get the upgrade advice for the libraries inside the order service application (from its SBOM)."""
    return json.dumps({"application": SBOM["application"]["name"], "advice": SBOM["advice"][:8]})


TOOLS = {f.__name__: f for f in [get_company_overview, get_top_findings, get_finding_details,
                                  get_attack_paths, get_fix_plan, get_library_upgrades]}

SYSTEM = """You are PatchPilot, a vulnerability management analyst for the company Waalstad Logistics.

Glossary:
- KEV = CISA's Known Exploited Vulnerabilities catalog. in_kev=true means attackers are actively exploiting it.
- ransomware=true means ransomware gangs are known to use it.
- opens_attack_path=true means the bug lets an attacker move toward the crown jewels.
- risk_score_out_of_100 is a score from 0 to 100, not a percentage.

Rules:
- ALWAYS use your tools to look up facts before answering.
- Answer ONLY with facts from tool results. Never invent CVE IDs, numbers, systems or dates.
- Always write the CVE ID next to every vulnerability you mention.
- Copy in_kev and ransomware values exactly from the tool results.
- Never do arithmetic yourself. Use totals the tools give you (for example total_hours_this_week).
- For every fix, say which system it is on and WHY it matters (exploited, ransomware, opens attack path).
- If the tools do not contain the answer, say that you don't know.
- Be concise and practical, like a senior security engineer briefing a colleague."""

CVE_PATTERN = r"CVE-\d{4}-\d{4,7}"


# ---------- GUARDRAIL: fact-check the answer ----------
def collect_facts(evidence):
    """Find every {cve, in_kev, ransomware} and every total hours value inside the tool results."""
    facts, totals = {}, set()

    def walk(x):
        if isinstance(x, dict):
            if "cve" in x and "in_kev" in x:
                facts[x["cve"]] = {"kev": x["in_kev"], "ransomware": x.get("ransomware", False)}
            if "total_hours_this_week" in x:
                totals.add(x["total_hours_this_week"])
            for v in x.values():
                walk(v)
        elif isinstance(x, list):
            for v in x:
                walk(v)

    for e in evidence:
        try:
            walk(json.loads(e))
        except json.JSONDecodeError:
            pass
    return facts, totals


def fact_check(answer, evidence):
    warnings = []
    upper = answer.upper()

    # 1. Invented CVE IDs
    mentioned = set(re.findall(CVE_PATTERN, upper))
    grounded = set(re.findall(CVE_PATTERN, " ".join(evidence).upper()))
    invented = sorted(mentioned - grounded)
    if invented:
        warnings.append(f"INVENTED CVE IDs (not in any tool result): {', '.join(invented)}")

    # 2. Wrong claims about real CVEs: exploited (KEV) and ransomware
    facts, totals = collect_facts(evidence)
    matches = list(re.finditer(CVE_PATTERN, upper))
    checked, wrong = 0, 0
    for n, m in enumerate(matches):
        end = matches[n + 1].start() if n + 1 < len(matches) else len(answer)
        text = answer[m.end():end].lower()
        cve = m.group()
        if cve not in facts:
            continue
        truth = facts[cve]

        says_not_kev = "not in kev" in text or "not exploited" in text or "not actively exploited" in text
        says_kev = not says_not_kev and ("in kev" in text or "exploited" in text)
        if says_kev or says_not_kev:
            checked += 1
            if (says_not_kev and truth["kev"]) or (says_kev and not truth["kev"]):
                wrong += 1
                warnings.append(f"WRONG CLAIM about {cve}: it {'IS' if truth['kev'] else 'is NOT'} in KEV")

        says_no_ransom = "no ransomware" in text or "not ransomware" in text or "not used by ransomware" in text
        says_ransom = not says_no_ransom and "ransomware" in text
        if says_ransom or says_no_ransom:
            checked += 1
            if (says_ransom and not truth["ransomware"]) or (says_no_ransom and truth["ransomware"]):
                wrong += 1
                warnings.append(f"WRONG CLAIM about {cve}: it {'IS' if truth['ransomware'] else 'is NOT'} used by ransomware")

    # 3. Wrong total hours
    for claimed in re.findall(r"total of (\d+) hours", answer.lower()):
        if totals and int(claimed) not in totals:
            warnings.append(f"WRONG TOTAL: answer says {claimed} hours, tool data says {sorted(totals)}")

    if not evidence:
        warnings.append("Answered WITHOUT using any tool - treat with caution")

    # 4. Claims that cannot be verified are NOT ok
    claim_words = ["kev", "exploited", "ransomware"]
    if evidence and not mentioned and any(w in answer.lower() for w in claim_words):
        warnings.append("UNVERIFIABLE: the answer makes exploit/ransomware claims without CVE IDs, "
                        "so they cannot be checked")

    return {"cves_mentioned": len(mentioned), "cves_verified": len(mentioned) - len(invented),
            "claims_checked": checked, "wrong_claims": wrong, "warnings": warnings}


# ---------- THE AGENT LOOP ----------
def ask(question, show_steps=True):
    messages = [{"role": "system", "content": SYSTEM}, {"role": "user", "content": question}]
    evidence = []
    answer = "(the agent stopped after too many steps)"

    for step in range(MAX_STEPS):
        response = ollama.chat(model=MODEL, messages=messages, tools=list(TOOLS.values()),
                               options={"temperature": 0})
        msg = response.message
        messages.append(msg)

        if not msg.tool_calls:          # no more tools needed -> this is the final answer
            answer = msg.content
            break

        for call in msg.tool_calls:     # run every tool the AI asked for
            name = call.function.name
            args = call.function.arguments or {}
            if show_steps:
                print(f"   [tool] {name}({', '.join(f'{k}={v}' for k, v in args.items())})")
            try:
                result = TOOLS[name](**args) if name in TOOLS else json.dumps({"error": f"unknown tool {name}"})
            except Exception as e:
                result = json.dumps({"error": str(e)})
            evidence.append(result)
            messages.append({"role": "tool", "content": result, "tool_name": name})

    check = fact_check(answer, evidence)

    # SELF-CORRECTION: if the fact-check found errors, give them back to the AI once
    if check["warnings"] and evidence:
        if show_steps:
            print("   [guardrail] errors found, asking the AI to correct itself...")
        messages.append({"role": "user", "content":
                         "Your answer has these problems according to the tool data:\n- "
                         + "\n- ".join(check["warnings"])
                         + "\nRewrite the full answer with these problems fixed. Write the CVE ID next to every "
                           "vulnerability and copy in_kev and ransomware values exactly from the tool results."})
        response = ollama.chat(model=MODEL, messages=messages, options={"temperature": 0})
        fixed = response.message.content
        fixed_check = fact_check(fixed, evidence)
        if len(fixed_check["warnings"]) < len(check["warnings"]):
            answer, check = fixed, fixed_check
            check["warnings"].insert(0, "(answer was corrected automatically after the first fact-check)")

    return answer, check


if __name__ == "__main__":
    print("Ask PatchPilot anything about Waalstad's vulnerabilities. Type 'quit' to stop.")
    print("Try: What should we fix this week and why? | Is the customer database in danger? | Which library upgrade matters most?")
    while True:
        question = input("\nYou: ").strip()
        if question.lower() in ("quit", "exit", ""):
            break
        print("PatchPilot is investigating...")
        answer, check = ask(question)
        print()
        print("PatchPilot:", answer)
        print()
        real_warnings = [w for w in check["warnings"] if not w.startswith("(answer was corrected")]
        status = "OK" if not real_warnings else "WARNING"
        print(f"[fact-check {status}] {check['cves_verified']}/{check['cves_mentioned']} CVE IDs verified, "
              f"{check['claims_checked'] - check['wrong_claims']}/{check['claims_checked']} claims correct")
        for w in check["warnings"]:
            print("   !", w)