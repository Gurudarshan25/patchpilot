"""PatchPilot risk scoring: every score is explainable, so the team can see WHY."""


def score_finding(finding, asset, intel):
    breakdown = {}

    # 1. Exploitation (max 45)
    #    Confirmed exploited (KEV) always beats "predicted": 40, +5 if ransomware uses it.
    #    Otherwise use the EPSS PERCENTILE (backtest showed raw EPSS gets drowned out by CVSS).
    if intel["in_kev"]:
        exploitation = 40 + (5 if intel["ransomware"] else 0)
    else:
        exploitation = intel["epss_percentile"] * 35
    breakdown["exploitation"] = round(exploitation, 1)

    # 2. Severity (max 20): how bad could it be?
    breakdown["severity"] = round((intel["cvss"] or 0) * 2, 1)

    # 3. Asset value (max 20): how important is this system?
    breakdown["asset_value"] = asset["criticality"] * 3 + (5 if asset["crown_jewel"] else 0)

    # 4. Exposure (max 15): can an attacker reach it?
    if asset["internet_facing"]:
        exposure = 15
    elif intel["attack_vector"] in ("NETWORK", "ADJACENT_NETWORK"):
        exposure = 7
    else:
        exposure = 3
    breakdown["exposure"] = exposure

    total = min(100, round(sum(breakdown.values()), 1))
    return total, breakdown


def priority(score, in_kev=False, reachable=False):
    """P1 only for bugs that are BOTH exploited and reachable by an attacker."""
    if in_kev and reachable:
        return "P1", "fix within 48 hours"
    if in_kev or score >= 80:
        return "P2", "fix within 7 days"
    if score >= 55:
        return "P3", "fix within 30 days"
    return "P4", "fix within 90 days"