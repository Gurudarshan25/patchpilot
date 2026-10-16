import json

with open("assets.json", "r", encoding="utf-8") as f:
    assets = json.load(f)
with open("findings.json", "r", encoding="utf-8") as f:
    findings = json.load(f)

# Turn the asset list into a dictionary so we can look up an asset by its id
assets_by_id = {a["id"]: a for a in assets}

print("=== WAALSTAD LOGISTICS ===")
print(f"Assets:   {len(assets)}")
print(f"Findings: {len(findings)} ({len(set(f['cve'] for f in findings))} unique CVEs)")
print(f"Total fix effort: {sum(f['fix_hours'] for f in findings)} hours (team has 20 hours/week)")
print()

print("Internet-facing:", ", ".join(a["id"] for a in assets if a["internet_facing"]))
print("Crown jewels:   ", ", ".join(a["id"] for a in assets if a["crown_jewel"]))
print()

print("=== FINDINGS PER ASSET ===")
for asset in assets:
    asset_findings = [f for f in findings if f["asset"] == asset["id"]]
    flag = " [INTERNET]" if asset["internet_facing"] else ""
    flag += " [CROWN JEWEL]" if asset["crown_jewel"] else ""
    print(f"{asset['id']:13} criticality {asset['criticality']}  {len(asset_findings)} findings{flag}")

# Safety check: every finding must point to an asset that exists
unknown = [f for f in findings if f["asset"] not in assets_by_id]
if unknown:
    print()
    print("WARNING: findings for unknown assets:", unknown)