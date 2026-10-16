import json
import os
import time
import requests
from cvss import CVSS3, CVSS4
from packaging.version import Version, InvalidVersion
from scoring import score_finding, priority

ASSET_ID = "app-01"   # the order service runs on this system
OSV_CACHE = "osv_cache.json"
ECOSYSTEMS = {"pypi": "PyPI", "maven": "Maven", "npm": "npm"}


def get_json(url, params=None, tries=6):
    for attempt in range(tries):
        try:
            r = requests.get(url, params=params, timeout=60)
            if r.status_code == 200:
                return r.json()
            print(f"   server said {r.status_code}, retrying...")
        except requests.exceptions.RequestException as e:
            print(f"   connection problem ({type(e).__name__}), retrying...")
        time.sleep(5 * (attempt + 1))
    raise RuntimeError(f"Could not download {url}")

def parse_purl(purl):
    """pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1 -> ('Maven', 'org.apache.logging.log4j:log4j-core')"""
    kind, rest = purl[4:].split("/", 1)
    name = rest.split("@")[0]
    if kind == "maven":
        name = name.replace("/", ":")
    return ECOSYSTEMS[kind], name


def ver(v):
    try:
        return Version(v)
    except InvalidVersion:
        return None


# ---------- 1. Read the SBOM ----------
with open("sbom.json", "r", encoding="utf-8") as f:
    sbom = json.load(f)
app = sbom["metadata"]["component"]
components = []
for c in sbom["components"]:
    eco, name = parse_purl(c["purl"])
    components.append({"name": name, "short": c["name"], "version": c["version"], "ecosystem": eco})
print(f"SBOM: {app['name']} {app['version']} with {len(components)} components")

# ---------- 2. Ask OSV.dev which vulnerabilities affect each component (ONE batch request) ----------
queries = [{"package": {"name": c["name"], "ecosystem": c["ecosystem"]}, "version": c["version"]} for c in components]
batch = requests.post("https://api.osv.dev/v1/querybatch", json={"queries": queries}, timeout=60).json()
for c, result in zip(components, batch["results"]):
    c["osv_ids"] = [v["id"] for v in result.get("vulns", [])]
print(f"OSV found {sum(len(c['osv_ids']) for c in components)} advisories")

# ---------- 3. Download the details of each advisory (cached) ----------
cache = {}
if os.path.exists(OSV_CACHE):
    with open(OSV_CACHE, "r", encoding="utf-8") as f:
        cache = json.load(f)
all_ids = sorted({i for c in components for i in c["osv_ids"]})
missing = [i for i in all_ids if i not in cache]
for n, vid in enumerate(missing, start=1):
    cache[vid] = get_json(f"https://api.osv.dev/v1/vulns/{vid}")
    if n % 20 == 0:
        print(f"   details {n}/{len(missing)}")
        with open(OSV_CACHE, "w", encoding="utf-8") as f:
            json.dump(cache, f)   # save progress every 20, so a crash never loses much
    time.sleep(0.1)
with open(OSV_CACHE, "w", encoding="utf-8") as f:
    json.dump(cache, f)


def cvss_from(vuln):
    for s in vuln.get("severity", []):
        try:
            if s["type"] == "CVSS_V3":
                return float(CVSS3(s["score"]).base_score), s["score"]
            if s["type"] == "CVSS_V4":
                return float(CVSS4(s["score"]).base_score), s["score"]
        except Exception:
            pass
    return None, ""


def needed_fix(vuln, comp):
    """Smallest fixed version that is newer than the installed version."""
    installed = ver(comp["version"])
    fixes = []
    for a in vuln.get("affected", []):
        pkg = a.get("package", {})
        if pkg.get("name", "").lower() != comp["name"].lower():
            continue
        for rng in a.get("ranges", []):
            for event in rng.get("events", []):
                v = ver(event.get("fixed", ""))
                if v and installed and v > installed:
                    fixes.append(v)
    return min(fixes) if fixes else None


# ---------- 4. One finding per (component, vulnerability), merging duplicate advisories ----------
findings = []
for c in components:
    seen = set()
    for vid in c["osv_ids"]:
        v = cache[vid]
        cves = [a for a in v.get("aliases", []) + [vid] if a.startswith("CVE-")]
        ident = cves[0] if cves else vid
        if ident in seen:
            continue  # same vulnerability published by two databases (e.g. GHSA + PYSEC)
        seen.add(ident)
        score, vector = cvss_from(v)
        findings.append({
            "component": c["short"], "ecosystem": c["ecosystem"], "installed": c["version"],
            "id": ident, "osv_id": vid, "summary": v.get("summary", "")[:120],
            "cvss": score, "attack_vector": "NETWORK" if "AV:N" in vector else ("LOCAL" if "AV:L" in vector else None),
            "fixed_in": str(needed_fix(v, c) or ""),
        })

# ---------- 5. Enrich with EPSS + KEV, then score with PatchPilot's brain ----------
cve_ids = sorted({f["id"] for f in findings if f["id"].startswith("CVE-")})
epss = {}
for i in range(0, len(cve_ids), 50):
    rows = get_json("https://api.first.org/data/v1/epss", {"cve": ",".join(cve_ids[i:i + 50]), "limit": 100})["data"]
    epss.update({r["cve"]: r for r in rows})
kev = {v["cveID"]: v for v in get_json(
    "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json")["vulnerabilities"]}

with open("assets.json", "r", encoding="utf-8") as f:
    asset = next(a for a in json.load(f) if a["id"] == ASSET_ID)

for f in findings:
    k = kev.get(f["id"])
    e = epss.get(f["id"], {})
    intel = {"in_kev": k is not None, "ransomware": bool(k and k["knownRansomwareCampaignUse"] == "Known"),
             "epss": float(e.get("epss", 0)), "epss_percentile": float(e.get("percentile", 0)),
             "cvss": f["cvss"], "attack_vector": f["attack_vector"]}
    total, breakdown = score_finding(f, asset, intel)
    f.update({"in_kev": intel["in_kev"], "ransomware": intel["ransomware"], "epss": intel["epss"],
                           "score": total, "priority": priority(total, intel["in_kev"])[0], "breakdown": breakdown})
findings.sort(key=lambda f: -f["score"])

# ---------- 6. Upgrade advisor: which upgrades fix the most? ----------
advice = []
for c in components:
    mine = [f for f in findings if f["component"] == c["short"]]
    if not mine:
        continue
    targets = [ver(f["fixed_in"]) for f in mine if f["fixed_in"]]
    advice.append({
        "component": c["short"], "ecosystem": c["ecosystem"], "installed": c["version"],
        "upgrade_to": str(max(targets)) if targets else "no fix listed",
        "fixes": len(mine), "kev": sum(f["in_kev"] for f in mine),
        "max_score": max(f["score"] for f in mine), "risk_total": round(sum(f["score"] for f in mine), 1),
    })
advice.sort(key=lambda a: (-a["kev"], -a["max_score"], -a["risk_total"]))

# ---------- 7. Report ----------
print()
print(f"=== SBOM REPORT: {app['name']} {app['version']} (runs on {ASSET_ID}) ===")
print(f"Components: {len(components)}   vulnerable: {len(advice)}   unique vulnerabilities: {len(findings)}")
print(f"Actively exploited (KEV): {sum(f['in_kev'] for f in findings)}   "
      f"P1: {sum(f['priority'] == 'P1' for f in findings)}   P2: {sum(f['priority'] == 'P2' for f in findings)}")
print()
print("=== UPGRADE ADVISOR (do these, in this order) ===")
print(f"{'Component':18} {'Eco':6} {'Installed':>10} -> {'Upgrade to':12} {'Fixes':>5} {'KEV':>4} {'Top score':>9}")
for a in advice:
    print(f"{a['component']:18} {a['ecosystem']:6} {a['installed']:>10} -> {a['upgrade_to']:12} "
          f"{a['fixes']:5} {a['kev']:4} {a['max_score']:9.1f}")
print()
print("=== TOP 10 VULNERABILITIES ===")
for f in findings[:10]:
    print(f"{f['priority']} {f['score']:5.1f}  {f['component']:16} {f['id']:20} CVSS {f['cvss'] or '-':>4}  "
          f"{'KEV ' if f['in_kev'] else ''}{f['summary'][:60]}")

with open("sbom_report.json", "w", encoding="utf-8") as fh:
    json.dump({"application": app, "asset": ASSET_ID, "components": len(components),
               "advice": advice, "findings": findings}, fh, indent=2)
print()
print("Saved to sbom_report.json")