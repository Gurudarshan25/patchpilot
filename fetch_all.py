import json
import os
import time
import requests

NVD_CACHE = "nvd_cache.json"
OUTPUT = "threat_intel.json"

with open("findings_all.json", "r", encoding="utf-8") as f:
    findings = json.load(f)
cves = sorted(set(f["cve"] for f in findings))
print(f"{len(cves)} unique CVEs to look up")


def get_json(url, tries=4):
    """Download JSON, waiting and retrying if the server says 'too many requests'."""
    for attempt in range(tries):
        response = requests.get(url, timeout=60)
        if response.status_code == 200:
            return response.json()
        wait = 10 * (attempt + 1)
        print(f"   server said {response.status_code}, waiting {wait}s and trying again...")
        time.sleep(wait)
    raise RuntimeError(f"Could not download {url}")


# ---------- 1. NVD (one request per CVE, cached so we never download twice) ----------
nvd_cache = {}
if os.path.exists(NVD_CACHE):
    with open(NVD_CACHE, "r", encoding="utf-8") as f:
        nvd_cache = json.load(f)

missing = [c for c in cves if c not in nvd_cache]
print(f"{len(cves) - len(missing)} already cached, {len(missing)} to download from NVD")
for i, cve_id in enumerate(missing, start=1):
    print(f"[{i}/{len(missing)}] {cve_id}: downloading from NVD...")
    data = get_json(f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}")
    nvd_cache[cve_id] = data["vulnerabilities"][0]["cve"]
    with open(NVD_CACHE, "w", encoding="utf-8") as f:
        json.dump(nvd_cache, f)
    time.sleep(6)  # stay under NVD's rate limit

# ---------- 2. EPSS (batches of 50 CVEs per request) ----------
print("Downloading EPSS scores...")
epss = {}
for start in range(0, len(cves), 50):
    chunk = cves[start:start + 50]
    rows = get_json("https://api.first.org/data/v1/epss?limit=100&cve=" + ",".join(chunk))["data"]
    epss.update({row["cve"]: row for row in rows})

# ---------- 3. CISA KEV (one download for the whole list) ----------
print("Downloading CISA KEV catalog...")
kev_list = get_json("https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json")
kev = {v["cveID"]: v for v in kev_list["vulnerabilities"]}


# ---------- 4. Combine everything into one clean record per CVE ----------
def cvss_info(cve):
    metrics = cve.get("metrics", {})
    for version in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
        if version in metrics:
            data = metrics[version][0]["cvssData"]
            vector = data.get("attackVector") or data.get("accessVector")
            return data["baseScore"], vector
    return None, None


intel = {}
for cve_id in cves:
    cve = nvd_cache[cve_id]
    score, attack_vector = cvss_info(cve)
    weaknesses = cve.get("weaknesses", [])
    cwe = weaknesses[0]["description"][0]["value"] if weaknesses else None
    k = kev.get(cve_id)

    intel[cve_id] = {
        "description": next(d["value"] for d in cve["descriptions"] if d["lang"] == "en"),
        "published": cve.get("published", "")[:10],
        "cvss": score,
        "attack_vector": attack_vector,
        "cwe": cwe,
        "epss": float(epss[cve_id]["epss"]) if cve_id in epss else 0.0,
        "epss_percentile": float(epss[cve_id]["percentile"]) if cve_id in epss else 0.0,
        "in_kev": k is not None,
        "kev_date_added": k["dateAdded"] if k else None,
        "ransomware": k["knownRansomwareCampaignUse"] == "Known" if k else False,
    }

with open(OUTPUT, "w", encoding="utf-8") as f:
    json.dump(intel, f, indent=2)


# ---------- 5. Summary ----------
in_kev = [c for c in cves if intel[c]["in_kev"]]
high_cvss = [c for c in cves if (intel[c]["cvss"] or 0) >= 9]
scary_but_quiet = [c for c in high_cvss if intel[c]["epss"] < 0.10 and not intel[c]["in_kev"]]
low_but_exploited = [c for c in in_kev if (intel[c]["cvss"] or 0) < 7]

print()
print("=== THREAT INTEL SUMMARY ===")
print(f"Unique CVEs:                          {len(cves)}")
print(f"Actively exploited (in KEV):          {len(in_kev)} ({len(in_kev) / len(cves) * 100:.0f}%)")
print(f"EPSS above 10%:                       {sum(1 for c in cves if intel[c]['epss'] >= 0.10)}")
print(f"CVSS 9 or higher:                     {len(high_cvss)}")
print(f"  ...of which scary but quiet:        {len(scary_but_quiet)}  (CVSS 9+, EPSS under 10%, not in KEV)")
print(f"Exploited but CVSS under 7:           {len(low_but_exploited)}  -> {', '.join(low_but_exploited) or 'none'}")
print(f"Saved to {OUTPUT}")