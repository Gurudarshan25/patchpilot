import requests

CVE_ID = "CVE-2019-0708"
# ---------- 1. NVD: description + CVSS severity score ----------
nvd_url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={CVE_ID}"
nvd = requests.get(nvd_url, timeout=30).json()
cve = nvd["vulnerabilities"][0]["cve"]

description = next(d["value"] for d in cve["descriptions"] if d["lang"] == "en")

metrics = cve.get("metrics", {})
cvss = None
for version in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
    if version in metrics:
        cvss = metrics[version][0]["cvssData"]["baseScore"]
        break

# ---------- 2. EPSS: chance of being exploited in the next 30 days ----------
epss_url = f"https://api.first.org/data/v1/epss?cve={CVE_ID}"
epss_data = requests.get(epss_url, timeout=30).json()["data"]
epss = float(epss_data[0]["epss"]) if epss_data else 0.0

# ---------- 3. CISA KEV: is it confirmed exploited in real attacks? ----------
kev_url = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
kev = requests.get(kev_url, timeout=60).json()
kev_entry = next((v for v in kev["vulnerabilities"] if v["cveID"] == CVE_ID), None)

# ---------- Print what we found ----------
print("CVE:         ", CVE_ID)
print("Description: ", description[:200], "...")
print("CVSS score:  ", cvss, "/ 10")
print(f"EPSS:         {epss * 100:.1f}% chance of exploitation in the next 30 days")
print("In CISA KEV: ", "YES - actively exploited" if kev_entry else "no")
if kev_entry:
    print("   Added to KEV:", kev_entry["dateAdded"])
    print("   Used by ransomware:", kev_entry["knownRansomwareCampaignUse"])
print()
print(f"KEV catalog contains {len(kev['vulnerabilities'])} known exploited vulnerabilities in total")