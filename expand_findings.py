import json
import os
import random
import time
import requests

random.seed(42)  # same "random" picks every time, so results are repeatable

# Which software runs on which system (the keyword we search NVD for)
SOFTWARE = {
    "fw-edge":      ["PAN-OS"],
    "vpn-gw":       ["NetScaler"],
    "web-shop":     ["Apache HTTP Server", "Spring Framework"],
    "mail-01":      ["Microsoft Exchange"],
    "app-01":       ["Apache Tomcat", "curl"],
    "mq-01":        ["ActiveMQ"],
    "db-customers": ["PostgreSQL", "OpenSSL"],
    "dc-01":        ["Windows Server"],
    "backup-01":    ["Linux kernel"],
    "wiki":         ["Confluence"],
    "laptop-fleet": ["Google Chrome", "Microsoft Office"],
    "dev-server":   ["Linux kernel", "Python"],
}
PER_SOFTWARE = 6                      # max extra findings per software
WINDOW = ("2024-01-01T00:00:00.000", "2024-04-29T23:59:59.999")  # NVD allows max 120 days

with open("findings.json", "r", encoding="utf-8") as f:
    base = json.load(f)

nvd_cache = {}
if os.path.exists("nvd_cache.json"):
    with open("nvd_cache.json", "r", encoding="utf-8") as f:
        nvd_cache = json.load(f)


def has_score(cve):
    m = cve.get("metrics", {})
    return any(v in m for v in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"])


search_cache = {}
extra = []
existing = {(f["asset"], f["cve"]) for f in base}

for asset, keywords in SOFTWARE.items():
    for keyword in keywords:
        if keyword not in search_cache:
            print(f"Searching NVD for '{keyword}'...")
            params = {"keywordSearch": keyword, "pubStartDate": WINDOW[0], "pubEndDate": WINDOW[1], "resultsPerPage": 2000}
            for attempt in range(4):
                r = requests.get("https://services.nvd.nist.gov/rest/json/cves/2.0", params=params, timeout=120)
                if r.status_code == 200:
                    break
                print(f"   server said {r.status_code}, waiting...")
                time.sleep(10 * (attempt + 1))
            results = [v["cve"] for v in r.json().get("vulnerabilities", [])]
            search_cache[keyword] = [c for c in results if has_score(c) and c.get("vulnStatus") != "Rejected"]
            print(f"   found {len(search_cache[keyword])} usable CVEs")
            time.sleep(6)

        pool = search_cache[keyword]
        for cve in random.sample(pool, min(PER_SOFTWARE, len(pool))):
            if (asset, cve["id"]) in existing:
                continue
            existing.add((asset, cve["id"]))
            nvd_cache[cve["id"]] = cve  # save the details so fetch_all.py doesn't download them again
            extra.append({
                "asset": asset,
                "cve": cve["id"],
                "software": keyword,
                "fix": "Apply vendor update",
                "fix_hours": random.choice([1, 1, 2, 2, 3]),
                "source": "background",
            })

for f in base:
    f["source"] = "headline"

with open("findings_all.json", "w", encoding="utf-8") as f:
    json.dump(base + extra, f, indent=2)
with open("nvd_cache.json", "w", encoding="utf-8") as f:
    json.dump(nvd_cache, f)

print()
print(f"Original findings:   {len(base)}")
print(f"Background findings: {len(extra)}")
print(f"Total:               {len(base) + len(extra)} -> saved to findings_all.json")