import json
import math
import os
import random
import time
import requests

WINDOWS = [
    {"name": "2023 (tuning)", "cutoff": "2023-05-01", "horizon": "2024-05-01",
     "pub": ("2023-01-01T00:00:00.000", "2023-04-30T23:59:59.999")},
    {"name": "2024 (test)", "cutoff": "2024-05-01", "horizon": "2025-05-01",
     "pub": ("2024-01-01T00:00:00.000", "2024-04-29T23:59:59.999")},
]


def get_json(url, params=None, tries=5):
    for attempt in range(tries):
        r = requests.get(url, params=params, timeout=180)
        if r.status_code == 200:
            return r.json()
        wait = 10 * (attempt + 1)
        print(f"   server said {r.status_code}, waiting {wait}s...")
        time.sleep(wait)
    raise RuntimeError(f"Could not download {url}")


def cvss_info(cve):
    metrics = cve.get("metrics", {})
    for version in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV40", "cvssMetricV2"]:
        if version in metrics:
            data = metrics[version][0]["cvssData"]
            return data["baseScore"], data.get("attackVector") or data.get("accessVector")
    return None, None


def load_nvd(window):
    path = f"backtest_nvd_{window['cutoff']}.json"
    if os.path.exists(path):
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    pool, start = [], 0
    while True:
        params = {"pubStartDate": window["pub"][0], "pubEndDate": window["pub"][1],
                  "resultsPerPage": 2000, "startIndex": start}
        data = get_json("https://services.nvd.nist.gov/rest/json/cves/2.0", params)
        for v in data["vulnerabilities"]:
            c = v["cve"]
            if c.get("vulnStatus") == "Rejected":
                continue
            score, vector = cvss_info(c)
            if score is not None:
                pool.append({"cve": c["id"], "cvss": score, "attack_vector": vector})
        start += data["resultsPerPage"]
        print(f"   NVD: {min(start, data['totalResults'])}/{data['totalResults']}")
        if start >= data["totalResults"]:
            break
        time.sleep(6)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(pool, f)
    return pool


def load_epss(window, cves):
    """EPSS score AND percentile as they were on the cutoff date."""
    path = f"backtest_epss_{window['cutoff']}.json"
    cache = {}
    if os.path.exists(path):
        with open(path, "r", encoding="utf-8") as f:
            cache = json.load(f)
    missing = [c for c in cves if c not in cache]
    print(f"   EPSS on {window['cutoff']}: {len(missing)} to download")
    for i in range(0, len(missing), 100):
        chunk = missing[i:i + 100]
        rows = get_json("https://api.first.org/data/v1/epss",
                        {"cve": ",".join(chunk), "date": window["cutoff"], "limit": 100})["data"]
        found = {r["cve"]: [float(r["epss"]), float(r["percentile"])] for r in rows}
        for c in chunk:
            cache[c] = found.get(c, [0.0, 0.0])
        if (i // 100) % 10 == 0:
            print(f"      {min(i + 100, len(missing))}/{len(missing)}")
            with open(path, "w", encoding="utf-8") as f:
                json.dump(cache, f)
        time.sleep(0.5)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(cache, f)
    return cache


def exposure(r):
    return 7 if r["attack_vector"] in ("NETWORK", "ADJACENT_NETWORK") else 3


METHODS = {
    "CVSS only": lambda r: r["cvss"],
    "EPSS only": lambda r: r["epss"],
    "PP v1 raw EPSS": lambda r: r["epss"] * 35 + r["cvss"] * 2 + exposure(r),
    "PP v2 percentile": lambda r: r["pct"] * 35 + r["cvss"] * 2 + exposure(r),
    "PP v3 percentile^2": lambda r: r["pct"] ** 2 * 35 + r["cvss"] * 2 + exposure(r),
}
CANDIDATES = ["PP v1 raw EPSS", "PP v2 percentile", "PP v3 percentile^2"]

print("Downloading CISA KEV...")
kev = get_json("https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json")["vulnerabilities"]
kev_date = {v["cveID"]: v["dateAdded"] for v in kev}

all_results = {}
chosen = None

for window in WINDOWS:
    print()
    print(f"========== {window['name'].upper()}: time machine set to {window['cutoff']} ==========")
    pool = load_nvd(window)
    epss = load_epss(window, [r["cve"] for r in pool])

    pool = [dict(r) for r in pool if not (r["cve"] in kev_date and kev_date[r["cve"]] < window["cutoff"])]
    for r in pool:
        r["epss"], r["pct"] = epss.get(r["cve"], [0.0, 0.0])
        d = kev_date.get(r["cve"])
        r["later"] = d is not None and window["cutoff"] <= d < window["horizon"]
    positives = sum(r["later"] for r in pool)
    print(f"Candidates: {len(pool)}   exploited in the next 12 months: {positives}")

    random.seed(42)
    random.shuffle(pool)  # fair tie-breaking

    results = {}
    print(f"{'Ranking':20} {'top 1%':>8} {'top 5%':>8} {'top 10%':>8} {'fixes to catch half':>20}")
    for name, fn in METHODS.items():
        order = sorted(pool, key=lambda r: -fn(r))
        tops = []
        for pct in (1, 5, 10):
            n = math.ceil(len(order) * pct / 100)
            tops.append(sum(r["later"] for r in order[:n]) / positives * 100 if positives else 0)
        needed, found, half = math.ceil(positives / 2), 0, len(order)
        for i, r in enumerate(order, start=1):
            found += r["later"]
            if found >= needed:
                half = i
                break
        results[name] = {"top1": tops[0], "top5": tops[1], "top10": tops[2], "fixes_to_half": half}
        print(f"{name:20} {tops[0]:7.0f}% {tops[1]:7.0f}% {tops[2]:7.0f}% {half:20}")
    print(f"{'Random guess':20} {1:7.0f}% {5:7.0f}% {10:7.0f}% {round(len(pool) / 2):20}")

    if chosen is None:  # pick the winner on the TUNING window only, by a fixed rule
        chosen = min(CANDIDATES, key=lambda m: results[m]["fixes_to_half"])
        print(f"-> Chosen on tuning data (fewest fixes to catch half): {chosen}")
    else:
        r = results[chosen]
        print(f"-> Test check for '{chosen}': {r['fixes_to_half']} fixes to catch half "
              f"(EPSS only: {results['EPSS only']['fixes_to_half']}, CVSS only: {results['CVSS only']['fixes_to_half']})")

    all_results[window["name"]] = {"cutoff": window["cutoff"], "candidates": len(pool),
                                   "exploited_later": positives, "results": results}

with open("backtest_results.json", "w", encoding="utf-8") as f:
    json.dump({"chosen": chosen, "windows": all_results}, f, indent=2)
print()
print("Saved to backtest_results.json")