# PatchPilot

Every company has more vulnerabilities than time to fix them. Most teams sort by CVSS score, but a 9.8 that nobody exploits matters less than a 5.5 that ransomware gangs use every day. I wanted to build something that answers the question security teams actually have: *what should we fix first, this week, with the people we have?*

PatchPilot combines live threat data (NVD, EPSS, CISA KEV, OSV.dev) with a company's network and builds a week-by-week fix plan. I tested it on a fictional Dutch logistics company, Waalstad Logistics, with 14 systems and 112 findings using real CVEs.

**[Open the live dashboard](https://gurudarshan25.github.io/patchpilot/)** (updates itself every day)

![Dashboard](docs/dashboard.png)

## Results

Same team (20 hours a week), same findings, different order:

| | Sort by CVSS | PatchPilot (Hybrid) |
|---|---|---|
| Crown jewels unreachable | week 10 | **week 3** |
| All actively exploited bugs fixed | week 11 | **week 5** |
| All ransomware-linked bugs fixed | week 11 | **week 5** |

**Backtest.** I went back to 1 May 2024 and ranked 12,183 vulnerabilities using only data available that day, then checked which ones got exploited in the next year. To catch half of them:

| Ranking | Fixes needed |
|---|---|
| CVSS only | 557 |
| EPSS only | 217 |
| **PatchPilot** | **138** |
| Random | 6,092 |

The formula was picked on 2023 data and tested on 2024, so it wasn't tuned on the data it was judged on.

## What it does

- **Explainable risk score (0-100):** exploitation (KEV, ransomware, EPSS percentile), severity, asset value, exposure, plus a bonus for bugs that open attack paths.
- **Attack-path graph:** finds every route from the internet to the crown jewels and the chokepoints that cut the most routes.
- **Strategy planner:** five strategies scheduled into 20-hour weeks with a risk burn-down.
- **SBOM scanning:** reads a CycloneDX SBOM, finds library vulnerabilities via OSV.dev, and suggests one upgrade per library.
- **Compliance:** deadline forecast, a capacity what-if, Cyber Resilience Act notification drafts and a CycloneDX VEX export.
- **AI analyst (local, qwen2.5:3b via Ollama):** an agent with tools, plus tickets and an executive summary, with guardrails.
- **Daily auto-update:** GitHub Actions refreshes the threat data and the dashboard every morning.

## What I learned

**My first formula was worse than EPSS alone.** The backtest showed it. Raw EPSS values for new bugs are tiny (0.001-0.05), so CVSS × 2 was secretly making every decision. Switching to the EPSS percentile fixed it. Without the backtest I would never have noticed.

**Attack paths change what "urgent" means.** After week 4, some systems still have bugs, but no route from the internet reaches them anymore. You don't have to fix everything to be safe, you have to cut the routes.

**No strategy wins everything.** "Exploited first" clears KEV fastest, "close attack paths first" protects the crown jewels fastest. The Hybrid strategy is near the best on every measure.

**Some problems aren't ordering problems.** Fixing all 27 exploited findings in two weeks needs about 36 hours a week. The team has 20. My first deadline policy was impossible even with 120 hours a week, because 38 findings were labelled P1. Redefining P1 as "exploited and reachable" brought it down to 17.

**Small AI models can't be trusted with facts.** The agent got 3-4 facts wrong per answer (wrong KEV status, wrong totals, "ransomware" on bugs that aren't). Each time I added a check, it found another way to be wrong, including dropping CVE IDs so nothing could be checked. What worked: **code writes the facts, the AI only writes the words**, with guardrails that check every number exists in the facts. That produced 10 out of 10 clean documents.

## Limitations

- The company is fictional and the scan is enriched with well-known exploited bugs, so it has more KEV findings than a typical company.
- Fix-effort hours are estimates.
- The backtest test window has only 12 later-exploited bugs, so numbers can move a few percent.
- The guardrails check that numbers exist in the facts, not that each number is used for the right claim. A human should review anything sent to management.
- The daily update refreshes threat data and scores; the AI-written tickets are regenerated only when I run `reports.py` locally.

## Running it

Python 3.10+. The AI parts need [Ollama](https://ollama.com) with `qwen2.5:3b`.

```bash
python -m venv venv
venv\Scripts\activate
pip install -r requirements.txt
python update_all.py      # threat data -> scores -> plan -> compliance -> dashboard
python reports.py         # AI tickets + executive summary (needs Ollama)
python agent.py           # ask questions (needs Ollama)
python backtest.py        # time-travel backtest (downloads a lot, cached)
```

## Files

| File | What it does |
|---|---|
| `assets.json`, `findings.json` | The company: systems, network links, scanner findings |
| `expand_findings.py` | Adds realistic background findings from NVD |
| `fetch_all.py` | NVD + EPSS + KEV data for every CVE |
| `scoring.py` | The risk score and priority rules |
| `attack_graph.py` | Attack paths and chokepoints |
| `prioritize_paths.py` | Scores and ranks every finding |
| `backtest.py` | Time-travel backtest with a train/test split |
| `planner.py` | Strategies, weekly plans, burn-down |
| `sbom.json`, `sbom_scan.py` | SBOM scanning with OSV.dev |
| `compliance.py` | Deadlines, CRA drafts, VEX, capacity what-if |
| `agent.py` | AI agent with tools and fact-checking |
| `reports.py` | AI tickets + executive summary with guardrails |
| `make_dashboard.py` | Builds the dashboard |
| `update_all.py` | Runs the daily pipeline |

---

Gurudharshan Nagarle Lokesh, MSc Computing Science (Cybersecurity and AI), Radboud University
[LinkedIn](https://www.linkedin.com/in/guru-dharshan-0092a3266)