"""PatchPilot attack graph: how could an attacker hop from the internet to the crown jewels?"""
import json
import networkx as nx

LIKELY_EPSS = 0.10  # EPSS of 10% or more counts as "likely to be used"


def load():
    with open("assets.json", "r", encoding="utf-8") as f:
        assets = {a["id"]: a for a in json.load(f)}
    with open("findings_all.json", "r", encoding="utf-8") as f:
        findings = json.load(f)
    with open("threat_intel.json", "r", encoding="utf-8") as f:
        intel = json.load(f)
    return assets, findings, intel


def key(finding):
    return finding["asset"] + "|" + finding["cve"]


def build_graph(assets):
    """Dots = systems (+ 'internet'), arrows = who can reach whom."""
    G = nx.DiGraph()
    G.add_node("internet")
    for a in assets.values():
        G.add_node(a["id"])
        if a["internet_facing"]:
            G.add_edge("internet", a["id"])
        for target in a["connects_to"]:
            G.add_edge(a["id"], target)
    return G


def is_enabling(finding, asset, intel):
    """Can an attacker use this bug to break INTO this system?"""
    i = intel[finding["cve"]]
    likely = i["in_kev"] or i["epss"] >= LIKELY_EPSS
    remote = i["attack_vector"] in ("NETWORK", "ADJACENT_NETWORK")
    phishing = asset["type"] == "endpoint" and i["in_kev"]  # user clicks something
    return likely and (remote or phishing)


def breakable(assets, findings, intel, fixed=frozenset()):
    """Systems with at least one enabling bug that is NOT fixed yet."""
    return {f["asset"] for f in findings
            if key(f) not in fixed and is_enabling(f, assets[f["asset"]], intel)}


def open_paths(G, assets, broken):
    """All routes from the internet to a crown jewel where every hop in between is breakable."""
    paths = []
    for target, a in assets.items():
        if not a["crown_jewel"]:
            continue
        for path in nx.all_simple_paths(G, "internet", target, cutoff=7):
            if all(node in broken for node in path[1:-1]):
                paths.append(path)
    return paths


def chokepoints(paths):
    """How many open paths go through each system (not counting start and target)."""
    counts = {}
    for p in paths:
        for node in p[1:-1]:
            counts[node] = counts.get(node, 0) + 1
    return counts


# This part only runs when you start THIS file directly (python attack_graph.py),
# not when another script imports the functions above.
if __name__ == "__main__":
    assets, findings, intel = load()
    G = build_graph(assets)
    broken = breakable(assets, findings, intel)
    paths = open_paths(G, assets, broken)
    counts = chokepoints(paths)

    print("=== ATTACK GRAPH ===")
    print(f"Systems: {len(assets)}   Network connections: {G.number_of_edges()}")
    print(f"Breakable systems ({len(broken)}): {', '.join(sorted(broken))}")
    print()

    print("=== OPEN ATTACK PATHS TO CROWN JEWELS ===")
    for target in [t for t, a in assets.items() if a["crown_jewel"]]:
        n = sum(1 for p in paths if p[-1] == target)
        print(f"{target:13} {n} open paths")
    print(f"Total: {len(paths)}")
    print()

    print("Shortest paths:")
    for p in sorted(paths, key=len)[:8]:
        print("  " + " -> ".join(p))
    print()

    print("=== CHOKEPOINTS (systems most attack paths go through) ===")
    for node, n in sorted(counts.items(), key=lambda x: -x[1]):
        enabling = [f["cve"] for f in findings if f["asset"] == node and is_enabling(f, assets[node], intel)]
        print(f"{node:13} on {n:3} paths   bugs that open it: {', '.join(enabling)}")

    if counts:
        top = max(counts, key=counts.get)
        fix_keys = {key(f) for f in findings if f["asset"] == top}
        after = open_paths(G, assets, breakable(assets, findings, intel, fixed=fix_keys))
        print()
        print(f"What if we fix the enabling bugs on '{top}'? Open paths: {len(paths)} -> {len(after)}")

    with open("attack_paths.json", "w", encoding="utf-8") as f:
        json.dump({"paths": paths, "chokepoints": counts}, f, indent=2)
    print("Saved to attack_paths.json")