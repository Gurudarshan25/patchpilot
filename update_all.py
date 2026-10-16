"""Run the whole PatchPilot pipeline. Used daily by GitHub Actions (no AI needed: tickets are reused)."""
import shutil
import subprocess
import sys

STEPS = ["fetch_all.py", "sbom_scan.py", "prioritize_paths.py", "planner.py", "compliance.py", "make_dashboard.py"]

for step in STEPS:
    print(f"===== running {step} =====", flush=True)
    result = subprocess.run([sys.executable, step])
    if result.returncode != 0:
        sys.exit(f"{step} failed, stopping")

shutil.copy("dashboard.html", "index.html")  # so the site's main address opens the dashboard
print("All steps done. index.html updated.")