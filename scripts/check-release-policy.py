#!/usr/bin/env python3
"""Check hosted runner routing and release safety on SRV."""
from pathlib import Path
import re
import subprocess
import sys
import yaml

root = Path(__file__).resolve().parents[1]
workflows = root / ".github/workflows"
def require(ok, reason):
    if not ok:
        raise SystemExit("RELEASE POLICY BLOCK: " + reason)


def check_workflow(path):
    data = yaml.load(path.read_text(), Loader=yaml.BaseLoader)
    require(data["permissions"] == {"contents": "read"}, "workflows must have read-only contents")
    require(len(data["jobs"]) == 1, "expected exactly one macOS job per workflow")
    job, = data["jobs"].values()
    require(job.get("runs-on") == "macos-15" and "strategy" not in job and "permissions" not in job,
            "expected a single Apple Silicon runner with inherited permissions")
    for step in job["steps"]:
        if "uses" in step:
            require(re.fullmatch(r"[\w.-]+/[\w.-]+@[a-f0-9]{40}", step["uses"]), "pin each external action by SHA")
    if path.name == "release-packages.yml":
        require(data["on"] == {"push": {"tags": ["v[0-9]*"]}}, "stable tag trigger required")
        require(any(s.get("uses", "").startswith("actions/upload-artifact@") for s in job["steps"]), "missing macOS artifact")
        require(any(s.get("with", {}).get("toolchain") == "1.100.0" for s in job["steps"]), "versioned release toolchain required")
    else:
        require(set(data["on"]) == {"push", "pull_request"}, "public CI triggers differ")


require({p.name for p in workflows.iterdir()} == {"ci.yml","release-packages.yml"}, "unexpected public workflow")
for path in sorted(workflows.iterdir()):
    check_workflow(path)
subprocess.run([sys.executable, "-B", str(root / "scripts/test-release-publication.py")], check=True)
print("PUBLIC_RELEASE_POLICY_PASS")
