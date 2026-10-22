#!/usr/bin/env python3
"""Fail-closed source policy for the public release workflow."""
from pathlib import Path
import re

root = Path(__file__).resolve().parents[1]
workflow = (root / ".github/workflows/release-packages.yml").read_text()
def check(cond, message):
    if not cond:
        raise SystemExit("RELEASE POLICY BLOCK: " + message)

check("  push:\n    tags:" in workflow, "tag push must start release build")
check("  workflow_dispatch:" not in workflow, "manual rebuild trigger forbidden")
check("types: [published]" not in workflow, "published-release trigger too late")
check(bool(re.search(r'^\s+toolchain:\s*"?\d+\.\d+\.\d+"?\s*$', workflow, re.M)), "pin exact Rust version")
check("gh release create \"$TAG\"" in workflow and "--draft" in workflow, "draft before publish")
check("gh release upload \"$TAG\" dist/*" in workflow, "expected upload")
check(not re.search(r'^\s*gh release upload[^\n]*--clobber', workflow, re.M), "no clobber")
check('gh release edit "$TAG"' in workflow and "--draft=false" in workflow, "publish verified draft")
check('uploaded[name].get("digest")' in workflow, "verify remote SHA256 digests")
check('"isDraft,assets"' in workflow and '["gh", "release", "view"' in workflow,
      "draft-aware asset inspection; REST by-tag omits drafts")
check("Remote tag moved after validation" in workflow and "Remote tag changed before publication" in workflow,
      "compare peeled remote tag with pinned verified commit before draft and publish")
check('".immutable"' in workflow or ".immutable)" in workflow or "--jq .immutable" in workflow, "check immutable")
check("Already published; refusing replacement" in workflow, "refuse published tag")
check("Historical tag: refuse rebuild" in workflow, "no historical rebuilds")
check("Expected eight immutable release assets" in workflow, "final asset count")
print("PUBLIC_RELEASE_POLICY_PASS")
