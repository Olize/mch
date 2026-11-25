#!/usr/bin/env python3
"""Verify a local MCH bundle and seal an explicitly authorized public release."""
import argparse
import gzip
import hashlib
import http.client
import json
import os
from pathlib import Path
import re
import runpy
import subprocess
import tarfile
import urllib.parse
import zipfile

pkg = runpy.run_path(str(Path(__file__).with_name("package-on-srv.py")))
require = pkg["require"]
git = pkg["git"]
API_REPO = "/repos/Olize/mch"


def check_bundle(repo, dist, inputs, rehearsal):
    commit = git(repo, "rev-parse", "HEAD").decode().strip()
    version = pkg["release_version"](repo, commit)
    pattern = r"\d+\.\d+\.\d+-rc\.\d+" if rehearsal else r"\d+\.\d+\.\d+"
    require(re.fullmatch(pattern, version), "invalid release version for this mode")
    tag = "v" + version
    require(git(repo, "remote", "get-url", "origin").decode().strip() in
            ("https://github.com/Olize/mch.git", "git@github.com:Olize/mch.git"), "public origin required")
    manifest = json.loads((inputs / "binaries.json").read_text())
    if not rehearsal:
        require(tuple(map(int, version.split("."))) >= (0, 2, 3), "historical tag refused")
        require(manifest["commit"] == commit, "stable bundle requires the public producer SHA")
        require(git(repo, "rev-parse", f"refs/tags/{tag}^{{commit}}").decode().strip() == commit, "wrong tag")
        subprocess.run(["git", "-C", repo, "merge-base", "--is-ancestor", commit, "origin/main"], check=True)
    expected = {}
    for platform, target in pkg["PLATFORMS"].items():
        root = f"mch-{tag}-{platform}"
        windows = platform == "windows-x86_64"
        name = "mch.exe" if windows else "mch"
        archive = dist / (root + (".zip" if windows else ".tar.gz"))
        wanted = {root + "/" + x for x in (name, "BUILD-INFO.txt", "LICENSE", "README.md")}
        if windows:
            with zipfile.ZipFile(archive) as z:
                require(len(z.namelist()) == 4 and set(z.namelist()) == wanted and z.testzip() is None, "invalid Windows ZIP")
                data = {key: z.read(root + "/" + key) for key in (name, "BUILD-INFO.txt", "LICENSE", "README.md")}
        else:
            with tarfile.open(archive, "r:gz") as t:
                members = t.getmembers()
                require(len(members) == 4 and all(m.isfile() for m in members) and {m.name for m in members} == wanted,
                        "invalid binary archive")
                require(t.getmember(root + "/" + name).mode & 0o111, "missing executable permission")
                data = {key: t.extractfile(root + "/" + key).read() for key in (name, "BUILD-INFO.txt", "LICENSE", "README.md")}
        rec = manifest["platforms"][platform]
        require(rec["commit"] == manifest["commit"] and rec["version"] == version, "wrong producer identity")
        require(hashlib.sha256(data[name]).hexdigest() == rec["sha256"] == pkg["sha256"](inputs / platform / name),
                "packaged executable differs from the tested input")
        info = f"Version: {version}\nTarget: {target}\nSource commit: {commit}\nBinary producer commit: {manifest['commit']}\n"
        require(data["BUILD-INFO.txt"] == info.encode(), "build provenance differs")
        for doc in ("LICENSE", "README.md"):
            require(data[doc] == git(repo, "show", commit + ":" + doc), "incorrect package documentation")
        expected[archive.name] = pkg["sha256"](archive)
    root = f"mch-{tag}-src"
    for kind in ("zip", "tar"):
        path = dist / (root + (".tar.gz" if kind == "tar" else ".zip"))
        data = gzip.decompress(path.read_bytes()) if kind == "tar" else path.read_bytes()
        require(data == git(repo, "archive", "--format=" + kind, "--prefix=" + root + "/", commit), "public source archive mismatch")
        expected[path.name] = pkg["sha256"](path)
    sums = dist / "SHA256SUMS.txt"
    require(sums.read_text("ascii") == "".join(f"{expected[n]}  {n}\n" for n in sorted(expected)), "checksum list differs")
    expected[sums.name] = pkg["sha256"](sums)
    require(len(expected) == 8 and {p.name for p in dist.iterdir()} == set(expected), "expected exactly eight assets")
    require(all(p.is_file() and not p.is_symlink() for p in dist.iterdir()), "non-regular asset")
    return tag, commit, expected


def request(method, path, token, body=None, upload=False):
    host = "uploads.github.com" if upload else "api.github.com"
    headers = {"User-Agent": "MCH-SRV-release", "Authorization": "Bearer " + token,
               "Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28"}
    if body is not None:
        headers["Content-Type"] = "application/octet-stream" if upload else "application/json"
        if not upload:
            body = json.dumps(body).encode()
    conn = http.client.HTTPSConnection(host, timeout=90)
    try:
        conn.request(method, API_REPO + path, body, headers)
        response = conn.getresponse()
        data = response.read()
        require(200 <= response.status < 300, f"{method} {path} returned HTTP {response.status}")
        return json.loads(data) if data else None
    finally:
        conn.close()


def check_tag(repo, tag, commit):
    rows = git(repo, "ls-remote", "origin", f"refs/tags/{tag}", f"refs/tags/{tag}^{{}}").decode().splitlines()
    refs = {name: sha for sha, name in (line.split() for line in rows)}
    require(refs.get(f"refs/tags/{tag}^{{}}", refs.get("refs/tags/" + tag)) == commit, "remote tag changed")
    main = git(repo, "ls-remote", "origin", "refs/heads/main").decode().split()[0]
    subprocess.run(["git", "-C", repo, "merge-base", "--is-ancestor", commit, main], check=True)


def publish(repo, dist, tag, commit, expected, token):
    check_tag(repo, tag, commit)
    require(request("GET", "/immutable-releases", token)["enabled"] is True, "repository immutability is disabled")
    require(request("GET", "", token)["permissions"]["push"] is True, "draft visibility requires push access")
    existing = []
    page = 1
    while True:
        releases = request("GET", f"/releases?per_page=100&page={page}", token)
        existing.extend(r for r in releases if r["tag_name"] == tag)
        if len(releases) < 100:
            break
        page += 1
    require(len(existing) <= 1, "multiple matching releases")
    if existing:
        release = existing[0]
        require(release["draft"] and not release["assets"], "published release or populated draft requires operator review")
    else:
        release = request("POST", "/releases", token, {"tag_name": tag, "target_commitish": commit, "name": "MCH " + tag,
                          "draft": True, "prerelease": False, "body": "See CHANGELOG.md and SHA256SUMS.txt."})
    path = f"/releases/{release['id']}"
    for name, sha in expected.items():
        data = (dist / name).read_bytes()
        require(hashlib.sha256(data).hexdigest() == sha, "local asset changed")
        request("POST", path + "/assets?name=" + urllib.parse.quote(name), token, data, upload=True)
    draft = request("GET", path, token)
    require(draft["draft"] and draft["tag_name"] == tag, "wrong draft")
    require(len(draft["assets"]) == 8 and {a["name"]: a["digest"] for a in draft["assets"]} ==
            {name: "sha256:" + sha for name, sha in expected.items()}, "eight remote asset digests must match")
    check_tag(repo, tag, commit)
    require(request("GET", "/immutable-releases", token)["enabled"] is True, "immutability changed")
    request("PATCH", path, token, {"draft": False, "make_latest": "true"})
    final = request("GET", path, token)
    require(final["immutable"] and not final["draft"] and len(final["assets"]) == 8, "published release integrity check failed")
    print(final["html_url"])


if __name__ == "__main__":
    cli = argparse.ArgumentParser(description=__doc__)
    for key in ("public", "dist", "inputs"):
        cli.add_argument("--" + key, type=Path, required=True)
    mode = cli.add_mutually_exclusive_group()
    mode.add_argument("--rehearsal", action="store_true")
    mode.add_argument("--publish", action="store_true")
    args = cli.parse_args()
    try:
        tag, commit, sums = check_bundle(args.public, args.dist, args.inputs, args.rehearsal)
        print(f"Verified eight local assets for {tag} at {commit}.")
        if args.publish:
            require(input(f"Publish immutable MCH {tag} at {commit}? Type FREIGEBEN: ") == "FREIGEBEN", "cancelled")
            publish(args.public, args.dist, tag, commit, sums, os.environ["MCH_RELEASE_TOKEN"])
    except (OSError, ValueError, EOFError, KeyError, subprocess.SubprocessError) as exc:
        cli.exit(1, f"RELEASE BLOCKED: {exc}\n")
