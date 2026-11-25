#!/usr/bin/env python3
"""Assemble MCH archives on SRV from verified platform results and public Git."""
import argparse
import gzip
import hashlib
import io
import json
from pathlib import Path
import re
import stat
import subprocess
import tarfile
import tempfile
import tomllib
import zipfile

PLATFORMS = {
    "linux-x86_64": "x86_64-unknown-linux-gnu",
    "linux-aarch64": "aarch64-unknown-linux-gnu",
    "android-aarch64-termux": "aarch64-linux-android",
    "windows-x86_64": "x86_64-pc-windows-msvc",
    "macos-aarch64": "aarch64-apple-darwin",
}


def require(value, reason):
    if not value:
        raise ValueError(reason)


def git(repo, *args):
    return subprocess.check_output(["git", "-C", str(repo), *args])


def source_identity(repo, commit):
    paths = git(repo, "ls-tree", "-r", "-z", commit, "--", "src", "tests", "Cargo.toml",
                "Cargo.lock", "build.rs", ".cargo", "rust-toolchain", "rust-toolchain.toml")
    return hashlib.sha256(paths).hexdigest()


def sha256(path):
    with path.open("rb") as file:
        return hashlib.file_digest(file, "sha256").hexdigest()


def release_version(repo, commit):
    return tomllib.loads(git(repo, "show", commit + ":Cargo.toml").decode())["package"]["version"]


def versioned_archive(out, prefix, payload, windows):
    suffix = ".zip" if windows else ".tar.gz"
    path = out / (prefix + suffix)
    if windows:
        with zipfile.ZipFile(path, "x", zipfile.ZIP_DEFLATED) as archive:
            for name, data in payload.items():
                archive.writestr(prefix + "/" + name, data)
    else:
        with tarfile.open(path, "x:gz") as archive:
            for name, data in payload.items():
                info = tarfile.TarInfo(prefix + "/" + name)
                info.size = len(data)
                info.mode = 0o755 if name == "mch" else 0o644
                archive.addfile(info, io.BytesIO(data))
    return path


def assemble(public, built, inputs, output, rehearsal):
    remote = git(public, "remote", "get-url", "origin").decode().strip()
    require(remote in ("https://github.com/Olize/mch.git", "git@github.com:Olize/mch.git"), "expected public MCH checkout")
    commit = git(public, "rev-parse", "HEAD").decode().strip()
    manifest = json.loads((inputs / "binaries.json").read_text())
    producer = manifest["commit"]
    require(re.fullmatch("[0-9a-f]{40}", producer), "invalid binary producer commit")
    version = release_version(public, commit)
    require(version == release_version(built, producer), "package version mismatch")
    require(source_identity(public, commit) == source_identity(built, producer), "build inputs differ between producer and public source")
    pattern = r"\d+\.\d+\.\d+-rc\.\d+" if rehearsal else r"\d+\.\d+\.\d+"
    require(re.fullmatch(pattern, version), "version does not match packaging mode")
    tag = "v" + version
    if not rehearsal:
        require(producer == commit, "stable binaries must be built against the exact public tag commit")
        require(tuple(map(int, version.split("."))) >= (0, 2, 3), "historical release")
        require(git(public, "rev-parse", "refs/tags/" + tag + "^{commit}").decode().strip() == commit, "tag mismatch")
        subprocess.run(["git", "-C", public, "merge-base", "--is-ancestor", commit, "origin/main"], check=True)
    require(set(manifest["platforms"]) == set(PLATFORMS), "expected five tested executables")
    require(not output.exists(), "output already exists")
    output.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(dir=output.parent) as work:
        out = Path(work) / "dist"
        out.mkdir()
        for platform, target in PLATFORMS.items():
            name = "mch.exe" if platform == "windows-x86_64" else "mch"
            entry = manifest["platforms"][platform]
            binary = inputs / platform / name
            require(stat.S_ISREG(binary.lstat().st_mode) and sha256(binary) == entry["sha256"], "binary digest mismatch for " + platform)
            require(entry["commit"] == producer and entry["version"] == version, "binary provenance mismatch for " + platform)
            data = binary.read_bytes()
            if platform == "windows-x86_64":
                pe = int.from_bytes(data[60:64], "little")
                require(data[:2] == b"MZ" and data[pe:pe+6] == b"PE\0\0\x64\x86", "expected PE AMD64")
            elif platform == "macos-aarch64":
                require(data[:8] == bytes.fromhex("cffaedfe0c000001"), "expected Mach-O arm64")
            else:
                arch = 62 if platform == "linux-x86_64" else 183
                require(data[:6] == b"\x7fELF\x02\x01" and int.from_bytes(data[18:20], "little") == arch, "ELF ABI mismatch")
                interp = subprocess.check_output(["readelf", "-lW", binary], text=True)
                loader = {"linux-x86_64": "/lib64/ld-linux-x86-64.so.2", "linux-aarch64": "/lib/ld-linux-aarch64.so.1",
                          "android-aarch64-termux": "/system/bin/linker64"}[platform]
                require(f"Requesting program interpreter: {loader}]" in interp, "incorrect ELF interpreter")
            info = f"Version: {version}\nTarget: {target}\nSource commit: {commit}\nBinary producer commit: {producer}\n"
            versioned_archive(out, f"mch-{tag}-{platform}", {
                name: data, "README.md": git(public, "show", commit + ":README.md"),
                "LICENSE": git(public, "show", commit + ":LICENSE"), "BUILD-INFO.txt": info.encode(),
            }, platform == "windows-x86_64")
        prefix = "mch-" + tag + "-src"
        for kind in ("zip", "tar"):
            data = git(public, "archive", "--format=" + kind, "--prefix=" + prefix + "/", commit)
            if kind == "tar":
                (out / (prefix + ".tar.gz")).write_bytes(gzip.compress(data, mtime=0))
            else:
                (out / (prefix + ".zip")).write_bytes(data)
        checksums = "".join(f"{sha256(path)}  {path.name}\n" for path in sorted(out.iterdir()))
        (out / "SHA256SUMS.txt").write_text(checksums, encoding="ascii")
        require(len(checksums.splitlines()) == 7, "expected seven archives")
        out.rename(output)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    for option in ("public", "built", "inputs", "output"):
        parser.add_argument("--" + option, required=True, type=Path)
    parser.add_argument("--rehearsal", action="store_true")
    args = parser.parse_args()
    try:
        assemble(args.public.resolve(), args.built.resolve(), args.inputs.resolve(), args.output.resolve(), args.rehearsal)
    except (OSError, ValueError, KeyError, subprocess.SubprocessError) as exc:
        parser.exit(1, f"PACKAGING BLOCKED: {exc}\n")
