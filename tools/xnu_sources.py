"""Pinned public XNU source cache. Network only with explicit --fetch; no build scripts run."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import urllib.request

ROOT = Path(__file__).resolve().parents[1]
CACHE = ROOT / "out/m09-upstream"


def lock():
    return json.loads((ROOT / "xnu/sources.lock.json").read_text(encoding="utf-8"))


def verify_file(path, expected):
    data = Path(path).read_bytes()
    blob = hashlib.sha1(f"blob {len(data)}\0".encode() + data).hexdigest()
    if (len(data) != expected["bytes"] or hashlib.sha256(data).hexdigest() != expected["sha256"]
            or blob != expected["git_blob_sha1"]):
        raise ValueError("pinned source mismatch: " + str(path))


def verify(directory=CACHE):
    directory = Path(directory)
    spec = lock()
    source = directory / "xnu"
    for item in spec["files"]:
        verify_file(source / item["path"], item)
    for key in ("build_reference", "release"):
        verify_file(directory / spec[key]["file"], spec[key])
    # Full clone integrity plus clean tracked source, beyond the per-file SHA256 list.
    for expr, expected in (("HEAD", spec["xnu"]["commit"]),
                           ("HEAD^{tree}", spec["xnu"]["tree"]),
                           (spec["xnu"]["tag"], spec["xnu"]["tag_object"])):
        actual = subprocess.check_output(["git", "-C", str(source), "rev-parse", expr], text=True).strip()
        if actual != expected:
            raise ValueError("XNU git identity mismatch")
    status = subprocess.check_output(["git", "-C", str(source), "status", "--porcelain"], text=True)
    if status:
        raise ValueError("XNU cache must be pristine; use a separate patch workspace")
    return {"commit": spec["xnu"]["commit"], "sha256_files": len(spec["files"]) + 2,
            "pristine_tree": True}


def fetch():
    spec = lock()
    CACHE.mkdir(parents=True, exist_ok=True)
    if not (CACHE / "xnu").exists():
        subprocess.run(["git", "-c", "core.autocrlf=false", "clone", "--depth", "1", "--branch",
                        spec["xnu"]["tag"], spec["xnu"]["repository"] + ".git", str(CACHE / "xnu")], check=True)
    for key, filename in (("build_reference", "build.sh"), ("release", "release.json")):
        item = spec[key]
        target = CACHE / item["file"]
        if not target.exists():
            url = item["repository"].replace("github.com", "raw.githubusercontent.com")
            with urllib.request.urlopen(url + "/" + item["commit"] + "/" + filename, timeout=30) as response:
                data = response.read()
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(data)
        verify_file(target, item)
    return verify()


if __name__ == "__main__":
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--fetch", action="store_true")
    args = p.parse_args()
    print(json.dumps(fetch() if args.fetch else verify(), indent=2))
