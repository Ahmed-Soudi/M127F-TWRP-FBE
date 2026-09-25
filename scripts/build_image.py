#!/usr/bin/env python3
import argparse, hashlib, json, shutil, subprocess, sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for block in iter(lambda: f.read(1024 * 1024), b""):
            h.update(block)
    return h.hexdigest()

def run(cmd):
    print("+", " ".join(map(str, cmd)))
    subprocess.run(list(map(str, cmd)), check=True)

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--version", required=True)
    ap.add_argument("--dist", default="dist")
    args = ap.parse_args()

    version_file = ROOT / "versions" / f"{args.version}.json"
    if not version_file.exists():
        raise SystemExit(f"Unknown version: {args.version}")

    spec = json.loads(version_file.read_text())
    dist = ROOT / args.dist
    work = ROOT / ".work"
    shutil.rmtree(work, ignore_errors=True)
    work.mkdir(parents=True)
    dist.mkdir(parents=True, exist_ok=True)

    base = spec["base"]
    base_img = work / f"{base}.img"
    run([
        sys.executable, ROOT / "scripts/reassemble_base.py",
        "--manifest", ROOT / "base" / base / "manifest.json",
        "--output", base_img
    ])

    output = dist / spec["output"]
    patch_script = spec.get("patch_script")
    if patch_script:
        run([
            sys.executable, ROOT / patch_script,
            "--input", base_img,
            "--output", output
        ])
    else:
        shutil.copy2(base_img, output)

    run([sys.executable, ROOT / "scripts/verify_bootimg.py", output])

    digest = sha256_file(output)
    (dist / "SHA256SUMS.txt").write_text(f"{digest}  {output.name}\n")
    info = {
        "version": args.version,
        "output": output.name,
        "size": output.stat().st_size,
        "sha256": digest,
        "base": base,
        "description": spec.get("description", ""),
    }
    (dist / "build-info.json").write_text(json.dumps(info, indent=2) + "\n")
    print(json.dumps(info, indent=2))

if __name__ == "__main__":
    main()
