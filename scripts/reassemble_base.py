#!/usr/bin/env python3
import argparse, hashlib, json
from pathlib import Path

def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for block in iter(lambda: f.read(1024 * 1024), b""):
            h.update(block)
    return h.hexdigest()

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--manifest", required=True)
    ap.add_argument("--output", required=True)
    args = ap.parse_args()

    manifest_path = Path(args.manifest)
    root = manifest_path.parents[2]
    manifest = json.loads(manifest_path.read_text())
    out = Path(args.output)
    out.parent.mkdir(parents=True, exist_ok=True)

    with out.open("wb") as dst:
        for item in manifest["parts"]:
            part = root / item["file"]
            data = part.read_bytes()
            got = hashlib.sha256(data).hexdigest()
            if got != item["sha256"]:
                raise SystemExit(f"Part checksum mismatch: {part}: {got} != {item['sha256']}")
            if len(data) != item["size"]:
                raise SystemExit(f"Part size mismatch: {part}")
            dst.write(data)

    got_size = out.stat().st_size
    got_sha = sha256_file(out)
    if got_size != manifest["size"]:
        raise SystemExit(f"Base size mismatch: {got_size} != {manifest['size']}")
    if got_sha != manifest["sha256"]:
        raise SystemExit(f"Base SHA256 mismatch: {got_sha} != {manifest['sha256']}")

    print(f"Reassembled {out}")
    print(f"size={got_size}")
    print(f"sha256={got_sha}")

if __name__ == "__main__":
    main()
