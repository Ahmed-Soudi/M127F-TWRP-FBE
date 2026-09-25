#!/usr/bin/env python3
import argparse, hashlib, struct
from pathlib import Path

def align(v, n):
    return (v + n - 1) // n * n

def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for block in iter(lambda: f.read(1024 * 1024), b""):
            h.update(block)
    return h.hexdigest()

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("image")
    args = ap.parse_args()
    p = Path(args.image)
    data = p.read_bytes()
    if data[:8] != b"ANDROID!":
        raise SystemExit("Not an Android boot image")

    vals = struct.unpack_from("<10I", data, 8)
    kernel_size, kernel_addr, ramdisk_size, ramdisk_addr, second_size, second_addr, tags_addr, page_size, hdr_or_dt, os_version = vals

    # M127F image is a legacy Android boot image with 2048-byte page alignment.
    if page_size not in (2048, 4096, 8192, 16384):
        raise SystemExit(f"Unexpected page size: {page_size}")
    kernel_off = page_size
    ramdisk_off = kernel_off + align(kernel_size, page_size)

    if kernel_off + kernel_size > len(data):
        raise SystemExit("Kernel exceeds image")
    if ramdisk_off + ramdisk_size > len(data):
        raise SystemExit("Ramdisk exceeds image")
    if ramdisk_size == 0:
        raise SystemExit("Empty ramdisk")

    ramdisk_magic = data[ramdisk_off:ramdisk_off+6].hex()
    print(f"image={p}")
    print(f"size={len(data)}")
    print(f"sha256={sha256_file(p)}")
    print(f"kernel_size={kernel_size}")
    print(f"ramdisk_size={ramdisk_size}")
    print(f"page_size={page_size}")
    print(f"kernel_offset=0x{kernel_off:x}")
    print(f"ramdisk_offset=0x{ramdisk_off:x}")
    print(f"ramdisk_first6={ramdisk_magic}")

if __name__ == "__main__":
    main()
