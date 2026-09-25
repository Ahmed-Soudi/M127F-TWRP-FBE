#!/usr/bin/env python3
import argparse, hashlib, lzma, struct
from pathlib import Path

BOOT_MAGIC = b"ANDROID!"
PARTITION_LIMIT = 55574528

def align(x, n):
    return (x + n - 1) // n * n

def parse_newc(blob):
    pos = 0
    entries = []
    while True:
        if blob[pos:pos+6] not in (b"070701", b"070702"):
            raise ValueError(f"bad cpio magic at 0x{pos:x}")
        hdr = blob[pos:pos+110]
        fields = [int(hdr[6+i*8:14+i*8], 16) for i in range(13)]
        namesize, filesize = fields[11], fields[6]
        name_start = pos + 110
        name = blob[name_start:name_start+namesize-1].decode("utf-8", "surrogateescape")
        data_start = align(name_start + namesize, 4)
        data = blob[data_start:data_start+filesize]
        entries.append((hdr[:6], fields, name, data))
        pos = align(data_start + filesize, 4)
        if name == "TRAILER!!!":
            return entries

def build_newc(entries, replacement_path, replacement):
    out = bytearray()
    found = False
    for magic, fields, name, data in entries:
        if name.lstrip("./") == replacement_path:
            data = replacement
            fields = list(fields)
            fields[6] = len(data)
            found = True
        fields = list(fields)
        fields[11] = len(name.encode("utf-8", "surrogateescape")) + 1
        hdr = magic + b"".join(f"{v:08x}".encode() for v in fields)
        out += hdr
        out += name.encode("utf-8", "surrogateescape") + b"\0"
        out += b"\0" * ((-len(out)) % 4)
        out += data
        out += b"\0" * ((-len(out)) % 4)
    if not found:
        raise SystemExit(f"did not find {replacement_path}")
    return bytes(out)

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--base", required=True)
    ap.add_argument("--recovery-bin", required=True)
    ap.add_argument("--output", required=True)
    args = ap.parse_args()

    base = Path(args.base).read_bytes()
    if base[:8] != BOOT_MAGIC:
        raise SystemExit("not an Android boot image")

    vals = struct.unpack_from("<10I", base, 8)
    kernel_size, kernel_addr, ramdisk_size, ramdisk_addr, second_size, second_addr, tags_addr, page_size, header_version, os_version = vals
    if header_version != 2:
        raise SystemExit(f"expected header v2, got {header_version}")

    recovery_dtbo_size = struct.unpack_from("<I", base, 1632)[0]
    recovery_dtbo_offset = struct.unpack_from("<Q", base, 1636)[0]
    dtb_size = struct.unpack_from("<I", base, 1648)[0]

    kernel_off = page_size
    ramdisk_off = kernel_off + align(kernel_size, page_size)
    second_off = ramdisk_off + align(ramdisk_size, page_size)
    dtbo_off = recovery_dtbo_offset if recovery_dtbo_offset else second_off + align(second_size, page_size)
    dtb_off = align(dtbo_off + recovery_dtbo_size, page_size)

    kernel = base[kernel_off:kernel_off+kernel_size]
    old_rd = base[ramdisk_off:ramdisk_off+ramdisk_size]
    second = base[second_off:second_off+second_size] if second_size else b""
    dtbo = base[dtbo_off:dtbo_off+recovery_dtbo_size] if recovery_dtbo_size else b""
    dtb = base[dtb_off:dtb_off+dtb_size] if dtb_size else b""

    raw = lzma.decompress(old_rd, format=lzma.FORMAT_ALONE)
    entries = parse_newc(raw)
    new_rec = Path(args.recovery_bin).read_bytes()
    new_raw = build_newc(entries, "system/bin/recovery", new_rec)

    filters = [{
        "id": lzma.FILTER_LZMA1,
        "dict_size": 64 * 1024 * 1024,
        "lc": 3, "lp": 0, "pb": 2,
        "mode": lzma.MODE_NORMAL,
        "mf": lzma.MF_BT4,
        "nice_len": 128,
    }]
    new_rd = lzma.compress(new_raw, format=lzma.FORMAT_ALONE, filters=filters)

    hdr = bytearray(base[:page_size])
    struct.pack_into("<I", hdr, 16, len(new_rd))

    new_ramdisk_off = page_size + align(len(kernel), page_size)
    new_second_off = new_ramdisk_off + align(len(new_rd), page_size)
    new_dtbo_off = new_second_off + align(len(second), page_size)
    new_dtb_off = align(new_dtbo_off + len(dtbo), page_size)
    struct.pack_into("<Q", hdr, 1636, new_dtbo_off)

    h = hashlib.sha1()
    for payload in (kernel, new_rd, second, dtbo, dtb):
        h.update(payload)
        h.update(struct.pack("<I", len(payload)))
    digest = h.digest()
    hdr[576:608] = digest + b"\0" * (32 - len(digest))

    out = bytearray(hdr)
    def add(payload):
        out.extend(payload)
        out.extend(b"\0" * ((-len(out)) % page_size))
    add(kernel)
    add(new_rd)
    add(second)
    add(dtbo)
    out.extend(dtb)

    if len(out) > PARTITION_LIMIT:
        raise SystemExit(f"image too large: {len(out)} > {PARTITION_LIMIT}")

    Path(args.output).write_bytes(out)

    rebuilt = Path(args.output).read_bytes()
    rsz = struct.unpack_from("<I", rebuilt, 16)[0]
    roff = page_size + align(kernel_size, page_size)
    check_raw = lzma.decompress(rebuilt[roff:roff+rsz], format=lzma.FORMAT_ALONE)
    got = None
    for _, _, name, data in parse_newc(check_raw):
        if name.lstrip("./") == "system/bin/recovery":
            got = data
            break
    if got != new_rec:
        raise SystemExit("self-check failed: recovery mismatch")

    print(f"output={args.output}")
    print(f"size={len(out)}")
    print(f"sha256={hashlib.sha256(out).hexdigest()}")
    print(f"recovery_size={len(new_rec)}")
    print(f"ramdisk_size={len(new_rd)}")

if __name__ == "__main__":
    main()
