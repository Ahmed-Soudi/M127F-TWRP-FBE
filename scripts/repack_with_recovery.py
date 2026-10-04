#!/usr/bin/env python3
import argparse, hashlib, lzma, stat, struct
from pathlib import Path

BOOT_MAGIC = b"ANDROID!"
PARTITION_LIMIT = 55574528
V20_SIZE = 54814720
V20_SHA256 = "9d8e4c6889adc7381cc1edc35e12ff4460672324216face7a551ade30b4f5a74"
RECOVERY_PATH = "system/bin/recovery"

def align(x, n):
    return (x + n - 1) // n * n

def require_v20(base):
    if len(base) != V20_SIZE:
        raise ValueError(f"expected known-good v20 size {V20_SIZE}, got {len(base)}")
    if hashlib.sha256(base).hexdigest() != V20_SHA256:
        raise ValueError("base SHA256 does not match known-good v20")

def require_recovery_elf(blob):
    """Reject placeholders, shared libraries and binaries for another ABI."""
    if len(blob) < 64 or blob[:7] != b"\x7fELF\x02\x01\x01":
        raise ValueError("recovery must be an ELF64 little-endian executable")
    values = struct.unpack_from("<HHIQQQIHHHHHH", blob, 16)
    elf_type, machine, version, entry, phoff = values[:5]
    ehsize, phentsize, phnum = values[7:10]
    if machine != 183 or version != 1 or elf_type not in (2, 3):
        raise ValueError("recovery must be an AArch64 executable (ET_EXEC or PIE ET_DYN)")
    if ehsize != 64 or phentsize != 56 or not phnum or phnum == 0xffff:
        raise ValueError("invalid recovery ELF program header table")
    if phoff < ehsize or phoff + phnum * phentsize > len(blob):
        raise ValueError("truncated recovery ELF program header table")
    executable_entry = False
    for index in range(phnum):
        kind, flags, offset, vaddr, _, filesz, memsz, _ = struct.unpack_from(
            "<IIQQQQQQ", blob, phoff + index * phentsize)
        if offset + filesz > len(blob):
            raise ValueError("recovery ELF segment exceeds file")
        if kind == 1:
            if filesz > memsz:
                raise ValueError("invalid recovery ELF load segment")
            if flags & 1 and filesz and vaddr <= entry < vaddr + filesz:
                executable_entry = True
    if not entry or not executable_entry:
        raise ValueError("recovery ELF entry point is not in a file-backed executable load segment")

def is_recovery(name):
    while name.startswith("./"):
        name = name[2:]
    return name == RECOVERY_PATH

def require_one_recovery(entries):
    matches = [entry for entry in entries if is_recovery(entry[2])]
    if len(matches) != 1:
        raise ValueError(f"ramdisk must contain exactly one {RECOVERY_PATH}; found {len(matches)}")
    mode = matches[0][1][1]
    if not stat.S_ISREG(mode) or not mode & 0o111:
        raise ValueError("ramdisk recovery must be an executable regular file")

def parse_newc(blob):
    pos = 0
    entries = []
    while True:
        if blob[pos:pos+6] not in (b"070701", b"070702"):
            raise ValueError(f"bad cpio magic at 0x{pos:x}")
        hdr = blob[pos:pos+110]
        if len(hdr) != 110:
            raise ValueError("truncated cpio header")
        fields = [int(hdr[6+i*8:14+i*8], 16) for i in range(13)]
        namesize, filesize = fields[11], fields[6]
        name_start = pos + 110
        if not namesize or name_start + namesize > len(blob):
            raise ValueError("invalid cpio name size")
        if blob[name_start+namesize-1] != 0 or b"\0" in blob[name_start:name_start+namesize-1]:
            raise ValueError("invalid cpio name terminator")
        name = blob[name_start:name_start+namesize-1].decode("utf-8", "surrogateescape")
        data_start = align(name_start + namesize, 4)
        if data_start + filesize > len(blob):
            raise ValueError(f"truncated cpio payload for {name}")
        data = blob[data_start:data_start+filesize]
        entries.append((hdr[:6], fields, name, data))
        pos = align(data_start + filesize, 4)
        if name == "TRAILER!!!":
            return entries

def build_newc(entries, replacement_path, replacement):
    if replacement_path != RECOVERY_PATH:
        raise ValueError("only system/bin/recovery replacement is supported")
    require_one_recovery(entries)
    out = bytearray()
    for magic, fields, name, data in entries:
        if is_recovery(name):
            data = replacement
            fields = list(fields)
            fields[6] = len(data)
            if magic == b"070702":
                fields[12] = sum(data) & 0xffffffff
        fields = list(fields)
        fields[11] = len(name.encode("utf-8", "surrogateescape")) + 1
        hdr = magic + b"".join(f"{v:08x}".encode() for v in fields)
        out += hdr
        out += name.encode("utf-8", "surrogateescape") + b"\0"
        out += b"\0" * ((-len(out)) % 4)
        out += data
        out += b"\0" * ((-len(out)) % 4)
    return bytes(out)

def boot_payloads(image):
    if len(image) < 1660 or image[:8] != BOOT_MAGIC:
        raise ValueError("not an Android boot image")
    vals = struct.unpack_from("<10I", image, 8)
    kernel_size, kernel_addr, ramdisk_size, ramdisk_addr, second_size, second_addr, tags_addr, page_size, header_version, os_version = vals
    if header_version != 2:
        raise ValueError(f"expected header v2, got {header_version}")
    if page_size not in (2048, 4096, 8192, 16384) or len(image) < page_size:
        raise ValueError(f"invalid boot page size: {page_size}")

    recovery_dtbo_size = struct.unpack_from("<I", image, 1632)[0]
    recovery_dtbo_offset = struct.unpack_from("<Q", image, 1636)[0]
    dtb_size = struct.unpack_from("<I", image, 1648)[0]

    kernel_off = page_size
    ramdisk_off = kernel_off + align(kernel_size, page_size)
    second_off = ramdisk_off + align(ramdisk_size, page_size)
    dtbo_off = recovery_dtbo_offset if recovery_dtbo_offset else second_off + align(second_size, page_size)
    dtb_off = align(dtbo_off + recovery_dtbo_size, page_size)

    payloads = {}
    for name, offset, size in (
            ("kernel", kernel_off, kernel_size), ("ramdisk", ramdisk_off, ramdisk_size),
            ("second", second_off, second_size), ("dtbo", dtbo_off, recovery_dtbo_size),
            ("dtb", dtb_off, dtb_size)):
        if size and (offset < page_size or offset + size > len(image)):
            raise ValueError(f"{name} exceeds boot image")
        payloads[name] = image[offset:offset+size] if size else b""
    return page_size, payloads

def check_ramdisk_preserved(original, rebuilt, replacement):
    require_one_recovery(original)
    require_one_recovery(rebuilt)
    if len(original) != len(rebuilt):
        raise ValueError("self-check failed: ramdisk entry count changed")
    for old, new in zip(original, rebuilt):
        magic, fields, name, data = old
        expected_fields = list(fields)
        if is_recovery(name):
            data = replacement
            expected_fields[6] = len(data)
            if magic == b"070702":
                expected_fields[12] = sum(data) & 0xffffffff
        if new != (magic, expected_fields, name, data):
            raise ValueError(f"self-check failed: ramdisk entry changed unexpectedly: {name}")

def check_image_preserved(base, rebuilt, entries, replacement):
    page_size, original = boot_payloads(base)
    new_page_size, current = boot_payloads(rebuilt)
    if page_size != new_page_size:
        raise ValueError("self-check failed: boot page size changed")
    for name in ("kernel", "second", "dtbo", "dtb"):
        if original[name] != current[name]:
            raise ValueError(f"self-check failed: {name} changed")
    old_header, new_header = bytearray(base[:page_size]), bytearray(rebuilt[:page_size])
    for start, end in ((16, 20), (576, 608), (1636, 1644)):
        old_header[start:end] = new_header[start:end]
    if old_header != new_header:
        raise ValueError("self-check failed: unrelated boot header fields changed")
    digest = hashlib.sha1()
    for name in ("kernel", "ramdisk", "second", "dtbo", "dtb"):
        digest.update(current[name])
        digest.update(struct.pack("<I", len(current[name])))
    if rebuilt[576:608] != digest.digest() + b"\0" * 12:
        raise ValueError("self-check failed: boot image ID mismatch")
    raw = lzma.decompress(current["ramdisk"], format=lzma.FORMAT_ALONE)
    check_ramdisk_preserved(entries, parse_newc(raw), replacement)

def repack(base, new_rec):
    require_v20(base)
    require_recovery_elf(new_rec)
    page_size, payloads = boot_payloads(base)
    kernel, old_rd, second, dtbo, dtb = (payloads[name] for name in
        ("kernel", "ramdisk", "second", "dtbo", "dtb"))

    raw = lzma.decompress(old_rd, format=lzma.FORMAT_ALONE)
    entries = parse_newc(raw)
    new_raw = build_newc(entries, RECOVERY_PATH, new_rec)

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
        raise ValueError(f"image too large: {len(out)} > {PARTITION_LIMIT}")
    check_image_preserved(base, out, entries, new_rec)
    return bytes(out), len(new_rd)

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--base", required=True)
    ap.add_argument("--recovery-bin", required=True)
    ap.add_argument("--output", required=True)
    args = ap.parse_args()
    base_path, recovery_path, output_path = map(Path, (args.base, args.recovery_bin, args.output))
    if output_path.resolve() in (base_path.resolve(), recovery_path.resolve()):
        raise SystemExit("output must not overwrite either input")
    try:
        if base_path.stat().st_size != V20_SIZE:
            raise ValueError(f"expected known-good v20 size {V20_SIZE}, got {base_path.stat().st_size}")
        base = base_path.read_bytes()
        require_v20(base)
        new_rec = recovery_path.read_bytes()
        out, ramdisk_size = repack(base, new_rec)
    except (ValueError, OSError, lzma.LZMAError, struct.error) as exc:
        raise SystemExit(str(exc)) from exc
    output_path.write_bytes(out)

    print(f"output={args.output}")
    print(f"size={len(out)}")
    print(f"sha256={hashlib.sha256(out).hexdigest()}")
    print(f"recovery_size={len(new_rec)}")
    print(f"ramdisk_size={ramdisk_size}")

if __name__ == "__main__":
    main()
