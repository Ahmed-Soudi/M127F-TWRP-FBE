#!/usr/bin/env python3
"""Offline repack safety checks; synthetic images are never flashable outputs."""

import importlib.util
import lzma
from pathlib import Path
import struct
import subprocess
import sys
import tempfile
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "repack_with_recovery.py"
SPEC = importlib.util.spec_from_file_location("repack_with_recovery", SCRIPT)
REPACK = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(REPACK)


def fixture_elf():
    # Minimal test ELF with an AArch64 RET instruction, not a recovery fallback.
    size = 124
    ident = b"\x7fELF\x02\x01\x01" + b"\0" * 9
    header = struct.pack("<HHIQQQIHHHHHH", 2, 183, 1, 0x400078, 64, 0,
                         0, 64, 56, 1, 0, 0, 0)
    segment = struct.pack("<IIQQQQQQ", 1, 5, 0, 0x400000, 0, size, size, 4096)
    return ident + header + segment + b"\xc0\x03\x5f\xd6"


def fixture_entries():
    def entry(name, mode, data, inode):
        # Deliberately nontrivial uid/gid/mtime/device metadata.
        fields = [inode, mode, 1000, 1001, 1, 123456, len(data), 4, 5, 6, 7,
                  len(name.encode()) + 1, 0]
        return b"070701", fields, name, data
    return [
        entry("system", 0o40755, b"", 9),
        entry("./system/bin/recovery", 0o100755, b"old-recovery", 10),
        entry("etc/recovery.fstab", 0o100640, b"keep metadata and credential mounts\n", 11),
        entry("init.rc", 0o100600, b"keep daemon startup\n", 12),
        entry("bin/sh", 0o120777, b"/system/bin/toybox", 13),
        entry("TRAILER!!!", 0, b"", 0),
    ]


def fixture_cpio(entries):
    out = bytearray()
    for magic, fields, name, data in entries:
        out.extend(magic + b"".join(f"{value:08x}".encode() for value in fields))
        out.extend(name.encode() + b"\0")
        out.extend(b"\0" * (-len(out) % 4))
        out.extend(data)
        out.extend(b"\0" * (-len(out) % 4))
    return bytes(out)


def fixture_boot():
    page = 2048
    payloads = (b"kernel\x00keep", lzma.compress(fixture_cpio(fixture_entries()),
                format=lzma.FORMAT_ALONE), b"second\x01keep", b"dtbo\x02keep", b"dtb\x03keep")
    header = bytearray(page)
    header[:8] = b"ANDROID!"
    struct.pack_into("<10I", header, 8, len(payloads[0]), 0x1000, len(payloads[1]),
                     0x2000, len(payloads[2]), 0x3000, 0x4000, page, 2, 1234)
    struct.pack_into("<I", header, 1632, len(payloads[3]))
    dtbo_offset = page + sum(((len(p) + page - 1) // page) * page for p in payloads[:3])
    struct.pack_into("<Q", header, 1636, dtbo_offset)
    struct.pack_into("<I", header, 1648, len(payloads[4]))
    header[100:120] = b"unrelated boot state"
    out = header
    for payload in payloads[:-1]:
        out.extend(payload)
        out.extend(b"\0" * (-len(out) % page))
    out.extend(payloads[-1])
    return bytes(out)


class BaseSafetyTests(unittest.TestCase):
    def test_cli_rejects_wrong_size_or_same_size_wrong_hash_without_output(self):
        for size, message in ((32, "known-good v20 size"),
                              (REPACK.V20_SIZE, "SHA256 does not match known-good v20")):
            with self.subTest(size=size), tempfile.TemporaryDirectory() as tmp:
                base, output = Path(tmp) / "base.img", Path(tmp) / "output.img"
                with base.open("wb") as handle:
                    handle.truncate(size)
                # A missing binary also proves the base gate runs before reading it.
                result = subprocess.run([sys.executable, str(SCRIPT), "--base", str(base),
                                         "--recovery-bin", str(Path(tmp) / "missing"),
                                         "--output", str(output)], capture_output=True, text=True)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn(message, result.stderr)
                self.assertFalse(output.exists())

    def test_cli_rejection_preserves_existing_output(self):
        with tempfile.TemporaryDirectory() as tmp:
            base, output = Path(tmp) / "base.img", Path(tmp) / "output.img"
            base.write_bytes(b"wrong base")
            output.write_bytes(b"existing artifact")
            result = subprocess.run([sys.executable, str(SCRIPT), "--base", str(base),
                                     "--recovery-bin", "missing", "--output", str(output)],
                                    capture_output=True, text=True)
            self.assertNotEqual(result.returncode, 0)
            self.assertEqual(output.read_bytes(), b"existing artifact")

    def test_known_base_constants_are_fixed(self):
        self.assertEqual(REPACK.V20_SIZE, 54814720)
        self.assertEqual(REPACK.V20_SHA256,
                         "9d8e4c6889adc7381cc1edc35e12ff4460672324216face7a551ade30b4f5a74")


class ReplacementSafetyTests(unittest.TestCase):
    def test_wrong_arch_class_endian_type_and_entry_are_rejected(self):
        variants = [b"not a build output", fixture_elf()[:63]]
        for offset, value in ((4, 1), (5, 2)):
            data = bytearray(fixture_elf())
            data[offset] = value
            variants.append(bytes(data))
        for offset, fmt, value in ((18, "<H", 62), (16, "<H", 1),
                                   (24, "<Q", 0), (24, "<Q", 0x500000),
                                   (32, "<Q", 10000), (68, "<I", 4),
                                   (96, "<Q", 10000)):
            data = bytearray(fixture_elf())
            struct.pack_into(fmt, data, offset, value)
            variants.append(bytes(data))
        for data in variants:
            with self.subTest(length=len(data), prefix=data[:24]):
                with self.assertRaises(ValueError):
                    REPACK.require_recovery_elf(data)
        REPACK.require_recovery_elf(fixture_elf())

    def test_wrong_elf_and_failed_selfcheck_do_not_create_output(self):
        # Production's exact base gate is tested above. Only this offline fixture
        # test bypasses it so main's output ordering can be exercised without v20.
        for binary, failure in ((b"build failed", None), (fixture_elf(), "injected self-check failure")):
            with self.subTest(failure=failure), tempfile.TemporaryDirectory() as tmp:
                base, recovery, output = (Path(tmp) / name for name in
                                          ("base.img", "recovery", "output.img"))
                synthetic = fixture_boot()
                base.write_bytes(synthetic)
                recovery.write_bytes(binary)
                argv = [str(SCRIPT), "--base", str(base), "--recovery-bin", str(recovery),
                        "--output", str(output)]
                check = (mock.patch.object(REPACK, "check_image_preserved", side_effect=ValueError(failure))
                         if failure else mock.patch.object(REPACK, "check_image_preserved",
                                                           wraps=REPACK.check_image_preserved))
                with mock.patch.object(REPACK, "V20_SIZE", len(synthetic)), \
                     mock.patch.object(REPACK, "require_v20"), mock.patch.object(sys, "argv", argv), check:
                    with self.assertRaises(SystemExit) as error:
                        REPACK.main()
                self.assertIn(failure or "ELF64", str(error.exception))
                self.assertFalse(output.exists())


class PreservationTests(unittest.TestCase):
    def test_only_recovery_bytes_and_filesize_change_in_synthetic_cpio(self):
        original = REPACK.parse_newc(fixture_cpio(fixture_entries()))
        replacement = fixture_elf()
        rebuilt = REPACK.parse_newc(REPACK.build_newc(original, REPACK.RECOVERY_PATH, replacement))
        REPACK.check_ramdisk_preserved(original, rebuilt, replacement)
        self.assertEqual(original[0], rebuilt[0])
        self.assertEqual(original[2:], rebuilt[2:])
        self.assertEqual(original[1][2], rebuilt[1][2])
        self.assertEqual(rebuilt[1][3], replacement)
        self.assertEqual(rebuilt[1][1][6], len(replacement))
        for index in set(range(13)) - {6}:
            self.assertEqual(original[1][1][index], rebuilt[1][1][index])

    def test_missing_or_duplicate_recovery_and_nonexecutable_entry_fail(self):
        original = fixture_entries()
        duplicate = original[:2] + [(original[1][0], original[1][1],
                                     "system/bin/recovery", original[1][3])] + original[2:]
        invalid_mode = fixture_entries()
        invalid_mode[1][1][1] = 0o100644
        for entries in (original[:1] + original[2:], duplicate, invalid_mode):
            with self.subTest(entries=len(entries)):
                with self.assertRaises(ValueError):
                    REPACK.build_newc(entries, REPACK.RECOVERY_PATH, fixture_elf())

    def test_existing_crc_format_updates_only_recovery_checksum(self):
        original = fixture_entries()
        magic, fields, name, data = original[1]
        fields[12] = sum(data) & 0xffffffff
        original[1] = (b"070702", fields, name, data)
        replacement = fixture_elf()
        rebuilt = REPACK.parse_newc(REPACK.build_newc(original, REPACK.RECOVERY_PATH, replacement))
        self.assertEqual(rebuilt[1][1][12], sum(replacement) & 0xffffffff)
        self.assertEqual(original[2:], rebuilt[2:])
        REPACK.check_ramdisk_preserved(original, rebuilt, replacement)

    def test_selfcheck_detects_other_payload_metadata_name_or_order_changes(self):
        original = fixture_entries()
        new = REPACK.parse_newc(REPACK.build_newc(original, REPACK.RECOVERY_PATH, fixture_elf()))
        for kind in ("payload", "metadata", "name", "order"):
            changed = [(magic, list(fields), name, data) for magic, fields, name, data in new]
            magic, fields, name, data = changed[2]
            if kind == "payload":
                data = b"modified mount configuration"
                fields[6] = len(data)
            elif kind == "metadata":
                fields[2] = 0
            elif kind == "name":
                name = "etc/other.fstab"
            changed[2] = (magic, fields, name, data)
            if kind == "order":
                changed[2], changed[3] = changed[3], changed[2]
            with self.subTest(kind=kind), self.assertRaises(ValueError):
                REPACK.check_ramdisk_preserved(original, changed, fixture_elf())

    def test_synthetic_full_image_preserves_all_nonramdisk_payloads(self):
        base = fixture_boot()
        with mock.patch.object(REPACK, "require_v20"):
            rebuilt, ramdisk_size = REPACK.repack(base, fixture_elf())
        _, before = REPACK.boot_payloads(base)
        _, after = REPACK.boot_payloads(rebuilt)
        for name in ("kernel", "second", "dtbo", "dtb"):
            self.assertEqual(before[name], after[name])
        self.assertEqual(len(after["ramdisk"]), ramdisk_size)
        entries = REPACK.parse_newc(lzma.decompress(before["ramdisk"], format=lzma.FORMAT_ALONE))
        for name in ("kernel", "second", "dtbo", "dtb"):
            changed = bytearray(rebuilt)
            offset = rebuilt.index(after[name])
            changed[offset] ^= 1
            with self.subTest(payload=name), self.assertRaisesRegex(ValueError, name + " changed"):
                REPACK.check_image_preserved(base, changed, entries, fixture_elf())
        for offset, message in ((100, "unrelated boot header fields"), (576, "boot image ID")):
            changed = bytearray(rebuilt)
            changed[offset] ^= 1
            with self.subTest(header_offset=offset), self.assertRaisesRegex(ValueError, message):
                REPACK.check_image_preserved(base, changed, entries, fixture_elf())

    def test_partition_ceiling_stops_output(self):
        with mock.patch.object(REPACK, "require_v20"), mock.patch.object(REPACK, "PARTITION_LIMIT", 1):
            with self.assertRaisesRegex(ValueError, "image too large"):
                REPACK.repack(fixture_boot(), fixture_elf())


if __name__ == "__main__":
    unittest.main()
