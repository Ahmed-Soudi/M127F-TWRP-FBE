#!/usr/bin/env python3
"""Give Android fs_mgr a native fstab, rather than TWRP's UI fstab."""
from pathlib import Path
import sys

ORIGINAL_CALL = 'android::vold::fscrypt_mount_metadata_encrypted(Decrypt_Data->Actual_Block_Device, Decrypt_Data->Mount_Point, false, false, Decrypt_Data->Current_File_System)'
FIX11_CALL = ORIGINAL_CALL[:-1] + ', "/etc/recovery.fstab")'
NATIVE_CALL = ORIGINAL_CALL[:-1] + ', "/tmp/v21-metadata.fstab")'
PREPARE_CALL = ('v21PrepareMetadataFstab(Decrypt_Data->Actual_Block_Device, '
                'Decrypt_Data->Mount_Point, Decrypt_Data->Current_File_System, '
                'Decrypt_Data->Key_Directory, Decrypt_Data->Mount_Options, '
                'Decrypt_Data->Mount_Flags, Decrypt_Data->Mount_Read_Only)')
ANCHOR = 'void TWPartitionManager::Decrypt_Data() {'

CPP_HELPER = r'''#if defined(TW_INCLUDE_FBE_METADATA_DECRYPT) && defined(USE_FSCRYPT)
// v21 fix13: Android fs_mgr needs device/mount/fs/mount-options/fs_mgr-options.
// TWRP recovery.fstab has a different column order and semicolon UI flags.
static bool v21PrepareMetadataFstab(const std::string& block_device,
                                   const std::string& mount_point,
                                   const std::string& fs_type,
                                   const std::string& key_directory,
                                   const std::string& mount_options,
                                   unsigned long mount_flags, bool read_only) {
    const std::string file_encryption = android::base::GetProperty("fbe.contents", "") +
            ":" + android::base::GetProperty("fbe.filenames", "");
    std::string metadata_encryption = android::base::GetProperty("metadata.contents", "");
    const std::string metadata_flags = android::base::GetProperty("metadata.filenames", "");
    if (!metadata_flags.empty()) metadata_encryption += ":" + metadata_flags;
    // Fail closed on a different device/configuration; do not guess crypto options.
    if (mount_point != "/data" || fs_type != "f2fs" ||
        key_directory != "/metadata/vold/metadata_encryption" ||
        file_encryption != "aes-256-xts:aes-256-cts:v2" ||
        metadata_encryption != "aes-256-xts" ||
        block_device.compare(0, 11, "/dev/block/") != 0 ||
        block_device.find_first_of(" \t\r\n,;") != std::string::npos ||
        mount_options.find_first_of(" \t\r\n;") != std::string::npos) {
        LOGERR("v21: metadata fstab preflight rejected unexpected device/options\n");
        return false;
    }
    const unsigned long supported_flags = MS_RDONLY | MS_NOATIME | MS_NOSUID |
            MS_NODEV | MS_NOEXEC | MS_NODIRATIME | MS_SYNCHRONOUS;
    if ((mount_flags & ~supported_flags) != 0) {
        LOGERR("v21: metadata fstab preflight rejected unsupported mount flags\n");
        return false;
    }
    std::string options = read_only || (mount_flags & MS_RDONLY) ? "ro" : "rw";
    // TWRP splits standard flags into Mount_Flags and filesystem options into
    // Mount_Options. Preserve both when translating to native fs_mgr syntax.
    if (mount_flags & MS_NOATIME) options += ",noatime";
    if (mount_flags & MS_NOSUID) options += ",nosuid";
    if (mount_flags & MS_NODEV) options += ",nodev";
    if (mount_flags & MS_NOEXEC) options += ",noexec";
    if (mount_flags & MS_NODIRATIME) options += ",nodiratime";
    if (mount_flags & MS_SYNCHRONOUS) options += ",sync";
    if (!mount_options.empty()) options += "," + mount_options;
    const std::string native_fstab = block_device + " " + mount_point + " " + fs_type +
            " " + options + " fileencryption=" + file_encryption +
            ",keydirectory=" + key_directory + ",metadata_encryption=" + metadata_encryption + "\n";
    // This is a ramdisk file. Never rewrite the stock or TWRP fstab or any key file.
    if (!android::base::WriteStringToFile(native_fstab, "/tmp/v21-metadata.fstab")) {
        LOGERR("v21: unable to write native metadata fstab\n");
        return false;
    }
    android::fs_mgr::Fstab parsed;
    if (!android::fs_mgr::ReadFstabFromFile("/tmp/v21-metadata.fstab", &parsed)) {
        LOGERR("v21: unable to parse native metadata fstab\n");
        return false;
    }
    auto data = android::fs_mgr::GetEntryForMountPoint(&parsed, mount_point);
    if (parsed.size() != 1 || data == nullptr || data->blk_device != block_device ||
        data->fs_type != fs_type || data->metadata_key_dir != key_directory ||
        data->encryption_options != file_encryption ||
        data->metadata_encryption != metadata_encryption) {
        LOGERR("v21: native metadata fstab round-trip validation failed\n");
        return false;
    }
    LOGINFO("v21: native metadata fstab validated for /data\n");
    return true;
}
#endif

'''


def patch_source(source: str) -> str:
    if CPP_HELPER in source:
        if (source.count(CPP_HELPER) != 1 or source.count(NATIVE_CALL) != 1 or
                source.count('android::vold::fscrypt_mount_metadata_encrypted(') != 1 or
                source.count(PREPARE_CALL) != 1 or ORIGINAL_CALL in source or FIX11_CALL in source):
            raise ValueError("fix13: ambiguous existing native fstab patch")
        return source
    if 'v21PrepareMetadataFstab' in source or NATIVE_CALL in source:
        raise ValueError("fix13: partial native fstab patch")
    calls = [call for call in (ORIGINAL_CALL, FIX11_CALL) if call in source]
    if (len(calls) != 1 or source.count(calls[0]) != 1 or source.count(ANCHOR) != 1 or
            source.count('android::vold::fscrypt_mount_metadata_encrypted(') != 1):
        raise ValueError("fix13: expected exactly one pinned metadata call and Decrypt_Data anchor")
    return source.replace(ANCHOR, CPP_HELPER + ANCHOR, 1).replace(
        calls[0], PREPARE_CALL + ' &&\n\t\t\t\t' + NATIVE_CALL, 1)


def main():
    if len(sys.argv) != 2:
        raise SystemExit("usage: fix_v21_metadata_fstab.py partitionmanager.cpp")
    path = Path(sys.argv[1])
    try:
        result = patch_source(path.read_text())
    except ValueError as exc:
        raise SystemExit(str(exc))
    path.write_text(result)
    print("fix13: native metadata fstab with parser preflight installed")


if __name__ == "__main__":
    main()
