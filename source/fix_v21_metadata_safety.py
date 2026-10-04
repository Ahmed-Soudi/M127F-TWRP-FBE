#!/usr/bin/env python3
"""Keep recovery metadata decryption on the existing-key retrieval path.

Only key retrieval is retried. A successful mapper is never recreated to retry
the filesystem mount: the caller already mounts the published mapper itself.
"""

import argparse
import os
import stat
import tempfile
from pathlib import Path


READ_KEY_ANCHOR = "static bool read_key(const std::string& metadata_key_dir, const KeyGeneration& gen,\n"
OLD_KEY_CALL = "    if (!read_key(data_rec->metadata_key_dir, gen, &key)) return false;"
NEW_KEY_CALL = """    // Recovery must retrieve the stock key without creating key directories or keys.
    if (needs_encrypt) {
        if (!read_key(data_rec->metadata_key_dir, gen, &key)) return false;
    } else {
        if (!v21_read_existing_metadata_key(data_rec->metadata_key_dir, &key)) return false;
    }"""
OLD_MOUNT = """    mount_via_fs_mgr(mount_point.c_str(), crypto_blkdev.c_str());
    android::base::SetProperty("ro.crypto.fs_crypto_blkdev", crypto_blkdev);"""
NEW_MOUNT = """    const bool mounted = mount_via_fs_mgr(mount_point.c_str(), crypto_blkdev.c_str());
    LOG(INFO) << "v21: metadata mapper ready " << crypto_blkdev
              << "; fs_mgr_mount_success=" << mounted;
    // Keep mapper-ready success: TWRP mounts this same mapper after this call.
    // Returning failure here would encourage another mapper creation attempt.
    android::base::SetProperty("ro.crypto.fs_crypto_blkdev", crypto_blkdev);"""
CPP_HELPER = """// v21 existing metadata key retrieval: never generate, delete, or overwrite stock keys.
static bool v21_read_existing_metadata_key(const std::string& metadata_key_dir, KeyBuffer* key) {
    key->clear();
    if (metadata_key_dir.empty()) {
        LOG(ERROR) << "v21: metadata key directory is empty; refusing key generation";
        return false;
    }
    const std::string dir = metadata_key_dir + "/key";
    struct stat st;
    if (stat(dir.c_str(), &st) != 0 || !S_ISDIR(st.st_mode)) {
        LOG(ERROR) << "v21: existing metadata key directory unavailable: " << dir;
        return false;
    }
    constexpr int max_attempts = 3;
    for (int attempt = 1; attempt <= max_attempts; ++attempt) {
        LOG(INFO) << "v21: retrieving existing metadata key; attempt " << attempt
                  << "/" << max_attempts;
        if (retrieveKey(dir, kEmptyAuthentication, key)) {
            LOG(INFO) << "v21: existing metadata key retrieved before mapper creation";
            return true;
        }
        key->clear();
        LOG(WARNING) << "v21: existing metadata key retrieval failed; attempt " << attempt;
        if (attempt < max_attempts) {
            std::this_thread::sleep_for(std::chrono::milliseconds(250));
        }
    }
    LOG(ERROR) << "v21: metadata key retrieval exhausted; mapper was not created";
    return false;
}

"""


def _once(source: str, old: str, new: str, label: str) -> str:
    count = source.count(old)
    if count != 1:
        raise ValueError(f"{label}: expected exactly one source anchor, found {count}")
    return source.replace(old, new, 1)


def patch_source(source: str) -> str:
    """Patch the reviewed vold source; identical reruns are a no-op."""
    marker = "static bool v21_read_existing_metadata_key("
    if marker in source:
        if (source.count(CPP_HELPER) == 1 and source.count(NEW_KEY_CALL) == 1
                and source.count(NEW_MOUNT) == 1
                and source.count(OLD_KEY_CALL) == 1 and OLD_MOUNT not in source
                and source.count(READ_KEY_ANCHOR) == 1
                and source.count("#include <chrono>\n") == 1
                and source.count("#include <thread>\n") == 1
                and source.count(marker) == 1):
            return source
        raise ValueError("metadata safety: incomplete or changed existing patch")

    # Do all source validation before the caller writes anything.
    patched = _once(source, READ_KEY_ANCHOR, CPP_HELPER + READ_KEY_ANCHOR,
                    "metadata existing-key helper")
    patched = _once(patched, OLD_KEY_CALL, NEW_KEY_CALL, "metadata key retrieval")
    patched = _once(patched, OLD_MOUNT, NEW_MOUNT, "metadata mapper mount result")
    missing_includes = "".join(
        f"#include <{name}>\n" for name in ("chrono", "thread")
        if f"#include <{name}>\n" not in patched
    )
    if missing_includes:
        patched = _once(patched, "#include <string>\n",
                        missing_includes + "#include <string>\n", "metadata includes")
    return patched


def apply_patch(path: Path) -> bool:
    original = path.read_text()
    patched = patch_source(original)
    if patched == original:
        return False
    mode = stat.S_IMODE(path.stat().st_mode)
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(mode="w", dir=path.parent,
                                         prefix=f".{path.name}.", delete=False) as handle:
            temporary = Path(handle.name)
            handle.write(patched)
            handle.flush()
            os.fsync(handle.fileno())
        temporary.chmod(mode)
        os.replace(temporary, path)
        temporary = None
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)
    return True


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source", type=Path, help="path to system/vold/MetadataCrypt.cpp")
    args = parser.parse_args()
    try:
        changed = apply_patch(args.source)
    except (OSError, ValueError) as error:
        parser.exit(1, f"metadata safety: {error}\n")
    print("metadata safety: " + ("existing-key retrieval and pre-mapper retry applied"
                                if changed else "already applied"))


if __name__ == "__main__":
    main()
