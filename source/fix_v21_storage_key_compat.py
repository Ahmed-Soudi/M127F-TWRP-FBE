#!/usr/bin/env python3
"""Handle Keystore2 hardware blob prefixes only for metadata and DE storage.

Apply after patch_v21.py. The existing no-auth and HAT begin methods are left
unchanged. Normalization and upgrades occur in memory; KeyStorage's existing
upgraded-blob handling writes only its /tmp scratch file.
"""

import argparse
import os
import stat
import tempfile
from pathlib import Path


HEADER_ANCHOR = "    // Begin with HardwareAuthToken for user-authenticated keys\n"
CPP_DECLARATION = """    // Metadata/DE only: unwrap Keystore2 hardware blobs without changing stored keys.
    KeymasterOperation beginForDeStorage(const std::string& key,
                                         const km::AuthorizationSet& inParams,
                                         km::AuthorizationSet* outParams);

"""
METHOD_ANCHOR = """KeymasterOperation Keymaster::begin(const std::string& key, const km::AuthorizationSet& inParams,
                                    km::AuthorizationSet* outParams,
                                    const km_hidl::HardwareAuthToken& authToken) {"""
CPP_METHOD = r'''// v21 fix14: metadata/DE storage only; existing begin/HAT paths stay unchanged.
KeymasterOperation Keymaster::beginForDeStorage(const std::string& key,
                                                const km::AuthorizationSet& inParams,
                                                km::AuthorizationSet* outParams) {
    if (!mDevice) {
        LOG(ERROR) << "v21: metadata/DE storage Keymaster has no device";
        return KeymasterOperation(km::ErrorCode::UNKNOWN_ERROR);
    }

    // Keystore2 km_compat: seven magic bytes, then origin 0=hardware, 1=software.
    // A partial recognized marker, missing payload, or unsupported origin is not
    // a raw hardware blob. Never guess another offset after INVALID_KEY_BLOB.
    const std::string compat_magic = "pKMblob";
    constexpr size_t prefix_size = 8;
    if (key.empty() || (key.size() < compat_magic.size() &&
                       compat_magic.compare(0, key.size(), key) == 0)) {
        LOG(ERROR) << "v21: metadata/DE storage rejected empty/truncated key blob";
        return KeymasterOperation(km::ErrorCode::INVALID_KEY_BLOB);
    }
    const bool hardware_wrapper = key.compare(0, compat_magic.size(), compat_magic) == 0;
    std::string rawKey = key;
    if (hardware_wrapper) {
        if (key.size() <= prefix_size || static_cast<unsigned char>(key[7]) != 0) {
            LOG(ERROR) << "v21: metadata/DE storage rejected unsupported/truncated compat wrapper";
            return KeymasterOperation(km::ErrorCode::INVALID_KEY_BLOB);
        }
        rawKey = key.substr(prefix_size);
        LOG(INFO) << "v21: metadata/DE storage hardware compat prefix removed in memory; stored_size="
                  << key.size() << " raw_size=" << rawKey.size();
    } else {
        LOG(INFO) << "v21: metadata/DE storage raw key blob unchanged; size=" << key.size();
    }

    auto purposeOpt = extractPurpose(inParams);
    km_hidl::KeyPurpose purpose = purposeOpt.value_or(km_hidl::KeyPurpose::ENCRYPT);
    auto keyBlob = km_hidl::support::blob2hidlVec(rawKey);
    auto hidlParams = convertToHidl(inParams);
    uint64_t mOpHandle = 0;
    km_hidl::ErrorCode km_error = km_hidl::ErrorCode::UNKNOWN_ERROR;
    km_hidl::AuthorizationSet hidlOutParams;
    auto hidlCb = [&](km_hidl::ErrorCode ret, const hidl_vec<km_hidl::KeyParameter>& _outParams,
                      uint64_t operationHandle) {
        km_error = ret;
        if (km_error != km_hidl::ErrorCode::OK) return;
        hidlOutParams = _outParams;
        mOpHandle = operationHandle;
    };

    auto error = mDevice->begin(purpose, keyBlob, hidlParams.hidl_data(),
                                km_hidl::HardwareAuthToken(), hidlCb);
    if (!error.isOk()) {
        LOG(ERROR) << "v21: metadata/DE storage begin HIDL transport error";
        return KeymasterOperation(km::ErrorCode::UNKNOWN_ERROR);
    }
    LOG(INFO) << "v21: metadata/DE storage Keymaster begin result=" << static_cast<int32_t>(km_error);

    if (km_error == km_hidl::ErrorCode::KEY_REQUIRES_UPGRADE) {
        // Preserve only the key's application binding. Operation nonce, purpose,
        // and other begin parameters do not belong in upgradeKey's parameter set.
        km::AuthorizationSet upgradeParams;
        for (const auto& param : inParams) {
            if (param.tag == km::Tag::APPLICATION_ID || param.tag == km::Tag::APPLICATION_DATA) {
                upgradeParams.push_back(param);
            }
        }
        std::string upgradedKey;
        LOG(INFO) << "v21: metadata/DE storage key requires upgrade; binding_params=" << upgradeParams.size();
        if (upgradeKey(rawKey, upgradeParams, &upgradedKey)) {
            if (upgradedKey.empty()) {
                LOG(ERROR) << "v21: metadata/DE storage upgrade returned an empty blob";
                return KeymasterOperation(km::ErrorCode::INVALID_KEY_BLOB);
            }
            auto upgradedKeyBlob = km_hidl::support::blob2hidlVec(upgradedKey);
            error = mDevice->begin(purpose, upgradedKeyBlob, hidlParams.hidl_data(),
                                   km_hidl::HardwareAuthToken(), hidlCb);
            if (!error.isOk()) {
                LOG(ERROR) << "v21: metadata/DE storage upgraded begin HIDL transport error";
                return KeymasterOperation(km::ErrorCode::UNKNOWN_ERROR);
            }
            LOG(INFO) << "v21: metadata/DE storage upgraded begin result=" << static_cast<int32_t>(km_error);
            if (km_error == km_hidl::ErrorCode::OK) {
                if (outParams) *outParams = convertFromHidl(hidlOutParams);
                // Preserve the original format only for the existing /tmp scratch
                // writer. The HAL always receives the raw upgraded key above.
                const std::string scratchKey = hardware_wrapper
                        ? key.substr(0, prefix_size) + upgradedKey : upgradedKey;
                return KeymasterOperation(mDevice.get(), mOpHandle, scratchKey);
            }
        }
    }

    if (km_error != km_hidl::ErrorCode::OK) {
        return KeymasterOperation(Keymaster::convertErrorFromHidl(km_error));
    }
    if (outParams) *outParams = convertFromHidl(hidlOutParams);
    return KeymasterOperation(mDevice.get(), mOpHandle);
}

'''
SCOPE_ANCHOR = "// Begins a Keymaster operation using the key stored in |dir|.\n"
CPP_SCOPE = r'''// v21 fix14: exact stock metadata and DE key directories; never CE paths.
static bool v21IsDeStorageKeyDirectory(const std::string& dir) {
    if (dir == "/metadata/vold/metadata_encryption/key" || dir == "/data/unencrypted/key") {
        return true;
    }
    const std::string de_prefix = "/data/misc/vold/user_keys/de/";
    if (dir.compare(0, de_prefix.size(), de_prefix) != 0 || dir.size() == de_prefix.size()) {
        return false;
    }
    for (size_t i = de_prefix.size(); i < dir.size(); ++i) {
        if (dir[i] < '0' || dir[i] > '9') return false;
    }
    return true;
}

'''
NO_AUTH_BRANCH = r'''    } else {
        opHandle = keymaster.begin(blob, inParams, outParams);
    }
    printf("[DEBUG] BeginKeymasterOp: keymaster.begin() returned, valid=%d\n", (bool)opHandle);'''
CPP_ROUTE = r'''    } else {
        if (v21IsDeStorageKeyDirectory(dir)) {
            opHandle = keymaster.beginForDeStorage(blob, inParams, outParams);
        } else {
            opHandle = keymaster.begin(blob, inParams, outParams);
        }
    }
    printf("[DEBUG] BeginKeymasterOp: keymaster.begin() returned, valid=%d\n", (bool)opHandle);'''


def _once(source: str, old: str, new: str, label: str) -> str:
    count = source.count(old)
    if count != 1:
        raise ValueError(f"fix14 {label}: expected exactly one source anchor, found {count}")
    return source.replace(old, new, 1)


def patch_source(source: str, kind: str | None = None) -> str:
    """Patch one reviewed file, inferring its kind when omitted; reruns are exact no-ops."""
    if kind is None:
        candidates = [name for name, marker in (
            ("Keymaster.h", "#ifndef ANDROID_VOLD_KEYMASTER_H"),
            ("Keymaster.cpp", "KeymasterOperation Keymaster::begin("),
            ("KeyStorage.cpp", "static KeymasterOperation BeginKeymasterOp("),
        ) if marker in source]
        if len(candidates) != 1:
            raise ValueError("fix14: expected exactly one recognized source file kind")
        kind = candidates[0]

    if kind == "Keymaster.h":
        if source.count(HEADER_ANCHOR) != 1 or source.count("    KeymasterOperation begin(") != 2:
            raise ValueError("fix14: expected both original Keymaster begin declarations")
        if "beginForDeStorage" in source:
            if source.count(CPP_DECLARATION) == 1 and source.count("beginForDeStorage") == 1:
                return source
            raise ValueError("fix14: partial or duplicate storage begin declaration")
        return _once(source, HEADER_ANCHOR, CPP_DECLARATION + HEADER_ANCHOR, "declaration")

    if kind == "Keymaster.cpp":
        if source.count(METHOD_ANCHOR) != 1 or source.count("KeymasterOperation Keymaster::begin(") != 2:
            raise ValueError("fix14: expected both original Keymaster begin methods")
        if "beginForDeStorage" in source:
            if source.count(CPP_METHOD) == 1 and source.count("beginForDeStorage") == 1:
                return source
            raise ValueError("fix14: partial or duplicate storage begin method")
        return _once(source, METHOD_ANCHOR, CPP_METHOD + METHOD_ANCHOR, "method")

    if kind == "KeyStorage.cpp":
        if source.count(SCOPE_ANCHOR) != 1 or source.count("static KeymasterOperation BeginKeymasterOp(") != 1:
            raise ValueError("fix14: expected one KeyStorage operation helper")
        if "v21IsDeStorageKeyDirectory" in source or "beginForDeStorage" in source:
            if (source.count(CPP_SCOPE) == 1 and source.count(CPP_ROUTE) == 1
                    and source.count("v21IsDeStorageKeyDirectory") == 2
                    and source.count("beginForDeStorage") == 1):
                return source
            raise ValueError("fix14: partial or duplicate storage route")
        # Require the v21 HAT branch and change only its no-auth else branch.
        if source.count("opHandle = keymaster.begin(blob, inParams, outParams, hat);") != 1:
            raise ValueError("fix14: patch_v21 HAT branch must be present and unique")
        result = _once(source, NO_AUTH_BRANCH, CPP_ROUTE, "no-auth route")
        return _once(result, SCOPE_ANCHOR, CPP_SCOPE + SCOPE_ANCHOR, "directory scope")

    raise ValueError(f"fix14: unsupported source file {kind!r}")


def patch_sources(sources: dict[str, str]) -> dict[str, str]:
    expected = {"Keymaster.h", "Keymaster.cpp", "KeyStorage.cpp"}
    if set(sources) != expected:
        raise ValueError("fix14: exactly Keymaster.h, Keymaster.cpp, KeyStorage.cpp are required")
    return {name: patch_source(source, name) for name, source in sources.items()}


def apply_patch(root: Path) -> bool:
    paths = {name: root / name for name in ("Keymaster.h", "Keymaster.cpp", "KeyStorage.cpp")}
    original = {name: path.read_text() for name, path in paths.items()}
    # Validate all three inputs before opening any output file.
    patched = patch_sources(original)
    changed = {name for name in paths if patched[name] != original[name]}
    if not changed:
        return False
    staged: dict[str, Path] = {}
    backups: dict[str, Path] = {}
    published: list[str] = []
    try:
        for name in sorted(changed):
            path = paths[name]
            mode = stat.S_IMODE(path.stat().st_mode)
            for collection, text in ((staged, patched[name]), (backups, original[name])):
                with tempfile.NamedTemporaryFile(mode="w", dir=root, prefix=f".{name}.",
                                                 delete=False) as handle:
                    temporary = Path(handle.name)
                    collection[name] = temporary
                    handle.write(text)
                    handle.flush()
                    os.fsync(handle.fileno())
                temporary.chmod(mode)
        try:
            for name in sorted(changed):
                os.replace(staged[name], paths[name])
                del staged[name]
                published.append(name)
        except OSError:
            # There is no cross-file rename primitive. Restore earlier published
            # files if a later replace fails; validation/staging failures above
            # leave all three originals untouched.
            for name in reversed(published):
                os.replace(backups[name], paths[name])
                del backups[name]
            raise
    finally:
        for temporary in (*staged.values(), *backups.values()):
            temporary.unlink(missing_ok=True)
    return True


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("vold_source", type=Path, help="path to system/vold after patch_v21.py")
    args = parser.parse_args()
    try:
        changed = apply_patch(args.vold_source)
    except (OSError, ValueError) as error:
        parser.exit(1, f"fix14 storage compatibility: {error}\n")
    print("fix14 storage compatibility: " + ("metadata/DE hardware wrapper handling applied"
                                            if changed else "already applied"))


if __name__ == "__main__":
    main()
