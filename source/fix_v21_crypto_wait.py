#!/usr/bin/env python3
"""Wait for registration, and never attempt metadata decryption after timeout."""
from pathlib import Path
import sys

NATIVE_CALL = 'android::vold::fscrypt_mount_metadata_encrypted(Decrypt_Data->Actual_Block_Device, Decrypt_Data->Mount_Point, false, false, Decrypt_Data->Current_File_System, "/tmp/v21-metadata.fstab")'
ANCHOR = 'void TWPartitionManager::Decrypt_Data() {'
INCLUDE_ANCHOR = '\t#include "MetadataCrypt.h"\n'
INCLUDES = '''\t#include <android/hardware/keymaster/4.0/IKeymasterDevice.h>
\t#include <android/hardware/gatekeeper/1.0/IGatekeeper.h>
\t#include <android/binder_manager.h>
\t#include <android/binder_ibinder.h>
\t#include <chrono>
'''
# Exact legacy fix12 block. Upgrade it rather than stacking another wait.
LEGACY_WAIT = '''\t\t\tLOGINFO("v21: waiting for crypto services before metadata decrypt\\n");
\t\t\tfor (int i = 0; i < 60; ++i) {
\t\t\t\tconst std::string km = android::base::GetProperty("init.svc.dxj1_keymaster", "");
\t\t\t\tconst std::string gk = android::base::GetProperty("init.svc.dxj1_gatekeeper", "");
\t\t\t\tconst std::string ks = android::base::GetProperty("init.svc.keystore2", "");
\t\t\t\tif (km == "running" && gk == "running" && ks == "running") {
\t\t\t\t\tLOGINFO("v21: crypto services ready after %d ms\\n", i * 250);
\t\t\t\t\tbreak;
\t\t\t\t}
\t\t\t\tif (i == 59) {
\t\t\t\t\tLOGINFO("v21: crypto wait timeout km=%s gk=%s ks=%s\\n",
\t\t\t\t\t\tkm.c_str(), gk.c_str(), ks.c_str());
\t\t\t\t}
\t\t\t\tusleep(250000);
\t\t\t}
'''

CPP_HELPER = r'''#if defined(TW_INCLUDE_FBE_METADATA_DECRYPT) && defined(USE_FSCRYPT)
// v21 fix13: process state does not imply HIDL/AIDL service registration.
static bool v21WaitForCryptoServices() {
    const auto start = std::chrono::steady_clock::now();
    const auto deadline = start + std::chrono::seconds(20);
    std::string km, gk, ks, hwsm, sm;
    bool managers_ready = false;
    bool km_registered = false, gk_registered = false, ks_registered = false;
    LOGINFO("v21: waiting for registered crypto services before metadata decrypt\n");
    while (std::chrono::steady_clock::now() < deadline) {
        km = android::base::GetProperty("init.svc.dxj1_keymaster", "");
        gk = android::base::GetProperty("init.svc.dxj1_gatekeeper", "");
        ks = android::base::GetProperty("init.svc.keystore2", "");
        hwsm = android::base::GetProperty("init.svc.hwservicemanager", "");
        sm = android::base::GetProperty("init.svc.servicemanager", "");
        // Even nonwaiting HAL checks can wait internally for their service
        // manager. Gate startup before entering those library accessors.
        managers_ready = hwsm == "running" && sm == "running" &&
                android::base::GetProperty("hwservicemanager.ready", "") == "true";
        // tryGetService/checkService do not wait for a missing named service.
        km_registered = managers_ready && km == "running" &&
                android::hardware::keymaster::V4_0::IKeymasterDevice::tryGetService("default") != nullptr;
        gk_registered = managers_ready && gk == "running" &&
                android::hardware::gatekeeper::V1_0::IGatekeeper::tryGetService("default") != nullptr;
        ks_registered = false;
        if (managers_ready && ks == "running") {
            AIBinder* service = AServiceManager_checkService(
                    "android.system.keystore2.IKeystoreService/default");
            ks_registered = service != nullptr;
            if (service != nullptr) AIBinder_decStrong(service);
        }
        if (km_registered && gk_registered && ks_registered) {
            const auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
                    std::chrono::steady_clock::now() - start).count();
            LOGINFO("v21: crypto services registered after %lld ms\n",
                    static_cast<long long>(elapsed));
            return true;
        }
        usleep(250000);
    }
    LOGERR("v21: crypto registration timeout; skipping metadata decrypt "
           "managers=%d hwsm=%s sm=%s km=%s/%d gk=%s/%d ks=%s/%d\n",
           managers_ready, hwsm.c_str(), sm.c_str(), km.c_str(), km_registered,
           gk.c_str(), gk_registered, ks.c_str(), ks_registered);
    return false;
}
#endif

'''


def patch_source(source: str) -> str:
    if CPP_HELPER in source:
        if (source.count(CPP_HELPER) != 1 or source.count(INCLUDES) != 1 or
                source.count(NATIVE_CALL) != 1 or LEGACY_WAIT in source or
                source.count('android::vold::fscrypt_mount_metadata_encrypted(') != 1 or
                source.count('v21WaitForCryptoServices() &&') != 1):
            raise ValueError("fix13: ambiguous existing registration wait")
        return source
    if 'v21WaitForCryptoServices' in source:
        raise ValueError("fix13: partial registration wait")
    if source.count(LEGACY_WAIT) > 1:
        raise ValueError("fix13: duplicate fix12 waits")
    source = source.replace(LEGACY_WAIT, '', 1)
    if 'v21: waiting for crypto services before metadata decrypt' in source:
        raise ValueError("fix13: unrecognized legacy fix12 wait")
    if (source.count(NATIVE_CALL) != 1 or source.count(ANCHOR) != 1 or
            source.count('android::vold::fscrypt_mount_metadata_encrypted(') != 1 or
            source.count(INCLUDE_ANCHOR) != 1):
        raise ValueError("fix13: native metadata fstab patch and pinned include required")
    return source.replace(INCLUDE_ANCHOR, INCLUDE_ANCHOR + INCLUDES, 1).replace(
        ANCHOR, CPP_HELPER + ANCHOR, 1).replace(
        NATIVE_CALL, 'v21WaitForCryptoServices() &&\n\t\t\t\t' + NATIVE_CALL, 1)


def main():
    if len(sys.argv) != 2:
        raise SystemExit("usage: fix_v21_crypto_wait.py partitionmanager.cpp")
    path = Path(sys.argv[1])
    try:
        result = patch_source(path.read_text())
    except ValueError as exc:
        raise SystemExit(str(exc))
    path.write_text(result)
    print("fix13: bounded HIDL/AIDL registration wait installed")


if __name__ == "__main__":
    main()
