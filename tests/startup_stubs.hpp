// Minimal Android boundary stubs for the real injected C++ startup helpers.
// Time advances through fake usleep, so a 20-second timeout is tested instantly.
#include <cassert>
#include <chrono>
#include <cstdarg>
#include <cstdio>
#include <map>
#include <memory>
#include <sstream>
#include <string>
#include <sys/mount.h>
#include <vector>

static int elapsed_us = 0;
static int sleeps = 0;
static int ready_after_us = 0;
static bool keymaster_registered = true;
static bool gatekeeper_registered = true;
static bool keystore_registered = true;
static int binder_releases = 0;
static int service_probes = 0;
static int managers_ready_after_us = 0;
static int metadata_calls = 0;
static bool file_write_ok = true;
static bool parser_ok = true;
static bool parser_corrupt = false;
static std::map<std::string, std::string> properties;
static std::map<std::string, std::string> files;
static std::vector<std::string> diagnostics;

struct TestClock {
    static std::chrono::steady_clock::time_point now() {
        return std::chrono::steady_clock::time_point(std::chrono::microseconds(elapsed_us));
    }
};

static int usleep(unsigned int us) {
    assert(us == 250000);
    elapsed_us += us;
    ++sleeps;
    return 0;
}

static void log_message(const char* format, ...) {
    char buffer[1024];
    va_list args;
    va_start(args, format);
    vsnprintf(buffer, sizeof(buffer), format, args);
    va_end(args);
    diagnostics.emplace_back(buffer);
}
#define LOGINFO(...) log_message(__VA_ARGS__)
#define LOGERR(...) log_message(__VA_ARGS__)

namespace android {
namespace base {
static std::string GetProperty(const std::string& key, const std::string& fallback) {
    if (key == "hwservicemanager.ready" && elapsed_us < managers_ready_after_us) return "false";
    const auto found = properties.find(key);
    return found == properties.end() ? fallback : found->second;
}
static bool WriteStringToFile(const std::string& content, const std::string& path) {
    assert(path == "/tmp/v21-metadata.fstab");
    if (!file_write_ok) return false;
    files[path] = content;
    return true;
}
}
namespace fs_mgr {
struct FstabEntry {
    std::string blk_device, mount_point, fs_type, metadata_key_dir;
    std::string encryption_options, metadata_encryption;
    std::string fs_options;
    unsigned long flags = 0;
};
using Fstab = std::vector<FstabEntry>;

// Enforce Android fstab's five-column format and comma-separated fs_mgr flags.
// A TWRP recovery.fstab line or semicolon flags cannot pass this stub.
static bool ReadFstabFromFile(const std::string& path, Fstab* result) {
    if (!parser_ok || files.count(path) != 1) return false;
    std::istringstream stream(files.at(path));
    FstabEntry entry;
    std::string mount_options, flags, extra;
    if (!(stream >> entry.blk_device >> entry.mount_point >> entry.fs_type >> mount_options >> flags)) return false;
    if (stream >> extra) return false;
    if (entry.blk_device.compare(0, 11, "/dev/block/") != 0 || flags.find(';') != std::string::npos) return false;
    std::istringstream mounts(mount_options);
    std::string mount_option;
    while (std::getline(mounts, mount_option, ',')) {
        if (mount_option == "ro") entry.flags |= MS_RDONLY;
        else if (mount_option == "rw") entry.flags &= ~MS_RDONLY;
        else if (mount_option == "nosuid") entry.flags |= MS_NOSUID;
        else if (mount_option == "nodev") entry.flags |= MS_NODEV;
        else if (mount_option == "noexec") entry.flags |= MS_NOEXEC;
        else if (mount_option == "noatime") entry.flags |= MS_NOATIME;
        else if (mount_option == "nodiratime") entry.flags |= MS_NODIRATIME;
        else if (mount_option == "sync") entry.flags |= MS_SYNCHRONOUS;
        else if (mount_option == "dirsync") entry.flags |= MS_DIRSYNC;
        else if (mount_option == "relatime") entry.flags |= MS_RELATIME;
        else {
            if (!entry.fs_options.empty()) entry.fs_options += ",";
            entry.fs_options += mount_option;
        }
    }
    std::istringstream options(flags);
    std::string option;
    while (std::getline(options, option, ',')) {
        const auto eq = option.find('=');
        if (eq == std::string::npos) return false;
        const auto name = option.substr(0, eq);
        const auto value = option.substr(eq + 1);
        if (name == "fileencryption") entry.encryption_options = value;
        else if (name == "keydirectory") entry.metadata_key_dir = value;
        else if (name == "metadata_encryption") entry.metadata_encryption = value;
        else return false;
    }
    if (parser_corrupt) entry.metadata_encryption = "unsupported-cipher";
    result->push_back(entry);
    return true;
}
static FstabEntry* GetEntryForMountPoint(Fstab* entries, const std::string& mount_point) {
    for (auto& entry : *entries) if (entry.mount_point == mount_point) return &entry;
    return nullptr;
}
}
namespace hardware {
static void assertManagersReady() {
    assert(elapsed_us >= managers_ready_after_us);
    assert(properties.at("hwservicemanager.ready") == "true");
    assert(properties.at("init.svc.hwservicemanager") == "running");
    assert(properties.at("init.svc.servicemanager") == "running");
    ++service_probes;
}
namespace keymaster { namespace V4_0 {
struct IKeymasterDevice {
    static std::shared_ptr<IKeymasterDevice> tryGetService(const std::string& name) {
        assert(name == "default");
        assertManagersReady();
        if (keymaster_registered && elapsed_us >= ready_after_us) return std::make_shared<IKeymasterDevice>();
        return nullptr;
    }
};
} }
namespace gatekeeper { namespace V1_0 {
struct IGatekeeper {
    static std::shared_ptr<IGatekeeper> tryGetService(const std::string& name) {
        assert(name == "default");
        assertManagersReady();
        if (gatekeeper_registered && elapsed_us >= ready_after_us) return std::make_shared<IGatekeeper>();
        return nullptr;
    }
};
} }
}
namespace vold {
static bool fscrypt_mount_metadata_encrypted(const std::string& block_device,
        const std::string& mount_point, bool needs_encrypt, bool should_format,
        const std::string& fs_type, const std::string& fstab_path) {
    ++metadata_calls;
    assert(block_device == "/dev/block/by-name/userdata");
    assert(mount_point == "/data" && fs_type == "f2fs");
    assert(!needs_encrypt && !should_format);
    assert(fstab_path == "/tmp/v21-metadata.fstab");
    return true;
}
}
}

struct AIBinder {};
static AIBinder keystore_binder;
static AIBinder* AServiceManager_checkService(const char* name) {
    assert(std::string(name) == "android.system.keystore2.IKeystoreService/default");
    android::hardware::assertManagersReady();
    return keystore_registered && elapsed_us >= ready_after_us ? &keystore_binder : nullptr;
}
static void AIBinder_decStrong(AIBinder* binder) {
    assert(binder == &keystore_binder);
    ++binder_releases;
}

struct TestPartition {
    std::string Actual_Block_Device = "/dev/block/by-name/userdata";
    std::string Mount_Point = "/data";
    std::string Current_File_System = "f2fs";
    std::string Key_Directory = "/metadata/vold/metadata_encryption";
    std::string Mount_Options = "inlinecrypt";
    unsigned long Mount_Flags = MS_NOATIME | MS_NOSUID | MS_NODEV;
    bool Mount_Read_Only = false;
};
static TestPartition partition;
static TestPartition* Decrypt_Data = &partition;

static void configure() {
    properties["fbe.contents"] = "aes-256-xts";
    properties["fbe.filenames"] = "aes-256-cts:v2";
    properties["metadata.contents"] = "aes-256-xts";
    properties["metadata.filenames"] = "";
    properties["init.svc.dxj1_keymaster"] = "running";
    properties["init.svc.dxj1_gatekeeper"] = "running";
    properties["init.svc.keystore2"] = "running";
    properties["hwservicemanager.ready"] = "true";
    properties["init.svc.hwservicemanager"] = "running";
    properties["init.svc.servicemanager"] = "running";
}
