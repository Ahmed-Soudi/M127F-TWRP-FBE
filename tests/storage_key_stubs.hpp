// Recording HIDL boundary for the actual Keymaster methods under test.
// No filesystem API or key-blob file writer is supplied to these methods.
#include <cassert>
#include <cstdint>
#include <cstring>
#include <iostream>
#include <memory>
#include <optional>
#include <string>
#include <utility>
#include <vector>

struct TestLog {
    template<class T> TestLog& operator<<(const T&) { return *this; }
};
#define LOG(level) TestLog()

namespace android {
namespace hardware {
template<class T> using hidl_vec = std::vector<T>;
namespace keymaster { namespace V4_1 { namespace support {
static hidl_vec<uint8_t> blob2hidlVec(const std::string& bytes) {
    return {bytes.begin(), bytes.end()};
}
} } }
}
namespace vold {
template<class T> using hidl_vec = std::vector<T>;
namespace km {
enum class Tag {
    PURPOSE, APPLICATION_ID, APPLICATION_DATA, NONCE, BLOCK_MODE, PADDING,
    DIGEST, AUTH_TIMEOUT, NO_AUTH_REQUIRED, OS_VERSION, OS_PATCHLEVEL
};
enum class ErrorCode : int32_t { OK = 0, INVALID_KEY_BLOB = -33, KEY_REQUIRES_UPGRADE = -62, UNKNOWN_ERROR = -1000 };
struct KeyParameter {
    Tag tag;
    std::vector<uint8_t> blob;
    bool operator==(const KeyParameter& other) const { return tag == other.tag && blob == other.blob; }
};
struct AuthorizationSet : std::vector<KeyParameter> {
    using std::vector<KeyParameter>::vector;
    using std::vector<KeyParameter>::operator=;
    const std::vector<KeyParameter>& hidl_data() const { return *this; }
};
}
namespace km_hidl {
using ErrorCode = km::ErrorCode;
using KeyParameter = km::KeyParameter;
using AuthorizationSet = km::AuthorizationSet;
enum class KeyPurpose { ENCRYPT, DECRYPT };
struct HardwareAuthToken {
    uint64_t challenge = 0;
    std::vector<uint8_t> mac;
};
namespace support {
static hidl_vec<uint8_t> blob2hidlVec(const std::string& bytes) {
    return {bytes.begin(), bytes.end()};
}
}
}

struct TestReturn {
    bool ok;
    bool isOk() const { return ok; }
    std::string description() const { return "synthetic HIDL transport failure"; }
};
struct BeginRecord {
    std::string blob;
    km::AuthorizationSet parameters;
    km_hidl::HardwareAuthToken token;
    km_hidl::KeyPurpose purpose;
};
struct UpgradeRecord { std::string blob; km::AuthorizationSet parameters; };
struct FakeHAL {
    std::vector<BeginRecord> begins;
    std::vector<UpgradeRecord> upgrades;
    std::vector<std::string> events;
    std::vector<km_hidl::ErrorCode> begin_errors = {km_hidl::ErrorCode::OK};
    std::vector<bool> begin_transports = {true};
    km_hidl::ErrorCode upgrade_error = km_hidl::ErrorCode::OK;
    bool upgrade_transport = true;
    std::string upgraded_blob = "synthetic upgraded raw blob";
    km::AuthorizationSet output = {{km::Tag::NONCE, {1, 2, 3}}};

    template<class Callback> TestReturn begin(km_hidl::KeyPurpose purpose,
            const hidl_vec<uint8_t>& blob, const hidl_vec<km_hidl::KeyParameter>& parameters,
            const km_hidl::HardwareAuthToken& token, Callback callback) {
        const auto index = begins.size();
        begins.push_back({std::string(blob.begin(), blob.end()), km::AuthorizationSet(parameters.begin(), parameters.end()), token, purpose});
        events.push_back("begin");
        const bool transport = begin_transports.at(index < begin_transports.size() ? index : begin_transports.size() - 1);
        if (!transport) return {false};
        const auto error = begin_errors.at(index < begin_errors.size() ? index : begin_errors.size() - 1);
        callback(error, output, uint64_t(77));
        return {true};
    }
    template<class Callback> TestReturn upgradeKey(const hidl_vec<uint8_t>& blob,
            const hidl_vec<km_hidl::KeyParameter>& parameters, Callback callback) {
        upgrades.push_back({std::string(blob.begin(), blob.end()), km::AuthorizationSet(parameters.begin(), parameters.end())});
        events.push_back("upgrade");
        if (!upgrade_transport) return {false};
        callback(upgrade_error, hidl_vec<uint8_t>(upgraded_blob.begin(), upgraded_blob.end()));
        return {true};
    }
};

class KeymasterOperation {
  public:
    KeymasterOperation() : valid(false), error(km::ErrorCode::UNKNOWN_ERROR) {}
    explicit KeymasterOperation(km::ErrorCode code) : valid(false), error(code) {}
    KeymasterOperation(FakeHAL*, uint64_t handle) : valid(handle != 0), error(km::ErrorCode::OK) {}
    KeymasterOperation(FakeHAL*, uint64_t handle, const std::string& blob)
        : valid(handle != 0), error(km::ErrorCode::OK), upgraded(blob) {}
    explicit operator bool() const { return valid; }
    km::ErrorCode getErrorCode() const { return error; }
    std::optional<std::string> getUpgradedBlob() const { return upgraded; }
  private:
    bool valid;
    km::ErrorCode error;
    std::optional<std::string> upgraded;
};

class Keymaster {
  public:
    explicit Keymaster(std::shared_ptr<FakeHAL> device) : mDevice(std::move(device)) {}
    KeymasterOperation begin(const std::string&, const km::AuthorizationSet&, km::AuthorizationSet*);
    KeymasterOperation begin(const std::string&, const km::AuthorizationSet&, km::AuthorizationSet*, const km_hidl::HardwareAuthToken&);
    KeymasterOperation beginForDeStorage(const std::string&, const km::AuthorizationSet&, km::AuthorizationSet*);
    bool upgradeKey(const std::string&, const km::AuthorizationSet&, std::string*);
    static km::ErrorCode convertErrorFromHidl(km_hidl::ErrorCode error) { return error; }
  private:
    std::shared_ptr<FakeHAL> mDevice;
    static std::optional<km_hidl::KeyPurpose> extractPurpose(const km::AuthorizationSet&) {
        return km_hidl::KeyPurpose::DECRYPT;
    }
    static km_hidl::AuthorizationSet convertToHidl(const km::AuthorizationSet& parameters) { return parameters; }
    static km::AuthorizationSet convertFromHidl(const km_hidl::AuthorizationSet& parameters) { return parameters; }
};

struct KeyAuthentication { std::string token; };
struct hw_auth_token_t { unsigned char bytes[69]; };
}
namespace hardware { namespace keymaster { namespace V4_1 { namespace support {
static vold::km_hidl::HardwareAuthToken hidlVec2AuthToken(const hidl_vec<uint8_t>& token) {
    vold::km_hidl::HardwareAuthToken result;
    result.mac = token;
    return result;
}
} } } }
}
