// Boundary stubs for existing-key retrieval and the mapper creation sequence.
#include <cassert>
#include <chrono>
#include <fstream>
#include <string>
#include <sys/stat.h>
#include <vector>

using KeyBuffer = std::string;
struct KeyAuthentication {};
static const KeyAuthentication kEmptyAuthentication;
struct KeyGeneration {};
struct CryptoOptions {};
struct DataEntry { std::string metadata_key_dir; };
static int retrieve_attempts = 0;
static int succeed_on_attempt = 1;
static int sleeps = 0;
static int mapper_calls = 0;
static int generation_calls = 0;
static std::vector<std::string> events;

struct TestLog {
    template<class T> TestLog& operator<<(const T&) { return *this; }
};
#define LOG(level) TestLog()

static void test_sleep_for(std::chrono::milliseconds delay) {
    assert(delay.count() == 250);
    ++sleeps;
    events.push_back("sleep");
}

static bool retrieveKey(const std::string& dir, const KeyAuthentication& auth, KeyBuffer* key) {
    assert(&auth == &kEmptyAuthentication);
    assert(key->empty());
    ++retrieve_attempts;
    events.push_back("retrieve");
    std::ifstream marker(dir + "/synthetic_key_material", std::ios::binary);
    std::string contents((std::istreambuf_iterator<char>(marker)), {});
    assert(contents == "synthetic read-only fixture");
    *key = "partial result from failed operation";
    if (retrieve_attempts < succeed_on_attempt) return false;
    *key = "retrieved test key";
    return true;
}

static KeyGeneration makeGen(const CryptoOptions&) { return {}; }
static KeyGeneration neverGen() { return {}; }
static bool read_key(const std::string&, const KeyGeneration&, KeyBuffer*) {
    ++generation_calls;
    return false;
}
static const std::string kDmNameUserdata = "userdata";
static bool create_crypto_blk_dev(const std::string& name, const std::string&,
        const KeyBuffer& key, const CryptoOptions&, std::string*, uint64_t*) {
    assert(name == "userdata" && key == "retrieved test key");
    assert(retrieve_attempts == succeed_on_attempt);
    ++mapper_calls;
    events.push_back("mapper");
    return true;
}
