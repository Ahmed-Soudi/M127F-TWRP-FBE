#!/usr/bin/env python3
from pathlib import Path
import sys

def replace_once(s, old, new, label):
    n = s.count(old)
    if n != 1:
        raise SystemExit(f"{label}: expected exactly 1 match, found {n}")
    return s.replace(old, new, 1)

def patch_keystorage_h(root):
    p = root / "KeyStorage.h"
    s = p.read_text()
    old = '''class KeyAuthentication {
  public:
    KeyAuthentication(const std::string& s) : secret{s} {};

    bool usesKeymaster() const { return secret.empty(); };

    const std::string secret;
};'''
    new = '''class KeyAuthentication {
  public:
    KeyAuthentication(const std::string& s) : token{}, secret{s} {};
    KeyAuthentication(const std::string& t, const std::string& s) : token{t}, secret{s} {};

    bool usesKeymaster() const { return !token.empty() || secret.empty(); };

    const std::string token;
    const std::string secret;
};'''
    s = replace_once(s, old, new, "KeyStorage.h KeyAuthentication")
    p.write_text(s)

def patch_fscrypt_h(root):
    p = root / "FsCrypt.h"
    s = p.read_text()
    s = replace_once(
        s,
        'bool fscrypt_add_user_key_auth(userid_t user_id, int serial, const std::string& secret);',
        'bool fscrypt_add_user_key_auth(userid_t user_id, int serial, const std::string& token, const std::string& secret);',
        "FsCrypt.h add auth",
    )
    s = replace_once(
        s,
        'bool fscrypt_clear_user_key_auth(userid_t user_id, int serial, const std::string& secret);',
        'bool fscrypt_clear_user_key_auth(userid_t user_id, int serial, const std::string& token, const std::string& secret);',
        "FsCrypt.h clear auth",
    )
    s = replace_once(
        s,
        'bool fscrypt_unlock_user_key(userid_t user_id, int serial, const std::string& secret);',
        'bool fscrypt_unlock_user_key(userid_t user_id, int serial, const std::string& token, const std::string& secret);',
        "FsCrypt.h unlock",
    )
    p.write_text(s)

def patch_fscrypt_cpp(root):
    p = root / "FsCrypt.cpp"
    s = p.read_text()

    old = '''static std::optional<android::vold::KeyAuthentication> authentication_from_hex(
        const std::string& secret_hex) {
    std::string secret;
    if (!parse_hex(secret_hex, &secret)) return std::optional<android::vold::KeyAuthentication>();
    if (secret.empty()) {
        return kEmptyAuthentication;
    } else {
        return android::vold::KeyAuthentication(secret);
    }
}'''
    new = '''static std::optional<android::vold::KeyAuthentication> authentication_from_hex(
        const std::string& token_hex, const std::string& secret_hex) {
    std::string token, secret;
    if (!parse_hex(token_hex, &token)) return std::optional<android::vold::KeyAuthentication>();
    if (!parse_hex(secret_hex, &secret)) return std::optional<android::vold::KeyAuthentication>();
    if (secret.empty()) {
        return kEmptyAuthentication;
    } else {
        return android::vold::KeyAuthentication(token, secret);
    }
}'''
    s = replace_once(s, old, new, "FsCrypt.cpp authentication_from_hex")

    s = s.replace(
        'bool fscrypt_add_user_key_auth(userid_t user_id, int serial, const std::string& secret_hex) {',
        'bool fscrypt_add_user_key_auth(userid_t user_id, int serial, const std::string& token_hex, const std::string& secret_hex) {',
    )
    s = s.replace(
        'bool fscrypt_clear_user_key_auth(userid_t user_id, int serial, const std::string& secret_hex) {',
        'bool fscrypt_clear_user_key_auth(userid_t user_id, int serial, const std::string& token_hex, const std::string& secret_hex) {',
    )
    s = s.replace(
        'bool fscrypt_unlock_user_key(userid_t user_id, int serial, const std::string& secret_hex) {',
        'bool fscrypt_unlock_user_key(userid_t user_id, int serial, const std::string& token_hex, const std::string& secret_hex) {',
    )
    s = s.replace(
        'auto auth = authentication_from_hex(secret_hex);',
        'auto auth = authentication_from_hex(token_hex, secret_hex);',
    )
    s = s.replace(
        'fscrypt_unlock_user_key(0, 0, "!");',
        'fscrypt_unlock_user_key(0, 0, "!", "!");',
    )
    p.write_text(s)

def patch_keystorage_cpp(root):
    p = root / "KeyStorage.cpp"
    s = p.read_text()

    if '#include <keymasterV4_1/keymaster_utils.h>' not in s:
        s = s.replace(
            '#include <cutils/properties.h>\n',
            '#include <cutils/properties.h>\n#include <hardware/hw_auth_token.h>\n#include <keymasterV4_1/keymaster_utils.h>\n',
            1,
        )

    s = replace_once(
        s,
        'static constexpr size_t SECDISCARDABLE_BYTES = 1 << 14;\n',
        'static constexpr size_t SALT_BYTES = 1 << 4;\n'
        'static constexpr size_t SECDISCARDABLE_BYTES = 1 << 14;\n'
        'static constexpr size_t STRETCHED_BYTES = 1 << 6;\n',
        "KeyStorage.cpp constants",
    )

    s = replace_once(
        s,
        'static const char* kHashPrefix_secdiscardable = "Android secdiscardable SHA512";\n',
        'static const char* kStretch_none = "none";\n'
        'static const char* kStretch_nopassword = "nopassword";\n'
        'static const std::string kStretchPrefix_scrypt = "scrypt ";\n'
        'static const char* kHashPrefix_secdiscardable = "Android secdiscardable SHA512";\n',
        "KeyStorage.cpp stretching constants",
    )

    s = replace_once(
        s,
        'static const char* kFn_secdiscardable = "secdiscardable";\n'
        'static const char* kFn_version = "version";\n'
        '// Note: old key directories may contain a file named "stretching".',
        'static const char* kFn_salt = "salt";\n'
        'static const char* kFn_secdiscardable = "secdiscardable";\n'
        'static const char* kFn_stretching = "stretching";\n'
        'static const char* kFn_version = "version";',
        "KeyStorage.cpp filenames",
    )

    s = replace_once(
        s,
        '''static KeymasterOperation BeginKeymasterOp(Keymaster& keymaster, const std::string& dir,
                                           const km::AuthorizationSet& keyParams,
                                           const km::AuthorizationSet& opParams,
                                           km::AuthorizationSet* outParams) {''',
        '''static KeymasterOperation BeginKeymasterOp(Keymaster& keymaster, const std::string& dir,
                                           const km::AuthorizationSet& keyParams,
                                           const km::AuthorizationSet& opParams,
                                           km::AuthorizationSet* outParams,
                                           const KeyAuthentication* auth = nullptr) {''',
        "KeyStorage.cpp BeginKeymasterOp signature",
    )

    old_begin = '''    auto opHandle = keymaster.begin(blob, inParams, outParams);
    printf("[DEBUG] BeginKeymasterOp: keymaster.begin() returned, valid=%d\\n", (bool)opHandle);'''
    new_begin = '''    KeymasterOperation opHandle;
    if (auth != nullptr && !auth->token.empty()) {
        if (auth->token.size() != sizeof(hw_auth_token_t)) {
            LOG(ERROR) << "v21: unexpected HAT size " << auth->token.size()
                       << ", expected " << sizeof(hw_auth_token_t);
            return KeymasterOperation();
        }
        auto hat = ::android::hardware::keymaster::V4_1::support::hidlVec2AuthToken(
                ::android::hardware::keymaster::V4_1::support::blob2hidlVec(auth->token));
        LOG(INFO) << "v21: supplying Gatekeeper HAT directly to Keymaster";
        opHandle = keymaster.begin(blob, inParams, outParams, hat);
    } else {
        opHandle = keymaster.begin(blob, inParams, outParams);
    }
    printf("[DEBUG] BeginKeymasterOp: keymaster.begin() returned, valid=%d\\n", (bool)opHandle);'''
    s = replace_once(s, old_begin, new_begin, "KeyStorage.cpp direct HAT")

    s = replace_once(
        s,
        '''static bool decryptWithKeymasterKey(Keymaster& keymaster, const std::string& dir,
                                    const km::AuthorizationSet& keyParams,
                                    const std::string& ciphertext, KeyBuffer* message) {''',
        '''static bool decryptWithKeymasterKey(Keymaster& keymaster, const std::string& dir,
                                    const km::AuthorizationSet& keyParams,
                                    const KeyAuthentication& auth,
                                    const std::string& ciphertext, KeyBuffer* message) {''',
        "KeyStorage.cpp decrypt signature",
    )
    s = replace_once(
        s,
        'auto opHandle = BeginKeymasterOp(keymaster, dir, keyParams, opParams, nullptr);',
        'auto opHandle = BeginKeymasterOp(keymaster, dir, keyParams, opParams, nullptr, &auth);',
        "KeyStorage.cpp decrypt begin",
    )

    insert_before = '\nstatic void logOpensslError()'
    idx = s.find(insert_before)
    if idx < 0:
        raise SystemExit("KeyStorage.cpp logOpensslError marker missing")

    legacy_helpers = r'''
static bool v21StretchSecret(const std::string& stretching, const std::string& secret,
                             const std::string& salt, std::string* stretched) {
    if (stretching == kStretch_nopassword) {
        stretched->clear();
    } else if (stretching == kStretch_none) {
        *stretched = secret;
    } else if (stretching.rfind(kStretchPrefix_scrypt, 0) == 0) {
        int Nf, rf, pf;
        if (!parse_scrypt_parameters(
                stretching.substr(kStretchPrefix_scrypt.size()).c_str(), &Nf, &rf, &pf)) {
            LOG(ERROR) << "v21: unable to parse scrypt params: " << stretching;
            return false;
        }
        stretched->assign(STRETCHED_BYTES, '\0');
        if (crypto_scrypt(reinterpret_cast<const uint8_t*>(secret.data()), secret.size(),
                          reinterpret_cast<const uint8_t*>(salt.data()), salt.size(),
                          1 << Nf, 1 << rf, 1 << pf,
                          reinterpret_cast<uint8_t*>(&(*stretched)[0]),
                          stretched->size()) != 0) {
            LOG(ERROR) << "v21: scrypt failed: " << stretching;
            return false;
        }
    } else {
        LOG(ERROR) << "v21: unknown stretching type: " << stretching;
        return false;
    }
    return true;
}

static bool v21GenerateLegacyAppId(const KeyAuthentication& auth,
                                   const std::string& stretching,
                                   const std::string& salt,
                                   const std::string& secdiscardable_hash,
                                   std::string* appId) {
    std::string stretched;
    if (!v21StretchSecret(stretching, auth.secret, salt, &stretched)) return false;
    *appId = secdiscardable_hash + stretched;
    LOG(INFO) << "v21: legacy CE appId generated; token_present=" << !auth.token.empty()
              << " stretching=" << stretching;
    return true;
}
'''
    s = s[:idx] + "\n" + legacy_helpers + s[idx:]

    old_app = '    std::string appId = generateAppId(auth, secdiscardable_hash);\n'
    idx = s.rfind(old_app)
    if idx < 0:
        raise SystemExit("KeyStorage.cpp retrieve appId missing")
    new_app = '''    std::string appId;
    const std::string stretching_file = dir + "/" + kFn_stretching;
    if (pathExists(stretching_file)) {
        std::string stretching;
        if (!readFileToString(stretching_file, &stretching)) return false;
        std::string salt;
        if (stretching != kStretch_nopassword && stretching != kStretch_none) {
            if (!readFileToString(dir + "/" + kFn_salt, &salt)) return false;
        }
        if (!v21GenerateLegacyAppId(auth, stretching, salt, secdiscardable_hash, &appId))
            return false;
    } else {
        appId = generateAppId(auth, secdiscardable_hash);
    }
'''
    s = s[:idx] + new_app + s[idx + len(old_app):]

    s = replace_once(
        s,
        'if (!decryptWithKeymasterKey(keymaster, dir, keyParams, encryptedMessage, key)) {',
        'if (!decryptWithKeymasterKey(keymaster, dir, keyParams, auth, encryptedMessage, key)) {',
        "KeyStorage.cpp retrieve decrypt",
    )
    p.write_text(s)

def patch_decrypt_cpp(root):
    p = root / "Decrypt.cpp"
    s = p.read_text()

    old = '''bool Decrypt_CE_storage(const userid_t user_id, int token, const std::string& secret) {
\tprintf("Attempting to unlock user storage\\n");
\tint flags = android::os::IVold::STORAGE_FLAG_CE;
\tif (!fscrypt_unlock_user_key(user_id, token, secret)) {'''
    new = '''bool Decrypt_CE_storage(const userid_t user_id, const std::string& token, const std::string& secret) {
\tprintf("Attempting to unlock user storage\\n");
\tint flags = android::os::IVold::STORAGE_FLAG_CE;
\tif (!fscrypt_unlock_user_key(user_id, 0, token, secret)) {'''
    s = replace_once(s, old, new, "Decrypt.cpp CE wrapper")

    s = replace_once(
        s,
        'int token = 0; // there is no token used for this kind of decrypt, key escrow is handled by weaver',
        'std::string token = "!"; // v21 raw Gatekeeper HAT, hex encoded',
        "Decrypt.cpp token declaration",
    )

    s = replace_once(
        s,
        '[&gkResponse]\n',
        '[&gkResponse, &token]\n',
        "Decrypt.cpp callback capture",
    )

    needle = '''\t\t\t\t\t\t\t\t\t\t\tgkResponse = GKResponse::ok({rsp.data.begin(), rsp.data.end()});
\t\t\t\t\t\t\t\t\t\t\tconst hw_auth_token_t* hwAuthToken ='''
    repl = '''\t\t\t\t\t\t\t\t\t\t\tgkResponse = GKResponse::ok({rsp.data.begin(), rsp.data.end()});
\t\t\t\t\t\t\t\t\t\t\tstatic const char hexchars[] = "0123456789ABCDEF";
\t\t\t\t\t\t\t\t\t\t\ttoken.clear();
\t\t\t\t\t\t\t\t\t\t\ttoken.reserve(rsp.data.size() * 2);
\t\t\t\t\t\t\t\t\t\t\tfor (uint8_t b : rsp.data) {
\t\t\t\t\t\t\t\t\t\t\t\ttoken.push_back(hexchars[(b >> 4) & 0xF]);
\t\t\t\t\t\t\t\t\t\t\t\ttoken.push_back(hexchars[b & 0xF]);
\t\t\t\t\t\t\t\t\t\t\t}
\t\t\t\t\t\t\t\t\t\t\tprintf("v21: captured Gatekeeper HAT (%zu bytes) for CE Keymaster\\n", rsp.data.size());
\t\t\t\t\t\t\t\t\t\t\tconst hw_auth_token_t* hwAuthToken ='''
    s = replace_once(s, needle, repl, "Decrypt.cpp HAT capture")

    s = s.replace(
        'Decrypt_CE_storage(user_id, 0, "!")',
        'Decrypt_CE_storage(user_id, "!", "!")',
    )

    # Legacy non-synthetic path already computes token_hex. Use it rather than dropping it.
    legacy = 'if (!Decrypt_CE_storage(user_id, 0, secret)) {'
    if legacy in s:
        s = s.replace(
            legacy,
            'if (!Decrypt_CE_storage(user_id, std::string(token_hex), secret)) {',
            1,
        )

    p.write_text(s)

def main():
    if len(sys.argv) != 2:
        raise SystemExit("usage: patch_v21.py /path/to/system/vold")
    root = Path(sys.argv[1])
    patch_keystorage_h(root)
    patch_fscrypt_h(root)
    patch_fscrypt_cpp(root)
    patch_keystorage_cpp(root)
    patch_decrypt_cpp(root)
    print("v21 source patch applied")

if __name__ == "__main__":
    main()
