#!/usr/bin/env python3
from pathlib import Path
import sys

def replace_once(s, old, new, label):
    n = s.count(old)
    if n != 1:
        raise SystemExit(f"{label}: expected exactly 1 match, found {n}")
    return s.replace(old, new, 1)

def main():
    if len(sys.argv) != 2:
        raise SystemExit("usage: fix_v21_vold_native.py /path/to/system/vold")
    p = Path(sys.argv[1]) / "VoldNativeService.cpp"
    s = p.read_text()

    # Android 12 upstream removed HAT support and rejects non-empty token
    # parameters. v21 restores token+secret plumbing, so remove those guards.
    blocks = [
        "    if (!token_empty(token)) {\n"
        "        LOG(ERROR) << \"Vold doesn't use auth tokens, but non-empty token passed to addUserKeyAuth.\";\n"
        "        return binder::Status::fromServiceSpecificError(-EINVAL);\n"
        "    }\n\n",

        "    if (!token_empty(token)) {\n"
        "        LOG(ERROR)\n"
        "                << \"Vold doesn't use auth tokens, but non-empty token passed to clearUserKeyAuth.\";\n"
        "        return binder::Status::fromServiceSpecificError(-EINVAL);\n"
        "    }\n\n",

        "    if (!token_empty(token)) {\n"
        "        LOG(ERROR) << \"Vold doesn't use auth tokens, but non-empty token passed to unlockUserKey.\";\n"
        "        return binder::Status::fromServiceSpecificError(-EINVAL);\n"
        "    }\n\n",
    ]
    for block in blocks:
        if block in s:
            s = s.replace(block, "", 1)

    s = replace_once(
        s,
        "return translateBool(fscrypt_add_user_key_auth(userId, userSerial, secret));",
        "return translateBool(fscrypt_add_user_key_auth(userId, userSerial, token, secret));",
        "addUserKeyAuth",
    )
    s = replace_once(
        s,
        "return translateBool(fscrypt_clear_user_key_auth(userId, userSerial, secret));",
        "return translateBool(fscrypt_clear_user_key_auth(userId, userSerial, token, secret));",
        "clearUserKeyAuth",
    )
    s = replace_once(
        s,
        "return translateBool(fscrypt_unlock_user_key(userId, userSerial, secret));",
        "return translateBool(fscrypt_unlock_user_key(userId, userSerial, token, secret));",
        "unlockUserKey",
    )

    # After the three guards above are removed, this helper has no callers.
    # The tree builds with -Werror, so leaving it triggers -Wunused-function.
    helper = (
        "static bool token_empty(const std::string& token) {\n"
        "    return token.size() == 0 || token == \"!\";\n"
        "}\n\n"
    )
    if helper in s:
        s = s.replace(helper, "", 1)

    p.write_text(s)
    print("v21 fix3: restored token plumbing and removed unused token_empty helper")

if __name__ == "__main__":
    main()
