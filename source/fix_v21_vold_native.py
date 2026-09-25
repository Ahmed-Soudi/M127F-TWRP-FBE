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

    p.write_text(s)
    print("v21 fix2: patched VoldNativeService token plumbing")

if __name__ == "__main__":
    main()
