# M127F-TWRP-FBE

Reproducible recovery-image workspace for the Samsung Galaxy M12 **SM-M127F**,
stock **Android 13**, focused on decrypting the existing FBE `/data` partition
without formatting it.

## Current baseline

`v20` is stored as split binary parts so every repository file stays below the
GitHub web-upload limit. The workflow reassembles those pieces, validates the
known checksum, and emits the **complete flashable `.img`**.

Known v20:

- Size: `54814720` bytes
- SHA-256: `9d8e4c6889adc7381cc1edc35e12ff4460672324216face7a551ade30b4f5a74`
- File: `M127F_DXJ1_TWRP_crypto_test_v20_ce_keymaster_fast_pin.img`

The v20 lineage includes the working EFS mapping correction, Samsung
TEE/Keymaster/Gatekeeper/Keystore2 startup, legacy `scrypt 15:3:1` handling, and
the faster PIN-screen path.

## v21 target

v20 reaches Samsung Keymaster for the CE `keymaster_key_blob`, but the operation
fails with `-26` / `auth required but no token`.

The v21 target is therefore narrowly scoped:

1. preserve the Gatekeeper HardwareAuthToken returned during synthetic-password verification;
2. carry that HAT to the CE KeyStorage/Keymaster retrieval path;
3. preserve all v20 fixes;
4. emit a complete recovery `.img`.

`patches/v21/apply.py` is deliberately a fail-closed scaffold right now. It will
not pretend to build a valid v21 until the HAT propagation patch is implemented
and verified.

## Build from GitHub Actions

Open **Actions → Build M127F TWRP image → Run workflow** and enter:

```text
v20
```

The job creates an artifact containing:

```text
M127F_DXJ1_TWRP_crypto_test_v20_ce_keymaster_fast_pin.img
SHA256SUMS.txt
build-info.json
```

For permanent downloads, push a tag such as `v20`. The workflow will create a
GitHub Release and attach the complete image.

## Local build

```bash
python3 scripts/build_image.py --version v20
```

Output is written to `dist/`.

## Safety

This project is for recovery development. It must not delete or reset EFS,
Gatekeeper state, locksettings, synthetic-password blobs, Keymaster blobs, or
CE key files as a decryption workaround.
