# v21 source build

Use **Actions → Build v21 source recovery → Run workflow**.

The workflow compiles a patched TWRP 12.1 `recovery` executable, then injects it
into the known-good v20 image. It keeps the v20 kernel, DTB/DTBO, Samsung crypto
bootstrap, EFS mapping and fast-PIN ramdisk changes.

The v21 source patch restores:
- Gatekeeper HAT propagation into CE Keymaster operations;
- token + secret `KeyAuthentication` semantics;
- legacy `scrypt 15:3:1` appId derivation required by this Android 13 CE key.

The artifact is the complete flashable image:
`M127F_DXJ1_TWRP_crypto_test_v21_hat_ce_auth.img`.
