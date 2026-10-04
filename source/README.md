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
`M127F_DXJ1_TWRP_crypto_test_v21_fix14_storage_key_compat.img`.

Fix13 changes only metadata startup: a parser-validated native fstab in `/tmp`,
registered-service checks with a 20-second polling deadline, and three attempts
to retrieve the existing metadata key before any mapper creation. Missing keys
fail closed; the recovery metadata path cannot generate/delete keys or format data.
Registration is a prerequisite, not proof that a Keymaster operation will succeed.

The fix13 device capture reached Samsung Keymaster and failed with
`INVALID_KEY_BLOB (-33)` before mapper creation. Fix14 adds a separate
metadata/DE begin method: recognized hardware compatibility headers are removed
in memory before raw HIDL calls, and application binding is retained during key
upgrades. Unprefixed blobs pass through unchanged; software or malformed
compatibility wrappers fail closed. Both original begin methods and all CE/HAT
behavior remain unchanged. Upgraded blobs retain their original wrapper format
for the existing temporary `/tmp` scratch path; persisted key files are untouched.
See [the evidence and phone capture steps](../docs/metadata-keyblob-fix14.md).

The workflow pins direct-HIDL vold to
`c20fb263dd56dd6e73a48ba5ba7ee8982ab1cf9f`. The existing CE/HAT source patch
and recovery UI pin are preserved. The repacker verifies the v20 checksum and
checks that only the recovery executable changes in the ramdisk.

Local regression checks: `python3 -m unittest discover -s tests -v`.
These compile production startup helpers with simulated Android services; the
workflow performs the full Android executable build and verified v20 repack.
