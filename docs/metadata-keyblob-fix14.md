# v21 fix14: metadata and DE key compatibility

## Fresh device evidence

The fix13 external-SD capture was supplied on 2026-10-04. Its TWRP startup
header records 21:16:35; logcat uses 16:16:35. The timestamp difference does not
affect the event ordering:

- Native `/tmp/v21-metadata.fstab` validation succeeds.
- The crypto services register after 13,266 ms. Keymaster, Gatekeeper,
  keystore2, and both service managers are running.
- `/metadata` and `/cache` mount. `/data` does not mount.
- The existing metadata key is readable: version 1, application ID length 64,
  encrypted message length 92, and stored keymaster blob length 546.
- Samsung `SKeymaster(Keymaster MDFPP)` is found through the default HIDL 4.0
  service. All three metadata retrieval attempts fail at hardware `begin`
  with error `-33`, before update or finish.
- There are only `dm-0` through `dm-3`. `ro.crypto.fs_crypto_blkdev` is empty.
- The validated row is `/data`, f2fs, `rw,inlinecrypt`,
  `fileencryption=aes-256-xts:aes-256-cts:v2`,
  `keydirectory=/metadata/vold/metadata_encryption`, and
  `metadata_encryption=aes-256-xts`.

Keymaster `-33` is `INVALID_KEY_BLOB`, not a password failure. The fstab and
readiness markers establish that this capture passed the two startup gates.
They do not establish successful metadata or user decryption.

## Compatibility boundary

Working v20 calls through keystore2. Its known-good log reads the same metadata
blob, performs a successful Samsung begin, logs an in-memory key upgrade, and
then completes update/finish. The direct-HIDL fork forwards the stored blob
unchanged to the hardware service.

The Android 12L KeyMint compatibility layer uses a seven-byte public magic
`pKMblob` followed by an origin byte: 0 for hardware and 1 for software. It
removes recognized headers before hardware begin/upgrade calls and restores
the hardware header around returned upgraded blobs. Raw older blobs pass
through unchanged. A subsequent read-only check from Android confirmed the
hardware wrapper on the stored metadata blob. The check printed only
`KeyMint hardware wrapper present`; no blob bytes were disclosed. The patch
still recognizes the header explicitly rather than assuming every blob is wrapped.

The hardware upgrade contract also requires application binding parameters.
The fork's original no-auth begin retries an upgrade with empty parameters,
although this metadata key is bound to a 64-byte application ID. This second
gap matters because v20 reported a key upgrade on the metadata path.

Pinned references:

- [KeyMint compatibility source](https://github.com/LineageOS/android_system_security/blob/d8fbb1f86c7405ddaa55dce780f18f5ec19f0422/keystore2/src/km_compat/km_compat.cpp):
  git blob `2c565c614e2ca4df00e532bf956f0f96cc0320cf`.
- [Hardware Keymaster upgrade contract](https://github.com/LineageOS/android_hardware_interfaces/blob/ae469cee0dce6d71489588126a15da8e67a50102/keymaster/4.0/IKeymasterDevice.hal):
  git blob `dfde060e3f5b5733c8d62b011c515af26e6d2246`.

## Scope and safety

`source/fix_v21_storage_key_compat.py` adds a separate metadata/DE begin method.
Only no-token calls for `/metadata/vold/metadata_encryption/key`,
`/data/unencrypted/key`, and numeric children of
`/data/misc/vold/user_keys/de/` select it. Both original Keymaster begin
methods, the HAT branch, CE path selection, and `source/patch_v21.py` remain
unchanged.

Recognized hardware wrappers are removed from a memory copy. Genuine
unprefixed blobs are unchanged. Software, malformed, truncated, or empty
compatibility wrappers are rejected before any hardware call. No failed
`INVALID_KEY_BLOB` call is converted into an upgrade attempt.

If hardware returns `KEY_REQUIRES_UPGRADE (-62)`, only `APPLICATION_ID` and
`APPLICATION_DATA` are retained as upgrade parameters. Hardware receives raw
blob bytes; a successful upgraded blob is retried in memory and its original
wrapper format is restored for the existing `/tmp` scratch write. Persisted
key blobs and credentials are not rewritten. No raw HAT or key bytes are logged.

Fix13's existing-key retrieval, native-fstab validation, registration wait,
and three pre-mapper attempts remain in place. The v20 repack base and its
checksum requirements are unchanged.

## Completed build

[Run 37237197492](https://github.com/Ahmed-Soudi/M127F-TWRP-FBE/actions/runs/37237197492)
completed successfully from source commit
`4971d8167aabd5b2f691f1d49fa0945d18efa49a`. All 44 regression tests, the
full Android recovery compile, checksum-verified v20 reassembly, executable-only
repack, and artifact upload passed.

[Download the fix14 artifact](https://github.com/Ahmed-Soudi/M127F-TWRP-FBE/actions/runs/37237197492/artifacts/11316913858).
It contains one flashable image, `SHA256SUMS.txt`, and the debug executable
`recovery-v21.elf`.

- Image: `M127F_DXJ1_TWRP_crypto_test_v21_fix14_storage_key_compat.img`.
- Image size: 54,944,884 bytes.
- Image SHA-256: `febd5de30b07304e0909f76af5b05c1fe7d26aab7a68054b001d9691ec66da8b`.
- v20 base SHA-256: `9d8e4c6889adc7381cc1edc35e12ff4460672324216face7a551ade30b4f5a74`.

Device decryption and the automatic PIN page still require the phone test.

## Phone-only capture

Save [the external-SD capture script](../scripts/capture-v21-external.sh) as
`capture-v21-external.sh` in the card's top-level folder in Android.
In TWRP, mount **Micro SDcard**, then use **Advanced -> Terminal** to run it
before a manual password attempt:

```sh
sh /external_sd/capture-v21-external.sh
```

The previously supplied fix13 external capture script also selects the fix14
metadata diagnostics and can be reused under its existing filename.

After the script reports a saved nonempty status file, reboot Android. In
Termux enter `su` separately, then read:

```sh
cat /storage/*/fix13-status.txt
```

Accept metadata only after the wrapper classification and hardware result
markers lead to mapper creation and `/data` mounting. DE initialization and
the automatic PIN page must follow. Only then test the existing CE/HAT path.
Compilation and repack verification alone do not establish device success.
