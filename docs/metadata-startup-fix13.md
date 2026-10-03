# Metadata startup: fix13 evidence and validation

Fix13 prepares a native fs_mgr fstab, waits for registered crypto services, and
retries retrieval of the existing metadata key before creating a mapper. This
change has not been validated on the phone. Metadata decryption, `/data` mounting,
and CE decryption remain runtime acceptance criteria.

## What the supplied logs establish

References below name files in the original context bundle's `logs/` directory.

| Event | Known-good `v20_logcat.txt` | Latest `Pasted text(20260927-044327).txt` |
|---|---|---|
| Metadata function entry | 17:58:20.603, line 6629 | 04:37:16.575, line 10 |
| Samsung Keymaster starts | 17:58:26.092, line 7473 | 04:37:22.095, line 32 |
| Keymaster registers | 17:58:26.177, line 7617 | 04:37:22.178, line 82 |
| DXJ1 bootstrap ready marker | 17:58:33.447, line 7887 | 04:37:29.453, line 106 |
| Metadata blob read | 17:58:33.623, line 7893 | Absent from supplied filtered capture |
| `/data` mount | Successful, line 7999 | No mount; only dm-0 through dm-3, lines 109–114 |

Both versions enter metadata decryption before the crypto stack is ready. Their
entry-to-bootstrap intervals are almost identical: 12.844 seconds for v20 and
12.878 seconds for the latest capture. The handoff's claim that v20 enters this
function only after service startup is incorrect.

In v20 the existing metadata directory and key retrieval are logged immediately
at lines 6630 and 6633–6634. Recovery then waits inside the AIDL-backed Keymaster
path for `android.system.keystore2.IKeystoreService/default`; repeated waits are
visible at lines 6933, 7856 and 7862. Keystore registers at line 7885, then the
metadata blob is read. Moving metadata operations to direct HIDL removes this
particular AIDL wait, so explicit synchronization is appropriate.

The latest capture is filtered and has no `metadata_key_dir/key`, key-retrieval,
or blob-read marker. It cannot identify the exact return branch or source commit.
The handoff reports the failure as tested through fix11. The displayed September
27 04:37 device timestamp and fix11's roughly 05:00 workflow timestamp do not
conclusively identify the image without aligned clocks and an image hash.
Fix12 remains unconfirmed by the supplied runtime evidence. The standalone
`v21-recovery.txt` and `v21-logcat.txt` describe an older September 25 build,
including the already-investigated theme mismatch.

The latest capture does establish that `/metadata` mounts from mmcblk0p28
(line 235), the existing metadata key files are present (lines 239–245), and
TWRP's `/data` record contains the expected crypto settings (line 220). File
presence does not establish that key retrieval succeeds. Likewise,
`ro.crypto.metadata.encrypted=1` describes encryption state, not a working mapper.

## Definite fix11 parser incompatibility

Fix11 passes `/etc/recovery.fstab` to the direct-HIDL fork's
`fscrypt_mount_metadata_encrypted()`. That function calls Android
`ReadFstabFromFile()`, then looks up `/data` and its native encryption fields.
The supplied file instead uses TWRP's mount-point-first columns and semicolon
`flags=...` options. It is valid input for TWRP's partition parser but is not
the five-column Android fs_mgr record required at this call site. Waiting for
services cannot repair that mismatch. Generic init/default-fstab errors are
also present in working v20, so those errors alone were not evidence of this
specific failure.

Fix13 writes and round-trip validates a dedicated `/tmp/v21-metadata.fstab`.
An example native record with the existing device settings is:

```text
/dev/block/by-name/userdata /data f2fs rw,inlinecrypt fileencryption=aes-256-xts:aes-256-cts:v2,keydirectory=/metadata/vold/metadata_encryption,metadata_encryption=aes-256-xts
```

The implementation uses TWRP's actual resolved block device (currently
`/dev/block/mmcblk0p38`), existing numeric mount flags, read-only state and
filesystem mount options. The five fields are device,
mount point, filesystem, mount options, and comma-separated fs_mgr options.
The stock/TWRP fstab and all existing key files are preserved.

## Synchronization and retry boundaries

`init.svc.*=running` is only a process-state check. In v20, keystore starts at
17:58:31.325 (line 7822) but registers at 17:58:33.401 (line 7885), over two
seconds later. The fix13 polling loop checks both process state and actual
registration of Keymaster 4.0/default, Gatekeeper 1.0/default, and the keystore2
AIDL service, with a 20-second polling deadline and 250 ms poll interval. It
checks `hwservicemanager.ready=true` and both service-manager process states
before entering service accessors, which can otherwise wait internally during
manager startup. Timeout skips
metadata decryption and reports states; it does not proceed as though ready.

Registration is a prerequisite, not proof of a successful Keymaster operation.
The deadline bounds polling and sleeps; it cannot interrupt a stalled Binder or
HAL call after a registered service crashes or stops responding. The existing
crypto operations retain their platform IPC behavior.
The bounded retry is restricted to retrieving/decrypting the existing
metadata key, with three attempts before mapper creation. It must not retry
the entire mount function after mapper or filesystem side effects. Missing
keys fail closed: no key generation, deletion, replacement, or formatting.
CE/HAT logic is unchanged while metadata startup is under investigation.

## Runtime acceptance and Windows CMD capture

First check native-fstab validation and registered-service markers, then the
metadata blob read, dm-4 creation, `/data` mount, DE initialization, and automatic
PIN page. Only after these succeed, enter the PIN once and check the safe
markers `captured Gatekeeper HAT (... bytes)`, `legacy CE appId generated`, and
`supplying Gatekeeper HAT directly to Keymaster`. HAT marker presence alone does
not prove user 0 CE decryption.

Preserve evidence before any reboot. These are Windows CMD commands; remote
operations only read state. The first copy retains the recovery log privately
on the PC without printing its contents. Share filtered evidence, not raw
credential-bearing logs or key files. The logcat command deliberately selects
known status messages instead of saving or displaying unfiltered logcat.

```bat
mkdir M127F_FIX13_LOGS
adb pull /tmp/recovery.log M127F_FIX13_LOGS\recovery-private.log
adb shell "cat /tmp/recovery.log | grep -iE 'v21:|Successfully decrypted metadata|Unable to decrypt metadata|User 0 is not decrypted|Successfully decrypted user|Failed to decrypt user|Attempting to decrypt FBE'" > M127F_FIX13_LOGS\recovery-status.txt
adb shell "logcat -d | grep -iE 'recovery: (fscrypt_mount_metadata_encrypted:|metadata_key_dir/key:|Key exists, using:|Retrieving key from keymaster|reading blob_file:|v21:)|DXJ1-crypto-v16: TEE, Keymaster, Gatekeeper, and keystore2 are running|LegacySupport: Registration complete for android.hardware.gatekeeper|HidlServiceManagement: Registered android.hardware.keymaster|keystore2_main: Successfully registered Keystore 2.0 service|Failed to open .*Fstab|Failed to get data_rec'" > M127F_FIX13_LOGS\crypto-status.txt
adb shell "mount | grep -E ' /(data|metadata) '; ls -l /dev/block/dm-*; getprop twrp.user.0.decrypt; getprop twrp.all.users.decrypted; getprop ro.crypto.fs_crypto_blkdev; getprop init.svc.dxj1_keymaster; getprop init.svc.dxj1_gatekeeper; getprop init.svc.keystore2" > M127F_FIX13_LOGS\mount-services.txt
adb shell "cat /tmp/v21-metadata.fstab; ls -l /metadata/vold/metadata_encryption/key" > M127F_FIX13_LOGS\metadata-status.txt
```

Retain the tested image filename and SHA256 alongside these captures. No
runtime log or image hash supplied so far establishes that fix13 restored
metadata or CE decryption.
