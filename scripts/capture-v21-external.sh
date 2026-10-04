#!/system/bin/sh
# Run manually in TWRP after mounting the external SD. Saves status only.
if [ ! -s /tmp/recovery.log ]; then
    echo 'Run this script in TWRP Advanced > Terminal.'
    exit 1
fi
if ! grep -q ' /external_sd ' /proc/mounts; then
    echo 'Mount the external SD in TWRP, then run this script again.'
    exit 1
fi
umask 077
events='Starting TWRP|v21:.*(metadata|crypto)|decrypt.*metadata|metadata.*decrypt|failed to mount.*data|unable to mount.*data|fscrypt_mount_metadata_encrypted:|metadata_key_dir/key:|Key exists, using:|Retrieving key from keymaster|reading blob_file:|Failed to open .*Fstab|Failed to get data_rec|fs_mgr_do_mount failed|Could not create default-key device|Unable to parse encryption options|Unknown options_format_version|BeginKeymasterOp:|decryptWithKeymasterKey:|retrieveKey:|\[Keymaster\] (Constructor:|begin|upgradeKey|updateCompletely:|finish:)|Attempting to decrypt FBE|User 0 is not decrypted|fscrypt_initialize_systemwide_keys|fscrypt_init_user0|fscrypt::load_all_de_keys::retrieveKey|fscrypt_prepare_user_storage|fscrypt_unlock_user_key|Failed to find working ce key'
services='DXJ1-crypto-v16:.*running|Registration complete for android.hardware.gatekeeper|Registered android.hardware.keymaster|Successfully registered Keystore 2.0 service'
if ! printf '' > /external_sd/fix13-status.txt; then
    echo 'Cannot write /external_sd/fix13-status.txt; keep this session open.'
    exit 1
fi
{
    echo 'M127F v21 external SD recovery capture v1'
    date
    echo 'RECOVERY'
    grep -iE "$events" /tmp/recovery.log
    echo 'LOGCAT'
    logcat -d -v threadtime | grep -iE "$events|$services"
    echo 'MOUNTS'
    grep -E ' /(data|metadata|cache|external_sd) ' /proc/mounts
    echo 'MAPPER NODES'
    ls -l /dev/block/dm-*
    echo 'PROPERTIES'
    for p in hwservicemanager.ready init.svc.hwservicemanager init.svc.servicemanager init.svc.dxj1_keymaster init.svc.dxj1_gatekeeper init.svc.keystore2 ro.crypto.fs_crypto_blkdev ro.crypto.state twrp.user.0.decrypt twrp.all.users.decrypted fbe.contents fbe.filenames metadata.contents metadata.filenames; do
        echo "$p=$(getprop "$p")"
    done
    echo 'NATIVE FSTAB'
    cat /tmp/v21-metadata.fstab
    echo 'INPUT DATA FSTAB'
    grep -E '(^|[[:space:]])/data([[:space:]]|$)' /etc/recovery.fstab /etc/twrp.flags
} >> /external_sd/fix13-status.txt 2>&1
if [ ! -s /external_sd/fix13-status.txt ]; then
    echo 'Capture failed; keep this recovery session open.'
    exit 1
fi
sync
echo 'Saved /external_sd/fix13-status.txt'
wc -c /external_sd/fix13-status.txt
