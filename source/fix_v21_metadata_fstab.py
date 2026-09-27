#!/usr/bin/env python3
from pathlib import Path
import sys
p = Path(sys.argv[1])
s = p.read_text()
old = 'if (android::vold::fscrypt_mount_metadata_encrypted(Decrypt_Data->Actual_Block_Device, Decrypt_Data->Mount_Point, false, false, Decrypt_Data->Current_File_System)) {'
new = 'if (android::vold::fscrypt_mount_metadata_encrypted(Decrypt_Data->Actual_Block_Device, Decrypt_Data->Mount_Point, false, false, Decrypt_Data->Current_File_System, "/etc/recovery.fstab")) {'
count = s.count(old)
if count != 1:
    raise SystemExit(f"fix11: expected exactly one metadata decrypt call, found {count}")
p.write_text(s.replace(old, new, 1))
print('fix11: metadata decrypt will use /etc/recovery.fstab explicitly')
