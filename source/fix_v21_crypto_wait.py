#!/usr/bin/env python3
from pathlib import Path
import sys

p = Path(sys.argv[1])
s = p.read_text()

needle = '\t\t\tif (android::vold::fscrypt_mount_metadata_encrypted(Decrypt_Data->Actual_Block_Device, Decrypt_Data->Mount_Point, false, false, Decrypt_Data->Current_File_System, "/etc/recovery.fstab")) {'

wait = '''\t\t\tLOGINFO("v21: waiting for crypto services before metadata decrypt\\n");
\t\t\tfor (int i = 0; i < 60; ++i) {
\t\t\t\tconst std::string km = android::base::GetProperty("init.svc.dxj1_keymaster", "");
\t\t\t\tconst std::string gk = android::base::GetProperty("init.svc.dxj1_gatekeeper", "");
\t\t\t\tconst std::string ks = android::base::GetProperty("init.svc.keystore2", "");
\t\t\t\tif (km == "running" && gk == "running" && ks == "running") {
\t\t\t\t\tLOGINFO("v21: crypto services ready after %d ms\\n", i * 250);
\t\t\t\t\tbreak;
\t\t\t\t}
\t\t\t\tif (i == 59) {
\t\t\t\t\tLOGINFO("v21: crypto wait timeout km=%s gk=%s ks=%s\\n",
\t\t\t\t\t\tkm.c_str(), gk.c_str(), ks.c_str());
\t\t\t\t}
\t\t\t\tusleep(250000);
\t\t\t}
'''

if needle not in s:
    raise SystemExit("fix12: metadata decrypt call not found; fix11 must be present")

p.write_text(s.replace(needle, wait + needle, 1))
print("fix12: added crypto-service wait before metadata decryption")
