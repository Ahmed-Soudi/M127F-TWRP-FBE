These are byte-exact upstream source fixtures for offline patch regression
tests. Their Git blob hashes were checked against GitHub.

Fix14 additionally uses `4accccc/android_system_vold` commit
`c20fb263dd56dd6e73a48ba5ba7ee8982ab1cf9f`:

- `Keymaster.cpp`: Git blob `c3c230c793501db721854c11082a361980e05955`.
- `Keymaster.h`: Git blob `0e4d01a00081b31e2fb469cf203933cb70764b0a`.
- `KeyStorage.cpp`: Git blob `d1f4203c82169853041b82fa8f0a3f2ccd2749a8`.

The KeyStorage fixture is pristine upstream; tests first apply the original
`source/patch_v21.py` CE/HAT patch, whose SHA256 is
`efb7fd94b9a18df506fd14e24d55ebf165521e71e5e564c0108fa78c873e9507`.
That SHA256 was checked against the user's original context ZIP.

- `partitionmanager.cpp`: TeamWin/android_bootable_recovery, commit
  `dbed985d1ccb9412fd19171a3ecfb621bb9d0a6b`; SHA256
  `554fa070abe1fb942fe9f464f53bae78bb50c52960a14d12f3db9711fc2c2624`;
  Git blob `8181c30285095f9100756a35edb995a59cdd56d4`.
- `MetadataCrypt.cpp`: 4accccc/android_system_vold, `twrp-12.1` source used by
  the v21 workflow; SHA256
  `f348fadb4f96a0e924611860565fd98b7c80c3ca51fc518300b10a3236a3ee8f`;
  Git blob `dd6d8803e4a876965d244f73105b3c94d047f31b`.

The upstream copyright/license headers are preserved. Tests never contact the
network or touch a device. The fixtures let patch anchors and unaffected CE
code be checked against complete source, rather than synthetic examples.
