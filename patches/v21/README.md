# v21 — HAT → CE Keymaster bridge

This folder is intentionally the v21 implementation point.

The v20 logs prove that the CE `keymaster_key_blob` path is reached, but Samsung
Keymaster returns `-26` (`auth required but no token`).  The v21 change must retain
the Gatekeeper HardwareAuthToken from the synthetic-password verification path and
make it available to the CE key retrieval / Keymaster operation.

The workflow already knows how to produce full flashable `.img` artifacts.  Once
`apply.py` contains the verified binary/source-equivalent patch, selecting `v21`
will emit the complete recovery image, not merely a patch file.
