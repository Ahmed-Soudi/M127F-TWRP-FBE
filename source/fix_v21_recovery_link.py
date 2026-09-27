#!/usr/bin/env python3
from pathlib import Path
import sys

p = Path(sys.argv[1])
s = p.read_text()

needle = """        libgatekeeper_aidl

    LOCAL_STATIC_LIBRARIES += libkeymint_support
"""

replacement = """        libgatekeeper_aidl \\
        android.hardware.keymaster@4.0 \\
        android.hardware.keymaster@4.1 \\
        libkeymaster4support \\
        libkeymaster4_1support

    LOCAL_STATIC_LIBRARIES += libkeymint_support
"""

if needle not in s:
    raise SystemExit("fix10: expected recovery crypto shared-lib block not found")

p.write_text(s.replace(needle, replacement, 1))
print("fix10: added Keymaster 4.0/4.1 and support libs to recovery link")
