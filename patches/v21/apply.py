#!/usr/bin/env python3
import argparse
from pathlib import Path
import sys

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--input", required=True)
    ap.add_argument("--output", required=True)
    args = ap.parse_args()

    # Safety: do not silently publish a fake v21.
    # Replace this scaffold only after the HAT propagation patch is verified.
    print("v21 patch scaffold: HAT -> CE Keymaster bridge is not implemented yet.", file=sys.stderr)
    print("Refusing to emit a misleading v21 image.", file=sys.stderr)
    return 21

if __name__ == "__main__":
    raise SystemExit(main())
