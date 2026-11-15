#!/usr/bin/env python3
"""Validate the native release's architecture, ABI floor and TLS linkage."""
import argparse
import json
import os
from pathlib import Path
import re
import subprocess


def inspect(path, maximum):
    env = dict(os.environ, LC_ALL="C")
    def readelf(*args):
        return subprocess.check_output(["readelf", *args, str(path)], text=True, env=env)
    header = readelf("-h")
    if "Advanced Micro Devices X86-64" not in header or "ELF64" not in header:
        raise ValueError("Expected a native x86_64 ELF64 executable")
    version_info = readelf("--version-info")
    named_versions = set(re.findall(r"\bGLIBC_([A-Za-z0-9_.]+)\b", version_info))
    if any(not re.fullmatch(r"\d+(?:\.\d+)+", version) for version in named_versions):
        raise ValueError(f"Unsupported private/extension GLIBC ABI requirement: {named_versions}")
    versions = sorted(set(re.findall(r"\bGLIBC_(\d+(?:\.\d+)+)\b", version_info)),
                      key=lambda version: tuple(map(int, version.split("."))))
    if not versions or tuple(map(int, versions[-1].split("."))) > tuple(map(int, maximum.split("."))):
        raise ValueError(f"Required GLIBC {versions[-1] if versions else 'unknown'} exceeds {maximum}")
    dynamic = readelf("-d")
    needed = re.findall(r"\(NEEDED\).*?\[([^\]]+)\]", dynamic)
    if any(re.match(r"lib(?:ssl|crypto)[-.]", library) for library in needed):
        raise ValueError("Unexpected dynamic OpenSSL dependency")
    paths = re.findall(r"\((?:RPATH|RUNPATH)\).*?\[([^\]]*)\]", dynamic)
    if any(part and not part.startswith("$ORIGIN") for group in paths for part in group.split(":")):
        raise ValueError(f"Nonportable build-machine RPATH: {paths}")
    return {"file": path.name, "architecture": "x86_64", "maximum_glibc_symbol": versions[-1],
            "dynamic_dependencies": needed, "runtime_paths": paths, "static_openssl": True}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary", type=Path)
    parser.add_argument("--max-glibc", default="2.28")
    args = parser.parse_args()
    try:
        print(json.dumps(inspect(args.binary, args.max_glibc), indent=2))
    except (OSError, ValueError, subprocess.CalledProcessError) as error:
        parser.exit(1, f"ELF validation failed: {error}\n")
