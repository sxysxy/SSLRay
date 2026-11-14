#!/usr/bin/env python3
"""Verify the pinned OpenSSL Git tree without Git or repository metadata.

Ordinary files, executable bits and symlink targets participate in Git's SHA-1
object format. Optional upstream gitlinks are injected from the pin metadata;
their contents are deliberately not verified or used by our no-tests build.
Every other entry participates, including untracked/generated source files.
Updating OpenSSL requires an explicit update of openssl-source.json as well.
"""

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys


class VerificationError(Exception):
    pass


def object_hash(kind, data):
    digest = hashlib.sha1(usedforsecurity=False)
    digest.update(f"{kind} {len(data)}\0".encode("ascii"))
    digest.update(data)
    return digest.digest()


def file_hash(path, info):
    digest = hashlib.sha1(usedforsecurity=False)
    digest.update(f"blob {info.st_size}\0".encode("ascii"))
    size = 0
    with open(path, "rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            size += len(chunk)
            digest.update(chunk)
        after = os.fstat(source.fileno())
    before_key = (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_mode)
    after_key = (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_mode)
    if size != info.st_size or before_key != after_key:
        raise VerificationError("source changed while being verified")
    return digest.digest()


def load_pin(path):
    if path.stat().st_size > 64 * 1024:
        raise VerificationError("source pin metadata is too large")
    pin = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(pin, dict) or pin.get("format_version") != 1:
        raise VerificationError("unsupported source pin metadata format")
    sha1 = re.compile(r"[0-9a-f]{40}\Z")
    for name in ("commit", "tree"):
        if not isinstance(pin.get(name), str) or not sha1.fullmatch(pin[name]):
            raise VerificationError(f"invalid {name} in source pin metadata")
    if not isinstance(pin.get("url"), str) or not pin["url"].startswith("https://"):
        raise VerificationError("invalid URL in source pin metadata")
    if not isinstance(pin.get("tag"), str) or not pin["tag"]:
        raise VerificationError("missing tag in source pin metadata")
    links = pin.get("optional_gitlinks", {})
    if not isinstance(links, dict):
        raise VerificationError("invalid optional gitlinks in source pin metadata")
    tree = {}
    for name, commit in links.items():
        if (not isinstance(name, str) or not name
                or any(part in ("", ".", "..", ".git") for part in name.split("/"))
                or "\\" in name or "\0" in name
                or not isinstance(commit, str) or not sha1.fullmatch(commit)):
            raise VerificationError("invalid optional gitlink in source pin metadata")
        parts = name.split("/")
        node = tree
        for part in parts[:-1]:
            node = node.setdefault(os.fsencode(part), {})
            if not isinstance(node, dict):
                raise VerificationError("overlapping optional gitlinks in source pin metadata")
        leaf = os.fsencode(parts[-1])
        if leaf in node:
            raise VerificationError("overlapping optional gitlinks in source pin metadata")
        node[leaf] = bytes.fromhex(commit)
    return pin, tree


def tree_hash(path, gitlinks):
    # Byte paths preserve Git's filename ordering and symlink target bytes.
    entries = {}
    if path is not None:
        with os.scandir(path) as scan:
            entries = {entry.name: entry for entry in scan if entry.name != b".git"}
    objects = []
    for name in entries.keys() | gitlinks.keys():
        entry = entries.get(name)
        optional = gitlinks.get(name)
        if isinstance(optional, bytes):
            if entry is not None and not entry.is_dir(follow_symlinks=False):
                raise VerificationError("an optional gitlink path is not a directory")
            mode, digest = b"160000", optional
        elif entry is None:
            mode, digest = b"40000", tree_hash(None, optional)
        else:
            info = entry.stat(follow_symlinks=False)
            if stat.S_ISDIR(info.st_mode):
                mode = b"40000"
                digest = tree_hash(entry.path, optional or {})
                # Git does not represent empty directories.
                if digest == object_hash("tree", b""):
                    continue
            elif stat.S_ISREG(info.st_mode):
                mode = b"100755" if info.st_mode & stat.S_IXUSR else b"100644"
                digest = file_hash(entry.path, info)
            elif stat.S_ISLNK(info.st_mode):
                mode = b"120000"
                digest = object_hash("blob", os.readlink(entry.path))
            else:
                raise VerificationError("source contains an unsupported filesystem entry")
        order = name + (b"/" if mode == b"40000" else b"")
        objects.append((order, mode + b" " + name + b"\0" + digest))
    return object_hash("tree", b"".join(record for _, record in sorted(objects)))


def main():
    root = Path(__file__).resolve().parent.parent
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, default=root / "third_party" / "openssl",
                        help="OpenSSL source directory (including a metadata-free export)")
    arguments = parser.parse_args()
    try:
        pin, gitlinks = load_pin(root / "third_party" / "openssl-source.json")
        source = arguments.source
        if not source.is_dir():
            raise VerificationError("OpenSSL source directory is missing; initialize the submodule or unpack the complete source archive")
        actual = tree_hash(os.fsencode(source), gitlinks).hex()
        if actual != pin["tree"]:
            raise VerificationError(f"source content or executable modes differ from {pin['tag']} (expected tree {pin['tree']}, got {actual})")
    except (VerificationError, OSError, ValueError, TypeError, RecursionError) as error:
        print(f"OpenSSL source verification failed: {error}", file=sys.stderr)
        return 1
    print(pin["commit"])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
