#!/usr/bin/env python3
"""Check the pinned OpenSSL checkout on NTFS, using Git's executable modes.

Unlike POSIX, NTFS does not expose Git's executable bit through stat(). Git
supplies the pinned file inventory; actual file bytes must still match exactly.
No checkout, download, configuration change or working-tree repair is performed.
"""
import ctypes
import hashlib
import importlib.util
import os
from pathlib import Path
import subprocess
import sys

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parent.parent


class FileTime(ctypes.Structure):
    _fields_ = [("low", ctypes.c_uint32), ("high", ctypes.c_uint32)]


class FileInformation(ctypes.Structure):
    # BY_HANDLE_FILE_INFORMATION: fixed-width fields also allow layout testing
    # on non-Windows hosts, where ctypes.c_ulong has a different width.
    _fields_ = [("attributes", ctypes.c_uint32), ("creation", FileTime),
                ("access", FileTime), ("write", FileTime),
                ("volume", ctypes.c_uint32), ("size_high", ctypes.c_uint32),
                ("size_low", ctypes.c_uint32), ("links", ctypes.c_uint32),
                ("index_high", ctypes.c_uint32), ("index_low", ctypes.c_uint32)]

    def size(self):
        return (self.size_high << 32) | self.size_low

    def identity(self):
        # Last-access time may change simply because the file is being read.
        return (self.attributes, self.volume, self.index_high, self.index_low,
                self.size_high, self.size_low, self.write.high, self.write.low)


def windows_file_hash(path):
    """Hash bytes through one locked native handle, without Python stat mixing.

    Windows path.stat() and fstat() may expose different inode representations.
    A read-only sharing mode instead prevents concurrent writes/deletes while
    the same Win32 metadata API checks the exact handle before and after reads.
    """
    api = ctypes.WinDLL("kernel32", use_last_error=True)
    api.CreateFileW.argtypes = [ctypes.c_wchar_p, ctypes.c_uint32, ctypes.c_uint32,
                               ctypes.c_void_p, ctypes.c_uint32, ctypes.c_uint32,
                               ctypes.c_void_p]
    api.CreateFileW.restype = ctypes.c_void_p
    api.GetFileInformationByHandle.argtypes = [ctypes.c_void_p, ctypes.POINTER(FileInformation)]
    api.GetFileInformationByHandle.restype = ctypes.c_int
    api.ReadFile.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_uint32,
                            ctypes.POINTER(ctypes.c_uint32), ctypes.c_void_p]
    api.ReadFile.restype = ctypes.c_int
    api.CloseHandle.argtypes = [ctypes.c_void_p]
    api.CloseHandle.restype = ctypes.c_int
    literal = os.path.abspath(os.fspath(path))
    if not literal.startswith("\\\\?\\"):
        literal = "\\\\?\\UNC\\" + literal[2:] if literal.startswith("\\\\") else "\\\\?\\" + literal
    # GENERIC_READ, FILE_SHARE_READ only, OPEN_EXISTING,
    # FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_SEQUENTIAL_SCAN.
    handle = api.CreateFileW(literal, 0x80000000, 1, None, 3, 0x00200000 | 0x08000000, None)
    if handle == ctypes.c_void_p(-1).value:
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        before = FileInformation()
        if not api.GetFileInformationByHandle(handle, ctypes.byref(before)):
            raise ctypes.WinError(ctypes.get_last_error())
        if before.attributes & (0x10 | 0x400):  # DIRECTORY | REPARSE_POINT
            raise ValueError(f"Nonregular/reparse source file: {path}")
        digest = hashlib.sha1(usedforsecurity=False)
        digest.update(f"blob {before.size()}\0".encode("ascii"))
        total = 0
        buffer = ctypes.create_string_buffer(1024 * 1024)
        count = ctypes.c_uint32()
        while True:
            if not api.ReadFile(handle, buffer, len(buffer), ctypes.byref(count), None):
                raise ctypes.WinError(ctypes.get_last_error())
            if count.value == 0:
                break
            total += count.value
            if total > before.size():
                raise ValueError(f"Source grew while being verified: {path}")
            digest.update(buffer.raw[:count.value])
        after = FileInformation()
        if not api.GetFileInformationByHandle(handle, ctypes.byref(after)):
            raise ctypes.WinError(ctypes.get_last_error())
        if total != before.size() or before.identity() != after.identity():
            raise ValueError(f"Source changed while being verified: {path}")
        return digest.digest()
    finally:
        api.CloseHandle(handle)


def git(source, *arguments):
    result = subprocess.run(["git", "-C", str(source), *arguments], check=True,
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    return result.stdout


def verify(source):
    spec = importlib.util.spec_from_file_location("openssl_pin", ROOT / "scripts/verify-openssl-source.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    pin, _ = module.load_pin(ROOT / "third_party/openssl-source.json")
    if git(source, "rev-parse", "HEAD").decode().strip() != pin["commit"]:
        raise ValueError("OpenSSL HEAD differs from the pinned commit")
    if git(source, "rev-parse", "HEAD^{tree}").decode().strip() != pin["tree"]:
        raise ValueError("OpenSSL Git tree differs from the pinned tree")
    inventory = git(source, "ls-tree", "-r", "-z", "--full-tree", "HEAD")
    expected, optional = set(), set()
    for record in inventory.split(b"\0"):
        if not record:
            continue
        metadata, raw_name = record.split(b"\t", 1)
        mode, kind, oid = metadata.split()
        name = raw_name.decode("utf-8")
        path = source.joinpath(*name.split("/"))
        if mode == b"160000":
            optional.add(name)
            continue
        if kind != b"blob" or mode not in (b"100644", b"100755", b"120000"):
            raise ValueError(f"Unsupported source entry: {name}")
        expected.add(name)
        if mode == b"120000":
            if not path.is_symlink():
                raise ValueError(f"A real symlink is required: {name}")
            content = os.fsencode(os.readlink(path))
            digest = module.object_hash("blob", content).hex()
        else:
            if path.is_symlink() or not path.is_file():
                raise ValueError(f"Missing/nonregular source file: {name}")
            info = path.stat()
            try:
                digest = (windows_file_hash(path) if os.name == "nt" else module.file_hash(path, info)).hex()
            except (OSError, ValueError, module.VerificationError) as error:
                raise ValueError(f"Cannot verify {name}: {error}") from error
            if os.name != "nt" and bool(info.st_mode & 0o100) != (mode == b"100755"):
                raise ValueError(f"Executable mode changed: {name}")
        if digest != oid.decode("ascii"):
            raise ValueError(f"Source bytes changed (including CRLF conversion): {name}")
    for directory, dirs, files in os.walk(source, followlinks=False):
        relative = Path(directory).relative_to(source).as_posix()
        relative = "" if relative == "." else relative + "/"
        dirs[:] = [name for name in dirs if name != ".git" and relative + name not in optional]
        for name in dirs:
            if (Path(directory) / name).is_symlink() and relative + name not in expected:
                raise ValueError(f"Unexpected source directory symlink: {relative + name}")
        for name in files:
            if name == ".git":
                continue
            if relative + name not in expected:
                raise ValueError(f"Unexpected generated/untracked source file: {relative + name}")
    return pin["commit"]


if __name__ == "__main__":
    try:
        source = Path(sys.argv[1]) if len(sys.argv) == 2 else ROOT / "third_party/openssl"
        print(verify(source))
    except (OSError, ValueError, subprocess.CalledProcessError) as error:
        print(f"OpenSSL checkout verification failed: {error}\n"
              "Use the pinned Git submodule with core.autocrlf=false; this verifier never repairs source files.",
              file=sys.stderr)
        sys.exit(1)
