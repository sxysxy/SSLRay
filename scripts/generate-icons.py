#!/usr/bin/env python3
"""Render the one SVG source with librsvg, then package its PNGs as ICO/ICNS.

No drawing is duplicated here. Requires rsvg-convert for generation/--check;
--verify uses only Python's standard library to inspect the checked-in assets.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import shutil
import struct
import subprocess
import tempfile
import xml.etree.ElementTree as ET
import zlib

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "assets/sslray.svg"
DESTINATION = ROOT / "assets/icons"
SIZES = (16, 20, 24, 32, 40, 48, 64, 128, 256, 512, 1024)
ICO_SIZES = tuple(size for size in SIZES if size <= 256)
# Standard macOS 1x and 2x representations. Each payload is the same rendered PNG.
ICNS_SIZES = {
    b"icp4": 16, b"icp5": 32, b"icp6": 64,
    b"ic07": 128, b"ic08": 256, b"ic09": 512, b"ic10": 1024,
    b"ic11": 32, b"ic12": 64, b"ic13": 256, b"ic14": 512,
}
PNG_SIGNATURE = b"\x89PNG\r\n\x1a\n"


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def png_size(data: bytes) -> tuple[int, int]:
    if not data.startswith(PNG_SIGNATURE):
        raise ValueError("Invalid PNG signature")
    position = 8
    dimensions = None
    while position < len(data):
        length, kind = struct.unpack_from(">I4s", data, position)
        end = position + length + 12
        if end > len(data):
            raise ValueError("Truncated PNG chunk")
        payload = data[position + 8: end - 4]
        expected_crc = struct.unpack_from(">I", data, end - 4)[0]
        if zlib.crc32(kind + payload) != expected_crc:
            raise ValueError("PNG CRC mismatch")
        if kind == b"IHDR":
            width, height, depth, color, compression, filtering, interlace = struct.unpack(
                ">IIBBBBB", payload
            )
            if depth != 8 or color != 6 or compression or filtering or interlace:
                raise ValueError("Expected noninterlaced 8-bit RGBA PNG")
            dimensions = (width, height)
        elif kind == b"IEND":
            if end != len(data) or dimensions is None:
                raise ValueError("Invalid PNG termination")
            return dimensions
        position = end
    raise ValueError("Missing PNG IEND")


def make_ico(pngs: dict[int, bytes]) -> bytes:
    entries = bytearray()
    payloads = bytearray()
    offset = 6 + 16 * len(ICO_SIZES)
    for size in ICO_SIZES:
        png = pngs[size]
        dimension = size if size < 256 else 0
        entries.extend(struct.pack("<BBBBHHII", dimension, dimension, 0, 0, 1, 32, len(png), offset))
        payloads.extend(png)
        offset += len(png)
    return struct.pack("<HHH", 0, 1, len(ICO_SIZES)) + entries + payloads


def make_icns(pngs: dict[int, bytes]) -> bytes:
    chunks = b"".join(
        kind + struct.pack(">I", len(pngs[size]) + 8) + pngs[size]
        for kind, size in ICNS_SIZES.items()
    )
    return b"icns" + struct.pack(">I", len(chunks) + 8) + chunks


def verify(folder: Path) -> None:
    manifest = json.loads((folder / "manifest.json").read_text())
    if manifest["source_sha256"] != digest(SOURCE.read_bytes()):
        raise ValueError("SVG changed: regenerate icon assets")
    expected_names = {f"sslray-{size}.png" for size in SIZES} | {"SSLRay.ico", "SSLRay.icns"}
    if set(manifest["sha256"]) != expected_names:
        raise ValueError("Incomplete icon manifest")
    for name, checksum in manifest["sha256"].items():
        if digest((folder / name).read_bytes()) != checksum:
            raise ValueError(f"Asset digest mismatch: {name}")
    pngs = {size: (folder / f"sslray-{size}.png").read_bytes() for size in SIZES}
    for size, png in pngs.items():
        if png_size(png) != (size, size):
            raise ValueError(f"Incorrect PNG dimensions: {size}")

    ico = (folder / "SSLRay.ico").read_bytes()
    if struct.unpack_from("<HHH", ico) != (0, 1, len(ICO_SIZES)):
        raise ValueError("Incorrect ICO header")
    expected_offset = 6 + 16 * len(ICO_SIZES)
    for index, size in enumerate(ICO_SIZES):
        w, h, colors, reserved, planes, bits, length, offset = struct.unpack_from(
            "<BBBBHHII", ico, 6 + 16 * index
        )
        if (w or 256, h or 256, colors, reserved, planes, bits) != (size, size, 0, 0, 1, 32):
            raise ValueError("Incorrect ICO directory entry")
        if offset != expected_offset or ico[offset:offset + length] != pngs[size]:
            raise ValueError("ICO payload differs from SVG-rendered PNG")
        expected_offset += length
    if expected_offset != len(ico):
        raise ValueError("Unexpected ICO trailing data")

    icns = (folder / "SSLRay.icns").read_bytes()
    if icns[:4] != b"icns" or struct.unpack_from(">I", icns, 4)[0] != len(icns):
        raise ValueError("Incorrect ICNS header")
    position = 8
    for kind, size in ICNS_SIZES.items():
        actual_kind, length = struct.unpack_from(">4sI", icns, position)
        if actual_kind != kind or icns[position + 8: position + length] != pngs[size]:
            raise ValueError("ICNS payload differs from SVG-rendered PNG")
        position += length
    if position != len(icns):
        raise ValueError("Unexpected ICNS trailing data")


def generate(folder: Path, renderer: str) -> None:
    # Keep the source self-contained: no linked images, scripts or external URLs.
    svg = ET.fromstring(SOURCE.read_bytes())
    namespace = "{http://www.w3.org/2000/svg}"
    if any(element.tag not in {namespace + name for name in ("svg", "title", "desc", "circle", "path")}
           for element in svg.iter()):
        raise ValueError("Icon source must contain only the local vector artwork")
    folder.mkdir(parents=True, exist_ok=True)
    for size in SIZES:
        subprocess.run(
            [renderer, "--format=png", f"--width={size}", f"--height={size}",
             f"--output={folder / f'sslray-{size}.png'}", str(SOURCE)],
            check=True,
        )
    pngs = {size: (folder / f"sslray-{size}.png").read_bytes() for size in SIZES}
    (folder / "SSLRay.ico").write_bytes(make_ico(pngs))
    (folder / "SSLRay.icns").write_bytes(make_icns(pngs))
    names = [f"sslray-{size}.png" for size in SIZES] + ["SSLRay.ico", "SSLRay.icns"]
    manifest = {
        "source": "assets/sslray.svg",
        "source_sha256": digest(SOURCE.read_bytes()),
        "renderer": subprocess.check_output([renderer, "--version"], text=True).splitlines()[0],
        "sha256": {name: digest((folder / name).read_bytes()) for name in names},
    }
    (folder / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
    verify(folder)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--check", action="store_true", help="regenerate and compare every checked-in byte")
    mode.add_argument("--verify", action="store_true", help="verify hashes, containers and dimensions without a renderer")
    parser.add_argument("--renderer", default="rsvg-convert", help="path to librsvg's rsvg-convert")
    args = parser.parse_args()
    if args.verify:
        verify(DESTINATION)
    else:
        renderer = shutil.which(args.renderer)
        if renderer is None:
            parser.error("rsvg-convert is required; install librsvg or pass --renderer")
        if args.check:
            with tempfile.TemporaryDirectory(prefix="sslray-icons-") as temporary:
                generated = Path(temporary)
                generate(generated, renderer)
                for path in generated.iterdir():
                    if path.read_bytes() != (DESTINATION / path.name).read_bytes():
                        raise ValueError(f"Icon differs; regenerate with this librsvg version: {path.name}")
        else:
            generate(DESTINATION, renderer)
    print("Verified 11 RGBA PNG sizes, 9 ICO images and 11 ICNS representations from assets/sslray.svg")


if __name__ == "__main__":
    main()
