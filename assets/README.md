# SSLRay icons

`sslray.svg` is the single vector source. It preserves the existing sidebar's
blue circle and white lightning bolt, with the light theme brand blue `#235edd`.
There are no external images, fonts, credentials, network data or image metadata
copied from screenshots.

Generate with Python 3.9+ and librsvg's standard SVG renderer:

```sh
python3 scripts/generate-icons.py
python3 scripts/generate-icons.py --check
```

`--check` renders again and compares every byte, including the renderer version.
After a deliberate librsvg upgrade, regenerate the assets. Container, PNG CRC,
dimension and SHA-256 checks do not need librsvg:

```sh
python3 scripts/generate-icons.py --verify
```

The generated PNGs cover 16, 20, 24, 32, 40, 48, 64, 128, 256, 512 and 1024 px.
`icons/SSLRay.ico` contains the nine sizes through 256 px as 32-bit RGBA PNGs for
modern Windows. `icons/SSLRay.icns` contains macOS standard 1x/2x representations
through 1024 px. Both containers copy the same PNG payloads without redrawing.
`icons/manifest.json` records the SVG and generated asset digests.

The tray and native window icon load their exact-size PNGs using eframe's existing
PNG decoder. Windows `build.rs` embeds the ICO as an ICON resource only for Windows
targets. This adds no administrator manifest; elevation remains limited to the
existing network helper. Windows Explorer/taskbar appearance still requires a
Windows runtime check. macOS packaging copies `SSLRay.icns` to `Contents/Resources`
and sets `CFBundleIconFile` to `SSLRay.icns`.
