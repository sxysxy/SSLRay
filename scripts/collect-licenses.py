#!/usr/bin/env python3
"""Copy local source notices into a bundle without Cargo or network access.

Uses Cargo.lock plus the selected build profile's rustc dep-info. The generated
index states its observed scope and reports source/notice gaps explicitly.
"""
import argparse
import json
import os
from pathlib import Path
import re
import shutil
import sys
import tomllib


ROOT = Path(__file__).resolve().parent.parent
MAX_NOTICE_SIZE = 4 * 1024 * 1024


def notice_files(root):
    """Include nested notices and font license texts while retaining paths."""
    root = root.resolve()
    found = []
    for path in root.rglob("*"):
        if not path.is_file() or path.is_symlink():
            continue
        relative = path.relative_to(root)
        name = path.name.upper()
        font_text = any("font" in part.lower() for part in relative.parts[:-1]) and path.suffix.lower() in (".txt", ".md")
        if ("LICENSE" in name or "LICENCE" in name or name.startswith(("COPYING", "NOTICE", "COPYRIGHT", "OFL", "UFL")) or font_text) and path.stat().st_size <= MAX_NOTICE_SIZE:
            found.append(path)
    return sorted(found)


def copy_files(source, target, files):
    source = source.resolve()
    copied = []
    for path in sorted(set(files)):
        resolved = path.resolve()
        if not resolved.is_file() or not resolved.is_relative_to(source):
            continue
        relative = resolved.relative_to(source)
        destination = target / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(resolved, destination)
        copied.append(relative.as_posix())
    return copied


def collect(output, binary, tls_libraries, tls_source):
    output = output.resolve()
    # This is a generated directory belonging to the selected app/output.
    # Recreate it so a change of dependencies cannot retain stale notices.
    if output.exists():
        if output == ROOT or output in ROOT.parents:
            raise ValueError("License output must not be the project or a parent directory")
        shutil.rmtree(output)
    output.mkdir(parents=True)
    index = {
        "scope": "Local notices for SSLRay, vendored Omnitun, actual TLS library prefixes, and Cargo.lock registry packages observed in this build profile's rustc dep-info. Build-profile dep-info may also retain earlier feature builds and build tools.",
        "complete_dependency_audit": False,
        "components": [],
        "missing_sources": [],
        "missing_notice_files": [],
    }
    sslray = output / "SSLRay"
    sslray.mkdir()
    shutil.copyfile(ROOT / "LICENSE", sslray / "LICENSE")
    shutil.copyfile(ROOT / "docs/THIRD-PARTY.md", output / "THIRD-PARTY.md")
    index["components"].append({"name": "SSLRay", "files": ["SSLRay/LICENSE"]})
    omnitun = ROOT / "third_party/omnitun"
    vendored = copy_files(omnitun, output / "Omnitun", [omnitun / name for name in ("LICENSE-MIT", "LICENSE-APACHE", "UPSTREAM.md")])
    index["components"].append({"name": "Omnitun", "version": "0.4.5", "revision": "d117595bdf1700faf14410e83cfd9676b7d5834d", "declared_license": "MIT OR Apache-2.0", "files": [f"Omnitun/{name}" for name in vendored]})

    seen_prefixes = set()
    for library in tls_libraries:
        resolved = Path(library).resolve(strict=True)
        prefix = resolved.parent.parent
        if prefix in seen_prefixes:
            continue
        seen_prefixes.add(prefix)
        # Only the linked installation prefix, not a scan of Homebrew or /usr.
        files = [p for p in prefix.iterdir() if p.is_file() and any(word in p.name.upper() for word in ("LICENSE", "LICENCE", "NOTICE", "COPYING", "COPYRIGHT"))]
        for location in (prefix / "share/doc", prefix / "share/licenses"):
            if location.is_dir() and prefix != Path("/usr"):
                files.extend(notice_files(location))
        group = "TLS/" + prefix.parent.name + "-" + prefix.name
        copied = copy_files(prefix, output / group, files)
        index["components"].append({"name": "Linked TLS library", "installation": f"{prefix.parent.name}/{prefix.name}", "linked_file": resolved.name, "files": [f"{group}/{name}" for name in copied]})
        if not copied:
            index["missing_notice_files"].append(f"TLS:{resolved.name}")
    # Static backends can explicitly identify their original source directory.
    # Do not guess a source tree from a library name or use unrelated OpenSSL.
    if tls_source:
        source = Path(tls_source).resolve(strict=True)
        files = [p for p in source.iterdir() if p.is_file() and any(word in p.name.upper() for word in ("LICENSE", "LICENCE", "NOTICE", "COPYING", "COPYRIGHT"))]
        copied = copy_files(source, output / "TLS/configured-source", files)
        index["components"].append({"name": "Explicitly configured TLS source", "files": [f"TLS/configured-source/{name}" for name in copied]})
        if not copied:
            index["missing_notice_files"].append("TLS:configured-source")
    elif not tls_libraries:
        index["missing_notice_files"].append("Static TLS source: set SSLRAY_TLS_SOURCE_DIR to its original source directory")

    lock = tomllib.loads((ROOT / "Cargo.lock").read_text())
    observed = set()
    dep_files = list((binary.resolve().parent / "deps").glob("*.d"))
    if not dep_files:
        raise ValueError("No rustc dep-info beside the selected binary; cannot select this build's dependency sources")
    pattern = re.compile(r"/registry/src/[^/\s]+/([^/\s]+)/")
    for dep in dep_files:
        observed.update(pattern.findall(dep.read_text(errors="replace")))
    homes = [Path(os.environ.get("CARGO_HOME", Path.home() / ".cargo")), Path.home() / ".cargo"]
    source_roots = []
    for home in homes:
        for registry in (home / "registry/src").glob("*"):
            if registry not in source_roots:
                source_roots.append(registry)
    packages = [p for p in lock["package"] if p.get("source", "").startswith("registry+") and f"{p['name']}-{p['version']}" in observed]
    for package in sorted(packages, key=lambda p: (p["name"], p["version"])):
        name = f"{package['name']}-{package['version']}"
        source = next((registry / name for registry in source_roots if (registry / name).is_dir()), None)
        if source is None:
            index["missing_sources"].append(name)
            continue
        manifest = tomllib.loads((source / "Cargo.toml").read_text()).get("package", {})
        files = notice_files(source)
        license_file = manifest.get("license-file")
        if license_file:
            candidate = (source / license_file).resolve()
            if candidate.is_file() and candidate.is_relative_to(source.resolve()):
                files.append(candidate)
        copied = copy_files(source, output / "Rust" / name, files)
        index["components"].append({"name": package["name"], "version": package["version"], "source": package["source"], "checksum": package.get("checksum"), "declared_license": manifest.get("license"), "files": [f"Rust/{name}/{file}" for file in copied]})
        if not copied:
            index["missing_notice_files"].append(name)
    index["observed_registry_packages"] = len(packages)
    (output / "INDEX.json").write_text(json.dumps(index, ensure_ascii=False, indent=2) + "\n")
    (output / "README.txt").write_text("Source license and notice collection for this build.\nSee INDEX.json for package versions, source provenance, collected files and missing local files.\nSelection uses Cargo.lock and this build profile's rustc dep-info; it includes available nested font notices.\nThis collection records locally available notices and is not a complete dependency or legal audit.\n")
    print(f"Collected licenses: {len(index['components'])} components; {len(index['missing_sources'])} missing source trees; {len(index['missing_notice_files'])} missing notice groups")
    return index


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--tls-libraries", default="", help="Newline-separated original linked TLS dylib paths")
    parser.add_argument("--tls-source", default=os.environ.get("SSLRAY_TLS_SOURCE_DIR", ""))
    args = parser.parse_args()
    collect(args.output, args.binary, [line for line in args.tls_libraries.splitlines() if line], args.tls_source)


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, tomllib.TOMLDecodeError) as error:
        print(f"License collection failed: {error}", file=sys.stderr)
        sys.exit(1)
