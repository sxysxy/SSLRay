#!/usr/bin/env python3
"""Copy local source notices into a bundle without Cargo or network access.

Uses Cargo.lock plus the selected build profile's rustc dep-info. The generated
index states its observed scope and reports source/notice gaps explicitly.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import sys
import tomllib


ROOT = Path(__file__).resolve().parent.parent
MAX_NOTICE_SIZE = 4 * 1024 * 1024
SUPPLEMENT_ROOT = ROOT / "third_party/license-notices"


def supplemental_manifest():
    path = SUPPLEMENT_ROOT / "manifest.json"
    if not path.is_file():
        return {}
    data = json.loads(path.read_text())
    if data.get("schema_version") != 1:
        raise ValueError("Unsupported supplemental notice manifest version")
    entries = {}
    for entry in data["packages"]:
        key = (entry["name"], entry["version"])
        if key in entries:
            raise ValueError(f"Duplicate supplemental notice mapping: {key}")
        state = entry.get("notice_state")
        if state not in ("full_text", "policy_only", "unavailable") or (state != "unavailable" and not entry.get("files")):
            raise ValueError(f"Invalid supplemental notice state/files: {key}")
        entries[key] = entry
    return entries


def safe_notice_path(value):
    path = PurePosixPath(value)
    reserved = {"CON", "PRN", "AUX", "NUL"} | {f"{prefix}{number}" for prefix in ("COM", "LPT") for number in range(1, 10)}
    if (not value or path.is_absolute() or ".." in path.parts or path.as_posix() != value
            or any(part.endswith((".", " ")) or part.split(".")[0].upper() in reserved
                   or any(character in part for character in "\\:%?#") for part in path.parts)):
        raise ValueError("Invalid supplemental notice path")
    return path


def supplemental_notices(package, source, target, entries):
    """Use only checked-in upstream text bound to this exact published crate."""
    entry = entries.get((package["name"], package["version"]))
    if entry is None:
        return [], None
    manifest = tomllib.loads((source / "Cargo.toml").read_text())["package"]
    vcs_path = source / ".cargo_vcs_info.json"
    if not vcs_path.is_file():
        raise ValueError(f"Missing version evidence for supplemental notices: {source.name}")
    vcs = json.loads(vcs_path.read_text())
    if (package.get("checksum") != entry["checksum"]
            or manifest.get("name") != entry["name"]
            or manifest.get("version") != entry["version"]
            or manifest.get("repository") != entry["crate_repository"]
            or manifest.get("license") != entry["declared_license"]
            or vcs.get("git", {}).get("sha1") != entry["revision"]
            or vcs.get("git", {}).get("dirty", False)
            or vcs.get("path_in_vcs", "") != entry["path_in_vcs"]):
        raise ValueError(f"Version evidence differs from supplemental notice mapping: {source.name}")
    repository = entry["upstream_repository"]
    repository_match = re.fullmatch(r"https://github\.com/([A-Za-z0-9_.-]+)/([A-Za-z0-9_.-]+)", repository)
    if (repository_match is None or any(part in (".", "..") for part in repository_match.groups())
            or not re.fullmatch(r"[0-9a-f]{40}", entry["revision"])):
        raise ValueError(f"Invalid supplemental notice repository/revision: {source.name}")
    archive = source.parent.parent.parent / "cache" / source.parent.name / f"{source.name}.crate"
    archive_verified = False
    if archive.is_file():
        with archive.open("rb") as original_archive:
            archive_verified = hashlib.file_digest(original_archive, "sha256").hexdigest() == package["checksum"]
        if not archive_verified:
            raise ValueError(f"Registry archive checksum differs from Cargo.lock: {source.name}")
    raw_prefix = "https://raw.githubusercontent.com/" + repository.removeprefix("https://github.com/") + "/" + entry["revision"] + "/"
    copied, origins, destinations = [], [], set()
    for item in entry["files"]:
        relative = safe_notice_path(item["local_path"])
        upstream = safe_notice_path(item["upstream_path"])
        destination = safe_notice_path(item.get("destination", item["upstream_path"]))
        destination_key = destination.as_posix().casefold()
        if destination_key in destinations:
            raise ValueError(f"Duplicate supplemental notice destination: {destination}")
        destinations.add(destination_key)
        original = (SUPPLEMENT_ROOT / relative).resolve(strict=True)
        if not original.is_file() or not original.is_relative_to(SUPPLEMENT_ROOT.resolve()) or original.stat().st_size > MAX_NOTICE_SIZE:
            raise ValueError("Invalid supplemental notice file")
        if hashlib.sha256(original.read_bytes()).hexdigest() != item["sha256"]:
            raise ValueError(f"Supplemental notice checksum mismatch: {relative}")
        if item["url"] != raw_prefix + upstream.as_posix():
            raise ValueError(f"Supplemental notice URL is not revision-pinned: {relative}")
        installed = Path("upstream") / Path(destination)
        output = target / installed
        output.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(original, output)
        copied.append(installed.as_posix())
        origin = {"file": installed.as_posix(), "url": item["url"], "sha256": item["sha256"], "upstream_path": item["upstream_path"]}
        for field in ("git_blob", "source_sha256", "line_range", "kind"):
            if field in item:
                origin[field] = item[field]
        origins.append(origin)
    provenance = {
        "repository": repository,
        "revision": entry["revision"],
        "path_in_vcs": entry["path_in_vcs"],
        "notice_state": entry["notice_state"],
        "registry_archive_verified": archive_verified,
        "files": origins,
    }
    if entry.get("limitation"):
        provenance["limitation"] = entry["limitation"]
    return copied, provenance


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


def vendored_package_map(lock):
    """Accept only the source release's lock-bound, portable vendor export."""
    path = ROOT / "CARGO-VENDOR.json"
    if not path.is_file():
        raise ValueError("Vendor dep-info requires the verified source release CARGO-VENDOR.json")
    proof = json.loads(path.read_text())
    config_path = ROOT / ".cargo/config.toml"
    if (proof.get("schema_version") != 1
            or proof.get("cargo_lock_sha256") != hashlib.sha256((ROOT / "Cargo.lock").read_bytes()).hexdigest()
            or not config_path.is_file()
            or proof.get("config_sha256") != hashlib.sha256(config_path.read_bytes()).hexdigest()):
        raise ValueError("Vendor provenance differs from Cargo.lock or portable source configuration")
    config = tomllib.loads(config_path.read_text())
    sources = config.get("source", {})
    if (sources.get("crates-io", {}).get("replace-with") != "vendored-sources"
            or sources.get("vendored-sources", {}).get("directory") != "vendor"):
        raise ValueError("Unsupported vendor source configuration")
    expected = {(p["name"], p["version"]): p for p in lock["package"] if p.get("source", "").startswith("registry+")}
    entries = proof.get("packages", [])
    if len(entries) != len(expected):
        raise ValueError("Vendor provenance does not cover the complete locked registry inventory")
    result = {}
    for entry in entries:
        key = (entry["name"], entry["version"])
        package = expected.get(key)
        if (package is None or key in result or entry.get("source") != package["source"]
                or entry.get("archive_sha256") != package.get("checksum")
                or entry.get("directory") != f"vendor/{key[0]}-{key[1]}"):
            raise ValueError("Vendor package provenance differs from Cargo.lock")
        result[key] = ROOT / entry["directory"]
    return result


def verify_vendored_source(package, source):
    """Check all original Cargo file hashes before collecting any notices."""
    if source.is_symlink() or not source.is_dir() or not source.resolve().is_relative_to((ROOT / "vendor").resolve()):
        raise ValueError("Vendor source escapes the verified directory")
    checksum_path = source / ".cargo-checksum.json"
    checksums = json.loads(checksum_path.read_text())
    if checksums.get("package") != package.get("checksum"):
        raise ValueError(f"Vendor archive checksum differs from Cargo.lock: {source.name}")
    actual = {p.relative_to(source).as_posix() for p in source.rglob("*") if p.is_file()}
    if actual != set(checksums["files"]) | {".cargo-checksum.json"}:
        raise ValueError(f"Vendor file inventory differs: {source.name}")
    for name, expected in checksums["files"].items():
        relative = PurePosixPath(name)
        path = source / relative
        if (relative.is_absolute() or ".." in relative.parts or "\\" in name
                or path.is_symlink() or not path.resolve().is_relative_to(source.resolve())
                or hashlib.sha256(path.read_bytes()).hexdigest() != expected):
            raise ValueError(f"Vendor source file checksum differs: {source.name}/{name}")
    manifest = tomllib.loads((source / "Cargo.toml").read_text())["package"]
    if manifest.get("name") != package["name"] or manifest.get("version") != package["version"]:
        raise ValueError(f"Vendor manifest identity differs: {source.name}")
    verification = {"kind": "vendored-directory", "package_checksum": package["checksum"],
                    "all_file_checksums_verified": True}
    vcs_path = source / ".cargo_vcs_info.json"
    if vcs_path.is_file():
        # The original VCS evidence is included in the file checksum check;
        # known supplements additionally require their exact revision/path.
        verification["vcs_info_sha256"] = hashlib.sha256(vcs_path.read_bytes()).hexdigest()
    return verification


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
        "scope": "Local notices for SSLRay, vendored Omnitun, actual TLS library prefixes, and Cargo.lock registry packages observed in this build profile's rustc dep-info. Version/checksum/revision-matched upstream supplements cover known crate packaging omissions. Build-profile dep-info may also retain earlier feature builds and build tools.",
        "complete_dependency_audit": False,
        "components": [],
        "missing_sources": [],
        "missing_notice_files": [],
        "upstream_notice_limitations": [],
    }
    sslray = output / "SSLRay"
    sslray.mkdir()
    shutil.copyfile(ROOT / "LICENSE", sslray / "LICENSE")
    shutil.copyfile(ROOT / "COPYRIGHT", sslray / "COPYRIGHT")
    shutil.copyfile(ROOT / "LICENSE-WINTUN-EXCEPTION", sslray / "LICENSE-WINTUN-EXCEPTION")
    shutil.copyfile(ROOT / "docs/THIRD-PARTY.md", output / "THIRD-PARTY.md")
    workspace_package = tomllib.loads((ROOT / "Cargo.toml").read_text())["workspace"]["package"]
    index["components"].append({"name": "SSLRay", "declared_license": workspace_package["license"], "additional_permission": "SSLRay Wintun linking permission", "files": ["SSLRay/LICENSE", "SSLRay/COPYRIGHT", "SSLRay/LICENSE-WINTUN-EXCEPTION"]})
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
    vendor_observed = set()
    dep_files = list((binary.resolve().parent / "deps").glob("*.d"))
    if not dep_files:
        raise ValueError("No rustc dep-info beside the selected binary; cannot select this build's dependency sources")
    pattern = re.compile(r"/registry/src/[^/\s]+/([^/\s]+)/")
    vendor_pattern = re.compile(r"/vendor/([^/\s]+)/")
    for dep in dep_files:
        paths = dep.read_text(errors="replace").replace("\\", "/")
        observed.update(pattern.findall(paths))
        vendor_observed.update(vendor_pattern.findall(paths))
    observed.update(vendor_observed)
    homes = [Path(os.environ.get("CARGO_HOME", Path.home() / ".cargo")), Path.home() / ".cargo"]
    source_roots = []
    for home in homes:
        for registry in (home / "registry/src").glob("*"):
            if registry not in source_roots:
                source_roots.append(registry)
    packages = [p for p in lock["package"] if p.get("source", "").startswith("registry+") and f"{p['name']}-{p['version']}" in observed]
    if not packages and any(p.get("source", "").startswith("registry+") for p in lock["package"]):
        raise ValueError("No locked Rust dependencies recognized in build dep-info; refusing an incomplete notice collection")
    vendor_sources = vendored_package_map(lock) if vendor_observed else {}
    supplements = supplemental_manifest()
    for package in sorted(packages, key=lambda p: (p["name"], p["version"])):
        name = f"{package['name']}-{package['version']}"
        source = (vendor_sources.get((package["name"], package["version"])) if name in vendor_observed else
                  next((registry / name for registry in source_roots if (registry / name).is_dir()), None))
        if source is None:
            index["missing_sources"].append(name)
            continue
        manifest = tomllib.loads((source / "Cargo.toml").read_text()).get("package", {})
        source_verification = verify_vendored_source(package, source) if name in vendor_observed else None
        files = notice_files(source)
        license_file = manifest.get("license-file")
        if license_file:
            candidate = (source / license_file).resolve()
            if candidate.is_file() and candidate.is_relative_to(source.resolve()):
                files.append(candidate)
        copied = copy_files(source, output / "Rust" / name, files)
        extra, provenance = supplemental_notices(package, source, output / "Rust" / name, supplements)
        copied.extend(extra)
        component = {"name": package["name"], "version": package["version"], "source": package["source"], "checksum": package.get("checksum"), "declared_license": manifest.get("license"), "files": [f"Rust/{name}/{file}" for file in copied]}
        if source_verification is not None:
            component["source_verification"] = source_verification
        if provenance is not None:
            component["supplemental_notices"] = provenance
            if provenance["notice_state"] != "full_text":
                index["upstream_notice_limitations"].append({"package": name, "notice_state": provenance["notice_state"], "detail": provenance.get("limitation", "")})
        index["components"].append(component)
        if not copied:
            index["missing_notice_files"].append(name)
    index["observed_registry_packages"] = len(packages)
    (output / "INDEX.json").write_text(json.dumps(index, ensure_ascii=False, indent=2) + "\n")
    (output / "README.txt").write_text("Source license and notice collection for this build.\nSee INDEX.json for package versions, pinned upstream provenance, collected files, missing files and upstream_notice_limitations.\nSelection uses Cargo.lock and this build profile's rustc dep-info; it includes available nested font notices.\nSupplemental notices are matched by package version, registry checksum, repository and published VCS revision/path; no network is used during collection.\nA policy-only upstream file is not represented as complete license/attribution text.\nThis collection is not a complete dependency or legal audit.\n")
    print(f"Collected licenses: {len(index['components'])} components; {len(index['missing_sources'])} missing source trees; {len(index['missing_notice_files'])} missing notice groups; {len(index['upstream_notice_limitations'])} upstream notice limitations")
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
