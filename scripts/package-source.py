#!/usr/bin/env python3
"""Stage a verified GPL source release under SSLRay/; archive only explicitly.

Uses the working-tree bytes of tracked and unignored new source files, not a
commit-only export. Requires the separately verified, public OpenSSL checkout
ZIP so the Windows source verifier also works without the main repository.
Optional sensitive-content patterns arrive only as a JSON array on stdin and
are never saved, printed, hashed into a report, or included in the release.
"""
import argparse
import gzip
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile
import tomllib
import zipfile

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parent.parent
OPENSSL_ZIP_SHA256 = "f4c0054a171e558911bb38007996859f39875f5bb4af3f454b1c27d79f3bc153"
EXCLUDED_ROOTS = {".git", "work", "dist", "outputs", "target"}
EXCLUDED_PARTS = {"__pycache__", ".cargo", ".ssh"}
PRIVATE_NAMES = {"profiles.json", "profile.json", "preferences.json", "ui-prefs.json", "credentials.json"}


def digest(path):
    with path.open("rb") as file:
        return hashlib.file_digest(file, "sha256").hexdigest()


def command(arguments, cwd=ROOT):
    result = subprocess.run(arguments, cwd=cwd, stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE, check=True)
    return result.stdout.decode("utf-8").strip()


def safe_relative(name):
    path = PurePosixPath(name)
    if (not name or path.is_absolute() or path.as_posix() != name
            or any(p in ("", ".", "..") for p in path.parts) or "\\" in name):
        raise ValueError("Unsafe source archive path")
    return path


def main_paths():
    raw = subprocess.check_output(["git", "ls-files", "--cached", "--others",
                                   "--exclude-standard", "-z"], cwd=ROOT)
    selected = []
    for raw_name in sorted(set(raw.split(b"\0"))):
        if not raw_name:
            continue
        name = raw_name.decode("utf-8")
        path = safe_relative(name)
        if (path.parts[0] in EXCLUDED_ROOTS or set(path.parts) & EXCLUDED_PARTS
                or path.suffix in (".pyc", ".pyo") or path.name == ".DS_Store"):
            continue
        if name == "third_party/openssl":
            continue  # Replaced by the verified public checkout below.
        if ".git" in path.parts:
            raise ValueError(f"Unexpected nested Git metadata: {name}")
        if path.name in PRIVATE_NAMES or path.name.startswith(".env"):
            raise ValueError(f"Possible private configuration must be reviewed: {name}")
        source = ROOT / name
        if source.is_symlink():
            if not source.resolve(strict=True).is_relative_to(ROOT):
                raise ValueError(f"Source link escapes project: {name}")
        elif not source.is_file():
            raise ValueError(f"Missing/nonregular selected source: {name}")
        selected.append(name)
    return selected


def read_patterns(enabled):
    if not enabled:
        return []
    raw = sys.stdin.buffer.read(65537)
    if len(raw) > 65536:
        raise ValueError("Sensitive scan input is too large")
    values = json.loads(raw)
    if (not isinstance(values, list) or not 1 <= len(values) <= 128
            or any(not isinstance(v, str) or not v or len(v) > 1024 for v in values)):
        raise ValueError("Sensitive scan input must be a nonempty JSON string array")
    return [value.encode("utf-8") for value in values]


def scan_source(names, patterns, base=ROOT):
    matches = []
    for name in names:
        path = base / name
        raw = os.fsencode(os.readlink(path)) if path.is_symlink() else path.read_bytes()
        if any(pattern in raw for pattern in patterns):
            matches.append(name)
    if matches:
        raise ValueError("Sensitive-content scan failed in: " + ", ".join(matches))
    return {"performed": bool(patterns), "patterns_checked": len(patterns),
            "matched_paths": [], "scope": "Selected main source only, excluding public upstream OpenSSL"}


def extract_openssl(archive, tree, pin):
    if digest(archive) != OPENSSL_ZIP_SHA256:
        raise ValueError("OpenSSL checkout archive SHA-256 differs from the approved generated public checkout archive")
    destination = tree / "third_party/openssl"
    marker = tree.parent / "openssl-input.json"
    if destination.is_dir() and marker.is_file():
        if json.loads(marker.read_text()).get("archive_sha256") == OPENSSL_ZIP_SHA256:
            return
    if destination.exists():
        shutil.rmtree(destination)
    with zipfile.ZipFile(archive) as source:
        seen = set()
        for item in source.infolist():
            name = item.filename.rstrip("/")
            path = safe_relative(name)
            if path.parts[:2] != ("third_party", "openssl"):
                raise ValueError("Unexpected OpenSSL archive root")
            if name in seen:
                raise ValueError("Duplicate OpenSSL archive member")
            seen.add(name)
            # Recreate only public, necessary Git metadata. In particular, do
            # not export an index's local stat cache, reflogs, hooks or config.
            if len(path.parts) > 2 and path.parts[2] == ".git":
                allowed = (len(path.parts) == 6 and path.parts[3:5] == ("objects", "pack")
                           and re.fullmatch(r"pack-[0-9a-f]{40}\.(pack|idx|rev)", path.name))
                if not allowed:
                    continue
            output = tree / name
            mode = item.external_attr >> 16
            if item.is_dir():
                output.mkdir(parents=True, exist_ok=True)
                output.chmod(0o755)
            elif stat.S_ISLNK(mode):
                target = source.read(item).decode("utf-8")
                if os.path.isabs(target) or not (output.parent / target).resolve().is_relative_to(destination):
                    raise ValueError("OpenSSL link escapes source tree")
                output.parent.mkdir(parents=True, exist_ok=True)
                output.symlink_to(target)
            elif stat.S_ISREG(mode):
                output.parent.mkdir(parents=True, exist_ok=True)
                with source.open(item) as original, output.open("wb") as copied:
                    shutil.copyfileobj(original, copied)
                output.chmod(stat.S_IMODE(mode))
            else:
                raise ValueError("Unsupported OpenSSL archive entry")
    git = destination / ".git"
    git.mkdir(exist_ok=True)
    (git / "refs").mkdir(exist_ok=True)
    (git / "HEAD").write_text(pin["commit"] + "\n")
    (git / "shallow").write_text(pin["commit"] + "\n")
    (git / "config").write_text(
        '[core]\n\trepositoryformatversion = 0\n\tfilemode = true\n'
        '\tbare = false\n\tlogAllRefUpdates = false\n\tautocrlf = false\n'
        '[remote "origin"]\n\turl = https://github.com/openssl/openssl.git\n'
        '\tfetch = +refs/tags/openssl-4.0.3:refs/tags/openssl-4.0.3\n')
    marker.write_text(json.dumps({"archive_sha256": OPENSSL_ZIP_SHA256}, indent=2) + "\n")


def inventory(tree):
    entries = {}
    for path in sorted(tree.rglob("*")):
        name = path.relative_to(tree).as_posix()
        if name == "SOURCE-INVENTORY.json":
            continue  # This manifest cannot hash itself; archive gets a SHA.
        mode = stat.S_IMODE(path.lstat().st_mode)
        if path.is_symlink():
            target = os.readlink(path)
            entries[name] = {"type": "symlink", "mode": oct(mode), "target": target,
                             "sha256": hashlib.sha256(os.fsencode(target)).hexdigest()}
        elif path.is_dir():
            entries[name] = {"type": "directory", "mode": oct(mode)}
        elif path.is_file():
            entries[name] = {"type": "file", "mode": oct(mode),
                             "bytes": path.stat().st_size, "sha256": digest(path)}
        else:
            raise ValueError(f"Unsupported staged filesystem entry: {name}")
    return entries


def vendor_packages(tree):
    lock = tomllib.loads((tree / "Cargo.lock").read_text())
    packages = [p for p in lock["package"] if p.get("source", "").startswith("registry+")]
    if any(p["source"] != "registry+https://github.com/rust-lang/crates.io-index" for p in packages):
        raise ValueError("A non-public registry needs separate source-release review")
    return sorted(packages, key=lambda p: (p["name"], p["version"]))


def cargo_vendor(tree, home):
    home = home.resolve()
    if not home.is_relative_to((ROOT / "work").resolve()) or home.is_relative_to(tree):
        raise ValueError("Isolated vendor Cargo home must be in work/ outside the exported tree")
    if any((home / name).exists() for name in ("credentials", "credentials.toml", "config", "config.toml")):
        raise ValueError("Vendor Cargo home must not contain credentials or configuration")
    packages = vendor_packages(tree)
    for package in packages:
        archives = list((home / "registry/cache").glob(f"*/{package['name']}-{package['version']}.crate"))
        if len(archives) != 1 or digest(archives[0]) != package["checksum"]:
            raise ValueError(f"Missing/unverified isolated crate archive: {package['name']}-{package['version']}")
    marker = home / ".sslray-source-vendor-cache.json"
    source_cache = home / "registry/src"
    ownership = {"schema_version": 1, "generated_source_vendor_cache": True}
    if source_cache.exists() and (not marker.is_file() or json.loads(marker.read_text()) != ownership):
        raise ValueError("Refusing to replace a source cache without this release helper's ownership marker")
    home.mkdir(parents=True, exist_ok=True)
    marker.write_text(json.dumps(ownership) + "\n")
    if source_cache.exists():
        if source_cache.is_symlink():
            raise ValueError("Owned source cache must not be a symlink")
        shutil.rmtree(source_cache)
    env = os.environ.copy()
    env.update({"CARGO_HOME": str(home), "CARGO_NET_OFFLINE": "true"})
    result = subprocess.run(["cargo", "vendor", "--locked", "--offline", "--versioned-dirs",
                             "--manifest-path", str(tree / "Cargo.toml"), str(tree / "vendor")],
                            cwd=tree, env=env, text=True, stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE)
    (tree.parent / "cargo-vendor.log").write_text(result.stdout + result.stderr)
    if result.returncode:
        raise ValueError("Cargo vendor failed; see generated stage/cargo-vendor.log")
    config = tree / ".cargo/config.toml"
    config.parent.mkdir(exist_ok=True)
    config.write_text('[source.crates-io]\nreplace-with = "vendored-sources"\n\n'
                      '[source.vendored-sources]\ndirectory = "vendor"\n\n'
                      '[net]\noffline = true\n')
    provenance = {"schema_version": 1, "cargo_lock_sha256": digest(tree / "Cargo.lock"),
                  "configuration": ".cargo/config.toml", "config_sha256": digest(config),
                  "method": "cargo vendor --locked --offline --versioned-dirs using an isolated public cache; published archives were checksum-verified before fresh Cargo extraction",
                  "packages": [{"name": p["name"], "version": p["version"],
                                "source": p["source"], "archive_sha256": p["checksum"],
                                "directory": f"vendor/{p['name']}-{p['version']}"} for p in packages],
                  "toolchain_scope": "Rust toolchain, operating-system SDKs and native build tools are not included."}
    (tree / "CARGO-VENDOR.json").write_text(json.dumps(provenance, indent=2) + "\n")
    return {"registry_packages": len(packages), "provenance": "CARGO-VENDOR.json",
            "configuration": ".cargo/config.toml", "offline": True}


def verify_vendor(tree):
    proof = json.loads((tree / "CARGO-VENDOR.json").read_text())
    if proof["cargo_lock_sha256"] != digest(tree / "Cargo.lock") or proof["config_sha256"] != digest(tree / ".cargo/config.toml"):
        raise ValueError("Vendor provenance differs from the lockfile/configuration")
    packages = vendor_packages(tree)
    expected = {f"{p['name']}-{p['version']}" for p in packages}
    if {p.name for p in (tree / "vendor").iterdir()} != expected:
        raise ValueError("Vendor package inventory does not exactly cover Cargo.lock")
    file_count = 0
    for package in packages:
        directory = tree / "vendor" / f"{package['name']}-{package['version']}"
        checksums = json.loads((directory / ".cargo-checksum.json").read_text())
        if checksums["package"] != package["checksum"]:
            raise ValueError(f"Vendor archive checksum differs: {directory.name}")
        actual = {p.relative_to(directory).as_posix() for p in directory.rglob("*") if p.is_file()}
        if actual != set(checksums["files"]) | {".cargo-checksum.json"}:
            raise ValueError(f"Vendor file inventory differs: {directory.name}")
        for name, expected_hash in checksums["files"].items():
            path = directory / safe_relative(name)
            if path.is_symlink() or digest(path) != expected_hash:
                raise ValueError(f"Vendor file checksum differs: {directory.name}/{name}")
        file_count += len(actual)
    # Each verification starts with an empty home. No registry/index/source
    # cache, network, or original build-machine configuration can satisfy it.
    with tempfile.TemporaryDirectory(prefix="empty-cargo-home-", dir=tree.parent) as temporary:
        home = Path(temporary)
        env = os.environ.copy()
        env.update({"CARGO_HOME": temporary, "CARGO_NET_OFFLINE": "true"})
        result = subprocess.run(["cargo", "metadata", "--offline", "--locked", "--format-version", "1"],
                                cwd=tree, env=env, text=True, stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE)
        if result.returncode:
            (tree.parent / "cargo-metadata-error.log").write_text(result.stderr)
            raise ValueError("Offline metadata failed with empty Cargo home; see stage/cargo-metadata-error.log")
        metadata = json.loads(result.stdout)
        resolved = {(p["name"], p["version"]) for p in metadata["packages"] if p.get("source", "") and p["source"].startswith("registry+")}
        if resolved != {(p["name"], p["version"]) for p in packages}:
            raise ValueError("Offline metadata does not resolve every locked registry package")
        # Cargo creates an empty registry/CACHEDIR.TAG even for directory
        # sources; only a real index/cache/src entry could satisfy resolution.
        registry_files = [p.relative_to(home).as_posix() for p in (home / "registry").rglob("*") if p.is_file()]
        if any(name != "registry/CACHEDIR.TAG" for name in registry_files):
            raise ValueError("Offline metadata unexpectedly used a Cargo registry cache")
    return {"registry_packages": len(packages), "vendored_files": file_count,
            "archive_checksums_and_all_file_hashes": "passed",
            "metadata_offline_locked_empty_cargo_home": "passed"}


def verify_tree(tree):
    expected = json.loads((tree / "SOURCE-INVENTORY.json").read_text())
    if inventory(tree) != expected["entries"]:
        raise ValueError("Source inventory bytes, modes, paths or link targets differ")
    for name in ("LICENSE", "COPYRIGHT", "LICENSE-WINTUN-EXCEPTION", "Cargo.lock",
                 "third_party/omnitun/LICENSE-MIT", "third_party/omnitun/LICENSE-APACHE"):
        if not (tree / name).is_file():
            raise ValueError(f"Required release source missing: {name}")
    if (tree / ".git").exists():
        raise ValueError("Main repository metadata must never be exported")
    source = tree / "third_party/openssl"
    git_files = sorted(p.relative_to(source / ".git").as_posix()
                       for p in (source / ".git").rglob("*") if p.is_file())
    allowed = re.compile(r"(?:HEAD|config|shallow|objects/pack/pack-[0-9a-f]{40}\.(?:pack|idx|rev))\Z")
    if not all(allowed.fullmatch(p) for p in git_files):
        raise ValueError("OpenSSL Git metadata exceeds the public minimal allowlist")
    if command(["git", "-C", str(source), "remote", "get-url", "origin"]) != "https://github.com/openssl/openssl.git":
        raise ValueError("Unexpected OpenSSL remote")
    checks = {}
    for script, arguments in [("verify-openssl-source.py", ["--source", str(source)]),
                              ("verify-openssl-windows.py", [str(source)])]:
        checks[script] = command([sys.executable, str(tree / "scripts" / script), *arguments])
    if len(set(checks.values())) != 1:
        raise ValueError("OpenSSL verifiers disagree")
    command(["git", "-C", str(source), "fsck", "--strict", "--no-reflogs", "--no-dangling"])
    report = {"inventory": "passed", "openssl_verifiers": checks,
              "windows_verifier_host": sys.platform,
              "native_windows_handle_branch_tested": os.name == "nt",
              "openssl_git_metadata": git_files}
    if (tree / "CARGO-VENDOR.json").is_file():
        report["cargo_vendor"] = verify_vendor(tree)
    return report


def prepare(stage, openssl_archive, patterns, vendor_home=None):
    version = tomllib.loads((ROOT / "Cargo.toml").read_text())["workspace"]["package"]["version"]
    tree = stage / "SSLRay"
    if stage.is_symlink() or not stage.resolve().is_relative_to((ROOT / "work").resolve()):
        raise ValueError("Generated staging directory must be inside this project's work/")
    stage.mkdir(parents=True, exist_ok=True)
    ownership = stage / ".sslray-source-stage.json"
    if tree.is_symlink() or ownership.is_symlink():
        raise ValueError("Staging tree/ownership marker must not be a symlink")
    if tree.exists() and not ownership.is_file():
        raise ValueError("Refusing to replace an unmarked staging tree")
    ownership.write_text(json.dumps({"generated_source_release": True, "version": version}) + "\n")
    tree.mkdir(exist_ok=True)
    # Refresh only this marked generated export. Keep the large, verified
    # upstream tree; both source verifiers recheck every byte on each run.
    for path in tree.iterdir():
        if path.name == "vendor" and vendor_home:
            continue
        if path.name == "third_party":
            for child in path.iterdir():
                if child.name != "openssl":
                    shutil.rmtree(child) if child.is_dir() and not child.is_symlink() else child.unlink()
        else:
            shutil.rmtree(path) if path.is_dir() and not path.is_symlink() else path.unlink()
    names = main_paths()
    scan_source(names, patterns)
    copied = {}
    for name in names:
        source, output = ROOT / name, tree / name
        output.parent.mkdir(parents=True, exist_ok=True)
        if source.is_symlink():
            output.symlink_to(os.readlink(source))
            copied[name] = {"target": os.readlink(source)}
        else:
            shutil.copyfile(source, output)
            output.chmod(stat.S_IMODE(source.stat().st_mode))
            copied[name] = {"sha256": digest(output), "mode": oct(stat.S_IMODE(output.stat().st_mode))}
    scan = scan_source(names, patterns, tree)
    pin = json.loads((tree / "third_party/openssl-source.json").read_text())
    extract_openssl(openssl_archive, tree, pin)
    rust_dependencies = (cargo_vendor(tree, vendor_home) if vendor_home else
                         "Public registry dependencies are pinned in Cargo.lock, not vendored; use network access or an existing Cargo cache.")
    source_epoch = int(os.environ.get("SOURCE_DATE_EPOCH", command(["git", "show", "-s", "--format=%ct", "HEAD"])))
    if source_epoch < 0:
        raise ValueError("Invalid SOURCE_DATE_EPOCH")
    release = {"project": "SSLRay", "version": version, "archive_root": tree.name, "license": "GPL-3.0-or-later",
               "additional_permission": "LICENSE-WINTUN-EXCEPTION", "working_tree_export": True,
               "base_commit": command(["git", "rev-parse", "HEAD"]), "source_date_epoch": source_epoch,
               "main_source_files": copied, "sensitive_content_scan": scan,
               "openssl": {"commit": pin["commit"], "tree": pin["tree"],
                           "url": pin["url"], "checkout_archive_sha256": OPENSSL_ZIP_SHA256,
                           "checkout_archive_origin": "Generated verified public shallow checkout, not an official upstream release archive",
                           "git_metadata": "Minimal public shallow repository; no main Git history, local index, reflog, hooks or private paths"},
               "rust_dependencies": rust_dependencies,
               "omnitun": "Vendored source and its original licenses/UPSTREAM.md are included.",
               "build_instructions": ["README.md", "docs/WINDOWS-BUILD.md", "docs/LINUX-BUILD.md"],
               "inventory_scope": "SOURCE-INVENTORY.json covers all entries except itself; the final archive has a separate SHA-256."}
    (tree / "SOURCE-RELEASE.json").write_text(json.dumps(release, indent=2) + "\n")
    (tree / "SOURCE-INVENTORY.json").write_text(json.dumps({"schema_version": 1, "entries": inventory(tree)}, indent=2) + "\n")
    verification = verify_tree(tree)
    # A concurrent doc/script/source edit must be refreshed before finalizing.
    if main_paths() != names:
        raise ValueError("Selected source inventory changed during staging; run again")
    for name, entry in copied.items():
        path = ROOT / name
        if ("target" in entry and os.readlink(path) != entry["target"]
                or "sha256" in entry and (digest(path) != entry["sha256"]
                    or oct(stat.S_IMODE(path.stat().st_mode)) != entry["mode"])):
            raise ValueError(f"Source changed during staging: {name}")
    entries = inventory(tree)
    report = {"stage": str(tree), "archive_root": tree.name, "status": "prepared_only", "main_source_files": len(copied),
              "staged_entries": len(entries),
              "staged_file_bytes": sum(e.get("bytes", 0) for e in entries.values()),
              "source_inventory_sha256": digest(tree / "SOURCE-INVENTORY.json"),
              "sensitive_content_scan": scan, "verification": verification}
    return tree, release, report


def make_archive(tree, archive, epoch):
    if archive.resolve().is_relative_to(tree.resolve()):
        raise ValueError("Archive output must be outside the exported source tree")
    if archive.resolve().is_relative_to(ROOT) and archive.relative_to(ROOT).parts[0] not in EXCLUDED_ROOTS:
        raise ValueError("Archive output inside the project must use an excluded generated directory")
    if archive.exists() or not archive.name.endswith(".tar.gz"):
        raise ValueError("Final archive must be a new .tar.gz file")
    archive.parent.mkdir(parents=True, exist_ok=True)
    temporary = archive.with_name(archive.name + ".part")
    if temporary.exists():
        raise ValueError("Previous partial archive exists; inspect it first")
    with temporary.open("xb") as file, gzip.GzipFile(filename="", mode="wb", fileobj=file, mtime=epoch) as compressed:
        with tarfile.open(fileobj=compressed, mode="w", format=tarfile.PAX_FORMAT) as tar:
            for path in [tree, *sorted(tree.rglob("*"))]:
                info = tar.gettarinfo(str(path), arcname=(Path(tree.name) / path.relative_to(tree)).as_posix())
                info.uid = info.gid = 0
                info.uname = info.gname = ""
                info.mtime = epoch
                info.pax_headers = {}
                if info.isfile():
                    with path.open("rb") as content:
                        tar.addfile(info, content)
                else:
                    tar.addfile(info)
    extracted = tree.parent / "archive-reextracted"
    if extracted.exists():
        raise ValueError("Prior archive extraction exists; use a fresh release stage")
    extracted.mkdir()
    with tarfile.open(temporary, "r:gz") as tar:
        for member in tar.getmembers():
            name = safe_relative(member.name)
            if name.parts[0] != tree.name:
                raise ValueError("Unexpected source archive root")
        def source_filter(member, destination):
            safe = tarfile.data_filter(member, destination)
            # data_filter adds owner read/write to regular 0444 files. Keep
            # its path/link/ownership checks while preserving our verified
            # source permission bits, including public Git pack-file 0444.
            return safe.replace(mode=member.mode & 0o777) if safe else None
        tar.extractall(extracted, filter=source_filter)
    verification = verify_tree(extracted / tree.name)
    if digest(tree / "SOURCE-INVENTORY.json") != digest(extracted / tree.name / "SOURCE-INVENTORY.json"):
        raise ValueError("Archive inventory changed after extraction")
    temporary.rename(archive)
    return {"path": str(archive), "bytes": archive.stat().st_size,
            "sha256": digest(archive), "reextraction_verification": verification}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--stage", type=Path, default=ROOT / "work/source-release-0.1.0")
    parser.add_argument("--openssl-checkout", type=Path, required=True)
    parser.add_argument("--scan-stdin", action="store_true", help="Read a JSON array of forbidden texts only from stdin; never store those texts")
    parser.add_argument("--vendor-cargo-home", type=Path, help="Isolated checksum-verified public Cargo cache for offline vendoring into the generated export only")
    parser.add_argument("--archive", type=Path, help="Create a final .tar.gz only after source/docs/scripts are frozen")
    args = parser.parse_args()
    tree, release, report = prepare(args.stage.resolve(), args.openssl_checkout.resolve(), read_patterns(args.scan_stdin), args.vendor_cargo_home)
    if args.archive:
        report["archive"] = make_archive(tree, args.archive.resolve(), release["source_date_epoch"])
        report["status"] = "archive_verified"
    (tree.parent / "verification.json").write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, subprocess.CalledProcessError, tarfile.TarError, zipfile.BadZipFile) as error:
        print(f"Source release preparation failed: {error}", file=sys.stderr)
        sys.exit(1)
