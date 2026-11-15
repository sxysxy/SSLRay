#!/bin/sh
set -eu
script_dir=$(CDPATH= cd "$(dirname "$0")" && pwd)
project_root=$(CDPATH= cd "$script_dir/.." && pwd)
. "$script_dir/macos-build-common.sh"
cd "$project_root"
[ "$#" -le 1 ] || { printf 'Usage: %s [OUTPUT_DIRECTORY]\n' "$0" >&2; exit 1; }
output=${1:-$project_root/dist}
mkdir -p "$output"
output=$(CDPATH= cd "$output" && pwd)
version=$(python3 -c 'import tomllib; print(tomllib.load(open("Cargo.toml", "rb"))["workspace"]["package"]["version"])')
icon="$project_root/assets/icons/SSLRay.icns"
[ -s "$icon" ] || { printf 'Missing app icon: %s\n' "$icon" >&2; exit 1; }
macos_cargo_environment
cargo build --release --target "$rust_target" -p sslray --locked
binary="$CARGO_TARGET_DIR/$rust_target/release/sslray"
check_macos_deployment "$binary"

# A project-source static TLS build must never retain a Homebrew/runtime TLS
# dependency. All remaining imports must be the OS's own frameworks/libraries.
libraries=$(tls_dylibs "$binary")
[ -z "$libraries" ] || { printf 'Unexpected dynamic TLS dependency in static build\n' >&2; exit 1; }
imports=$(macos_dylib_imports "$binary")
while IFS= read -r dependency; do
  [ -n "$dependency" ] || continue
  case "$dependency" in
    /usr/lib/*|/System/Library/*) ;;
    *) printf 'Unexpected non-system dynamic dependency: %s\n' "$dependency" >&2; exit 1 ;;
  esac
done <<IMPORTS
$imports
IMPORTS

# Build a fresh bundle and replace the old output only after validation/signing.
# No earlier Frameworks directory or running executable is modified in place.
staging=$(mktemp -d "$output/.SSLRay-build.XXXXXX")
cleanup_bundle() {
  result=$?
  trap - EXIT HUP INT TERM
  if [ "$result" -ne 0 ] && { [ -e "$staging/previous.app" ] || [ -L "$staging/previous.app" ]; }; then
    printf 'Previous app preserved for recovery: %s\n' "$staging/previous.app" >&2
    exit "$result"
  fi
  # The DMG helper preserves a failed detach for recovery. Its parent must not
  # recursively delete that still-mounted private staging directory either.
  if ! python3 - "$staging" <<'UNMOUNTED'
import os, sys
from pathlib import Path
try:
    for path in Path(sys.argv[1]).glob('.SSLRay-dmg.*/mounted'):
        path.stat()
        if path.is_symlink() or os.path.ismount(path):
            raise OSError(f'Owned image may still be mounted: {path}')
except OSError as error:
    print(error, file=sys.stderr)
    sys.exit(1)
UNMOUNTED
  then
    printf 'Image staging preserved: %s\n' "$staging" >&2
    exit 1
  fi
  rm -rf "$staging"
  exit "$result"
}
trap cleanup_bundle EXIT
trap 'exit 1' HUP INT TERM
app="$staging/SSLRay.app"
mkdir -p "$app/Contents/MacOS" "$app/Contents/Frameworks" "$app/Contents/Resources"
cp "$binary" "$app/Contents/MacOS/SSLRay"
cp "$icon" "$app/Contents/Resources/SSLRay.icns"
minimum_macos=$(macos_min_version "$app/Contents/MacOS/SSLRay")
cat > "$app/Contents/Info.plist" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>CFBundleName</key><string>SSLRay</string>
<key>CFBundleDisplayName</key><string>SSLRay</string>
<key>CFBundleIdentifier</key><string>tech.sslray.client</string>
<key>CFBundleExecutable</key><string>SSLRay</string>
<key>CFBundleIconFile</key><string>SSLRay.icns</string>
<key>CFBundlePackageType</key><string>APPL</string>
<key>CFBundleShortVersionString</key><string>$version</string>
<key>NSHighResolutionCapable</key><true/>
<key>LSMinimumSystemVersion</key><string>$minimum_macos</string>
</dict></plist>
PLIST
python3 scripts/collect-licenses.py \
  --output "$app/Contents/Resources/ThirdPartyLicenses" \
  --binary "$binary" \
  --tls-libraries "$libraries"
codesign --force --deep --sign - "$app"
codesign --verify --deep --strict "$app"
/usr/bin/plutil -lint "$app/Contents/Info.plist"
check_macos_deployment "$app/Contents/MacOS/SSLRay"
archive_name="SSLRay-$version-macos-$macos_arch.dmg"
for suffix in '' '.sha256' '.validation.json'; do
  [ ! -e "$output/$archive_name$suffix" ] && [ ! -L "$output/$archive_name$suffix" ] || {
    printf 'Versioned output already exists; choose an empty output directory\n' >&2; exit 1;
  }
done
/bin/sh "$script_dir/package-dmg-macos.sh" "$app" "$staging/$archive_name"
final_app="$output/SSLRay.app"
python3 - "$app" "$final_app" "$staging" "$archive_name" "$output" <<'PUBLISH'
import os, sys
from pathlib import Path
app, final_app, stage = map(Path, sys.argv[1:4])
name, output = sys.argv[4], Path(sys.argv[5])
previous = stage / 'previous.app'
had_previous = os.path.lexists(final_app)
app_identity = app.lstat()
app_published = False
published = []
try:
    if had_previous:
        final_app.rename(previous)
    app.rename(final_app)
    app_published = True
    for suffix in ['', '.sha256', '.validation.json']:
        candidate, destination = stage / (name + suffix), output / (name + suffix)
        os.link(candidate, destination)
        published.append((candidate, destination))
except BaseException:
    for candidate, destination in reversed(published):
        if os.path.lexists(destination) and os.path.samestat(candidate.stat(), destination.lstat()):
            destination.unlink()
    if app_published and os.path.lexists(final_app) and os.path.samestat(app_identity, final_app.lstat()):
        final_app.rename(app)
    if had_previous and os.path.lexists(previous) and not os.path.lexists(final_app):
        previous.rename(final_app)
    raise
PUBLISH
printf 'Built %s (minimum macOS %s, static project OpenSSL, %s)\n' "$final_app" "$minimum_macos" "$macos_arch"
printf 'DMG %s\n' "$output/$archive_name"
