#!/bin/sh
set -eu
script_dir=$(CDPATH= cd "$(dirname "$0")" && pwd)
project_root=$(CDPATH= cd "$script_dir/.." && pwd)
. "$script_dir/macos-build-common.sh"
cd "$project_root"
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
mkdir -p "$project_root/dist"
staging=$(mktemp -d "$project_root/dist/.SSLRay-build.XXXXXX")
trap 'rm -rf "$staging"' EXIT
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
<key>CFBundleShortVersionString</key><string>0.1.0</string>
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
final_app="$project_root/dist/SSLRay.app"
if [ -e "$final_app" ]; then mv "$final_app" "$staging/previous.app"; fi
if ! mv "$app" "$final_app"; then
  if [ -e "$staging/previous.app" ]; then
    # Preserve the previous output if the final rename fails.
    mv "$staging/previous.app" "$final_app" || trap - EXIT
  fi
  exit 1
fi
printf 'Built %s (minimum macOS %s, static project OpenSSL, %s)\n' "$final_app" "$minimum_macos" "$macos_arch"
