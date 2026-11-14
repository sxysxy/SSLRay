#!/bin/sh
set -eu

# Compare each numeric component, including patch versions; lexical sorting
# would incorrectly place 10.9 above 10.15. Accept every architecture in a fat
# Mach-O and use its highest requirement for the bundle-wide declaration.
highest_macos_version() {
  /usr/bin/awk '
    function newer(candidate, current, a, b, i) {
      split(candidate, a, ".")
      split(current, b, ".")
      for (i = 1; i <= 3; i++) {
        if (a[i] + 0 > b[i] + 0) return 1
        if (a[i] + 0 < b[i] + 0) return 0
      }
      return 0
    }
    {
      if (NF != 1 || $1 !~ /^[0-9]+([.][0-9]+)?([.][0-9]+)?$/) {
        invalid = 1
        exit 1
      }
      if (maximum == "" || newer($1, maximum)) maximum = $1
    }
    END {
      if (invalid || maximum == "") exit 1
      print maximum
    }
  '
}

macos_min_version() {
  load_commands=$(/usr/bin/otool -l "$1") || return 1
  minimum=$(printf '%s\n' "$load_commands" | /usr/bin/awk '
    $1 == "cmd" { command = $2; platform = "" }
    command == "LC_BUILD_VERSION" && $1 == "platform" { platform = $2 }
    command == "LC_BUILD_VERSION" && $1 == "minos" &&
      (platform == "1" || platform == "MACOS") { print $2 }
    command == "LC_VERSION_MIN_MACOSX" && $1 == "version" { print $2 }
  ' | highest_macos_version) || {
    printf 'Cannot determine minimum macOS version from %s\n' "$1" >&2
    return 1
  }
  printf '%s\n' "$minimum"
}

tls_dylibs() {
  linked_libraries=$(/usr/bin/otool -L "$1") || return 1
  printf '%s\n' "$linked_libraries" | /usr/bin/awk '
    /^[[:space:]]/ {
      sub(/^[[:space:]]+/, "")
      sub(/[[:space:]]+\(compatibility version.*$/, "")
      name = $0
      sub(/^.*\//, "", name)
      if (name ~ /^lib(ssl|crypto).*\.dylib$/) print
    }
  '
}

cd "$(dirname "$0")/.."
cargo build --release -p sslray --locked
app="$PWD/dist/SSLRay.app"
# Generated libraries must belong only to this build. In particular, a static
# Tongsuo build must not retain dylibs or minOS values from an earlier bundle.
rm -rf "$app/Contents/Frameworks"
mkdir -p "$app/Contents/MacOS" "$app/Contents/Frameworks" "$app/Contents/Resources"
cp "${CARGO_TARGET_DIR:-target}/release/sslray" "$app/Contents/MacOS/SSLRay"
minimum_macos=$(macos_min_version "$app/Contents/MacOS/SSLRay")
# Bundle the linked OpenSSL/Tongsuo dylibs using their observed paths.
libraries=$(tls_dylibs "$app/Contents/MacOS/SSLRay")
has_tls_dylibs=0
while IFS= read -r lib; do
  [ -n "$lib" ] || continue
  name=$(basename "$lib")
  cp -L "$lib" "$app/Contents/Frameworks/$name"
  chmod u+w "$app/Contents/Frameworks/$name"
  install_name_tool -id "@rpath/$name" "$app/Contents/Frameworks/$name"
  install_name_tool -change "$lib" "@rpath/$name" "$app/Contents/MacOS/SSLRay"
  has_tls_dylibs=1
done <<LIBRARIES
$libraries
LIBRARIES
for lib in "$app"/Contents/Frameworks/*.dylib; do
  [ -f "$lib" ] || continue
  library_minimum=$(macos_min_version "$lib")
  minimum_macos=$(printf '%s\n%s\n' "$minimum_macos" "$library_minimum" | highest_macos_version)
  dependencies=$(tls_dylibs "$lib")
  while IFS= read -r dependency; do
    [ -n "$dependency" ] || continue
    name=$(basename "$dependency")
    install_name_tool -change "$dependency" "@rpath/$name" "$lib"
  done <<DEPENDENCIES
$dependencies
DEPENDENCIES
done
if [ "$has_tls_dylibs" -eq 1 ]; then
  install_name_tool -add_rpath '@executable_path/../Frameworks' "$app/Contents/MacOS/SSLRay"
fi
cat > "$app/Contents/Info.plist" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>CFBundleName</key><string>SSLRay</string>
<key>CFBundleDisplayName</key><string>SSLRay</string>
<key>CFBundleIdentifier</key><string>tech.sslray.client</string>
<key>CFBundleExecutable</key><string>SSLRay</string>
<key>CFBundlePackageType</key><string>APPL</string>
<key>CFBundleShortVersionString</key><string>0.1.0</string>
<key>NSHighResolutionCapable</key><true/>
<key>LSMinimumSystemVersion</key><string>$minimum_macos</string>
</dict></plist>
PLIST
python3 scripts/collect-licenses.py \
  --output "$app/Contents/Resources/ThirdPartyLicenses" \
  --binary "${CARGO_TARGET_DIR:-target}/release/sslray" \
  --tls-libraries "$libraries"
codesign --force --deep --sign - "$app"
printf 'Built %s (minimum macOS %s)\n' "$app" "$minimum_macos"
