#!/bin/sh
set -eu
script_dir=$(CDPATH= cd "$(dirname "$0")" && pwd)
project_root=$(CDPATH= cd "$script_dir/.." && pwd)
. "$script_dir/linux-build-common.sh"
cd "$project_root"
linux_cargo_environment
cargo build --release --locked --target "$rust_target" -p sslray
binary="$CARGO_TARGET_DIR/$rust_target/release/sslray"
python3 "$script_dir/inspect-elf-linux.py" "$binary" --max-glibc "$linux_glibc_max" > "$tls_root/app-elf-validation.json"
version=$(python3 -c 'import tomllib; print(tomllib.load(open("Cargo.toml", "rb"))["workspace"]["package"]["version"])')
[ "$("$binary" --version)" = "sslray $version" ] || { printf 'CLI version mismatch\n' >&2; exit 1; }
output=${1:-$project_root/dist}
mkdir -p "$output"
output=$(CDPATH= cd "$output" && pwd)
name="SSLRay-$version-linux-x86_64"
[ ! -e "$output/$name" ] && [ ! -e "$output/$name.tar.gz" ] || { printf 'Versioned output already exists\n' >&2; exit 1; }
stage=$(mktemp -d "$project_root/work/linux-bundle.XXXXXXXX")
trap 'rm -rf "$stage"' EXIT
trap 'exit 1' HUP INT TERM
package="$stage/$name"
mkdir -p "$package/bin" "$package/share/icons/hicolor/scalable/apps" "$package/share/applications"
cp "$binary" "$package/bin/sslray"
cp "$project_root/assets/sslray.svg" "$package/share/icons/hicolor/scalable/apps/sslray.svg"
for notice in LICENSE COPYRIGHT LICENSE-WINTUN-EXCEPTION; do
  cp "$project_root/$notice" "$package/$notice"
done
cat > "$package/SSLRay" <<'LAUNCHER'
#!/bin/sh
set -eu
app_dir=$(CDPATH= cd "$(dirname "$0")" && pwd)
exec "$app_dir/bin/sslray" "$@"
LAUNCHER
chmod +x "$package/SSLRay" "$package/bin/sslray"
cat > "$package/share/applications/tech.sslray.client.desktop" <<'DESKTOP'
[Desktop Entry]
Type=Application
Name=SSLRay
Comment=Native SSL VPN client
Exec=SSLRay
Icon=sslray
Terminal=false
Categories=Network;
DESKTOP
python3 "$script_dir/collect-licenses.py" --output "$package/ThirdPartyLicenses" --binary "$binary" --tls-source "$SSLRAY_TLS_SOURCE_DIR"
"$binary" capabilities > "$package/tls-capabilities.json"
python3 - "$package/tls-capabilities.json" <<'CHECK'
import json,sys
data=json.load(open(sys.argv[1]))
assert data['gm_tls13'] and data['backend'].startswith('OpenSSL ')
CHECK
cp "$tls_root/app-elf-validation.json" "$package/elf-validation.json"
cp "$tls_root/build-settings.txt" "$package/tls-build-settings.txt"
python3 - "$package/build-info.json" <<'BUILDINFO'
import hashlib,json,platform,subprocess,sys
from pathlib import Path
record={"architecture":platform.machine(),"rustc":subprocess.check_output(["rustc","--version"],text=True).strip(),
        "compiler":subprocess.check_output(["gcc","--version"],text=True).splitlines()[0],
        "build_glibc":subprocess.check_output(["getconf","GNU_LIBC_VERSION"],text=True).strip()}
manifest=Path('BUILD-SOURCE-MANIFEST.json')
if manifest.is_file():
    data=json.loads(manifest.read_text());record['source_base_commit']=data.get('base_commit')
    record['source_manifest_sha256']=hashlib.sha256(manifest.read_bytes()).hexdigest()
Path(sys.argv[1]).write_text(json.dumps(record,indent=2)+'\n')
BUILDINFO
cat > "$package/README.txt" <<README
SSLRay $version - Linux x86_64
Start ./SSLRay. CLI commands are available through ./SSLRay --help.
The executable requires glibc <=$linux_glibc_max symbols; use a system with glibc $linux_glibc_max or newer.
Runtime GUI dependencies include GTK 3, X11/Wayland, OpenGL and a working display.
The tray requires libayatana-appindicator3.so.1 or libappindicator3.so.1 and desktop support.
These OS libraries are not bundled. OpenSSL is statically linked from the pinned project source.
Connecting requires /dev/net/tun, iproute2 and polkit/pkexec with a desktop authentication agent.
No service, desktop entry, user configuration or routing is installed by unpacking or launching this bundle.
The .desktop file is a template requiring the launcher/icon to be placed in your desktop search paths.
ThirdPartyLicenses/INDEX.json records the actual local notice collection scope and gaps.
See elf-validation.json and tls-capabilities.json for build validation, not a claim of all-distribution runtime testing.
README
python3 - "$package" <<'HASHES'
import hashlib,sys
from pathlib import Path
root=Path(sys.argv[1]); paths=sorted(p for p in root.rglob('*') if p.is_file())
(root/'SHA256SUMS.txt').write_text(''.join(hashlib.sha256(p.read_bytes()).hexdigest()+'  '+p.relative_to(root).as_posix()+'\n' for p in paths))
HASHES
tar -C "$stage" -czf "$stage/$name.tar.gz" "$name"
mkdir "$stage/unpacked"
tar -C "$stage/unpacked" -xzf "$stage/$name.tar.gz"
diff -r "$package" "$stage/unpacked/$name"
mv "$package" "$output/$name"
mv "$stage/$name.tar.gz" "$output/$name.tar.gz"
(cd "$output" && sha256sum "$name.tar.gz") > "$output/$name.tar.gz.sha256"
printf 'Built %s\n' "$output/$name.tar.gz"
