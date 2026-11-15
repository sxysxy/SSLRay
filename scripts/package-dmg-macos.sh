#!/bin/sh
# Package an existing signed bundle without rebuilding or changing it.
set -eu
if [ "$#" -ne 2 ]; then
  printf 'Usage: %s APP_PATH OUTPUT_DMG\n' "$0" >&2
  exit 1
fi
[ -d "$1" ] && [ ! -L "$1" ] || { printf 'Expected an app bundle directory\n' >&2; exit 1; }
source_app=$(CDPATH= cd "$1" && pwd)
identifier=$(/usr/libexec/PlistBuddy -c 'Print :CFBundleIdentifier' "$source_app/Contents/Info.plist")
[ "$identifier" = tech.sslray.client ] || { printf 'Expected the SSLRay app bundle\n' >&2; exit 1; }
/usr/bin/codesign --verify --deep --strict "$source_app"
output=$(python3 - "$source_app" "$2" <<'OUTPUT'
import sys
from pathlib import Path
source = Path(sys.argv[1]).resolve()
requested = Path(sys.argv[2])
if requested.is_symlink():
    raise SystemExit('Output must not be a symlink')
target = requested.resolve()
if target == source or source in target.parents:
    raise SystemExit('Output must be outside the source app bundle')
print(target)
OUTPUT
)
mkdir -p "$(dirname "$output")"
output_dir=$(CDPATH= cd "$(dirname "$output")" && pwd)
case "$output" in *.dmg) ;; *) printf 'Output must end in .dmg\n' >&2; exit 1 ;; esac
for destination in "$output" "$output.sha256" "$output.validation.json"; do
  [ ! -e "$destination" ] && [ ! -L "$destination" ] || { printf 'Output already exists: %s\n' "$destination" >&2; exit 1; }
done
stage=$(mktemp -d "$output_dir/.SSLRay-dmg.XXXXXXXX")
mountpoint="$stage/mounted"
mkdir "$mountpoint"

# Inspect the private mountpoint even after a partially failed attach. Never
# remove staging while an image is still mounted or mount state is uncertain.
owned_mount_state() {
  python3 - "$mountpoint" <<'MOUNT'
import os, sys
from pathlib import Path
try:
    path = Path(sys.argv[1])
    if path.is_symlink():
        raise OSError('Private mountpoint became a symlink')
    path.stat()
    path.parent.stat()
    sys.exit(0 if os.path.ismount(path) else 1)
except OSError as error:
    print(f'Cannot inspect private mountpoint: {error}', file=sys.stderr)
    sys.exit(2)
MOUNT
}
cleanup() {
  result=$?
  trap - EXIT HUP INT TERM
  mount_state=0
  owned_mount_state || mount_state=$?
  if [ "$mount_state" -eq 0 ]; then
    if ! /usr/bin/hdiutil detach "$mountpoint" >/dev/null; then
      printf 'Could not detach owned image; staging preserved: %s\n' "$stage" >&2
      exit 1
    fi
  elif [ "$mount_state" -ne 1 ]; then
    printf 'Mount state uncertain; staging preserved: %s\n' "$stage" >&2
    exit 1
  fi
  rm -rf "$stage"
  exit "$result"
}
trap cleanup EXIT
trap 'exit 1' HUP INT TERM

mkdir "$stage/root"
/usr/bin/ditto --rsrc --extattr "$source_app" "$stage/root/SSLRay.app"
ln -s /Applications "$stage/root/Applications"
image="$stage/SSLRay.dmg"
/usr/bin/hdiutil create -volname SSLRay -fs HFS+ -format UDZO \
  -imagekey zlib-level=9 -srcfolder "$stage/root" "$image"
/usr/bin/hdiutil verify "$image"
/usr/bin/hdiutil attach -readonly -nobrowse -noautoopen -mountpoint "$mountpoint" \
  -plist "$image" > "$stage/attach.plist"
/usr/sbin/diskutil info -plist "$mountpoint" > "$stage/volume.plist"
/usr/bin/codesign --verify --deep --strict "$mountpoint/SSLRay.app"
python3 - "$source_app" "$mountpoint" "$stage/volume.plist" "$stage/validation.json" <<'VERIFY'
import hashlib, json, os, plistlib, stat, sys
from pathlib import Path

def inventory(root):
    entries = {'.': {'type': 'directory', 'mode': stat.S_IMODE(root.lstat().st_mode)}}
    for path in sorted(root.rglob('*')):
        info = path.lstat()
        item = {'mode': stat.S_IMODE(info.st_mode)}
        if stat.S_ISREG(info.st_mode):
            item.update(type='file', bytes=info.st_size, sha256=hashlib.sha256(path.read_bytes()).hexdigest())
        elif stat.S_ISDIR(info.st_mode):
            item['type'] = 'directory'
        elif stat.S_ISLNK(info.st_mode):
            item.update(type='symlink', target=os.readlink(path))
        else:
            raise SystemExit(f'Unexpected app entry type: {path}')
        entries[path.relative_to(root).as_posix()] = item
    return entries

source, volume = map(Path, sys.argv[1:3])
visible = sorted(path.name for path in volume.iterdir() if not path.name.startswith('.'))
if visible != ['Applications', 'SSLRay.app']:
    raise SystemExit(f'Unexpected DMG root entries: {visible}')
link = volume / 'Applications'
if not link.is_symlink() or os.readlink(link) != '/Applications':
    raise SystemExit('Applications must be a symlink to /Applications')
with open(sys.argv[3], 'rb') as file:
    volume_info = plistlib.load(file)
if volume_info.get('VolumeName') != 'SSLRay':
    raise SystemExit('DMG volume name is not SSLRay')
original = inventory(source)
mounted = inventory(volume / 'SSLRay.app')
if original != mounted:
    changed = sorted(key for key in original.keys() | mounted.keys() if original.get(key) != mounted.get(key))
    raise SystemExit(f'Mounted app content/mode mismatch: {changed[:10]}')
record = {'volume_name': 'SSLRay', 'app_name': 'SSLRay.app', 'applications_link': '/Applications',
          'app_entries_verified': len(original), 'app_files_verified': sum(x['type'] == 'file' for x in original.values()),
          'app_manifest_sha256': hashlib.sha256(json.dumps(original, sort_keys=True).encode()).hexdigest(),
          'executable_sha256': hashlib.sha256((source / 'Contents/MacOS/SSLRay').read_bytes()).hexdigest(),
          'app_bytes_and_modes_unchanged': True, 'mounted_codesign_verified': True}
Path(sys.argv[4]).write_text(json.dumps(record, indent=2) + '\n')
VERIFY
/usr/bin/hdiutil detach "$mountpoint"
if owned_mount_state; then
  printf 'Owned image remained mounted; refusing publication\n' >&2
  exit 1
else
  mount_state=$?
  [ "$mount_state" -eq 1 ] || exit 1
fi
# Hard links publish verified files atomically on the staging/output filesystem
# and refuse to replace a concurrently created destination.
python3 - "$image" "$output" "$stage/validation.json" <<'PUBLISH'
import hashlib, json, os, sys
from pathlib import Path
image, output, proof = map(Path, sys.argv[1:])
checksum = hashlib.sha256(image.read_bytes()).hexdigest()
record = json.loads(proof.read_text())
record.update(dmg_file=output.name, dmg_sha256=checksum, dmg_bytes=image.stat().st_size, detached_after_validation=True)
proof.write_text(json.dumps(record, indent=2) + '\n')
checksum_file = proof.parent / 'checksum.txt'
checksum_file.write_text(checksum + '  ' + output.name + '\n')
published = []
try:
    for staged, final in [(image, output), (checksum_file, Path(str(output) + '.sha256')),
                          (proof, Path(str(output) + '.validation.json'))]:
        os.link(staged, final)
        published.append((staged, final))
except BaseException:
    for staged, final in reversed(published):
        try:
            if os.path.samestat(staged.stat(), final.lstat()):
                final.unlink()
        except FileNotFoundError:
            pass
    raise
PUBLISH
printf 'Built %s (SSLRay.app and Applications -> /Applications)\n' "$output"
