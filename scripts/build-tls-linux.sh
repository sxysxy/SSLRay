#!/bin/sh
set -eu
script_dir=$(CDPATH= cd "$(dirname "$0")" && pwd)
project_root=$(CDPATH= cd "$script_dir/.." && pwd)
. "$script_dir/linux-build-common.sh"
linux_build_settings
source="$project_root/third_party/openssl"
[ -f "$source/Configure" ] || { printf 'Initialize the pinned OpenSSL submodule first\n' >&2; exit 1; }
revision=$(python3 "$script_dir/verify-openssl-source.py" --source "$source")
configuration="REVISION=$revision
TARGET=$rust_target
GLIBC_MAX=$linux_glibc_max
CC=$(gcc --version | head -1)
CFLAGS=${CFLAGS:-}
CPPFLAGS=${CPPFLAGS:-}
LDFLAGS=${LDFLAGS:-}
OPTIONS=linux-x86_64 -fPIC -march=x86-64 -mtune=generic no-shared no-module no-tests enable-sm2 enable-sm3 enable-sm4"
if [ ! -f "$tls_root/build-settings.txt" ] || [ "$(cat "$tls_root/build-settings.txt")" != "$configuration" ] || \
   [ ! -f "$tls_prefix/lib/libssl.a" ] || [ ! -f "$tls_prefix/lib/libcrypto.a" ] || [ ! -x "$tls_prefix/bin/openssl" ]; then
  mkdir -p "$tls_root"
  rm -rf "$tls_root/build" "$tls_prefix"
  mkdir "$tls_root/build"
  cd "$tls_root/build"
  CC=gcc perl "$source/Configure" linux-x86_64 "--prefix=$tls_prefix" --libdir=lib --openssldir=/etc/ssl \
    -fPIC -march=x86-64 -mtune=generic no-shared no-module no-tests enable-sm2 enable-sm3 enable-sm4 \
    > "$tls_root/configure.log" 2>&1
  jobs=${SSLRAY_BUILD_JOBS:-8}
  case "$jobs" in ''|*[!0-9]*|0) printf 'Invalid SSLRAY_BUILD_JOBS\n' >&2; exit 1 ;; esac
  make -j"$jobs" build_sw > "$tls_root/build.log" 2>&1
  make install_sw > "$tls_root/install.log" 2>&1
fi
python3 "$script_dir/inspect-elf-linux.py" "$tls_prefix/bin/openssl" --max-glibc "$linux_glibc_max" > "$tls_root/elf-validation.json"
"$tls_prefix/bin/openssl" ciphers -s -tls1_3 -ciphersuites TLS_SM4_GCM_SM3:TLS_SM4_CCM_SM3 | \
  awk '/TLS_SM4_GCM_SM3/ && /TLS_SM4_CCM_SM3/ { ok=1 } END { exit !ok }'
[ "$(python3 "$script_dir/verify-openssl-source.py" --source "$source")" = "$revision" ]
printf '%s\n' "$configuration" > "$tls_root/build-settings.txt"
printf 'Verified project static OpenSSL: %s\n' "$tls_prefix"
