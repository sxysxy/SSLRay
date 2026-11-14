#!/bin/sh
# Build the pinned project OpenSSL submodule without modifying its source tree.
set -eu
script_dir=$(CDPATH= cd "$(dirname "$0")" && pwd)
project_root=$(CDPATH= cd "$script_dir/.." && pwd)
. "$script_dir/macos-build-common.sh"
macos_build_settings
openssl_source="$project_root/third_party/openssl"
if [ ! -f "$openssl_source/Configure" ]; then
  printf 'Missing OpenSSL submodule. Run: git submodule update --init third_party/openssl\n' >&2
  exit 1
fi
# Verify complete source bytes, executable bits and symlinks against the pin.
# This also works for a full source export without Git metadata.
revision=$(python3 "$script_dir/verify-openssl-source.py" --source "$openssl_source")
version=$(/usr/bin/awk -F= '/^MAJOR=/ { major=$2 } /^MINOR=/ { minor=$2 } /^PATCH=/ { patch=$2 } END { print major "." minor "." patch }' "$openssl_source/VERSION.dat")
compiler=$(/usr/bin/xcrun --sdk "$SDKROOT" --find clang)
sdk_version=$(/usr/bin/xcrun --sdk "$SDKROOT" --show-sdk-version)
compiler_version=$("$compiler" --version | /usr/bin/head -n 1)
configuration="OpenSSL=$version
REVISION=$revision
ARCH=$macos_arch
MACOSX_DEPLOYMENT_TARGET=$macos_target
SDKROOT=$SDKROOT
SDK_VERSION=$sdk_version
CC=$compiler_version
OPTIONS=no-shared no-module no-tests enable-sm2 enable-sm3 enable-sm4"
if [ -f "$tls_root/build-settings.txt" ] && \
   [ "$(cat "$tls_root/build-settings.txt")" = "$configuration" ] && \
   [ -f "$tls_prefix/lib/libssl.a" ] && [ -f "$tls_prefix/lib/libcrypto.a" ] && \
   [ -x "$tls_prefix/bin/openssl" ]; then
  check_macos_deployment "$tls_prefix/lib/libssl.a"
  check_macos_deployment "$tls_prefix/lib/libcrypto.a"
  check_macos_deployment "$tls_prefix/bin/openssl"
  printf 'Reusing static OpenSSL backend: %s\n' "$tls_prefix"
  exit 0
fi

# Configure from an independent directory. The submodule stays pristine and
# old working backends/binaries remain untouched throughout the build.
mkdir -p "$tls_root"
rm -rf "$tls_root/build" "$tls_prefix"
mkdir -p "$tls_root/build"
cd "$tls_root/build"
CC="$compiler" perl "$openssl_source/Configure" "$openssl_target" \
  "--prefix=$tls_prefix" --libdir=lib "--openssldir=$tls_prefix/ssl" \
  "-mmacosx-version-min=$macos_target" \
  no-shared no-module no-tests enable-sm2 enable-sm3 enable-sm4 \
  > "$tls_root/configure.log" 2>&1
jobs=${SSLRAY_BUILD_JOBS:-8}
case "$jobs" in ''|*[!0-9]*|0) printf 'Invalid SSLRAY_BUILD_JOBS\n' >&2; exit 1 ;; esac
make -j"$jobs" build_sw > "$tls_root/build.log" 2>&1
make install_sw > "$tls_root/install.log" 2>&1

# otool visits every Mach-O member in these archives, including assembly.
check_macos_deployment "$tls_prefix/lib/libssl.a"
check_macos_deployment "$tls_prefix/lib/libcrypto.a"
check_macos_deployment "$tls_prefix/bin/openssl"
if [ -n "$(tls_dylibs "$tls_prefix/bin/openssl")" ]; then
  printf 'Static OpenSSL unexpectedly imports a TLS dylib\n' >&2
  exit 1
fi
"$tls_prefix/bin/openssl" ciphers -s -tls1_3 \
  -ciphersuites TLS_SM4_GCM_SM3:TLS_SM4_CCM_SM3 | \
  /usr/bin/awk '/TLS_SM4_GCM_SM3/ && /TLS_SM4_CCM_SM3/ { found=1 } END { exit !found }'
verified_after=$(python3 "$script_dir/verify-openssl-source.py" --source "$openssl_source")
if [ "$verified_after" != "$revision" ]; then
  printf 'The OpenSSL source pin changed during the build\n' >&2
  exit 1
fi
printf '%s\n' "$configuration" > "$tls_root/build-settings.txt"
printf 'Built static OpenSSL %s: %s (macOS %s)\n' "$version" "$tls_prefix" "$macos_target"
