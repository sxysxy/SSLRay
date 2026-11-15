#!/bin/sh
# Native GNU/Linux build settings; no package installation or privilege changes.
linux_build_settings() {
  [ "$(uname -s)" = Linux ] && [ "$(uname -m)" = x86_64 ] || {
    printf 'This release entry point requires native Linux x86_64\n' >&2; return 1;
  }
  for tool in python3 perl make gcc ar readelf cargo; do
    command -v "$tool" >/dev/null || { printf 'Required build tool missing: %s\n' "$tool" >&2; return 1; }
  done
  python3 -c 'import sys; assert sys.version_info >= (3, 11)' || return 1
  perl -MIPC::Cmd -e 1 || { printf 'Install the native Perl IPC::Cmd module in the build environment\n' >&2; return 1; }
  rust_target=x86_64-unknown-linux-gnu
  linux_glibc_max=${SSLRAY_GLIBC_MAX:-2.28}
  case "$linux_glibc_max" in ''|*[!0-9.]*) printf 'Invalid GLIBC limit\n' >&2; return 1 ;; esac
  tls_root="$project_root/work/openssl-linux-x86_64-glibc$linux_glibc_max"
  tls_prefix="$tls_root/install"
}

linux_cargo_environment() {
  linux_build_settings
  /bin/sh "$script_dir/build-tls-linux.sh"
  OPENSSL_DIR=$tls_prefix
  OPENSSL_LIB_DIR="$tls_prefix/lib"
  OPENSSL_INCLUDE_DIR="$tls_prefix/include"
  OPENSSL_STATIC=1
  OPENSSL_NO_VENDOR=1
  OPENSSL_LIBS=ssl:crypto
  X86_64_UNKNOWN_LINUX_GNU_OPENSSL_DIR=$OPENSSL_DIR
  X86_64_UNKNOWN_LINUX_GNU_OPENSSL_LIB_DIR=$OPENSSL_LIB_DIR
  X86_64_UNKNOWN_LINUX_GNU_OPENSSL_INCLUDE_DIR=$OPENSSL_INCLUDE_DIR
  X86_64_UNKNOWN_LINUX_GNU_OPENSSL_STATIC=1
  X86_64_UNKNOWN_LINUX_GNU_OPENSSL_NO_VENDOR=1
  X86_64_UNKNOWN_LINUX_GNU_OPENSSL_LIBS=$OPENSSL_LIBS
  SSLRAY_TLS_SOURCE_DIR="$project_root/third_party/openssl"
  CARGO_BUILD_TARGET=$rust_target
  CARGO_TARGET_DIR=${CARGO_TARGET_DIR:-$project_root/work/linux-x86_64-glibc$linux_glibc_max-target}
  CARGO_BUILD_JOBS=${CARGO_BUILD_JOBS:-8}
  export OPENSSL_DIR OPENSSL_LIB_DIR OPENSSL_INCLUDE_DIR OPENSSL_STATIC OPENSSL_NO_VENDOR OPENSSL_LIBS
  export X86_64_UNKNOWN_LINUX_GNU_OPENSSL_DIR X86_64_UNKNOWN_LINUX_GNU_OPENSSL_LIB_DIR
  export X86_64_UNKNOWN_LINUX_GNU_OPENSSL_INCLUDE_DIR X86_64_UNKNOWN_LINUX_GNU_OPENSSL_STATIC
  export X86_64_UNKNOWN_LINUX_GNU_OPENSSL_NO_VENDOR X86_64_UNKNOWN_LINUX_GNU_OPENSSL_LIBS
  export SSLRAY_TLS_SOURCE_DIR CARGO_BUILD_TARGET CARGO_TARGET_DIR CARGO_BUILD_JOBS
}
