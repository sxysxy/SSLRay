#!/bin/sh
# Shared, side-effect-free Mach-O/version helpers for macOS builds.

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

macos_version_at_most() {
  /usr/bin/awk -v actual="$1" -v limit="$2" 'BEGIN {
    split(actual, a, "."); split(limit, b, ".")
    for (i = 1; i <= 3; i++) {
      if (a[i] + 0 > b[i] + 0) exit 1
      if (a[i] + 0 < b[i] + 0) exit 0
    }
    exit 0
  }'
}

macos_build_settings() {
  macos_target=${MACOSX_DEPLOYMENT_TARGET:-11.0}
  printf '%s\n' "$macos_target" | highest_macos_version >/dev/null || {
    printf 'Invalid macOS deployment target\n' >&2; return 1;
  }
  macos_version_at_most 11.0 "$macos_target" || {
    printf 'SSLRay macOS builds require a deployment target of at least 11.0\n' >&2; return 1;
  }
  macos_arch=${SSLRAY_MACOS_ARCH:-$(uname -m)}
  case "$macos_arch" in
    arm64) rust_target=aarch64-apple-darwin; openssl_target=darwin64-arm64-cc ;;
    x86_64) rust_target=x86_64-apple-darwin; openssl_target=darwin64-x86_64-cc ;;
    *) printf 'Unsupported macOS architecture: %s\n' "$macos_arch" >&2; return 1 ;;
  esac
  MACOSX_DEPLOYMENT_TARGET=$macos_target
  SDKROOT=${SDKROOT:-$(/usr/bin/xcrun --sdk macosx --show-sdk-path)}
  export MACOSX_DEPLOYMENT_TARGET SDKROOT
  tls_root="$project_root/work/openssl-macos-$macos_arch-$macos_target"
  tls_prefix="$tls_root/install"
}

check_macos_deployment() {
  actual_minimum=$(macos_min_version "$1")
  macos_version_at_most "$actual_minimum" "$macos_target" || {
    printf '%s requires macOS %s, above selected target %s\n' "$1" "$actual_minimum" "$macos_target" >&2
    return 1
  }
}

# Shared by the ordinary developer wrapper and the release packager. An
# explicit OPENSSL_DIR override must also contain target-compatible static libs.
macos_cargo_environment() {
  macos_build_settings
  if [ -n "${OPENSSL_DIR:-}" ]; then
    OPENSSL_DIR=$(CDPATH= cd "$OPENSSL_DIR" && pwd)
  else
    /bin/sh "$script_dir/build-tls-macos.sh"
    OPENSSL_DIR=$tls_prefix
    SSLRAY_TLS_SOURCE_DIR="$project_root/third_party/openssl"
    export SSLRAY_TLS_SOURCE_DIR
  fi
  for archive in "$OPENSSL_DIR/lib/libssl.a" "$OPENSSL_DIR/lib/libcrypto.a"; do
    [ -f "$archive" ] || {
      printf 'A static TLS archive is required: %s\n' "$archive" >&2; return 1;
    }
    check_macos_deployment "$archive"
  done
  OPENSSL_STATIC=1
  OPENSSL_NO_VENDOR=1
  OPENSSL_LIB_DIR="$OPENSSL_DIR/lib"
  OPENSSL_INCLUDE_DIR="$OPENSSL_DIR/include"
  CARGO_BUILD_TARGET=$rust_target
  CARGO_TARGET_DIR=${CARGO_TARGET_DIR:-$project_root/work/macos-$macos_arch-$macos_target-target}
  export OPENSSL_DIR OPENSSL_STATIC OPENSSL_NO_VENDOR OPENSSL_LIB_DIR OPENSSL_INCLUDE_DIR
  export CARGO_BUILD_TARGET CARGO_TARGET_DIR
}

macos_dylib_imports() {
  imports=$(/usr/bin/otool -L "$1") || return 1
  printf '%s\n' "$imports" | /usr/bin/awk '
    /^[[:space:]]/ {
      sub(/^[[:space:]]+/, "")
      sub(/[[:space:]]+\(compatibility version.*$/, "")
      print
    }
  '
}
