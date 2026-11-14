#!/bin/sh
# Developer Cargo entry point using the same pinned, static TLS backend as .app.
set -eu
script_dir=$(CDPATH= cd "$(dirname "$0")" && pwd)
project_root=$(CDPATH= cd "$script_dir/.." && pwd)
. "$script_dir/macos-build-common.sh"
cd "$project_root"
macos_cargo_environment
exec cargo "$@"
