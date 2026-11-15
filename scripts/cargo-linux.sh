#!/bin/sh
set -eu
script_dir=$(CDPATH= cd "$(dirname "$0")" && pwd)
project_root=$(CDPATH= cd "$script_dir/.." && pwd)
. "$script_dir/linux-build-common.sh"
cd "$project_root"
linux_cargo_environment
exec cargo "$@"
