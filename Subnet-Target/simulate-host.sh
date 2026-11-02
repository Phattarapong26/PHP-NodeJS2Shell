#!/usr/bin/env bash
# DRY RUN บนเครื่องนี้ (ไม่ต้องมี docker): จำลอง kernel/os ของ .38 หรือ .40
#   ./simulate-host.sh 38 -- uname -a
#   ./simulate-host.sh 40 -- cat /proc/version
set -euo pipefail
cd "$(dirname "$0")"
id="${1:?usage: simulate-host.sh <38|40> [--] <command...>}"
shift
[ "${1:-}" = "--" ] && shift
[ $# -gt 0 ] || set -- bash
root="$PWD/os/host$id"
[ -d "$root" ] || python3 make-os-tree.py "host$id" >/dev/null
rel=$(python3 -c "import json;print(json.load(open('$root/profile.json'))['kernel_release'])")
ver=$(python3 -c "import json;print(json.load(open('$root/profile.json'))['kernel_version'])")
host=$(python3 -c "import json;print(json.load(open('$root/profile.json'))['hostname'])")
exec env \
  LD_PRELOAD="$PWD/tools/libfakekernel.so" \
  FAKEKERNEL_ROOT="$root" \
  FAKEKERNEL_RELEASE="$rel" \
  FAKEKERNEL_VERSION="$ver" \
  FAKEKERNEL_HOSTNAME="$host" \
  PATH="$root/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin" \
  "$@"
