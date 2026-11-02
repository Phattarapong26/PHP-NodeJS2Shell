#!/usr/bin/env python3
"""
สร้าง "ต้นไม้ OS ปลอม" สำหรับแต่ละเครื่อง (.38 / .40)
ใช้ทั้งตอน dry-run บนเครื่องนี้ และถูก bind mount เข้า container

ผลลัพธ์ต่อโปรไฟล์ (os/hostNN/):
  proc_version                 -> bind mount ทับ /proc/version ใน container
  os-release                   -> bind mount ทับ /etc/os-release
  modules/<kernel_release>/    -> bind mount ทับ /lib/modules
  profile.json                 -> entrypoint อ่านไปตั้งค่า hostname/sshd/nginx
  bin/uname, bin/sysctl        -> wrapper สำหรับ dry-run (ใน container ใช้ของจริง)
  lab-kernel.env               -> ตัวแปรสำหรับ wrapper
"""
import json
import os
import pathlib
import shutil
import sys

HERE = pathlib.Path(__file__).resolve().parent
PROFILES = HERE / "profiles"
OUT = HERE / "os"


def sh(p: pathlib.Path, text: str):
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(text, encoding="utf-8")
    os.chmod(p, 0o755)


def build(name: str) -> pathlib.Path:
    p = json.loads((PROFILES / f"{name}.json").read_text(encoding="utf-8"))
    root = OUT / f"host{p['id']}"
    if root.exists():
        shutil.rmtree(root)

    rel, ver, host = p["kernel_release"], p["kernel_version"], p["hostname"]

    # ---- fake /proc/version ----
    sh(root / "proc" / "version",
       f"Linux version {rel} (buildd@{'buildd' if p['os_id']=='ubuntu' else 'mockbuild'}) "
       f"(gcc version 11.4.0) {ver}\n")

    # ---- fake /proc/sys (ให้ dry-run อ่านได้เหมือนเครื่องจริง) ----
    for path, val in {
        "proc/sys/kernel/osrelease": rel,
        "proc/sys/kernel/version": ver,
        "proc/sys/kernel/hostname": p["hostname"],
        "proc/sys/net/mptcp/enabled": "1",
        "proc/sys/net/ipv4/tcp_migrate_req": "0",
    }.items():
        sh(root / path, val + "\n")

    # ---- fake /etc/os-release ----
    (root / "etc" / "os-release").parent.mkdir(parents=True, exist_ok=True)
    (root / "etc" / "os-release").write_text("\n".join([
        f'PRETTY_NAME="{p["os_pretty"]}"',
        f'NAME="{p["os_name"]}"',
        f'VERSION_ID="{p["os_version_id"]}"',
        f'VERSION="{p["os_version"]}"',
        f'ID={p["os_id"]}',
        'ID_LIKE="rhel centos fedora"' if p["os_id"] == "almalinux" else 'ID_LIKE="debian"',
        'HOME_URL="https://example.internal"',
    ]) + "\n", encoding="utf-8")

    # ---- fake /lib/modules ----
    mod = root / "lib" / "modules" / rel
    for sub in ("kernel/net/ipv4", "kernel/net/mptcp", "kernel/fs"):
        (mod / sub).mkdir(parents=True, exist_ok=True)
    (mod / "modules.dep").write_text("", encoding="utf-8")

    # ---- profile + env สำหรับ wrapper ----
    (root / "profile.json").write_text(json.dumps(p, ensure_ascii=False, indent=2), encoding="utf-8")
    (root / "lab-kernel.env").write_text(
        f'FAKE_KREL="{rel}"\nFAKE_KVER="{ver}"\nFAKE_HOST="{host}"\n', encoding="utf-8")

    # ---- wrappers (dry-run) ----
    sh(root / "bin" / "uname", """#!/bin/sh
DIR="$(cd "$(dirname "$0")/.." && pwd)"
. "$DIR/lab-kernel.env" 2>/dev/null || true
case "$1" in
  -r) echo "${FAKE_KREL}" ;;
  -v) echo "${FAKE_KVER}" ;;
  -n) echo "${FAKE_HOST}" ;;
  -a) echo "Linux ${FAKE_HOST} ${FAKE_KREL} ${FAKE_KVER} x86_64 x86_64 GNU/Linux" ;;
  -s) echo Linux ;;
  -m) echo x86_64 ;;
  *)  echo "Linux ${FAKE_HOST} ${FAKE_KREL} ${FAKE_KVER} x86_64 x86_64 GNU/Linux" ;;
esac
""")
    return root


if __name__ == "__main__":
    names = sys.argv[1:] or [f.stem for f in sorted(PROFILES.glob("*.json"))]
    for n in names:
        print(build(n))


# ---------------------------------------------------------------------------
# หมายเหตุ: ใน container จะไม่ใช้ wrapper เหล่านี้
# - /proc/version : bind mount จาก proc_version
# - /etc/os-release : bind mount จาก os-release (หรือใช้ของ base image ก็ได้)
# - /lib/modules : bind mount จาก modules/
# - uname(2) : LD_PRELOAD shim (tools/libfakekernel.so) + wrapper /usr/local/bin/uname
# ---------------------------------------------------------------------------
