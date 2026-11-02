# subnet-target — ให้ Docker ทำงานเสมือนเป็นเครื่อง .38 / .40 ใน subnet จริง

ชุดนี้ทำให้ container ไป **ถือ IP ของตัวเองในวงเดียวกับ scanner** (macvlan) และตอบสนองเหมือนเครื่อง Linux
เครื่องหนึ่ง: มี sshd/nginx ของดิสโทรจริง, พอร์ตอื่นปิด, TTL แบบ Linux และข้อมูล OS ที่ตรงกับโปรไฟล์
ใช้สำหรับวัดว่าเครื่องมือ scan ของคุณ "ตรวจระบบปฏิบัติการได้จริง" หรือแค่เดาจาก banner

> ⚠️ ใช้ในวงแล็บที่ควบคุมได้ และ **IP .38/.40 ต้องว่างจริง** ถ้ามีเครื่องจริงใช้งานอยู่จะชนกันที่ระดับ ARP

---

## 1. ทำไมต้อง macvlan

ถ้าใช้ `ports:` แบบปกติ container จะอยู่หลัง IP ของ docker host → scanner เห็นเป็นเครื่องเดียวกับ host
macvlan ให้ container มี MAC + IP ของตัวเองในวง scanner จึงเห็นเป็น "อีกเครื่องหนึ่ง" จริง ๆ:

```
scanner (.50)  ──switch──  .38  [container host38: sshd/nginx + kernel 5.15 ปลอม]
                    └─────  .40  [container host40: sshd/nginx + kernel 5.14 ปลอม]
```

---

## 2. สิ่งที่ scanner จะเห็น (จริง vs จำลอง)

| สัญญาณที่ scanner ใช้ | ค่าที่เห็น | แหล่งที่มา |
|-----------------------|-----------|------------|
| IP / MAC / ARP | `.38`, `.40` พร้อม MAC ของ container | **จริง** (macvlan) |
| พอร์ตที่เปิด | 22, 80 (พอร์ตอื่นปิดสนิท) | **จริง** (เฉพาะบริการที่รัน) |
| SSH banner | `SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.10` / `SSH-2.0-OpenSSH_8.7` | **จริง** จาก openssh ใน base image |
| HTTP Server header | `nginx/1.18.0 (Ubuntu)` / `nginx/1.20.1` | **จริง** จาก nginx ใน base image |
| SSH KEX/host key algorithms | ตาม OpenSSH ของ base image | **จริง** |
| TTL | 64 (ตั้งผ่าน `net.ipv4.ip_default_ttl`) | **จริง/ปรับได้** |
| TCP/IP stack fingerprint (nmap -O) | kernel ของ docker host | **จริง แต่ไม่ตรงโปรไฟล์** (ข้อจำกัด 5) |
| `uname -r`, `uname -a` | 5.15.0-203-generic / 5.14.0-427.13.1.el9_6 | **จำลอง** (wrapper + shim) |
| `/proc/version`, `/proc/sys/kernel/*` | ตามโปรไฟล์ | **จำลอง** (bind mount) |
| `/etc/os-release`, `/etc/issue`, `/etc/motd` | Ubuntu 22.04.5 LTS / AlmaLinux 9.6 | **จริง** (base image) + ทับบางส่วน |
| `/lib/modules/<ver>` | มีเฉพาะเวอร์ชันในโปรไฟล์ | **จำลอง** (bind mount) |
| `sysctl net.mptcp.enabled`, `net.ipv4.tcp_migrate_req` | 1 / 0 | **จำลอง** (wrapper) |
| python `platform.release()`, agent ที่เรียก `uname(2)` | ตามโปรไฟล์ | **จำลอง** (`/etc/ld.so.preload`) |

สรุปสั้น: **ชั้น network กับบริการเป็นของจริง** ชั้น kernel userland เป็นของจำลอง เพราะ container ใช้ kernel ร่วมกับ host

---

## 3. ใช้งาน (4 ขั้น)

```bash
cd subnet-target
cp .env.example .env
vi .env                     # SUBNET / GATEWAY / PARENT_IFACE / IP38 / IP40
python3 make-os-tree.py     # สร้าง os/host38, os/host40
docker compose up -d --build
```

ตรวจจาก **เครื่องอื่นในวงเดียวกัน** (ไม่ใช่ docker host):

```bash
./check-from-network.sh 10.20.4.38 10.20.4.40
nmap -Pn -O -sV -p22,80 10.20.4.38
```

หยุด: `docker compose down`

### ตรวจก่อนมี Docker (dry run บนเครื่องนี้)

```bash
./simulate-host.sh 38 -- uname -a
./simulate-host.sh 38 -- cat /proc/version
./simulate-host.sh 40 -- python3 -c "import platform;print(platform.release())"
```

---

## 4. ค่าที่ใช้ในโปรไฟล์

| | host38 | host40 |
|---|--------|--------|
| base image | `ubuntu:22.04` | `almalinux:9` |
| hostname | app-prod-38 | db-prod-40 |
| OS | Ubuntu 22.04.5 LTS (jammy) | AlmaLinux 9.6 (Sage Margay) |
| kernel | 5.15.0-203-generic | 5.14.0-427.13.1.el9_6 |
| SSH banner | OpenSSH_8.9p1 Ubuntu-3ubuntu0.10 | OpenSSH_8.7 |
| CVE-2026-98432 | อยู่ในช่วงเสี่ยง (>= 4.4) | อยู่ในช่วงเสี่ยง |

แก้/เพิ่มเครื่อง: คัดลอก `profiles/host38.json` เป็น `host41.json` แล้วเพิ่ม service ใน `docker-compose.yml`
(และเพิ่ม `IP41` ใน `.env`)

---

## 5. ข้อจำกัดที่ต้องรู้ (สำคัญต่อการตีความผล)

1. **kernel stack ไม่ใช่ของโปรไฟล์** — container ใช้ kernel ของ docker host ถ้า scanner ใช้ `nmap -O`
   จะได้ fingerprint ของ host (เช่น Linux 5.15 ถ้า host เป็น Ubuntu 22.04) ซึ่งอาจตรงหรือไม่ตรงกับที่ประกาศ
   - ต้องการความสอดคล้อง 100%: รัน `host38` บน Docker host ที่ kernel 5.15 และ `host40` บน 5.14
   - หรือปล่อยให้ไม่ตรง แล้วดูว่า scanner จับ "ความไม่สอดคล้อง" ได้หรือไม่ (เป็นการทดสอบที่มีค่าเช่นกัน)
2. **macvlan มองไม่เห็น docker host** — ต้องตรวจจากเครื่องอื่นในวง (ข้อจำกัดของ macvlan เอง)
   ถ้าไม่มีเครื่องอื่น ให้เปลี่ยนไปใช้ `ipvlan` (driver: ipvlan, ipvlan_mode: l2)
3. **เครื่อง host ต้องอนุญาต promiscuous** — ถ้า docker host เป็น VM ต้องเปิด MAC spoofing/promiscuous
   ที่ virtual switch (VMware/Hyper-V/Proxmox) ไม่งั้น ARP ของ .38/.40 จะไม่ผ่าน
4. **ต้องมี 2 IP ว่าง** — ถ้า .38/.40 มีเครื่องจริงอยู่ ให้เปลี่ยนเป็น IP อื่นใน `.env`
5. **โปรแกรมแบบ static (Go/Rust)** — `LD_PRELOAD` ไม่มีผล ค่าที่ได้คือ kernel จริง (แก้ได้ด้วย wrapper CLI หรือ VM)
6. **ไม่มีข้อมูลระบบอื่นของเครื่องจริง** — ไม่มีข้อมูล users, package ทั้งระบบ, cron, log, process จริง
   ถ้า scanner เป็น agent-based แบบละเอียด (ต้อง login + เก็บ inventory) ควรใช้ VM จริงแทน

---

## 6. การใช้งานร่วมกับ CVE-2026-98432

ทั้งสองโปรไฟล์อยู่ในช่วงที่ได้รับผลกระทบ (kernel >= 4.4) จึงควรถูกตรวจพบ ใช้คู่กับ `kernel-lab` ได้:

```bash
# มุม network/service
nmap -Pn -O -sV -p22,80 10.20.4.38

# มุม agent (หลังใส่ SSH key ด้านล่าง)
ssh -i keys/lab_ed25519 root@10.20.4.38 'uname -r; cat /etc/os-release | head -2; sysctl net.mptcp.enabled'
```

เปิดใช้ agent scan (ไม่บังคับ): สร้างกุญแจแล้วเพิ่ม volume ใน compose

```bash
ssh-keygen -t ed25519 -f keys/lab_ed25519 -N ''
mkdir -p keys/authorized_keys_dir
cp keys/lab_ed25519.pub keys/authorized_keys_dir/authorized_keys
# ใน docker-compose.yml ของแต่ละ service เพิ่ม:
#   - ./keys/authorized_keys_dir/authorized_keys:/root/.ssh/authorized_keys:ro
```

---

## 7. ความปลอดภัย

- แล็บนี้ตั้งใจให้ "ดูเหมือนเครื่องจริง" แต่ไม่มีข้อมูลจริงและไม่แตะระบบภายนอก
- ห้ามเปิดพอร์ตเหล่านี้ออกอินเทอร์เน็ต และห้ามใช้ IP ที่ไม่ได้รับจัดสรรในวงองค์กร
- `LD_PRELOAD` + `/etc/ld.so.preload` เป็นเทคนิคเดียวกับที่มัลแวร์ใช้ ควรใช้ใน container ที่ทิ้งได้เท่านั้น
