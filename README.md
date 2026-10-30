# ThaiCERT SCANER: PHP & Node.js LAN Discovery & Security Auditor

ระบบตรวจจับบริการเว็บในเครือข่ายท้องถิ่น (LAN Discovery) และประเมินช่องโหว่ความปลอดภัยระดับสูงสำหรับ **PHP (php2shell / CVE-2024-4577)** และ **Node.js (Node2Shell / HTTP2Shell / CVE-2026-111497)** พร้อมระบุอุปกรณ์ด้วย IEEE OUI และแสดงผลผ่านหน้าจอควบคุมแบบ Neumorphic UI

---

## จุดเด่นของระบบ (Key Features)

1. **การตรวจจับเครือข่ายอัตโนมัติ (Zero Hardcode Dynamic Discovery):**
   - คำนวณขอบเขตเครือข่ายจริง (Subnet & CIDR) จาก Routing Table และ Interface ของระบบปฏิบัติการโดยตรง
   - รองรับทุก Class และ Subnet Mask (/24, /23, /22, /21, /20, /16 และกำหนด IP Range อิสระ)
   - สแกนสดจาก Kernel ARP Table (`arp -an` และ `ip neigh show`) แยกแยะ Gateway, RouterBoard, AP, ปริ้นเตอร์, กล้องวงจรปิด และมือถือ/แล็ปท็อป (Private MAC)

2. **การตรวจสอบความปลอดภัย PHP (php2shell / CVE-2024-4577):**
   - ประเมินสถานะ End-of-Life (PHP 5.x, 7.x, 8.0, 8.1)
   - ตรวจจับความเสี่ยง CGI Argument Injection (CVE-2024-4577) และตรวจเวอร์ชันแพตช์ (8.2.20+, 8.3.8+)
   - รองรับการตรวจจับผ่าน Fingerprints, Session Cookies, Headers และ Easter Egg Probing

3. **การตรวจสอบความปลอดภัย Node.js (Node2Shell / CVE-2026-111497 Brotli RCE):**
   - ตรวจสอบช่องโหว่ Brotli Compression ใน Node.js (CVSS 9.2)
   - รองรับกฎเกณฑ์ EOL และเวอร์ชันแพตช์:
     - **Node.js 26.x**: แพตช์แก้ไขใน `26.12.1` ขึ้นไป
     - **Node.js 24.x**: แพตช์แก้ไขใน `24.22.1` ขึ้นไป
     - **Node.js 22.x**: แพตช์แก้ไขใน `22.23.4` ขึ้นไป
     - **Node.js 25.x / 20.x หรือเก่ากว่า**: สิ้นสุดการสนับสนุน (EOL) ไม่มีแพตช์แก้ไข แนะนำอัปเกรดทันที
   - ตรวจสอบผ่าน HTTP Headers (`X-Powered-By`, `Server`, `X-Node-Version`), Cookies (`connect.sid`, `koa.sess`, `next-auth`), และ Content-Encoding (`br`)

4. **สถาปัตยกรรม High-concurrency Async Scanner:**
   - ใช้ `asyncio` และ `httpx.AsyncClient` สามารถตรวจสอบพอร์ตและดึง Headers ของโฮสต์นับพันเครื่องได้ภายในเวลาไม่กี่วินาที

5. **Neumorphic Soft UI Design:**
   - ดีไซน์ซอฟต์แวร์สไตล์ Neumorphic นุ่มนวล ทันสมัย
   - หน้าจอหลักสะอาดตา มีปุ่ม Radar Scanner ทรงกลมขนาดใหญ่
   - การตั้งค่า Subnet / CIDR และ Concurrency แยกอยู่ใน Settings Drawer เป็นระเบียบ
   - รองรับการ Export รายงานผลการตรวจสอบเป็นไฟล์ CSV

6. **การตรวจสอบโดเมนและ URL ภายนอก (Direct Domain & URL Audit):**
   - กล่องค้นหา Frosted Glass ใต้คำว่า SCANER สำหรับตรวจสอบ Domain หรือ URL เจาะจง (เช่น `thaicert.or.th` หรือ `http://10.255.254.68:18080`)
   - ระบบตรวจจับ CMS, Web Application Firewall (WAF), HSTS และสถานะการปิดบังเวอร์ชัน (`expose_php = Off`) พร้อมคำแนะนำคำสั่งตรวจสอบแพตช์จริงบนเซิร์ฟเวอร์ (`php -v`)

7. **ระบบเลือกพอร์ตตรวจสอบ 3 โหมด (3-Mode Web Port Inspection):**
   - **Mode 1 (กำหนดเอง / สไลเดอร์):** เลื่อนปรับขนาดช่วงพอร์ตด้วย Slider UI พร้อมระบบประเมินผลกระทบต่อเครือข่ายอัตโนมัติ ($\le$ 50 พอร์ตปลอดภัย, $>$ 50 พอร์ตแจ้งเตือนเลี่ยงการใช้งานเพื่อรักษาเสถียรภาพ)
   - **Mode 2 (มาตรฐานนักพัฒนา - Default):** 17 พอร์ตสำคัญที่ Dev/DevOps นิยมใช้งาน ภาระเครือข่ายต่ำมาก เสถียรภาพ 100%
   - **Mode 3 (ปล่อยสแกนกว้าง):** ขอบเขตขยาย Top 50 / 100 / 250 พอร์ต พร้อมกล่องแจ้งเตือนความปลอดภัยเด่นชัด

---

## ข้อกำหนดของระบบ (Prerequisites)

- Python 3.9 ขึ้นไป
- ระบบปฏิบัติการ: macOS หรือ Linux (Ubuntu / Debian / CentOS / Alpine)
- หรือรันผ่าน Docker & Docker Compose

---

## วิธีติดตั้งและเริ่มใช้งาน (Quick Start)

### วิธีที่ 1: รันแบบ Native (แนะนำสำหรับประสิทธิภาพสูงสุด)

```bash
# โคลนโปรเจกต์
git clone https://github.com/Phattarapong26/PHP-NodeJS2Shell.git
cd PHP-NodeJS2Shell

# สั่งรันสคริปต์ (ระบบจะเตรียม Virtual Environment และติดตั้งไลบรารีให้อัตโนมัติ)
bash run.sh
```

เมื่อสคริปต์เริ่มทำงาน เข้าใช้งานผ่านเบราว์เซอร์ได้ที่:
`http://127.0.0.1:5050`

---

### วิธีที่ 2: รันผ่าน Docker

```bash
# รันผ่าน Docker โดยตรง
bash run.sh --docker

# หรือใช้ Docker Compose
docker compose up -d
```

---

## โครงสร้างโปรเจกต์ (Project Structure)

```text
├── app.py              # Backend API, Network Engine, Vulnerability Auditor
├── GUI.html            # Neumorphic Desktop UI, Workflow Modal, Results Panel
├── run.sh              # Start script (Dynamic OS network probe & launcher)
├── Dockerfile          # Container build definition
├── docker-compose.yml  # Docker Compose configuration
├── requirements.txt    # Python dependencies (Flask, httpx)
└── .gitignore          # Git exclusion rules
```

---

## เอนด์พอยต์จำลองสำหรับทดสอบ (Test Lab)

สามารถทดสอบฟังก์ชันการตรวจจับช่องโหว่ความปลอดภัยผ่านเครื่องจำลอง:
- `http://localhost:5050/test-lab/php56` -> PHP 5.6.40 (Critical EOL + php2shell)
- `http://localhost:5050/test-lab/php74` -> PHP 7.4.33 (Critical EOL + php2shell)
- `http://localhost:5050/test-lab/php83` -> PHP 8.3.8 (Secure Patched)
- `http://localhost:5050/test-lab/node20-vuln` -> Node.js v20.18.0 (Critical EOL + Brotli Node2Shell)
- `http://localhost:5050/test-lab/node22-vuln` -> Node.js v22.12.0 (Critical Node2Shell)
- `http://localhost:5050/test-lab/node22-safe` -> Node.js v22.23.4 (Secure Patched)
- `http://localhost:5050/test-lab/node24-safe` -> Node.js v24.22.1 (Secure Patched)

---

## ลิขสิทธิ์และการนำไปใช้ (License)

พัฒนาขึ้นเพื่อการวิเคราะห์และตรวจสอบความปลอดภัยในเครือข่ายสำหรับองค์กรและการนำเสนอ ThaiCERT
