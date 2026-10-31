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
├── app.py              # Main Web Server & Blueprint Controller (Port 5050)
├── audit_cli.py        # Enterprise CLI Security Audit Toolkit
├── GUI.html            # Neumorphic Desktop UI & Workflow Dashboard
├── diagram.html        # Interactive Architecture & Security Chains Diagram
├── run.sh              # Production Launch Script (Auto-detects network & routes)
├── Dockerfile          # Production Container Definition
├── docker-compose.yml  # Docker Compose Production Service
├── .env.example        # Environment Configuration Template
├── core/               # Network Discovery, SemVer Engine, Dynamic CVE Catalog
│   ├── network.py
│   ├── multi_vector_discovery.py
│   ├── semver.py
│   ├── database.py
│   └── sync_arp.py
├── audit/              # Security Evaluators & ThaiCERT 8-Group Classifier
│   ├── php_audit.py
│   ├── node_audit.py
│   ├── nginx_audit.py
│   ├── thaicert_rules.py
│   ├── probe_audit.py
│   ├── sub_tools.py
│   └── rce_prover.py
├── reports/            # TLP:AMBER Official Advisory & PDF Engine
│   ├── amber_builder.py
│   ├── pdf_engine.py
│   └── assets.py
├── api/                # Production HTTP API Blueprints
│   ├── scan_routes.py
│   └── report_routes.py
├── fonts/              # Official Thai SarabunPSK TrueType Fonts
└── tests/              # Automated Test Suite & Production Readiness Verifications
```

---

## การใช้งานเครื่องมือตรวจสอบทางเทคนิค (CLI Edition)

นอกเหนือจากหน้าจอเว็บแอปพลิเคชัน OPScaner มาพร้อมกับ **CLI Toolkit (`audit_cli.py`)** สำหรับผู้เชี่ยวชาญด้านความมั่นคงปลอดภัยไซเบอร์ของ ThaiCERT / สกมช.:

```bash
# ตรวจสอบเป้าหมายแบบเจาะจง (Single Target Audit)
python3 audit_cli.py -t http://192.168.1.50:80

# ตรวจสอบและสร้างรายงาน TLP:AMBER HTML อัตโนมัติ
python3 audit_cli.py -t https://target-agency.go.th --export-report

# ส่งออกผลลัพธ์เป็น JSON Telemetry สำหรับเชื่อมต่อกับระบบ SIEM/SOC
python3 audit_cli.py -t http://10.0.0.10 --json target_telemetry.json
```

---

## การกำหนดค่าสภาพแวดล้อมระบบ (Configuration)

คัดลอกไฟล์ `.env.example` ไปเป็น `.env` เพื่อกำหนดค่านโยบายความปลอดภัย:

```bash
cp .env.example .env
```

| ตัวแปร | ความหมาย | ค่าเริ่มต้น |
|---|---|---|
| `OPSCANER_ENV` | สภาพแวดล้อมการทำงาน (`production` / `development`) | `production` |
| `PORT` | พอร์ตสำหรับ Web Service | `5050` |
| `FLASK_SECRET` | คีย์เข้ารหัสเซสชัน (หากเว้นว่างจะสุ่ม key อัตโนมัติ) | `secrets.token_hex(32)` |
| `OPSCANER_CORS_ORIGINS` | Whitelist โดเมนที่อนุญาตให้เรียกใช้งาน API | `http://127.0.0.1:5050,http://localhost:5050` |
| `OPSCANER_CVE_FEED_PATH` | พาธไฟล์ JSON สำหรับอัปเดต CVE feed เพิ่มเติมแบบ Dynamic | *(เว้นว่าง)* |

---

## การทดสอบระบบ (Quality & Production Verification)

รันชุดทดสอบเพื่อยืนยันความพร้อมของระบบทั้งหมด:

```bash
./venv/bin/python -m unittest discover tests
```

---

## ลิขสิทธิ์และการนำไปใช้ (License)

พัฒนาขึ้นเพื่อการวิเคราะห์ ประเมินความเสี่ยง และตรวจสอบความมั่นคงปลอดภัยระบบสารสนเทศตามมาตรฐาน ThaiCERT และสำนักงานคณะกรรมการการรักษาความมั่นคงปลอดภัยไซเบอร์แห่งชาติ (สกมช. / NCSA Thailand)
