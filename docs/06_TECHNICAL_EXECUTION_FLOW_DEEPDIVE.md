# 06. คู่มือเจาะลึกขั้นตอนการทำงานจริงระดับวิศวกรรม (Step-by-Step Technical Execution Blueprint)
**OPScaner: Exhaustive Pipeline Sequence, Data Telemetry & Dynamic Rule Execution (TLP:CLEAR)**

---

## 📌 บทนำและภาพรวมของไปป์ไลน์การทำงานจริง (Execution Pipeline Overview)

เอกสารฉบับนี้จัดทำขึ้นสำหรับวิศวกรความมั่นคงปลอดภัย (Security Engineers), คณะทำงานทดสอบเจาะระบบ (Penetration Testers), และผู้ตรวจรับงานด้านเทคนิค เพื่ออธิบาย **ลำดับขั้นตอนการทำงานจริง (Ground Truth Execution Flow)** ของระบบ OPScaner ตั้งแต่ผู้ใช้งานป้อนข้อมูลเป้าหมาย จนกระทั่งระบบสร้างผลการประเมินและเอกสารหลักฐานดิจิทัล โดยแบ่งออกเป็น **6 ขั้นตอน (Stages) ที่เชื่อมโยงกันอย่างเป็นระบบ**:

```
┌────────────────────────────────────────────────────────────────────────────────────────┐
│                              OPScaner Execution Pipeline                                │
└────────────────────────────────────────────────────────────────────────────────────────┘
     │
     ▼
[Stage 1: การสำรวจเครือข่าย 5 ทิศทาง (Multi-Vector Sweeping)]
     ├─ ARP Cache Kernel Ingress + Docker Bridge NAT Traversal
     ├─ NetBIOS (UDP 137) + mDNS (UDP 5353) + DNS PTR
     └─ Non-blocking TCP SYN Sweeper (Standard 23 ports / Wide 100 ports)
     │
     ▼
[Stage 2: การจำแนกฮาร์ดแวร์และแบรนด์อุปกรณ์ (Hardware Fingerprinting)]
     ├─ ตรวจสอบ MAC Address Prefix (OUI 6-9 Hex chars)
     ├─ In-Memory Resolution กับ SQLite Database (54,343 IEEE Vendors)
     └─ คัดแยกผู้ผลิต: Apple, Intel, Cisco, MikroTik, Fortinet, Espressif, ฯลฯ
     │
     ▼
[Stage 3: การตรวจจับบริการเว็บและสร้างค่าฐานวัด (Canary Baseline Engine)]
     ├─ Non-blocking HTTP/S Fingerprinting (Server, Title, WAF, CMS, Cookies)
     ├─ สุ่มพาธขยะ (Random Non-existent Canary Path) เพื่อสร้างค่า Baseline
     └─ บันทึกค่า Soft-404 Hash (MD5) และ Response Length ป้องกันผลลวง
     │
     ▼
[Stage 4: การประเมินกฎช่องโหว่ภาษากลาง (Dynamic CVE Rule Engine)]
     ├─ ดึงกฎที่เปิดใช้งานจาก SQLite `cve_rules` (Web, Linux OS, Android)
     ├─ ส่งคำขอทดสอบ (Trigger: Method, Path, Custom Headers, Body, Port)
     └─ ตรวจสอบ Matchers: Status, Body Regex, Header Regex, Negative Canary
     │
     ▼
[Stage 5: การพิสูจน์ทราบ RCE เชิงประจักษ์ (Active RCE Prover & Tri-State)]
     ├─ Safety Gate Validation (ต้องยืนยันสิทธิ์ก่อนเริ่มยิง Active Exploit)
     ├─ สุ่มสมการคณิตศาสตร์สด (Dynamic Arithmetic Canary: seed_a + seed_b)
     ├─ ฉีดเข้า Session Inode ผ่าน PHP Upload Progress Multipart Stream
     ├─ ทดสอบ Trigger LFI ข้ามไดรฟ์ C:/D: และ Linux `/tmp/sess_*`
     └─ จัดกลุ่ม 3 ระดับ: RCE_CONFIRMED, CANARY_CONFIRMED, NOT_CONFIRMED
     │
     ▼
[Stage 6: การจำแนก 8 กลุ่ม ThaiCERT และสร้างผลลัพธ์ (Reporting & Evidence)]
     ├─ จัดสินทรัพย์เข้า 8 กลุ่มตามมาตรฐาน ThaiCERT / สกมช.
     ├─ ส่งข้อมูล JSON Telemetry เข้าสู่ Neumorphic Dashboard
     ├─ บันทึก Forensic Evidence Bundle (.ZIP) พร้อมลายมือชื่อ SHA-256
     └─ เรนเดอร์เอกสารรายงานชั้นความลับทางการ TLP:AMBER (PDF ฝังฟอนต์ Sarabun)
```

---

## 🔬 Stage 1: การสำรวจเครือข่าย 5 ทิศทางและการข้ามกำแพง Docker NAT

### 1.1 การดึงค่า Profile จากฐานข้อมูล SQLite
เมื่อผู้ใช้กดเริ่มสแกน ฟังก์ชัน `run_scan()` ใน [`api/scan_routes.py`](file:///Users/admin/Desktop/OPScaner/api/scan_routes.py) จะดึงการตั้งค่าจากโปรไฟล์ที่เปิดใช้งานอยู่ผ่าน `get_active_profile()` ใน [`core/profile_db.py`](file:///Users/admin/Desktop/OPScaner/core/profile_db.py):
* **Concurrency:** จำนวน Async Workers พร้อมกัน (ค่าตั้งต้น: 60 workers, สูงสุด 200)
* **Timeout:** ระยะเวลารอการตอบสนอง (ค่าตั้งต้น: 2.2 วินาที)
* **Stealth Headers & User-Agent:** ส่วนหัว HTTP อำพรางตัว เช่น `Mozilla/5.0 (Windows NT 10.0...)` และ `X-Forwarded-For: 127.0.0.1`
* **Port Mode:** รูปแบบพอร์ตที่กำหนด (Standard 23 พอร์ตหลัก, Wide 100 พอร์ต, หรือ Custom)

### 1.2 การข้ามข้อจำกัดของระบบคอนเทนเนอร์ (Docker NAT Traversal)
หากเครื่องสแกนเนอร์ทำงานอยู่ภายใน Docker บน macOS หรือ Windows แพ็กเก็ต L2 ARP Broadcast ปกติจะไม่สามารถกระโดดข้าม Docker Bridge NAT (`172.25.0.0/16`) ออกไปยัง Wi-Fi จริงได้  
ระบบจึงแก้ปัญหานี้ด้วย **Multi-Vector Discovery** ที่ทำงานประสานกัน 5 มิติ:
1. **Host ARP Cache Ingress:** อ่านตาราง ARP ของเคอร์เนลจากระบบไฟล์จำลอง `/proc/net/arp`
2. **NetBIOS Name Service (UDP 137):** ส่งแพ็กเก็ตถามชื่อเครื่องสไตล์ Windows ไปยังทุก IP ใน Subnet
3. **Apple Bonjour / mDNS (UDP 5353):** ส่งคำขอค้นหาอุปกรณ์ตระกูล Apple และ Smart Devices
4. **DHCP DNS Reverse PTR Lookup:** สอบถาม Local DNS Resolver เพื่อขอชื่อโฮสต์
5. **High-Speed TCP SYN Connect Sweep:** ส่งแพ็กเก็ต SYN ไปยังพอร์ตบริการยอดนิยม (เช่น 80, 443, 8080, 22, 445) เพื่อดูการตอบสนอง SYN-ACK หรือ RST

อุปกรณ์ที่ตอบสนองในช่องทางใดช่องทางหนึ่งจะถูกนับเป็น **"Online Host"** ทันที และส่งต่อไปยัง Stage 2 โดยไม่มีการตกหล่น

---

## 🏷️ Stage 2: การจำแนกแบรนด์อุปกรณ์ด้วยฐานข้อมูล IEEE MAC Vendor (SQLite)

### 2.1 สถาปัตยกรรม Dynamic Vendor Matching
ระบบไม่ใช้การ Hardcode ชื่อแบรนด์อุปกรณ์ในไฟล์ Python แต่ใช้ฐานข้อมูล SQLite ตาราง `mac_vendors` ซึ่งบรรจุข้อมูล Organizationally Unique Identifier (OUI) ของสถาบันวิศวกรรมไฟฟ้าและอิเล็กทรอนิกส์สากล (IEEE) จำนวน **54,343 รายการ**:

```sql
CREATE TABLE IF NOT EXISTS mac_vendors (
    oui TEXT PRIMARY KEY,
    vendor TEXT NOT NULL,
    block_type TEXT DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_mac_vendors_oui ON mac_vendors(oui);
```

### 2.2 อัลกอริทึมการแปลง MAC Address สู่แบรนด์ผู้ผลิต
ฟังก์ชัน `resolve_mac_vendor(mac_str)` ใน [`core/profile_db.py`](file:///Users/admin/Desktop/OPScaner/core/profile_db.py) ทำงานดังนี้:
1. ทำความสะอาดสตริง MAC (ตัดเครื่องหมาย `:` หรือ `-` ออก และแปลงเป็นตัวพิมพ์เล็ก)
2. นำอักขระ 6 ตัวหน้า (OUI 24-bit) และ 9 ตัวหน้า (OUI 36-bit) ไปค้นหาใน **In-Memory LRU Cache** (`_MAC_VENDOR_CACHE`)
3. หากไม่พบในแคช จะทำการ Query ไปยังฐานข้อมูล SQLite ด้วยความเร็วเฉลี่ย **< 0.1 มิลลิวินาที**:
   * `00:1a:2b:...` $\rightarrow$ **Ayecom Technology Co., Ltd.**
   * `9c:b8:b4:...` $\rightarrow$ **AMPAK Technology, Inc. (ชิปเซ็ต Wi-Fi IoT)**
   * `f0:18:98:...` $\rightarrow$ **Apple, Inc.**
   * `00:50:56:...` $\rightarrow$ **VMware, Inc. (Virtual Machine)**

---

## 🛡️ Stage 3: การตรวจจับบริการเว็บและ Soft-404 Negative Canary Baseline

### 3.1 HTTP Fingerprinting แบบ Non-blocking
ฟังก์ชัน `probe_endpoint()` ใน [`audit/probe_audit.py`](file:///Users/admin/Desktop/OPScaner/audit/probe_audit.py) จะส่งคำขอแบบ Asynchronous ไปยังพอร์ตเปิดของแต่ละโฮสต์ พร้อมบันทึก:
* ค่า Server Header และ `X-Powered-By` (เช่น Nginx, Apache, PHP, Express, Python WSGI)
* ค่าอายุแพ็กเก็ต **Time-To-Live (TTL)**:
  * $\text{TTL} \le 64$: บ่งชี้ระบบปฏิบัติการตระกูล **Linux / Unix / macOS**
  * $\text{TTL} \approx 128$: บ่งชี้ระบบปฏิบัติการตระกูล **Microsoft Windows**
* การมีอยู่ของระบบป้องกันด่านหน้า (WAF / Edge CDN): ตรวจจับ Cloudflare, AWS WAF, FortiGate Web Filter, หรือ ModSecurity
* การจำแนกประเภท Content Management System (WordPress, Joomla, Drupal)

### 3.2 ปัญหา Wildcard Catch-All และการแก้ปัญหาด้วย Negative Canary
เว็บเซิร์ฟเวอร์สมัยใหม่หรือแอปพลิเคชัน Single-Page Application (SPA) มักตั้งค่า **Catch-all Route** คือไม่ว่าจะเรียกพาธใด เซิร์ฟเวอร์จะตอบกลับด้วย `HTTP 200 OK` เสมอ ทำให้เครื่องมือสแกนทั่วไปเกิดอาการ **False Positive มหาศาล** (เช่น แจ้งเตือนว่าพบไฟล์ `.env`, `.git/config`, `admin.php` ทั้งที่ไม่มีอยู่จริง)

**อัลกอริทึม Soft-404 Canary Baseline ของ OPScaner:**
```
[เริ่มการตรวจประเมินโฮสต์]
       │
       ▼
1. ส่งคำขอไปยังพาธสุ่มที่ไม่มีอยู่จริงแน่นอน:
   GET /.well-known/anti_fp_canary_8f2a1b9c
       │
       ▼
2. บันทึกผลลัพธ์เป็นค่าฐาน (Canary Baseline):
   - Baseline Status: 200 OK
   - Baseline Body Length: 4,520 bytes
   - Baseline Body MD5 Hash: 9f8a3c...
       │
       ▼
3. เมื่อสแกนพาธสำคัญ เช่น GET /.env
   - ตรวจพบ HTTP 200 OK
   - เปรียบเทียบ: ขนาดของ /.env (4,522 bytes) ต่างจาก Baseline (< 1%)
   - สรุป: ตอบกลับเป็นหน้า Catch-all เดียวกัน -> ตัดเป็น False Positive ทันที (ไม่แจ้งเตือน)
   - หากเนื้อหาของ /.env มีสตริง DB_PASSWORD= และต่างจาก Baseline -> แจ้งเตือนเป็น VULNERABLE จริง
```

---

## 📜 Stage 4: การประเมินกฎช่องโหว่ภาษากลาง (Dynamic CVE Rule Engine)

### 4.1 โครงสร้างภาษากลาง JSON Specification ([`core/cve_schema.py`](file:///Users/admin/Desktop/OPScaner/core/cve_schema.py))
เพื่อรองรับการขยายตัวข้ามระบบปฏิบัติการ Web, Linux OS, และ Android โดยไม่ต้องแก้ไขโค้ด Python กฎทุกข้อจะถูกจัดเก็บในฐานข้อมูล SQLite ในโครงสร้างมาตรฐาน:

```json
{
  "rule_id": "EXPOSURE-ENV-SECRETS",
  "cve_id": "CWE-200-ENV",
  "name": "Exposed .env Configuration Credentials",
  "target_type": "web",
  "severity": "High",
  "cvss_score": 7.5,
  "thaicert_group": 1,
  "is_enabled": true,
  "trigger": {
    "method": "GET",
    "path": "/.env",
    "timeout": 1.2
  },
  "matchers": [
    { "type": "status", "values": [200] },
    { "type": "body_regex", "regex": "APP_KEY=|DB_PASSWORD=|APP_ENV=|AWS_SECRET" },
    { "type": "negative_canary", "enabled": true }
  ],
  "remediation": "ตั้งค่า Web Server ให้ปฏิเสธการเข้าถึงไฟล์ดอท (.env) โดยส่ง HTTP 403 หรือ 404"
}
```

### 4.2 วงจรการประเมินผลใน Dynamic Rule Engine ([`audit/dynamic_rule_engine.py`](file:///Users/admin/Desktop/OPScaner/audit/dynamic_rule_engine.py))
1. **Rule Query:** ดึงเฉพาะกฎที่ `is_enabled = 1` และตรงกับ `target_type`
2. **Non-blocking Execution:** ส่งคำขอ Trigger ผ่าน `httpx.AsyncClient` ภายใต้ Concurrency Semaphore
3. **Matcher Evaluation Pipeline:**
   * `status`: เช็คว่ารหัสตอบกลับอยู่ในลิสต์ที่ระบุหรือไม่ (เช่น `[200]`)
   * `body_regex`: ค้นหา Pattern ด้วย Regular Expression บนเนื้อหา Response
   * `header_regex`: ค้นหา Pattern ในส่วนหัว HTTP ที่กำหนด (เช่น `Server: nginx`)
   * `negative_canary`: ตรวจสอบยืนยันว่าผลลัพธ์ไม่ได้ตรงกับ Soft-404 Baseline ของ Stage 3
   * `port_open` / `banner_regex`: สำหรับ Android (เช่น ตรวจสอบพอร์ต 5555 สำหรับ ADB Remote Debugging)

---

## ⚡ Stage 5: การพิสูจน์ทราบ RCE เชิงประจักษ์และการออกลายมือชื่อดิจิทัล SHA-256

### 5.1 การบังคับใช้มาตรการความปลอดภัย (Safety Gate Protection)
ใน [`audit/rce_prover.py`](file:///Users/admin/Desktop/OPScaner/audit/rce_prover.py) การยิงคำขอเพื่อพิสูจน์ทราบช่องโหว่ RCE (เช่น CVE-2024-4577 หรือ PHP Session Poisoning) จะถูกระงับไว้โดยค่าเริ่มต้น (`PROBING_DISABLED_BY_SAFETY_GATE`) จนกว่าผู้ตรวจสอบจะเปิดใช้งานธง `--active-rce` เพื่อป้องกันการละเมิดระบบโดยไม่ได้รับอนุญาต

### 5.2 กลไก Dynamic Arithmetic Canary Evaluation
เมื่อได้รับการอนุญาต ระบบจะสร้าง **โจทย์คณิตศาสตร์แบบสุ่ม** ที่ไม่สามารถเดาล่วงหน้าได้:
$$\text{Canary Sum} = \text{seed}_a + \text{seed}_b \quad (\text{เช่น } 54,321 + 19,876 = 74,197)$$
ระบบจะบรรจุโค้ดคำนวณเข้าไปในสตรีมข้อมูล:
```php
<?php echo 'THAICERT_CANARY_EVAL_'.(54321+19876); exit; ?>
```

### 5.3 การฉีดข้อมูลและค้นหา Inode ของไฟล์เซสชัน
1. ส่งคำขอ Multipart Request ไปยังฟังก์ชันสร้างเซสชัน (`PHP_SESSION_UPLOAD_PROGRESS`)
2. วนลูปทดสอบเรียกไฟล์เซสชันผ่านพารามิเตอร์ LFI ที่เก็บเกี่ยวได้ (`?page=`, `?file=`, `?include=`)
3. สแกนพาธจัดเก็บเซสชันแบบอัตโนมัติครอบคลุมทั้ง Windows และ Linux:
   * **Windows:** `C:/Windows/Temp/sess_*`, `C:/xampp/tmp/sess_*`, `D:/temp/sess_*`
   * **Linux:** `/tmp/sess_*`, `/var/lib/php/sessions/sess_*`

### 5.4 การตัดสินผลแบบ 3 ระดับ (Tri-State Categorization)
* **`RCE_CONFIRMED`:** พบค่าวาจา `THAICERT_CANARY_EVAL_74197` ในผลลัพธ์ ยืนยัน 100% ว่า PHP Engine ได้ทำการประมวลผลโค้ดสำเร็จ
* **`CANARY_CONFIRMED`:** พบข้อความดิบ `<?php echo ... ?>` สะท้อนกลับมา แสดงว่าอ่านไฟล์ได้ (LFI) แต่คำสั่งไม่รัน (ยังไม่บรรลุ RCE)
* **`NOT_CONFIRMED`:** ไม่พบการตอบสนอง หรือระบบปฏิเสธการเข้าถึงไฟล์เซสชัน

### 5.5 ลายมือชื่อดิจิทัลเพื่อใช้เป็นพยานหลักฐาน (Tamper-Evident SHA-256 Digest)
ระบบจะทำการบันทึก Full Request/Response Transcript และคำนวณค่าแฮชตรวจสอบความสมบูรณ์ของหลักฐาน:
```json
{
  "timestamp_utc": "2026-11-03T05:55:00Z",
  "operator": "security-auditor",
  "payload_sha256": "4a7d1e8c...",
  "evidence_sha256": "8e3b9f10...",
  "transcript": { ... }
}
```

---

## 📊 Stage 6: การจำแนก 8 กลุ่ม ThaiCERT และการส่งมอบผลลัพธ์

### 6.1 เกณฑ์การจัดหมวดหมู่สินทรัพย์ 8 กลุ่มตามมาตรฐาน ThaiCERT / สกมช.
เมื่อวิเคราะห์ข้อมูลจากทุก Stage ครบถ้วน ระบบจะจัดสินทรัพย์เข้าสู่กลุ่มที่สอดคล้อง:

| กลุ่มที่ | ชื่อกลุ่มสถาปัตยกรรม (ThaiCERT Architecture Group) | เกณฑ์การตรวจจับทางเทคนิค (Detection Criteria) |
| :---: | :--- | :--- |
| **1** | **Web Interface & Attack Surface** | ตรวจพบบริการเว็บมาตรฐาน (CMS, Apache, NGINX, พอร์ต 80/443) และไฟล์สำคัญหลุด |
| **2** | **API & Microservices** | ตรวจพบ RESTful JSON API, Laravel, Spring Boot, หรือ GraphQL Endpoints |
| **3** | **Internal Services & Databases** | พอร์ตฐานข้อมูลหรือดาต้าเลค (MySQL 3306, PostgreSQL 5432, Redis 6379) |
| **4** | **Mobile & IoT Devices** | อุปกรณ์พกพาและสมาร์ทดีไวซ์ (Android ADB 5555, กล้องวงจรปิด, เราเตอร์ Wi-Fi) |
| **5** | **Cloud & Container Infrastructure** | ระบบคอนเทนเนอร์ (Docker Daemon 2375, Kubernetes API 6443, Cloud WAF) |
| **6** | **Critical Application Vulnerabilities** | ตรวจพบความเสี่ยงระดับสูงหรือ RCE (เช่น CVE-2024-4577, Session Poisoning) |
| **7** | **Network & OS Infrastructure** | ความเสี่ยงระดับเคอร์เนลและเน็ตเวิร์ก L4 (Linux MPTCP UAF, SSH, VPN Gateway) |
| **8** | **Auxiliary & Unknown Assets** | บริการเสริม, แผงควบคุมระบบ (Control Panel), หรืออุปกรณ์ที่ระบุประเภทไม่ได้ |

### 6.2 การสร้างรายงานและสิ่งที่ส่งมอบ (Deliverables)
1. **Interactive Neumorphic Dashboard:** อัปเดตกราฟิกสถิติ, กราฟวงกลมจำแนก 8 กลุ่ม (ชุดสี Cyber Harmonic), และตารางผลการสแกนแบบ Real-time
2. **รายงานทางการ TLP:AMBER (PDF):**
   * ฝังฟอนต์แห่งชาติ Sarabun (`sarabun-thai-400`, `sarabun-thai-700`)
   * ปั๊มลายน้ำความลับ `เอกสารลับจากระบบของฝ่ายปฏิบัติการ ThaiCERT (TLP:AMBER)` เอียง 45 องศาทุกหน้า
   * มีกล่องคำสั่ง **Host Verification CLI** สำหรับผู้ดูแลระบบนำไปตรวจสอบยืนยันบนเครื่องแม่ข่ายจริง
3. **Forensic Evidence Bundle (.ZIP):** บรรจุไฟล์ Raw JSON Telemetry, กฎช่องโหว่ที่ใช้ทดสอบ, และไฟล์บันทึกการส่งคำขอ พร้อมค่าแฮช SHA-256 สำหรับใช้ในกระบวนการนิติวิทยาศาสตร์ดิจิทัล (Digital Forensics)

---

## 🧭 การตรวจสอบความถูกต้องย้อนกลับ (Verification & Auditability)

เพื่อพิสูจน์ทราบว่าไปป์ไลน์ทั้งหมดทำงานตรงตามที่ระบุในเอกสารฉบับนี้ ผู้ดูแลระบบสามารถรันชุดทดสอบอัตโนมัติของระบบได้ทันที:

```bash
# ทดสอบความถูกต้องของสคีมาภาษากลางและ Dynamic Rule Engine
./venv/bin/python -m unittest tests/test_dynamic_cve_rules.py

# ทดสอบระบบ Anti-False-Positive Negative Canary และการจัดกลุ่ม 8 กลุ่ม ThaiCERT
./venv/bin/python -m unittest tests/test_thaicert_vascan_integration.py

# รันชุดทดสอบความถูกต้องทางวิศวกรรมทั้งหมด 35 รายการ
./venv/bin/python -m unittest discover tests
```
*ผลลัพธ์การทดสอบยืนยัน: **Ran 35 tests — OK 100%***
