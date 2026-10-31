# OPScaner
### Web & Network Security Assessment Toolkit & LFI-to-RCE PoC Verifier

---

## 📌 ภาพรวมของเครื่องมือและขอบเขตทางเทคนิค (Overview & Technical Scope)

**OPScaner** เป็นเครื่องมือตรวจสอบความมั่นคงปลอดภัยเครือข่ายและเว็บแอปพลิเคชันแบบ **Blackbox (Blackbox Security Scanner & PoC Verifier)** ที่ถูกพัฒนาขึ้นเพื่อช่วยให้วิศวกรความมั่นคงปลอดภัย (Security Engineers) และผู้ดูแลระบบ สามารถสำรวจพื้นผิวการโจมตี (Attack Surface), จำแนกกลุ่มสถาปัตยกรรมระบบเว็บ, และทดสอบการขยายผลช่องโหว่จำพวก **Local File Inclusion (LFI) ไปสู่ Remote Code Execution (RCE)**

> [!IMPORTANT]
> **ข้อจำกัดและขอบเขตทางเทคนิค (Scope & Limitations):**
> * **การตรวจแบบ Blackbox:** เครื่องมือนี้วิเคราะห์ข้อมูลภายนอกที่เซิร์ฟเวอร์ตอบกลับ (HTTP Headers, Cookies, HTML Body, Status Codes, และ Error Messages) โดย**ไม่มีสิทธิ์เข้าถึง Source Code ฝั่งเซิร์ฟเวอร์จริง**
> * **เวอร์ชัน $\neq$ ความสามารถในการโจมตีจริง (Exploitability Prerequisites):** การตรวจพบเวอร์ชันซอฟต์แวร์ที่มีประวัติช่องโหว่ (เช่น Node.js หรือ PHP) เป็นเพียง **"ตัวชี้วัดความเสี่ยงเบื้องต้น (Vulnerability Indicator)"** การจะโจมตีสำเร็จได้จริงย่อมขึ้นอยู่กับเงื่อนไขเฉพาะของแอปพลิเคชัน (เช่น ช่องโหว่ Brotli ใน Node.js ต้องมีโค้ดที่รับข้อมูลจากภายนอกไปถอดรหัสผ่าน `node:zlib` จริง)
> * **การตรวจ LFI:** การส่งพารามิเตอร์ทดสอบพื้นฐาน (`?page=`, `?file=`) เป็นเพียงการตรวจจับเบื้องต้น (Heuristic Probing) **หากไม่พบข้อผิดพลาด แปลได้เพียง "ตรวจไม่พบด้วยพารามิเตอร์พื้นฐานเหล่านี้" เท่านั้น ไม่ได้รับประกันว่าระบบไม่มีช่องโหว่ LFI ในจุดอื่น**
> * **ความแตกต่างระหว่าง LFI และ RCE:** การอ่านไฟล์ระบบได้ (เช่น `/etc/passwd`) ถือเป็นช่องโหว่ **Arbitrary File Read / LFI** เท่านั้น ยังไม่นับเป็น Remote Code Execution (RCE) จนกว่าจะสามารถทำให้เกิดการประมวลผลคำสั่งหรือโค้ดบนระบบได้จริง
> * **Active Probing:** การทดสอบ PoC เช่น CVE-2024-4577 หรือการตรวจจับ Web Shell เป็นการส่งคำขอทดสอบช่องโหว่จริง (Active Probing) **ต้องใช้เฉพาะบนระบบที่ได้รับอนุญาตเป็นลายลักษณ์อักษรเท่านั้น**

---

## 🏗️ แผนผังสถาปัตยกรรมและขั้นตอนการทำงาน (Architecture & Workflow)

```mermaid
flowchart TD
    subgraph S1 [1. Network Scope and Discovery]
        A["เป้าหมายการตรวจ: Local Subnet / External IP / Domain"]
        B{"วิเคราะห์ขอบเขตเครือข่าย"}
        C["Multi-Vector Discovery: ARP / NetBIOS / mDNS / DNS"]
        D["Routed TCP Sweeper: Standard Production Ports"]
        E["Active Hosts Matrix"]
        A --> B
        B -->|ในวง Subnet เดียวกัน L2/L3| C
        B -->|ข้ามวง Subnet หรือ WAN L3/L4| D
        C --> E
        D --> E
    end

    subgraph S2 [2. Classification and Fingerprinting]
        F["Async HTTP and HTTPS Web Fingerprinting"]
        G["จำแนกตามโปรไฟล์สถาปัตยกรรมระบบ 8 กลุ่ม"]
        H["Dynamic CVE Feeds Matcher: Multi-Stack"]
        E --> F
        F --> G
        G --> H
    end

    subgraph S3 [3. Targeted Attack Chains Analysis: Chains A to E]
        I{"ประเมินปัจจัยเสี่ยง LFI และ Configuration"}
        J["Canary Probing Engine: Heuristic and PoC Vectors"]
        K1["Chain A: Upload Progress Inode Mutation"]
        K2["Chain B: INI Leak and Environment Reflection"]
        K3["Chain C: Serializer Mismatch and Tampering"]
        K4["Chain D: OOM Cleanup and Temp File Persistence"]
        K5["Chain E: FastCGI Worker Reuse Contamination"]
        H --> I
        I -->|ประเมินเงื่อนไขห่วงโซ่การโจมตี| J
        J --> K1
        J --> K2
        J --> K3
        J --> K4
        J --> K5
    end

    subgraph S4 [4. Evidence and Reporting]
        L["Proof Evaluation: Confirmed / Likely / Conditional / Inconclusive"]
        M["TLP:AMBER Style Security Advisory PDF"]
        N["Neumorphic Web Dashboard"]
        O["CLI JSON Telemetry for SIEM and SOC"]
        K1 --> L
        K2 --> L
        K3 --> L
        K4 --> L
        K5 --> L
        L --> M
        L --> N
        L --> O
    end
```

---

## ⚡ ทำไมจึงเลือกสถาปัตยกรรม High-Concurrency Async I/O (`asyncio` + `httpx`)?

การสแกนเครือข่ายเพื่อทำแผนที่ระบบจำเป็นต้องคำนึงถึงผลกระทบต่ออุปกรณ์ระหว่างทาง (Network Infrastructure Safety):

1. **ลดภาระทรัพยากรฝั่งเครื่องสแกน (Low Memory Footprint):**
   * โมเดล Multi-threading ดั้งเดิมจอง Stack Memory ราว 8MB ต่อหนึ่ง Thread เมื่อสแกนหลายร้อยโฮสต์พร้อมกันจะเกิด Context Switching และกินแรมมหาศาล
   * OPScaner ใช้ Single-Threaded Event Loop ร่วมกับ Non-blocking Sockets ทำให้สามารถสแกนเป้าหมายจำนวนมากพร้อมกันได้โดยใช้ Memory เพียงไม่กี่สิบเมกะไบต์
2. **ควบคุมอัตราการส่งแพ็กเก็ต ป้องกัน Network DoS (Safety & Concurrency Semaphore):**
   * การยิงคำขอเร็วเกินไปอาจทำให้ Stateful Table ของ Firewall, NAT Router หรือ Switch เต็มจนเครื่องค้าง
   * ระบบใช้ Concurrency Semaphore Pool และ Timeout ที่กระชับ (0.15s – 2.0s) เพื่อให้การกวาดตรวจเป็นไปอย่างนุ่มนวลและไม่ทำให้เซิร์ฟเวอร์ปลายทางล่ม

---

## 🔍 ห่วงโซ่การขยายผล LFI-to-RCE (Chains A – E) ตรวจสอบอะไรบ้าง?

เมื่อตรวจพบแอปพลิเคชัน PHP ระบบจะทำการประเมินว่ามีปัจจัยแวดล้อมที่อาจนำไปสู่การขยายผลจาก LFI เป็น RCE หรือไม่ โดยแบ่งเป็น 5 เส้นทาง:

| ห่วงโซ่การโจมตี (Attack Chain) | สิ่งที่ระบบทำการตรวจสอบ (Checks & Indicators) | วิธีการตรวจสอบ | ผลสะท้อนและความหมายจริง |
| :--- | :--- | :--- | :--- |
| **[A] Upload Progress Inode Mutation** | ตรวจสอบการเปิดใช้งาน `session.upload_progress.enabled` | ส่ง Multipart Request สั้นๆ พร้อม Session Key ทดสอบพฤติกรรม | หากเปิดใช้งานและมี LFI ผู้โจมตีอาจสร้างไฟล์เซสชันชั่วคราวเพื่อรันโค้ดได้ |
| **[B] INI Leak & Environment Reflection** | ตรวจสอบข้อมูลรั่วไหล เช่น `phpinfo()`, Environment Variables, Path Disclosure | ตรวจสอบ Diagnostic Endpoints และส่วนหัว Error | ข้อมูล Path ช่วยให้ผู้โจมตีระบุตำแหน่งไฟล์เป้าหมายในการทำ Traversal ได้ง่ายขึ้น |
| **[C] Serializer Mismatch & Session Tampering** | ตรวจสอบ Header / Cookie ที่บ่งชี้การใช้ Serializer ต่างชนิดกัน | วิเคราะห์ค่าตอบกลับและ Header โครงสร้างเซสชัน | ความขัดแย้งของ Parser อาจเปิดช่องโหว่ Object Injection |
| **[D] OOM Cleanup & Temp File Retention** | ตรวจสอบการจัดการไฟล์ชั่วคราวเมื่อเกิดข้อผิดพลาดในการประมวลผล | วิเคราะห์พฤติกรรมการคืนค่าเมื่อส่ง Request ขนาดใหญ่ | หากระบบลบไฟล์ชั่วคราวช้า อาจเกิดช่วงเวลา (Race Window) ให้ทำ LFI ได้ |
| **[E] Persistent Worker Reuse & Pollution** | ตรวจสอบการทำงานของ Worker (PHP-FPM / FastCGI) | ส่งคำขอ Pipelined Keep-Alive ตรวจจับ State Isolation | ประเมินความเสี่ยงของการปนเปื้อนข้อมูลระหว่าง Request |

---

## 💡 เข้าใจ "PHP2Shell": มุมมองของผู้ไม่หวังดี และการทดสอบของระบบ

### 1. มุมมองของผู้ไม่หวังดี (Attacker's Perspective)
* **ปัญหาของ LFI ทั่วไป:** ช่องโหว่ `include($_GET['file']);` ทำได้เพียงอ่านไฟล์ที่มีอยู่แล้วในเซิร์ฟเวอร์ หากเซิร์ฟเวอร์ไม่มีไฟล์ที่มีโค้ดแปลกปลอมของผู้โจมตี ก็จะไม่สามารถสั่งรันคำสั่งใหม่ (RCE) ได้
* **เป้าหมายของผู้ไม่หวังดี:** หาวิธีทำให้เซิร์ฟเวอร์ **"สร้างไฟล์อะไรก็ได้บนเครื่องที่มีโค้ดอันตรายฝังอยู่"** เช่น:
  * ฝากไว้ในไฟล์เซสชันผ่าน Session Upload Progress (`/tmp/sess_*`)
  * ฝากไว้ในไฟล์ชั่วคราวของ `phpinfo()`
  * ฉีดโค้ดผ่าน Arguments ในกรณี CGI Argument Injection (CVE-2024-4577)
  * ฉีดโค้ดลงใน Access Log ผ่านส่วนหัว User-Agent (Log Poisoning)
  เมื่อไฟล์ถูกสร้างขึ้น จึงใช้ LFI เรียกไฟล์นั้นเพื่อสั่งประมวลผลโค้ด

### 2. ลำดับขั้นตอนการพิสูจน์ทราบช่องโหว่ (LFI-to-RCE Verification Flow)
เพื่อให้การตรวจสอบเป็นไปตามมาตรฐานวิชาการด้านความมั่นคงปลอดภัย (Security Research Standard) OPScaner กำหนดลำดับขั้นตอนการทดสอบอย่างเคร่งครัด:

1. **ตรวจหา LFI (Detect LFI):** ส่งพารามิเตอร์ทดสอบพื้นฐาน (`?page=`, `?file=`) เพื่อตรวจจับข้อผิดพลาด `include` หรือ `open_basedir`
2. **หา Endpoint สร้าง Session (Discover Session):** ค้นหาจุดที่สร้างคุกกี้ `PHPSESSID` หรือใช้กลไก PHP Session Upload Progress
3. **ส่ง Canary Payload ปลอดภัย (Inject Safe Canary):** สุ่มตัวเลขทางคณิตศาสตร์สองชุด (เช่น `15200 + 4811 = 20011`) และส่งคำนวณโค้ดผ่านแท็ก PHP ใน Session Storage โดยไม่ส่งโค้ดอันตรายหรือสร้าง Backdoor
4. **พยายาม Trigger ผ่าน LFI (Trigger via LFI):** ส่งคำขอ LFI ไปเรียกอ่านไฟล์เซสชันปลายทาง (เช่น `/?page=/tmp/sess_<id>`)
5. **แยกสถานะผลลัพธ์ 3 ระดับอย่างแม่นยำ (Tri-State Categorization):**
   * **`RCE_CONFIRMED`:** ผลลัพธ์ตัวเลขคณิตศาสตร์ถูกคำนวณจริง (ยืนยันว่าโค้ดถูกประมวลผลโดย PHP Engine สำเร็จ)
   * **`CANARY_CONFIRMED`:** พบค่าวาจาของ Canary สะท้อนกลับมาเป็นข้อความล้วน แต่ไม่มีการ Execute (ยืนยันว่ามี LFI อ่านไฟล์เซสชันได้จริง แต่ไม่เกิดการรันโค้ด)
   * **`NOT_CONFIRMED`:** ไม่พบการตอบสนอง หรือระบบไม่สามารถเปิดอ่านไฟล์เซสชันได้
6. **บันทึกหลักฐานดิจิทัลพร้อมค่าแฮชตรวจสอบความถูกต้อง (Tamper-Evident Evidence Digest):**
   * บันทึกวันเวลา (ISO 8601 UTC), ชื่อผู้ตรวจสอบ (Operator), และ Full HTTP Transcript (Request/Response)
   * คำนวณค่า **SHA-256 Checksum** ของ Payload และ Transcript เพื่อใช้ตรวจสอบการแก้ไขดัดแปลงข้อมูล (Tamper Detection)
7. **กลไกความปลอดภัย (Safety Gate Protection):**
   * **ระงับการยิง Active RCE โดยค่าเริ่มต้น:** การสแกนปกติจะทำงานในโหมด Safe Passive & Heuristic Inspection เท่านั้น
   * **การเปิดใช้ Active Verification:** ผู้ใช้ต้องระบุพารามิเตอร์ `--active-rce` เจาะจง
   * **Public Target Safeguard:** หากเป้าหมายเป็น Public IP หรือโดเมนภายนอก ผู้ใช้ต้องระบุ `--i-own-this-target` หรือพิมพ์ `YES` ยืนยันสิทธิ์ความเป็นเจ้าของระบบก่อนเสมอ เพื่อป้องกันการละเมิดกฎหมาย พ.ร.บ. คอมพิวเตอร์ฯ

---

## 🏷️ โปรไฟล์สถาปัตยกรรม 8 กลุ่ม (Architecture Archetype Profiles)

เพื่อช่วยจัดหมวดหมู่ระบบที่พบในเครือข่าย ผู้พัฒนาได้จัดทำชุดโปรไฟล์สถาปัตยกรรมขึ้น 8 รูปแบบ โดยอ้างอิงจากโครงสร้างระบบไอทีที่พบได้ทั่วไปในประเทศไทย:
1. **เว็บไซต์และระบบภายในองค์กร (CMS / Internal Web):** เช่น WordPress, Drupal, หรือเว็บแอปทั่วไป
2. **ระบบหลังบ้านแอปมือถือ และ API:** เช่น Laravel, Lumen, RESTful APIs
3. **Hosting Control Panel:** เช่น cPanel, DirectAdmin, Plesk
4. **ซอฟต์แวร์และอุปกรณ์สำเร็จรูป (Appliance):** เช่น NAS, Firewall Web Admin, IoT Devices
5. **Container และ Microservices:** ระบบที่ทำงานบน Docker / Kubernetes
6. **Windows ที่มี PHP ติดตั้งอยู่:** บริการ PHP บน IIS หรือ Windows Server
7. **ระบบทดสอบ ระบบเก่า และระบบสำรอง:** ระบบ UAT, Staging, หรือเซิร์ฟเวอร์เก่าที่รอปลดระวาง
8. **ระบบที่ผู้ให้บริการภายนอกดูแล:** คลาวด์หรือ Third-party Hosted Services

> [!NOTE]
> โปรไฟล์ทั้ง 8 กลุ่มนี้เป็น **เกณฑ์การจัดหมวดหมู่เชิงสถาปัตยกรรม (Architectural Archetypes) ที่ผู้พัฒนายกร่างขึ้นสำหรับเครื่องมือนี้** ไม่ใช่มาตรฐานข้อกำหนดอย่างเป็นทางการที่ประกาศโดยหน่วยงานรัฐ

---

## 🌐 การตรวจสอบเป้าหมายนอกวง IP / ข้าม Subnet / โดเมน

* **ในวง LAN เดียวกัน (L2/L3):** สามารถค้นหาโฮสต์ได้ลึกผ่าน Kernel ARP, NetBIOS, และ mDNS แม้เครื่องเป้าหมายจะปิดกั้น ICMP Echo (Ping)
* **ข้าม Subnet / WAN / โดเมนภายนอก (L3/L4):**
  * ตามมาตรฐานเครือข่าย Frame ระดับ L2 ARP จะไม่ส่งข้าม Router
  * อย่างไรก็ดี ผู้ใช้งานสามารถระบุ IP ปลายทาง, CIDR ข้ามวง (เช่น `172.16.0.0/16`), หรือ Domain Name ได้โดยตรง
  * ระบบจะสลับเข้าสู่การสแกนผ่าน **TCP Routing & Web Handshake** เพื่อตรวจสอบพอร์ตและวิเคราะห์ช่องโหว่เว็บได้ตามปกติ

---

## 🚀 ขั้นตอนการติดตั้งและเริ่มใช้งาน (Quickstart Guide)

### 1. รันผ่าน Docker Compose (แนะนำ)

```bash
# โคลนโปรเจกต์
git clone https://github.com/Phattarapong26/PHP-NodeJS2Shell.git
cd PHP-NodeJS2Shell

# เริ่มการทำงานของระบบ
docker-compose up -d --build
```

เข้าใช้งานหน้าจอควบคุมผ่านเบราว์เซอร์ที่: **`http://localhost:5050`**

---

### 2. รันผ่าน CLI (สำหรับการทดสอบโฮสต์เดี่ยว)

```bash
# 1. การสแกนแบบปลอดภัย (Safe Passive & Fingerprint Mode - ค่าเริ่มต้น)
./venv/bin/python audit_cli.py -t http://192.168.1.50:8080

# 2. การเปิดทดสอบ Active RCE & Canary Verification (มี Safety Gate ป้องกัน)
./venv/bin/python audit_cli.py -t http://192.168.1.50:8080 --active-rce

# 3. การทดสอบเป้าหมายสาธารณะพร้อมยืนยันสิทธิ์ความเป็นเจ้าของระบบ
./venv/bin/python audit_cli.py -t https://my-app.internal:8443 --active-rce --i-own-this-target --operator "Auditor-Name" --export-report
```

---

## ⚖️ ข้อกำหนดการใช้งานและจริยธรรม (Legal & Ethical Disclaimer)

เครื่องมือนี้มีฟังก์ชันการส่งคำขอทดสอบช่องโหว่จริง (Active PoC Probing) พัฒนาขึ้นเพื่อวัตถุประสงค์ในการตรวจสอบและประเมินความเสี่ยงเชิงป้องกัน (Authorized Defensive Security Assessment) **ห้ามนำไปใช้สแกนหรือทดสอบระบบของผู้อื่นโดยไม่ได้รับความยินยอมเป็นลายลักษณ์อักษรโดยเด็ดขาด** ผู้พัฒนาจะไม่รับผิดชอบต่อความเสียหายหรือผลกระทบทางกฎหมายใดๆ ที่เกิดจากการนำเครื่องมือไปใช้งานในทางที่ผิด
