# สารบัญเอกสารทางเทคนิคและสถาปัตยกรรมระบบ OPScaner
**OPScaner Engineering Documentation & Architectural Blueprint**
*กรอบแนวคิด การตัดสินใจเชิงวิศวกรรม ตรรกะการประเมินความมั่นคงปลอดภัย และการวิเคราะห์ซอร์สโค้ดเชิงลึก*

---

## 📌 บทนำและวัตถุประสงค์ (Executive Intent)
เอกสารชุดนี้จัดทำขึ้นเพื่ออธิบายหลักการทำงานเชิงลึก (Deep Technical Mechanics) ของระบบ **OPScaner** ตั้งแต่ชั้นสถาปัตยกรรมเครือข่าย (Network Layer) จนถึงชั้นประเมินช่องโหว่ความมั่นคงปลอดภัยของแอปพลิเคชันและเคอร์เนล (Application & Kernel Security Layers) 

เอกสารนี้มุ่งเน้นการตอบคำถามสำคัญ 3 ประการ:
1. **สถาปัตยกรรมระบบถูกออกแบบมาอย่างไร และทำไมต้องใช้วิธีนี้?** (Design Rationale & Trade-offs)
2. **วิธีดั้งเดิมหรือเครื่องมือมาตรฐานสากลทั่วไปมีข้อจำกัดอะไร ที่ทำให้สแกนไม่สำเร็จหรือรายงานผลเพี้ยน?** (Failure Modes of Alternative Approaches)
3. **ตรรกะภายในซอร์สโค้ดทำงานอย่างไรในแต่ละมิติ?** (Source Code Walkthrough & Implementation Details)

---

## 📂 โครงสร้างเอกสารในโฟลเดอร์ `document/`

เอกสารแบ่งออกเป็น 5 เล่มหลักตามมิติทางวิศวกรรม:

| เอกสาร | หัวข้อหลัก | ประเด็นสำคัญที่อธิบาย |
| :--- | :--- | :--- |
| **[01_SYSTEM_ARCHITECTURE.md](./01_SYSTEM_ARCHITECTURE.md)** | **สถาปัตยกรรมระบบและการตัดสินใจออกแบบ** | • ภาพรวมสถาปัตยกรรม Dual-Mode (Container vs Standalone)<br>• การแบ่งเลเยอร์ตรวจสอบ 4 ชั้น (L2 Discovery $\to$ L4 Ports $\to$ L7 Application $\to$ OS/Kernel)<br>• ทำไมเครื่องมือสแกนแบบเดิมจึงล้มเหลว (Nmap, Masscan, Nessus blind spots) |
| **[02_NETWORK_ENGINE_DEEPDIVE.md](./02_NETWORK_ENGINE_DEEPDIVE.md)** | **เจาะลึกระบบสำรวจเครือข่ายและการข้ามข้อจำกัด Docker** | • ปัญหา Docker Bridge NAT & Virtual Switch Barrier<br>• กลไก **Multi-Vector Discovery Engine** (ARP Snoop + TCP Connect/RST + mDNS + SSDP + NetBIOS + DHCP PTR)<br>• การตรวจจับอุปกรณ์ไร้สายและ Smart IoT โดยไม่ต้องเปิดสแกนแบบกวาดล้าง |
| **[03_VULNERABILITY_ASSESSMENT_LOGIC.md](./03_VULNERABILITY_ASSESSMENT_LOGIC.md)** | **ตรรกะการประเมินช่องโหว่และความสอดคล้องของเทคโนโลยี** | • การจัดกลุ่มสินทรัพย์ 8 กลุ่มตามมาตรฐาน ThaiCERT / สกมช.<br>• **OS Boundary Gating**: กลไกป้องกันการระบุช่องโหว่ผิดฝาผิดตัว (Tech Stack Mismatch Prevention)<br>• การพิสูจน์เงื่อนไขจำเป็นเชิงรุก (Precondition Probing: NGINX, Brotli, PHP, MPTCP)<br>• การจำแนกความเชื่อมั่น: `Confirmed` vs `Likely` vs `Conditional` |
| **[04_SOURCE_CODE_ANALYSIS.md](./04_SOURCE_CODE_ANALYSIS.md)** | **วิเคราะห์ซอร์สโค้ดพร้อมคำอธิบายแบบบรรทัดต่อบรรทัด** | • โครงสร้างโค้ดหลัก (`core/`, `audit/`, `api/`, `reports/`)<br>• การทำงานของ Async Concurrency Semaphore<br>• การทำงานของ `kernel_audit.py` (Active MPTCP Probing)<br>• กลไกสร้างรายงาน TLP:AMBER PDF |
| **[05_OFFICER_DEFENSE_FAQ.md](./05_OFFICER_DEFENSE_FAQ.md)** | **แนวทางการตอบข้อซักถามเชิงเทคนิค (สำหรับนำเสนอผู้เชี่ยวชาญ/ผู้บังคับบัญชา)** | • แนวทางการตอบคำถาม "ทำไมไม่ใช้ Nmap หรือ Nessus?"<br>• "ตรวจเคอร์เนลจากภายนอก Subnet ได้อย่างไร?"<br>• "มั่นใจได้อย่างไรว่าไม่มี False Positive หรือรายงานมั่ว?"<br>• ศัพท์เทคนิคมาตรฐานสากล (Defensive Lexicon) สำหรับชี้แจง |

---

## 🎯 มาตรฐานและข้อกำหนดที่ระบบรองรับ
1. **ThaiCERT / NCSA 8-Group Taxonomy**: สอดคล้องกับกรอบจำแนกระบบสารสนเทศ 8 หมวดหมู่ของสำนักงานคณะกรรมการการรักษาความมั่นคงปลอดภัยไซเบอร์แห่งชาติ (สกมช.)
2. **Traffic Light Protocol (TLP:AMBER)**: การจัดหมวดหมู่ชั้นความลับและควบคุมการเผยแพร่ข้อมูลตามมาตรฐาน FIRST.org
3. **CWE / CVE Baseline**: รองรับการวิเคราะห์ช่องโหว่สำคัญ เช่น Direct OS Command Injection (CWE-78), Buffer Copy without Checking Size of Input (CWE-120), Use-After-Free (CWE-416) และ Argument Injection (CWE-88)
