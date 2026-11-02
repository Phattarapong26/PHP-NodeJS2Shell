# 04. วิเคราะห์ซอร์สโค้ดเชิงลึกพร้อมคำอธิบายการทำงาน
**OPScaner: Comprehensive Source Code Walkthrough & Architectural Blueprint**

---

## 1. ผังโครงสร้างไฟล์และโมดูลหลัก (Codebase Architecture)

```
OPScaner/
├── app.py                      # Flask Application Entrypoint & WSGI Server Bootstrap
├── GUI.html                    # Single Page Application (SPA) - TailwindCSS & Phosphor Icons
├── core/
│   ├── network.py              # การตรวจจับอินเทอร์เฟซ, คำนวณ Subnet, และดึง ARP Table
│   ├── multi_vector_discovery.py # เครื่องมือค้นหาโฮสต์ 5 เวกเตอร์ (L2/L4/UDP/DNS)
│   └── database.py             # ฐานข้อมูลลายเซ็นช่องโหว่ (16 CVE Signatures Catalog)
├── audit/
│   ├── probe_audit.py          # ตัวควบคุมการตรวจสอบเชิงลึกของแอปพลิเคชันเว็บ (L7 Coordinator)
│   ├── kernel_audit.py         # การตรวจสอบโปรโตคอล MPTCP และเคอร์เนล Linux (CVE-2026-98432)
│   ├── precondition_prober.py  # การพิสูจน์เงื่อนไขสถาปัตยกรรม (NGINX alias/rewrite, Brotli)
│   ├── rce_prover.py           # การพิสูจน์ผลเชิงประจักษ์แบบไม่ทำลายข้อมูล (Non-destructive PoC)
│   └── sub_tools.py            # การตรวจจับ WAF, CMS, และส่วนขยายความปลอดภัย
├── api/
│   ├── scan_routes.py          # RESTful Endpoints สำหรับการสั่งสแกนและประมวลผลเครือข่าย
│   └── report_routes.py        # Endpoints สำหรับสร้างและส่งออกรายงาน TLP:AMBER PDF
└── reports/
    └── amber_builder.py        # เครื่องมือเรนเดอร์เอกสาร TLP:AMBER PDF ทางการ (ReportLab Engine)
```

---

## 2. เจาะลึกโมดูลตรวจจับเครือข่าย ([`core/network.py`](file:///Users/admin/Desktop/OPScaner/core/network.py))

### หน้าที่หลัก:
ค้นหา IP Address, Gateway, Subnet, และ CIDR แท้จริงของเครื่องสแกนเนอร์โดยอัตโนมัติ โดยไม่ใช้การ Hardcode ค่าใด ๆ ทั้งสิ้น รองรับการทำงานทั้งบน macOS, Linux และภายใน Docker Container

### ตัวอย่างโค้ดสำคัญและการทำงาน:
```python
def get_host_network_info(force_refresh: bool = False) -> Dict[str, Any]:
    """ตรวจจับข้อมูลเครือข่ายของโฮสต์แบบ Dynamic พร้อมแคชผลลัพธ์ 60 วินาที"""
    # 1. หากรันใน Docker จะอ่านไฟล์ host_network.json ที่ Mount เข้ามา
    is_container = os.path.exists("/.dockerenv") or os.environ.get("IS_DOCKER") == "true"
    if is_container and os.path.isfile("host_network.json"):
        with open("host_network.json", "r") as f:
            data = json.load(f)
            if data.get("ip") and data.get("subnet"):
                return data

    # 2. หากรันบนเครื่อง Host จริง จะค้นหา Interface ที่มี Default Route
    default_gw, iface = get_default_gateway_and_interface()
    # 3. คำนวณ Subnet Mask และช่วง IP ทั้งหมดในวงแลนโดยใช้ ipaddress library
    net = ipaddress.IPv4Network(f"{ip}/{netmask}", strict=False)
    return {
        "ip": ip,
        "subnet": str(net),
        "cidr": net.prefixlen,
        "gateway": default_gw,
        "first_host": str(net.network_address + 1),
        "last_host": str(net.broadcast_address - 1),
        "total_hosts": net.num_addresses - 2
    }
```

---

## 3. เจาะลึกโมดูลตรวจสอบเคอร์เนลและ MPTCP ([`audit/kernel_audit.py`](file:///Users/admin/Desktop/OPScaner/audit/kernel_audit.py))

### หน้าที่หลัก:
ทำการทดสอบการเจรจาโปรโตคอล **MultiPath TCP (MPTCP)** บนพอร์ตบริการ และประเมินความเสี่ยงต่อช่องโหว่เคอร์เนล **CVE-2026-98432 (Use-After-Free ใน Linux Kernel IPv4 TCP, CVSS 9.8)**

### ตัวอย่างโค้ดสำคัญและการทำงาน:
```python
def probe_mptcp_capability(host: str, port: int, timeout: float = 2.0) -> Optional[bool]:
    """
    ทดสอบว่า TCP Listener บน host:port รองรับการเจรจา MPTCP หรือไม่
    IPPROTO_MPTCP คือโปรโตคอลหมายเลข 262 บน Linux Kernel 5.6 เป็นต้นมา
    """
    IPPROTO_MPTCP = getattr(socket, "IPPROTO_MPTCP", 262)
    SOL_MPTCP = 284
    MPTCP_INFO = 1

    try:
        # พยายามสร้าง Raw Socket แบบ MPTCP Stream
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM, IPPROTO_MPTCP)
    except (AttributeError, OSError):
        # หาก Platform (เช่น macOS) หรือ Host Kernel ไม่รองรับ ให้คืนค่า None
        return None

    try:
        sock.settimeout(timeout)
        sock.connect((host, port))
        try:
            # ดึง Socket Option SOL_MPTCP เพื่อตรวจสถานะการ Handshake
            info = sock.getsockopt(SOL_MPTCP, MPTCP_INFO, 16)
            if info and len(info) >= 16:
                return True   # ตอบรับ MPTCP สำเร็จ (เวกเตอร์เข้าข่ายความเสี่ยง)
        except OSError:
            pass
        return False          # ไม่ตอบรับ MPTCP (ตกกลับเป็น Standard TCP ปลอดภัย)
    except Exception:
        return None
    finally:
        sock.close()
```

### การประเมินผลพร้อมกล่องคำสั่ง Host-Check:
```python
def evaluate_cve_2026_98432(is_windows: bool, server: str, open_ports: List[int], ...):
    # หากเป้าหมายเป็น Windows ให้ตัดทิ้งทันที (ป้องกัน Tech Stack Mismatch)
    if is_windows or any(k in server.lower() for k in ["iis", "windows"]):
        return None, "ไม่ใช่ระบบปฏิบัติการ Linux — ไม่เข้าข่าย CVE-2026-98432"

    return {
        "id": "CVE-2026-98432",
        "severity": "Critical",
        "cvss": 9.8,
        "confidence": "Conditional",
        "verification_status": "CONDITIONAL (NEEDS_LOCAL_VERIFICATION)",
        "reason": "ตรวจพบสภาพแวดล้อม Linux ควรตรวจสอบเวอร์ชันเคอร์เนลผ่านคำสั่ง uname -r บนเครื่องจริง",
        # คำสั่งตรวจสอบฝั่ง Host ที่ใส่ลงในกล่องคำสั่งเพื่อให้ SysAdmin นำไปรันตรวจเช็ค
        "host_check": "cat /etc/os-release && uname -r && ps aux | grep -iE 'falcon|sentinel|wazuh|edr|defender'",
        "confirm_safe": "อัปเดต Linux Kernel เป็นรุ่นที่มีแพตช์แก้ไขล่าสุด หรือปิดการใช้งาน MPTCP/IPv4 options ที่ไม่จำเป็น"
    }
```

---

## 4. เจาะลึกโมดูลสร้างรายงาน TLP:AMBER PDF ([`reports/amber_builder.py`](file:///Users/admin/Desktop/OPScaner/reports/amber_builder.py))

### หน้าที่หลัก:
สร้างรายงานสรุปผลการประเมินความมั่นคงปลอดภัยฉบับสมบูรณ์ในรูปแบบ PDF ที่ได้มาตรฐานสากล (First.org TLP:AMBER) และฝังฟอนต์ภาษาไทย **TH Sarabun New** ในระดับไบนารี ป้องกันปัญหาตัวอักษรภาษาไทยลอยหรือสระไม่ตรงตำแหน่ง

### คุณลักษณะเด่นของเครื่องมือออกรายงาน:
1. **Dynamic Asset Synthesis**: รวมข้อมูลจากทุกโฮสต์ใน Subnet สรุปสถิติ 8 กลุ่ม ThaiCERT, สถานะช่องโหว่, และค่าเฉลี่ย Latency
2. **Coherent Threat Narrative**: เรียบเรียงเนื้อหารายงานตามข้อเท็จจริงทางสถาปัตยกรรม (Architecture Narrative) โดยไม่มีการกล่าวอ้างเกินจริง
3. **Admin Remediation Action Plan**: แนบชุดคำสั่ง Host-Check และแนวทางแก้ไขปรับปรุงระบบ (CIS Benchmark Baseline) กำกับไว้ในทุกหัวข้อช่องโหว่
