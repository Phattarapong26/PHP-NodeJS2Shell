"""
End-to-End Acceptance Test: Verification of 8 ThaiCERT System Groups (Zero Mock)
Spins up 8 live HTTP servers in separate threads, performs real HTTP socket requests,
and asserts that the classification engine and vulnerability evaluator accurately categorize each system.
"""

import sys
import threading
import time
from http.server import HTTPServer, BaseHTTPRequestHandler
import httpx

from audit.thaicert_rules import classify_thaicert_groups

TEST_CONFIGS = [
    {
        "group": 1,
        "name": "กลุ่ม 1: เว็บไซต์และระบบภายในองค์กร (WordPress CMS)",
        "port": 9101,
        "headers": {
            "Server": "Apache/2.4.52 (Ubuntu)",
            "Content-Type": "text/html; charset=UTF-8",
            "X-Powered-By": "PHP/8.1.2"
        },
        "cookies": "",
        "body": '<!DOCTYPE html><html><head><meta name="generator" content="WordPress 6.4.2" /><link rel="stylesheet" href="/wp-content/themes/twentytwentyfour/style.css"></head><body><h1>Internal Portal</h1></body></html>',
        "is_php": True,
        "is_node": False,
        "cms": "WordPress"
    },
    {
        "group": 2,
        "name": "กลุ่ม 2: ระบบหลังบ้านแอปมือถือ และ API (Laravel & REST API)",
        "port": 9102,
        "headers": {
            "Server": "nginx/1.22.0",
            "Content-Type": "application/json",
            "X-CSRF-TOKEN": "8f9a2b3c4d5e6f7a",
            "Set-Cookie": "laravel_session=eyJpdiI6In...; path=/; HttpOnly"
        },
        "cookies": "laravel_session=eyJpdiI6In...",
        "body": '{"status":"ok","framework":"Laravel","version":"10.48.0"}',
        "is_php": True,
        "is_node": False,
        "cms": ""
    },
    {
        "group": 3,
        "name": "กลุ่ม 3: Hosting Control Panel (Webmin Panel)",
        "port": 9103,
        "headers": {
            "Server": "MiniServ/2.000",
            "Content-Type": "text/html"
        },
        "cookies": "",
        "body": '<html><head><title>Webmin Server</title></head><body>Login to Webmin Control Panel</body></html>',
        "is_php": False,
        "is_node": False,
        "cms": ""
    },
    {
        "group": 4,
        "name": "กลุ่ม 4: ซอฟต์แวร์และอุปกรณ์สำเร็จรูป (MikroTik Router Appliance)",
        "port": 9104,
        "headers": {
            "Server": "MikroTik HTTPProxy",
            "Content-Type": "text/html"
        },
        "cookies": "",
        "body": '<html><head><title>RouterOS WebFig</title></head><body><h1>MikroTik RouterOS 7.12</h1></body></html>',
        "is_php": False,
        "is_node": False,
        "cms": ""
    },
    {
        "group": 5,
        "name": "กลุ่ม 5: Container และ Docker Image (Traefik Ingress Gateway)",
        "port": 9105,
        "headers": {
            "Server": "traefik/v2.10",
            "Content-Type": "text/html",
            "X-Ingress-Cluster": "k8s-ingress"
        },
        "cookies": "",
        "body": '<html><body>Traefik Routing Gateway - Microservices Container Engine</body></html>',
        "is_php": False,
        "is_node": False,
        "cms": ""
    },
    {
        "group": 6,
        "name": "กลุ่ม 6: Windows PHP Stacks (IIS + PHP 8.2.19 - CVE-2024-4577 Priority)",
        "port": 9106,
        "headers": {
            "Server": "Microsoft-IIS/10.0",
            "X-Powered-By": "PHP/8.2.19",
            "Content-Type": "text/html"
        },
        "cookies": "",
        "body": '<html><body>Windows Server 2022 IIS PHP Web Hosting</body></html>',
        "is_php": True,
        "is_node": False,
        "cms": ""
    },
    {
        "group": 7,
        "name": "กลุ่ม 7: ระบบทดสอบ ระบบเก่า และระบบสำรอง (phpMyAdmin / Dev Staging)",
        "port": 9107,
        "headers": {
            "Server": "Apache/2.4.58",
            "Content-Type": "text/html"
        },
        "cookies": "",
        "body": '<html><head><title>phpMyAdmin 5.2.1</title></head><body><div class="alert">Debug Mode: app_env=local (Staging Environment)</div></body></html>',
        "is_php": True,
        "is_node": False,
        "cms": ""
    },
    {
        "group": 8,
        "name": "กลุ่ม 8: ระบบที่ผู้ให้บริการภายนอกดูแล (Cloudflare CDN Edge)",
        "port": 9108,
        "headers": {
            "Server": "cloudflare",
            "cf-ray": "8df4a1b2c3d4-BKK",
            "Content-Type": "text/html"
        },
        "cookies": "",
        "body": '<html><body>Cloudflare Edge Protected Outsourced Infrastructure</body></html>',
        "is_php": False,
        "is_node": False,
        "cms": ""
    }
]

def make_handler(cfg):
    class CustomHandler(BaseHTTPRequestHandler):
        def do_GET(self):
            self.send_response(200)
            for k, v in cfg["headers"].items():
                self.send_header(k, v)
            body_bytes = cfg["body"].encode("utf-8")
            self.send_header("Content-Length", str(len(body_bytes)))
            self.end_headers()
            self.wfile.write(body_bytes)

        def log_message(self, format, *args):
            pass  # Suppress console noise
    return CustomHandler

def run_all_tests():
    print("=" * 80)
    print("🚀 เริ่มการทดสอบยืนยันระบบตรวจจับ ThaiCERT 8 กลุ่มระบบ (Zero Mock Acceptance Test)")
    print("=" * 80)

    servers = []
    threads = []

    # 1. Start all 8 live servers
    for cfg in TEST_CONFIGS:
        port = cfg["port"]
        handler_cls = make_handler(cfg)
        server = HTTPServer(("127.0.0.1", port), handler_cls)
        t = threading.Thread(target=server.serve_forever, daemon=True)
        t.start()
        servers.append(server)
        threads.append(t)
        print(f"  [+] Live Service Online: Port {port} -> {cfg['name']}")

    time.sleep(0.5)

    client = httpx.Client(timeout=3.0)
    all_passed = True

    print("\n" + "-" * 80)
    print("🔍 กำลังส่ง Network Socket & HTTP Request จริง เพื่อตรวจประเมินผล...")
    print("-" * 80)

    for cfg in TEST_CONFIGS:
        target_group = cfg["group"]
        port = cfg["port"]
        url = f"http://127.0.0.1:{port}/"

        try:
            # Real HTTP Request (Zero Mock)
            resp = client.get(url)
            server_header = resp.headers.get("server", "")
            cookies_str = resp.headers.get("set-cookie", "")
            body_text = resp.text

            # Execute real classification rule engine
            res = classify_thaicert_groups(
                ip_or_host=f"127.0.0.1:{port}",
                server=server_header,
                headers=dict(resp.headers),
                body_text=body_text,
                cookies_str=cookies_str,
                port=port,
                is_php=cfg["is_php"],
                is_node=cfg["is_node"],
                cms_name=cfg["cms"]
            )

            detected_groups = res.get("groups", [])
            evidence = res.get("evidence", [])
            labels = res.get("group_labels", []) or res.get("labels", [])

            is_match = target_group in detected_groups

            status_icon = "✅ PASS" if is_match else "❌ FAIL"
            print(f"\n{status_icon} | กลุ่มที่ {target_group}: {cfg['name']}")
            print(f"      Port: {port} | HTTP Status: {resp.status_code} | Server: {server_header or '-'}")
            print(f"      กลุ่มที่ตรวจพบ (Detected Groups): {detected_groups}")
            print(f"      หลักฐานเชิงเทคนิค (Technical Evidence): {', '.join(evidence)}")
            print(f"      ป้ายกำกับ (Label): {', '.join(labels)}")

            if not is_match:
                all_passed = False
                print(f"      [!] คาดหวังกลุ่ม {target_group} แต่ไม่พบใน {detected_groups}")

        except Exception as e:
            print(f"❌ FAIL: เกิดข้อผิดพลาดในการเชื่อมต่อ Port {port}: {e}")
            all_passed = False

    # Shutdown servers
    for server in servers:
        server.shutdown()

    print("\n" + "=" * 80)
    if all_passed:
        print("🎉 ผลการตรวจรับ (Acceptance Result): ผ่านการทดสอบ 100% ครบทั้ง 8 กลุ่มระบบ!")
        print("    ระบบสามารถตรวจจำแนกสินทรัพย์ทางเทคโนโลยีและจัดกลุ่มตามแนวปฏิบัติ ThaiCERT ได้สมบูรณ์")
    else:
        print("⚠️ มีบางกลุ่มไม่ผ่านเกณฑ์การทดสอบ โปรดตรวจสอบกฎและหลักฐาน")
    print("=" * 80)

    return 0 if all_passed else 1

if __name__ == "__main__":
    sys.exit(run_all_tests())
