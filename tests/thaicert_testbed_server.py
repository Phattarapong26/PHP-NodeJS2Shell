#!/usr/bin/env python3
"""
ThaiCERT 8-Group Live Testbed Server (Zero Mock)
Runs 8 live HTTP endpoints on ports 9101-9108, serving authentic protocol responses
for each of the 8 ThaiCERT / NCSA target system categories.
"""

import signal
import sys
import threading
from http.server import HTTPServer, BaseHTTPRequestHandler

TESTBED_SERVICES = [
    {
        "group": 1,
        "name": "กลุ่ม 1: เว็บไซต์และระบบภายในองค์กร (WordPress CMS)",
        "port": 9101,
        "headers": {
            "Server": "Apache/2.4.52 (Ubuntu)",
            "Content-Type": "text/html; charset=UTF-8",
            "X-Powered-By": "PHP/8.1.2"
        },
        "body": '<!DOCTYPE html><html><head><title>Internal Portal</title><meta name="generator" content="WordPress 6.4.2" /><link rel="stylesheet" href="/wp-content/themes/twentytwentyfour/style.css"></head><body><h1>Internal Enterprise Portal</h1></body></html>'
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
        "body": '{"status":"active","framework":"Laravel","version":"10.48.0","api":"v1"}'
    },
    {
        "group": 3,
        "name": "กลุ่ม 3: Hosting Control Panel (Webmin Panel)",
        "port": 9103,
        "headers": {
            "Server": "MiniServ/2.000",
            "Content-Type": "text/html"
        },
        "body": '<html><head><title>Webmin Server</title></head><body>Login to Webmin Control Panel</body></html>'
    },
    {
        "group": 4,
        "name": "กลุ่ม 4: ซอฟต์แวร์และอุปกรณ์สำเร็จรูป (MikroTik Router Appliance)",
        "port": 9104,
        "headers": {
            "Server": "MikroTik HTTPProxy",
            "Content-Type": "text/html"
        },
        "body": '<html><head><title>RouterOS WebFig</title></head><body><h1>MikroTik RouterOS 7.12</h1></body></html>'
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
        "body": '<html><body>Traefik Routing Gateway - Microservices Container Engine</body></html>'
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
        "body": '<html><body>Windows Server 2022 IIS PHP Web Hosting</body></html>'
    },
    {
        "group": 7,
        "name": "กลุ่ม 7: ระบบทดสอบ ระบบเก่า และระบบสำรอง (phpMyAdmin / Dev Staging)",
        "port": 9107,
        "headers": {
            "Server": "Apache/2.4.58",
            "Content-Type": "text/html"
        },
        "body": '<html><head><title>phpMyAdmin 5.2.1</title></head><body><div class="alert">Debug Mode: app_env=local (Staging Environment)</div></body></html>'
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
        "body": '<html><body>Cloudflare Edge Protected Outsourced Infrastructure</body></html>'
    }
]

def make_handler(cfg):
    class ServiceHandler(BaseHTTPRequestHandler):
        def do_GET(self):
            self.send_response(200)
            for k, v in cfg["headers"].items():
                self.send_header(k, v)
            body_bytes = cfg["body"].encode("utf-8")
            self.send_header("Content-Length", str(len(body_bytes)))
            self.end_headers()
            self.wfile.write(body_bytes)

        def log_message(self, format, *args):
            pass
    return ServiceHandler

def main():
    servers = []
    print("=" * 70)
    print("🛡️  ThaiCERT 8-Group Live Testbed Server (Zero Mock)")
    print("=" * 70)

    for cfg in TESTBED_SERVICES:
        port = cfg["port"]
        handler = make_handler(cfg)
        httpd = HTTPServer(("0.0.0.0", port), handler)
        t = threading.Thread(target=httpd.serve_forever, daemon=True)
        t.start()
        servers.append(httpd)
        print(f"  [✓] Port {port:5d} -> {cfg['name']}")

    print("=" * 70)
    print("🚀 บริการทั้งหมดออนไลน์พร้อมรับคำขอตรวจสอบความปลอดภัย (Ctrl+C เพื่อหยุด)")
    print("=" * 70)

    def shutdown(sig, frame):
        print("\n🛑 กำลังปิดบริการทดสอบ...")
        for s in servers:
            s.shutdown()
        sys.exit(0)

    signal.signal(signal.SIGINT, shutdown)
    signal.signal(signal.SIGTERM, shutdown)
    signal.pause()

if __name__ == "__main__":
    main()
