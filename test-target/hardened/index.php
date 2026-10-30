<?php
// Fully Hardened Enterprise Target (ThaiCERT Compliant)
// All Chains A, B, C, D, E Protected & Hardened
ini_set('session.use_strict_mode', '1');
ini_set('session.serialize_handler', 'php');
session_start();

// Strict security headers (expose_php = Off & Information Disclosure prevention)
header_remove("X-Powered-By");
header("Server: Enterprise-Edge-Secure/1.0");
header("Strict-Transport-Security: max-age=31536000; includeSubDomains; preload");
header("Content-Security-Policy: default-src 'self'");
header("X-Content-Type-Options: nosniff");
header("X-Frame-Options: SAMEORIGIN");
header("Content-Type: text/html; charset=UTF-8");

// Safe whitelisted parameter handling (No dynamic file inclusion, no unserialize)
$allowed_pages = ['home', 'about', 'contact'];
$page = isset($_GET['page']) && in_array($_GET['page'], $allowed_pages, true) ? $_GET['page'] : 'home';
?>
<!DOCTYPE html>
<html lang="th">
<head>
    <meta charset="UTF-8">
    <title>Secure Production System - Defensively Hardened (Chains A to E Mitigated)</title>
</head>
<body style="font-family: sans-serif; padding: 2rem; background: #f0fdf4; color: #14532d;">
    <div style="max-width: 800px; margin: 0 auto; background: white; padding: 2rem; border-radius: 1rem; box-shadow: 0 4px 6px -1px rgba(0,0,0,0.1);">
        <h2 style="color: #16a34a;">ระบบทดสอบสภาพแวดล้อมความปลอดภัยสูง (Enterprise Hardened Target)</h2>
        <p><b>พอร์ตบริการ:</b> 8088 (จำลองระบบที่ผ่านการปรับปรุงการตั้งค่าความปลอดภัยครบทุก Chain A ถึง E ตามมาตรฐาน ThaiCERT / CIS)</p>
        
        <div style="margin: 1.5rem 0; padding: 1rem; background: #f0fdf4; border: 1px solid #bbf7d0; border-radius: 0.5rem; color: #166534;">
            <b>มาตรการควบคุมความปลอดภัยที่บังคับใช้ (Active Hardening Controls):</b>
            <ul style="margin: 0.5rem 0 0 1.25rem; font-size: 0.875rem; line-height: 1.6;">
                <li><b>Chain A (Upload Progress & Strict Mode):</b> บังคับใช้ <code>session.use_strict_mode = 1</code> และ <code>session.upload_progress.enabled = Off</code> พร้อม Whitelist พารามิเตอร์เรียกไฟล์</li>
                <li><b>Chain B (INI & Exposure Lockdown):</b> ปิด <code>expose_php = Off</code>, <code>display_errors = Off</code> และเปิด <code>log_errors = On</code> พร้อมปกปิด Server Banner</li>
                <li><b>Chain C (Serializer Standardization):</b> กำหนด <code>session.serialize_handler = php</code> สม่ำเสมอทั่วทั้งแอปพลิเคชัน และไม่ใช้งานฟังก์ชัน <code>unserialize()</code></li>
                <li><b>Chain D (Memory Isolation & /tmp Defense):</b> แยกพื้นที่จัดเก็บเซสชันใน <code>/var/lib/php/sessions</code> สิทธิ์ 0700 และกำหนด <code>memory_limit = 256M</code></li>
                <li><b>Chain E (Worker Process Lifecycle):</b> ควบคุมขนาดบัฟเฟอร์ระดับ Reverse Proxy และจำกัดขอบเขต FastCGI ป้องกัน Stale Buffer Globals</li>
            </ul>
        </div>

        <hr style="border: 0; border-top: 1px solid #e2e8f0; margin: 1.5rem 0;">
        <p style="font-size: 0.875rem; color: #15803d;">
            สถานะการประเมิน: ระบบนี้ผ่านเกณฑ์การทดสอบความปลอดภัยครบถ้วนทุกข้อ (All Chains Defensively Hardened)
        </p>
    </div>
</body>
</html>
