<?php
// Fully Hardened Enterprise Target (ThaiCERT Compliant)
// All Chains A, B, C, D Protected
ini_set('session.use_strict_mode', '1');
session_start();

// Strict security headers (expose_php = Off simulation)
header_remove("X-Powered-By");
header("Server: Enterprise-Edge-Secure/1.0");
header("Strict-Transport-Security: max-age=31536000; includeSubDomains; preload");
header("Content-Type: text/html; charset=UTF-8");
?>
<!DOCTYPE html>
<html lang="th">
<head>
    <meta charset="UTF-8">
    <title>Secure Production System - Defensively Hardened</title>
</head>
<body style="font-family: sans-serif; padding: 2rem; background: #f0fdf4; color: #14532d;">
    <div style="max-width: 700px; margin: 0 auto; background: white; padding: 2rem; border-radius: 1rem; box-shadow: 0 4px 6px -1px rgba(0,0,0,0.1);">
        <h2 style="color: #16a34a;">ระบบทดสอบสภาพแวดล้อมความปลอดภัยสูง (Hardened Target)</h2>
        <p><b>พอร์ตบริการ:</b> 8088 (จำลองระบบที่ผ่านการปรับปรุงการตั้งค่าความปลอดภัยครบทุก Chain)</p>
        <ul>
            <li><b>expose_php:</b> Off (ปิดบังข้อมูลเวอร์ชันในระดับ Header)</li>
            <li><b>display_errors:</b> Off (ไม่แสดงข้อความผิดพลาดสู่ภายนอก)</li>
            <li><b>session.upload_progress:</b> Off (ป้องกันการสร้างไฟล์เซสชันแฝง)</li>
            <li><b>session.use_strict_mode:</b> 1 (บังคับใช้รหัสเซสชันที่ระบบสร้างขึ้นเท่านั้น)</li>
            <li><b>Transport Security:</b> HSTS Preload Enabled</li>
        </ul>
    </div>
</body>
</html>
