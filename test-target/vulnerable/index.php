<?php
// Simulated Pre-Hardening Web Application (QA Test Target)
// Represents ThaiCERT Group 1 (CMS) & Group 2 (REST API) & Group 5 (Container)
ini_set('display_errors', '1');
ini_set('session.use_strict_mode', '0');

session_start();

header("X-Powered-By: PHP/8.2.19");
header("Server: Apache/2.4.52 (Ubuntu) PHP-FPM");
header("Content-Type: text/html; charset=UTF-8");
?>
<!DOCTYPE html>
<html lang="th">
<head>
    <meta charset="UTF-8">
    <title>Enterprise Web Portal - WordPress 6.5.2 & REST API</title>
    <link rel="stylesheet" href="/wp-content/themes/enterprise/style.css">
    <link rel="stylesheet" href="/wp-includes/css/dist/block-library/style.min.css">
</head>
<body style="font-family: sans-serif; padding: 2rem; background: #f8fafc; color: #1e293b;">
    <div style="max-width: 700px; margin: 0 auto; background: white; padding: 2rem; border-radius: 1rem; box-shadow: 0 4px 6px -1px rgba(0,0,0,0.1);">
        <h2 style="color: #0284c7;">ระบบทดสอบสภาพแวดล้อมก่อนทำ Hardening (Pre-Hardening Target)</h2>
        <p><b>พอร์ตบริการ:</b> 8080 (จำลองระบบที่ยังไม่ได้รับการปรับปรุงการตั้งค่าความปลอดภัย)</p>
        <ul>
            <li><b>PHP Version:</b> 8.2.19 (มีความเสี่ยงตามเกณฑ์ ThaiCERT CVE-2024-4577 ที่ต้องเป็น 8.2.20+)</li>
            <li><b>ข้อมูลระบบ (expose_php):</b> เปิดเผยเลขเวอร์ชันใน Header</li>
            <li><b>การตั้งค่าเซสชัน:</b> ยังไม่ได้เปิด <code>session.use_strict_mode</code></li>
            <li><b>การจัดการไฟล์ชั่วคราว:</b> ยังไม่ได้ปิด <code>session.upload_progress.enabled</code></li>
        </ul>
        <hr style="border: 0; border-top: 1px solid #e2e8f0; margin: 1.5rem 0;">
        <p style="font-size: 0.875rem; color: #64748b;">
            จุดประสงค์: สำหรับใช้กับ OPScaner เพื่อทดสอบการตรวจจับช่องโหว่ความเสี่ยงเชิงรับ และตรวจสอบ Security Chains A, B, C, D
        </p>
    </div>
</body>
</html>
