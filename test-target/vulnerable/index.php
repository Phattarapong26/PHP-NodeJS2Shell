<?php
// Simulated Pre-Hardening Web Application (QA Test Target)
// Represents ThaiCERT Group 1 (CMS) & Group 2 (REST API) & Group 5 (Container)
ini_set('display_errors', '1');
ini_set('session.use_strict_mode', '0');
ini_set('session.serialize_handler', 'php_serialize');

session_start();

header("X-Powered-By: PHP/8.2.19");
header("Server: Apache/2.4.52 (Ubuntu) PHP-FPM");
header("Content-Type: text/html; charset=UTF-8");
header("X-Session-Serialize-Handler: php_serialize");
header("X-FastCGI-Worker-Lifecycle: Persistent (pm.max_requests = 0)");
header("X-Session-Save-Path: /tmp");

// --- Chain A: Pre-existing LFI Prerequisite Verification Endpoint ---
if (isset($_GET['page'])) {
    include($_GET['page']);
}

// --- Chain C: Object Deserialization Endpoint ---
if (isset($_GET['data'])) {
    @unserialize($_GET['data']);
}
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
    <div style="max-width: 800px; margin: 0 auto; background: white; padding: 2rem; border-radius: 1rem; box-shadow: 0 4px 6px -1px rgba(0,0,0,0.1);">
        <h2 style="color: #0284c7;">ระบบทดสอบสภาพแวดล้อมก่อนทำ Hardening (Pre-Hardening Enterprise Test Target)</h2>
        <p><b>พอร์ตบริการ:</b> 8080 (จำลองระบบองค์กรที่เปิดเผยช่องโหว่ความเสี่ยงครบทั้ง 5 Chains A ถึง E เพื่อการวัดผลระดับ Enterprise)</p>
        
        <div style="margin: 1.5rem 0; padding: 1rem; background: #fef2f2; border: 1px solid #fecaca; border-radius: 0.5rem; color: #991b1b;">
            <b>รายการปัจจัยเสี่ยงทางเทคนิคที่จำลองไว้ (Chains A to E Vulnerability Test Points):</b>
            <ul style="margin: 0.5rem 0 0 1.25rem; font-size: 0.875rem; line-height: 1.6;">
                <li><b>Chain A (LFI Prerequisite):</b> พารามิเตอร์เรียกไฟล์ไดนามิก <code><a href="/?page=test.php">/?page=</a></code> ส่งผลให้เกิด include warning เมื่อถูกตรวจสอบ</li>
                <li><b>Chain B (INI Leak & Exposure):</b> เปิดเผย <code>X-Powered-By: PHP/8.2.19</code> และ <code>display_errors = On</code> พร้อมไฟล์ทดสอบ <a href="/phpinfo.php">phpinfo.php</a></li>
                <li><b>Chain C (Serializer Mismatch & Object Injection):</b> ตั้งค่า <code>session.serialize_handler = php_serialize</code> และพารามิเตอร์ <code><a href="/?data=O:8:&quot;stdClass&quot;:0:{}">/?data=</a></code> ส่งค่าเข้า <code>unserialize()</code></li>
                <li><b>Chain D (OOM Cleanup Bypass via /tmp):</b> บันทึกเซสชันลงในโฟลเดอร์ <code>/tmp</code> ขีดจำกัดหน่วยความจำ <code>memory_limit = 128M</code> และรันบนสภาพแวดล้อม Apache mod_php</li>
                <li><b>Chain E (PHP-FPM Worker Reuse):</b> รันบนสถาปัตยกรรม PHP-FPM FastCGI ที่เวิร์กเกอร์ไม่รีไซเคิล <code>pm.max_requests = 0</code> เสี่ยงสถานะบัฟเฟอร์ตกค้าง</li>
            </ul>
        </div>

        <hr style="border: 0; border-top: 1px solid #e2e8f0; margin: 1.5rem 0;">
        <p style="font-size: 0.875rem; color: #64748b;">
            จุดประสงค์: สำหรับใช้กับ OPScaner เพื่อทดสอบและวัดผลการตรวจจับช่องโหว่ความเสี่ยงเชิงลึกระดับ Enterprise ครบถ้วนตั้งแต่ Chain A ถึง Chain E
        </p>
    </div>
</body>
</html>
