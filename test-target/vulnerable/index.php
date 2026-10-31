<?php
// Simulated Pre-Hardening Web Application (QA Test Target)
// Emulates Windows Server OS (Win64 / XAMPP) running WordPress CMS & PHP-CGI / PHP 8.2.19
// Represents ThaiCERT Group 6 (Windows PHP Stacks - CVE-2024-4577) & Group 1 (CMS / WordPress)
ini_set('display_errors', '1');
error_reporting(E_ALL);

// Set Windows Architecture & SAPI Headers FIRST before any output or session_start
header("X-Powered-By: PHP/8.2.19");
header("Server: Apache/2.4.58 (Win64) OpenSSL/3.1.3 PHP/8.2.19");
header("Content-Type: text/html; charset=UTF-8");
header("X-Session-Serialize-Handler: php_serialize");
header("X-FastCGI-Worker-Lifecycle: Persistent (pm.max_requests = 0)");
header("X-Session-Save-Path: C:\\xampp\\tmp");
header("X-Server-OS: Microsoft Windows Server 2022 (Win64)");
header("X-PHP-SAPI: CGI/FastCGI (Win64 - CVE-2024-4577 Sensitive)");
header("X-Zend-Engine-ASan: Vulnerable (var_unserializer.c:245/851; BG(serialize_lock)=0)");
header("Link: <http://" . ($_SERVER['HTTP_HOST'] ?? 'localhost:8080') . "/wp-json/>; rel=\"https://api.w.org/\"");

ini_set('session.use_strict_mode', '0');
ini_set('session.serialize_handler', 'php_serialize');
ini_set('session.upload_progress.enabled', '1');

@session_start();

$request_uri = $_SERVER['REQUEST_URI'] ?? '/';
$uri_path = parse_url($request_uri, PHP_URL_PATH);

// --- 1. WordPress REST API Endpoint Emulation ---
if (rtrim($uri_path, '/') === '/wp-json' || str_starts_with($uri_path, '/wp-json/')) {
    header("Content-Type: application/json; charset=UTF-8");
    header("X-WP-Total: 12");
    header("X-WP-TotalPages: 1");
    echo json_encode([
        "name" => "ThaiCERT Operations Portal (WordPress 6.4.2 on Windows Server)",
        "description" => "Internal Government Web Application & Document Management System on Windows OS",
        "url" => "http://" . ($_SERVER['HTTP_HOST'] ?? 'localhost:8080'),
        "home" => "http://" . ($_SERVER['HTTP_HOST'] ?? 'localhost:8080'),
        "namespaces" => [
            "wp/v2",
            "wordfence/v1",
            "filemanager/v1"
        ],
        "authentication" => [],
        "routes" => [
            "/" => ["namespace" => "", "methods" => ["GET"]],
            "/wp/v2" => ["namespace" => "wp/v2", "methods" => ["GET"]],
            "/wp/v2/posts" => ["namespace" => "wp/v2", "methods" => ["GET", "POST"]],
            "/wp/v2/pages" => ["namespace" => "wp/v2", "methods" => ["GET"]],
            "/wp/v2/users" => ["namespace" => "wp/v2", "methods" => ["GET"]],
            "/filemanager/v1" => ["namespace" => "filemanager/v1", "methods" => ["GET", "POST"]]
        ]
    ], JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);
    exit;
}

// --- 2. Low-Level C & AddressSanitizer (ASan) Memory Diagnostic Endpoint ---
if (isset($_GET['action']) && $_GET['action'] === 'asan_check') {
    header("Content-Type: application/json; charset=UTF-8");
    $mem_usage = memory_get_usage();
    $mem_peak = memory_get_peak_usage();
    $mem_limit = ini_get('memory_limit');
    echo json_encode([
        "status" => "vulnerable",
        "os_architecture" => "Microsoft Windows (Win64 - x86_64)",
        "zend_version" => zend_version(),
        "php_version" => "8.2.19 (Unpatched Zend Engine for Win32/Win64)",
        "server_api" => "CGI / FastCGI (Windows Best-Fit Injection Vector)",
        "memory_current_bytes" => $mem_usage,
        "memory_peak_bytes" => $mem_peak,
        "memory_limit" => $mem_limit,
        "allocator_profile" => "USE_ZEND_ALLOC=1 (Zend Memory Manager - Windows Small Chunk)",
        "c_source_points" => [
            "var_destroy_free" => "Zend/var_unserializer.c:245 (heap chunk free)",
            "unserialize_read" => "Zend/var_unserializer.c:851 (php_var_unserialize R:xxx read)",
            "stack_chunk_threshold" => 1018,
            "serialize_lock_flag" => 0
        ],
        "asan_verdict" => "CRITICAL: AddressSanitizer Heap-Use-After-Free confirmed on destructor reentry without BG(serialize_lock)",
        "patch_status" => "Missing Zend Commit 3584a98"
    ], JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);
    exit;
}

// --- 3. Windows Path Error Handler for Authentic Windows Emulation ---
set_error_handler(function($errno, $errstr, $errfile, $errline) {
    if (str_contains($errstr, 'include') || str_contains($errstr, 'require') || str_contains($errstr, 'failed to open stream')) {
        $param_val = htmlspecialchars($_GET['page'] ?? $_GET['file'] ?? $_GET['include'] ?? 'unknown');
        $win_root = "C:\\xampp\\htdocs\\index.php";
        $win_include_path = ".;C:\\xampp\\php\\PEAR";
        echo "<br />\n<b>Warning</b>:  include(" . $param_val . "): Failed to open stream: No such file or directory in <b>" . $win_root . "</b> on line <b>" . $errline . "</b><br />\n";
        echo "<b>Warning</b>:  include(): Failed opening '" . $param_val . "' for inclusion (include_path='" . $win_include_path . "') in <b>" . $win_root . "</b> on line <b>" . $errline . "</b><br />\n";
        return true;
    }
    return false;
});

// --- 4. Active File Inclusion (FI / LFI) Vulnerability Sink ---
$lfi_triggered = false;
$lfi_param_used = null;
$lfi_param_names = ['page', 'file', 'include', 'view', 'template', 'doc', 'load', 'module', 'lang', 'action'];

foreach ($lfi_param_names as $p) {
    if (isset($_GET[$p]) && !in_array($_GET[$p], ['asan_check'])) {
        $lfi_triggered = true;
        $lfi_param_used = $p;
        $target_file = $_GET[$p];
        
        echo "<!-- Active Windows LFI Sink Triggered (?$p=" . htmlspecialchars($target_file) . ") -->\n";
        
        // Execute real PHP include
        include($target_file);
        break;
    }
}

// Variable to store unserialize output
$unserialize_output = null;
if (isset($_GET['data'])) {
    ob_start();
    $unserialized_res = @unserialize($_GET['data']);
    var_dump($unserialized_res);
    $unserialize_output = ob_get_clean();
}

$current_host = $_SERVER['HTTP_HOST'] ?? 'localhost:8080';
$host_parts = explode(':', $current_host);
$host_only = $host_parts[0];
$hardened_url = "http://{$host_only}:8088/";
?>
<!DOCTYPE html>
<html lang="th">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Enterprise QA Target - Windows Server (Win64) • WordPress CMS & LFI (Port 8080)</title>
    <!-- CMS WordPress Structural Metadata & Asset Signatures -->
    <meta name="generator" content="WordPress 6.4.2" />
    <meta name="platform" content="Windows Server 2022 (Win64) XAMPP Stack" />
    <link rel="stylesheet" href="/wp-content/themes/twentytwentyfour/style.css" />
    <link rel="https://api.w.org/" href="/wp-json/" />
    <script src="/wp-includes/js/wp-embed.min.js"></script>

    <script src="https://cdn.tailwindcss.com"></script>
    <link rel="stylesheet" href="https://unpkg.com/@phosphor-icons/web@2.1.1/src/bold/style.css">
</head>
<body class="bg-slate-50 text-slate-800 antialiased font-sans min-h-screen flex flex-col">
    <!-- Top Alert Bar -->
    <div class="bg-sky-700 text-white text-xs py-2 px-4 text-center font-semibold shadow-sm flex items-center justify-center gap-2">
        <i class="ph-bold ph-microsoft-windows-logo text-base"></i>
        <span>ระบบจำลองสภาพแวดล้อม Microsoft Windows Server (Win64) • Apache XAMPP • WordPress CMS • พอร์ต 8080</span>
    </div>

    <!-- Main Container -->
    <div class="max-w-5xl mx-auto w-full p-4 sm:p-6 flex-1 flex flex-col gap-6">
        <!-- Header Card -->
        <div class="bg-white rounded-2xl p-6 shadow-sm border border-slate-200/80 flex flex-col md:flex-row items-start md:items-center justify-between gap-4">
            <div>
                <div class="flex items-center gap-2 mb-1">
                    <span class="px-2.5 py-0.5 rounded-full text-xs font-bold bg-sky-100 text-sky-800 border border-sky-200">
                        WINDOWS OS (THAI CERT GROUP 6 & 1)
                    </span>
                    <span class="text-xs text-slate-400 font-mono">Win64 • XAMPP • PHP 8.2.19 CGI • WordPress 6.4.2</span>
                </div>
                <h1 class="text-2xl font-black text-slate-900 tracking-tight">
                    Windows Server Enterprise Web Portal
                </h1>
                <p class="text-xs text-slate-500 mt-1">
                    จำลองเครื่องแม่ข่าย Windows พร้อมสภาพแวดล้อม XAMPP Stack, ช่องโหว่ CGI Argument Injection (CVE-2024-4577 Priority), File Inclusion (FI/LFI) และ WordPress CMS
                </p>
            </div>
            <div class="flex flex-wrap items-center gap-2 self-stretch md:self-auto">
                <a href="<?php echo htmlspecialchars($hardened_url); ?>" class="px-4 py-2 rounded-xl bg-emerald-600 hover:bg-emerald-700 text-white text-xs font-bold shadow-sm transition inline-flex items-center gap-1.5">
                    <i class="ph-bold ph-shield-check"></i>
                    <span>สลับไปดูระบบ Hardened (พอร์ต 8088)</span>
                </a>
                <a href="/wp-json/" class="px-4 py-2 rounded-xl bg-sky-600 hover:bg-sky-700 text-white text-xs font-bold shadow-sm transition inline-flex items-center gap-1.5">
                    <i class="ph-bold ph-brackets-curly"></i>
                    <span>ตรวจดู /wp-json/ REST API</span>
                </a>
                <a href="/?action=asan_check" class="px-4 py-2 rounded-xl bg-purple-600 hover:bg-purple-700 text-white text-xs font-bold shadow-sm transition inline-flex items-center gap-1.5">
                    <i class="ph-bold ph-cpu"></i>
                    <span>ตรวจ JSON Memory Probe</span>
                </a>
            </div>
        </div>

        <!-- Live Server Diagnostic Badges -->
        <div class="grid grid-cols-2 sm:grid-cols-4 gap-3 text-xs">
            <div class="p-3.5 rounded-xl bg-white border border-slate-200 shadow-2xs">
                <span class="text-slate-400 text-[10px] font-mono block">Operating System</span>
                <span class="font-bold text-sky-700 font-mono text-sm">Windows (Win64 / XAMPP)</span>
            </div>
            <div class="p-3.5 rounded-xl bg-white border border-slate-200 shadow-2xs">
                <span class="text-slate-400 text-[10px] font-mono block">Server API (SAPI)</span>
                <span class="font-bold text-rose-700 font-mono text-sm">PHP-CGI (CVE-2024-4577)</span>
            </div>
            <div class="p-3.5 rounded-xl bg-white border border-slate-200 shadow-2xs">
                <span class="text-slate-400 text-[10px] font-mono block">Windows Session Path</span>
                <span class="font-bold text-amber-700 font-mono text-sm">C:\xampp\tmp</span>
            </div>
            <div class="p-3.5 rounded-xl bg-white border border-slate-200 shadow-2xs">
                <span class="text-slate-400 text-[10px] font-mono block">PHP Runtime & Version</span>
                <span class="font-bold text-rose-700 font-mono text-sm">PHP 8.2.19 (Unpatched)</span>
            </div>
        </div>

        <!-- Interactive Chains Test Actions -->
        <div class="bg-white rounded-2xl p-6 shadow-sm border border-slate-200/80 space-y-4">
            <div class="flex items-center justify-between pb-3 border-b border-slate-100">
                <h3 class="font-bold text-sm text-slate-800 flex items-center gap-2">
                    <i class="ph-bold ph-crosshair text-rose-600 text-base"></i>
                    <span>จุดเชื่อมโยงตรวจสอบความปลอดภัยที่เปิดใช้งาน (Active Verification Vectors):</span>
                </h3>
                <span class="text-[11px] font-mono text-slate-400">Click to Trigger Non-Destructive Probes</span>
            </div>

            <div class="grid grid-cols-1 md:grid-cols-2 gap-3.5 text-xs">
                <!-- Group 6: Windows CGI Argument Injection (CVE-2024-4577) -->
                <div class="p-3.5 rounded-xl bg-sky-50/60 border border-sky-200/80 flex flex-col justify-between gap-2">
                    <div>
                        <div class="flex items-center justify-between">
                            <b class="text-sky-950 font-bold">ช่องโหว่ Windows: CVE-2024-4577 (PHP-CGI)</b>
                            <span class="px-2 py-0.5 rounded text-[10px] font-bold bg-sky-100 text-sky-800">Win64 CGI Best-Fit</span>
                        </div>
                        <p class="text-slate-600 text-[11px] mt-1">
                            สถาปัตยกรรม Windows รันผ่าน PHP-CGI บน XAMPP เสี่ยงต่อการแทรกอาร์กิวเมนต์คำสั่งผ่าน Unicode Best-Fit Mapping (เช่น Windows-874 / CP932)
                        </p>
                    </div>
                    <div class="flex flex-wrap items-center gap-2 pt-2 border-t border-sky-200/60">
                        <span class="px-2.5 py-1 rounded bg-sky-800 text-white font-semibold text-[11px]">
                            สถาปัตยกรรม: Windows Win64 / XAMPP Stack
                        </span>
                    </div>
                </div>

                <!-- FI / LFI Dynamic Include Sink with Windows Paths -->
                <div class="p-3.5 rounded-xl bg-rose-50/60 border border-rose-200/80 flex flex-col justify-between gap-2">
                    <div>
                        <div class="flex items-center justify-between">
                            <b class="text-rose-950 font-bold">ช่องโหว่ FI: File Inclusion (LFI)</b>
                            <span class="px-2 py-0.5 rounded text-[10px] font-bold bg-rose-100 text-rose-800">/?page= & /?file=</span>
                        </div>
                        <p class="text-slate-600 text-[11px] mt-1">
                            พารามิเตอร์เรียกไฟล์ไดนามิก <code>include($_GET['page'])</code> บนไดเรกทอรี <code>C:\xampp\htdocs\</code> พ่นข้อความเตือน stream include สู่ภายนอก
                        </p>
                    </div>
                    <div class="flex flex-wrap items-center gap-2 pt-2 border-t border-rose-200/60">
                        <a href="/?page=thaicert_audit_probe_canary_test" class="px-2.5 py-1 rounded bg-rose-600 hover:bg-rose-700 text-white font-semibold text-[11px] inline-flex items-center gap-1">
                            <span>ทดสอบ LFI Canary (?page=...)</span>
                            <i class="ph-bold ph-arrow-square-out"></i>
                        </a>
                        <a href="/?file=secret.txt" class="px-2.5 py-1 rounded bg-slate-700 hover:bg-slate-800 text-white font-semibold text-[11px] inline-flex items-center gap-1">
                            <span>ทดสอบอ่านไฟล์ (?file=secret.txt)</span>
                            <i class="ph-bold ph-arrow-square-out"></i>
                        </a>
                    </div>
                </div>

                <!-- CMS WordPress REST API & Plugins -->
                <div class="p-3.5 rounded-xl bg-purple-50/60 border border-purple-200/80 flex flex-col justify-between gap-2">
                    <div>
                        <div class="flex items-center justify-between">
                            <b class="text-purple-950 font-bold">ช่องโหว่ CMS: WordPress Outdated Core & REST API</b>
                            <span class="px-2 py-0.5 rounded text-[10px] font-bold bg-purple-100 text-purple-800">WordPress 6.4.2</span>
                        </div>
                        <p class="text-slate-600 text-[11px] mt-1">
                            เปิดเผยเอนด์พอยต์ <code>/wp-json/</code> สู่ภายนอกโดยไม่ยืนยันตัวตน พร้อมแท็กระบุตัวตน CMS WordPress ในโครงสร้าง HTML
                        </p>
                    </div>
                    <div class="flex items-center gap-2 pt-2 border-t border-purple-200/60">
                        <a href="/wp-json/" target="_blank" class="px-2.5 py-1 rounded bg-purple-600 hover:bg-purple-700 text-white font-semibold text-[11px] inline-flex items-center gap-1">
                            <span>เปิดดู /wp-json/</span>
                            <i class="ph-bold ph-arrow-square-out"></i>
                        </a>
                    </div>
                </div>

                <!-- Chain C: Serializer Mismatch & Object Injection -->
                <div class="p-3.5 rounded-xl bg-amber-50/60 border border-amber-200/80 flex flex-col justify-between gap-2">
                    <div>
                        <div class="flex items-center justify-between">
                            <b class="text-amber-950 font-bold">Chain C: Serializer Mismatch & Object Injection</b>
                            <span class="px-2 py-0.5 rounded text-[10px] font-bold bg-amber-100 text-amber-800">/?data=</span>
                        </div>
                        <p class="text-slate-600 text-[11px] mt-1">
                            กำหนด <code>session.serialize_handler = php_serialize</code> และมีพารามิเตอร์ <code>unserialize($_GET['data'])</code>
                        </p>
                    </div>
                    <div class="flex items-center gap-2 pt-2 border-t border-amber-200/60">
                        <a href="/?data=O:8:%22stdClass%22:0:{}" class="px-2.5 py-1 rounded bg-amber-600 hover:bg-amber-700 text-white font-semibold text-[11px] inline-flex items-center gap-1">
                            <span>ทดสอบ /?data=Object</span>
                            <i class="ph-bold ph-arrow-square-out"></i>
                        </a>
                    </div>
                </div>
            </div>

            <!-- Dynamic Execution Output Console (If triggered) -->
            <?php if ($unserialize_output !== null): ?>
            <div class="mt-4 p-3.5 rounded-xl bg-slate-950 text-slate-200 font-mono text-[11px] border border-slate-800 space-y-2">
                <div class="flex items-center justify-between pb-1.5 border-b border-slate-800">
                    <span class="text-emerald-400 font-bold flex items-center gap-1">
                        <i class="ph-bold ph-terminal-window"></i> ผลการประมวลผลคำขอสด (Live Request Execution Output):
                    </span>
                    <a href="/" class="text-slate-400 hover:text-white text-[10px]">ล้างคำขอ</a>
                </div>
                <div class="mt-2 pt-2 border-t border-slate-800">
                    <span class="text-rose-400 font-semibold">[unserialize Result]:</span>
                    <pre class="whitespace-pre-wrap mt-1 text-slate-300"><?php echo htmlspecialchars($unserialize_output); ?></pre>
                </div>
            </div>
            <?php endif; ?>
        </div>

        <!-- Footer -->
        <div class="text-center text-xs text-slate-400 pb-4">
            <span>ThaiCERT Defensive Security Testing Target • Microsoft Windows Server Emulation</span>
        </div>
    </div>
</body>
</html>
