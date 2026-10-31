<?php
/**
 * LAB TARGET #6 - กลุ่มที่ 6: Windows ที่มี PHP ติดตั้งอยู่ (IIS / XAMPP / WampServer / Laragon)
 * Simulated product: "HR Portal" on Windows Server 2019 + IIS 10 + PHP 7.4.33 (C:\xampp\htdocs\portal)
 * Weaknesses (ทั้งคู่เป็นของจริงบนสแตกนี้):
 *   1) handler mapping ผิด: *.jpg ถูก map เข้า PHP FastCGI  -> ไฟล์ shell.php.jpg รันโค้ดได้
 *   2) ชื่อไฟล์แบบ Windows: pageinfo.php::$DATA / จุดต่อท้าย ถูก normalize แล้วเก็บเป็น .php
 *   3) หน้า systeminfo ส่งค่าจากผู้ใช้เข้า cmd.exe ตรง ๆ
 * LISTEN: 8086
 */
require __DIR__ . '/../../common/lab.php';

header('X-Powered-By: PHP/7.4.33');
header('Server: Microsoft-IIS/10.0');
header('X-AspNet-Version: 4.0.30319');
ini_set('display_errors', '1');
error_reporting(E_ALL);

const APP_NAME = 'HR Portal';
const WINROOT  = 'C:\\xampp\\htdocs\\portal';
$PORT = 8086;
$uploads = __DIR__ . '/uploads';
@mkdir($uploads, 0777, true);

$path = parse_url($_SERVER['REQUEST_URI'] ?? '/', PHP_URL_PATH) ?: '/';
$path = rawurldecode($path);

if ($path === '/health') {
    lab_health([
        'system' => 'windows-iis',
        'group'  => 6,
        'group_name' => 'Windows ที่มี PHP ติดตั้งอยู่ (IIS/XAMPP)',
        'port'   => $PORT,
        'product'=> APP_NAME . ' on IIS 10 / PHP 7.4.33',
        'php'    => '7.4.33',
        'vuln'   => 'handler-mapping-double-extension / windows-filename-normalization / cmd-injection',
    ]);
}

/* ---------------- uploads: emulate the IIS + NTFS behaviour ---------
 * - handler mapping: *.php และ *.jpg ถูกส่งเข้า php-cgi
 * - ชื่อไฟล์ที่มี ::$DATA, ';' หรือจุดต่อท้าย ถูกตัดทิ้งตอนเขียนลง NTFS
 * ------------------------------------------------------------------ */
if (preg_match('#^/uploads/(.+)$#', $path, $m)) {
    $requested = $m[1];
    // NTFS/IIS normalization ของชื่อที่ร้องขอ
    $candidates = [$requested];
    $candidates[] = preg_replace('/::\$DATA$/i', '', $requested);
    $candidates[] = preg_replace('/;.*$/', '', $requested);
    $candidates[] = rtrim($requested, '. ');

    foreach (array_unique($candidates) as $cand) {
        $file = $uploads . '/' . basename($cand);
        if (!is_file($file)) continue;
        // handler mapping ครอบทั้ง .php และ .jpg/.php.jpg
        if (preg_match('/\.php(\.[a-z0-9]+)?$/i', $file) || preg_match('/\.(jpg|jpeg|png)$/i', $file) && strpos(basename($file), '.php') !== false) {
            header('Content-Type: text/html; charset=utf-8');
            include $file;                    // executed by the PHP handler
            exit;
        }
        header('Content-Type: application/octet-stream');
        readfile($file);
        exit;
    }
    http_response_code(404);
    lab_page('404 - File Not Found', 'IIS could not resolve the requested path', 'TARGET #6 · WINDOWS · PORT 8086', 'slate',
        '<div class="card"><p>Requested: <code>' . h($requested) . '</code></p>'
        . '<p class="sub">tried: ' . h(implode(' | ', array_unique($candidates))) . '</p></div>');
}

/* --------------------- upload endpoint (VULN) ----------------------
 * ตรวจ "ทุกส่วน" ของชื่อไฟล์ว่ามีส่วนใดเป็นรูปภาพหรือไม่ (bug ที่พบบ่อย)
 * แล้วเก็บด้วยชื่อเดิมหลัง normalize แบบ Windows
 * ------------------------------------------------------------------ */
if ($path === '/portal/upload.aspx' || $path === '/portal/upload.php') {
    if ($_SERVER['REQUEST_METHOD'] !== 'POST') lab_json(['error' => 'method not allowed'], 405);
    if (empty($_FILES['file']['name'])) lab_json(['error' => 'missing file field "file"'], 400);

    $original = basename($_FILES['file']['name']);

    // BUG: สแกนทุก dot-segment เจอรูปภาพที่ไหนก็ผ่าน
    $ok = false;
    foreach (explode('.', $original) as $seg) {
        if (in_array(strtolower(trim($seg)), ['jpg', 'jpeg', 'png', 'gif'], true)) { $ok = true; break; }
    }
    if (!$ok) lab_json(['error' => 'only image files are allowed'], 415);

    // Windows/NTFS normalization ก่อนเขียนไฟล์
    $stored = preg_replace('/::\$DATA$/i', '', $original);
    $stored = preg_replace('/;.*$/', '', $stored);
    $stored = rtrim($stored, ". ");
    if ($stored === '') $stored = 'upload.bin';

    move_uploaded_file($_FILES['file']['tmp_name'], $uploads . '/' . $stored);
    @chmod($uploads . '/' . $stored, 0666);
    lab_json([
        'received_name' => $original,
        'stored_as'     => $stored,
        'docroot'       => WINROOT . '\\uploads\\',
        'url'           => 'http://' . ($_SERVER['HTTP_HOST'] ?? 'localhost:' . $PORT) . '/uploads/' . rawurlencode($stored),
        'note'          => 'image extension found anywhere in the name; IIS maps .jpg to php-cgi',
    ]);
}

/* ------------------- system info: cmd.exe injection ---------------- */
if ($path === '/portal/systeminfo.aspx' || $path === '/portal/systeminfo.php') {
    $cmd = $_GET['cmd'] ?? 'ver';
    $out = shell_exec('cmd /c ' . $cmd . ' 2>&1');
    if (isset($_GET['format'])) lab_json(['shell' => 'cmd.exe', 'command' => $cmd, 'output' => $out ?: '(no output)']);
    lab_page('System Information', 'หน้าเว็บตรวจสอบระบบของเครื่อง Windows Server', 'TARGET #6 · WINDOWS · PORT 8086', 'slate',
        '<div class="card"><h2>Run command</h2>
          <form method="get" action="/portal/systeminfo.aspx">
            <p><input type="text" name="cmd" value="' . h($_GET['cmd'] ?? 'ver') . '"></p><button>Run</button>
          </form>
          <pre>cmd.exe /c ' . h($cmd) . "\n\n" . h($out ?: '(no output)') . '</pre>
          <p style="margin-top:8px"><a href="/portal/systeminfo.aspx?cmd=dir%3Bwhoami&format=json"><span class="mono">?cmd=dir;whoami&amp;format=json</span></a></p>
        </div>');
}

/* --------------------------- config disclosure --------------------- */
if ($path === '/web.config' || $path === '/portal/web.config') {
    header('Content-Type: text/plain; charset=utf-8');
    echo "<?xml version=\"1.0\"?>\n<configuration><system.webServer><handlers>\n";
    echo "  <add name=\"PHP_via_FastCGI\" path=\"*.php\" verb=\"*\" modules=\"FastCgiModule\" scriptProcessor=\"C:\\php\\php-cgi.exe\" />\n";
    echo "  <add name=\"PHP_images\" path=\"*.jpg\" verb=\"*\" modules=\"FastCgiModule\" scriptProcessor=\"C:\\php\\php-cgi.exe\" />\n";
    echo "</handlers><security><requestFiltering allowDoubleEscaping=\"true\" /></security></system.webServer>\n";
    echo "<appSettings><add key=\"sqlConn\" value=\"Server=.\\SQLEXPRESS;Database=hr;User Id=sa;Password=Hr_Lab_P@ss;\" /></appSettings>\n</configuration>";
    exit;
}

/* ------------------------------- homepage --------------------------- */
$files = lab_list_recent($uploads);
$rows = '';
foreach ($files as $f) {
    $rows .= '<tr><td class="mono">' . h($f['name']) . '</td><td>' . number_format($f['size']) . ' B</td><td>' . h($f['modified'])
           . '</td><td><a href="/uploads/' . h(rawurlencode($f['name'])) . '">open</a></td></tr>';
}
if ($rows === '') $rows = '<tr><td colspan="4" style="color:#94a3b8">ยังไม่มีไฟล์อัปโหลด</td></tr>';

lab_page(
    'HR Portal &mdash; Windows / IIS',
    'ระบบบริหารงานบุคคลบน Windows Server 2019 (IIS 10 + PHP 7.4.33) ติดตั้งใต้ C:\\xampp\\htdocs\\portal',
    'TARGET #6 · WINDOWS · PORT 8086 · IIS 10 / PHP 7.4.33',
    'slate',
    '<div class="card"><h2>Host</h2><div class="grid">
        <div class="tile"><b>OS</b>Windows Server 2019</div>
        <div class="tile"><b>Web</b>IIS 10.0 + FastCGI</div>
        <div class="tile"><b>Docroot</b>' . WINROOT . '</div>
        <div class="tile"><b>Handler</b>*.php และ *.jpg</div>
     </div></div>
     <div class="card"><h2>Profile picture upload</h2>
       <form action="/portal/upload.aspx" method="post" enctype="multipart/form-data">
         <p><input type="file" name="file"></p><button>Upload</button>
       </form>
       <pre>POST /portal/upload.aspx   file=@shell.php.jpg
GET  /uploads/shell.php.jpg?c=whoami

variants: shell.php::$DATA   shell.php.   shell.php;.jpg</pre>
       <p class="sub">ตัวตรวจหานามสกุลรูปภาพจากส่วนใดก็ได้ของชื่อไฟล์ แต่ IIS map <code>*.jpg</code> เข้า php-cgi ทำให้ไฟล์ double extension รันโค้ดได้</p>
     </div>
     <div class="card"><h2>Uploads</h2>
       <table><thead><tr><th>File</th><th>Size</th><th>Modified</th><th></th></tr></thead><tbody>' . $rows . '</tbody></table></div>
     <div class="card"><h2>Endpoints</h2><table><tbody>
       <tr><td class="mono">POST /portal/upload.aspx</td><td>อัปโหลดรูปโปรไฟล์ (ตรวจนามสกุลผิดวิธี)</td></tr>
       <tr><td class="mono">GET /portal/systeminfo.aspx?cmd=</td><td>รันคำสั่ง cmd.exe</td></tr>
       <tr><td class="mono">GET /web.config</td><td>เปิดเผย handler mapping และ connection string</td></tr>
     </tbody></table></div>'
);
