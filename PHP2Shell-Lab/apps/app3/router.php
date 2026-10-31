<?php
/**
 * LAB TARGET #3 - กลุ่มที่ 3: Hosting Control Panel
 * Simulated product: "cPanel/WHM-style panel (HostAdmin 110.0)" running as root
 * Weakness: file-manager upload validates only the client-supplied MIME type, and the
 *           panel API trusts a client-controlled role header -> privilege escalation
 *           from a low-privileged tenant to server-wide control.
 * LISTEN: 8083
 */
require __DIR__ . '/../../common/lab.php';

header('X-Powered-By: PHP/7.4.33');
header('Server: Apache/2.4.52 (Unix) OpenSSL/1.1.1');
ini_set('display_errors', '1');
error_reporting(E_ALL);

const APP_NAME = 'HostAdmin';
const APP_VER  = '110.0.24';
$PORT = 8083;
$homes = __DIR__ . '/home';
@mkdir($homes . '/demo/public_html', 0777, true);
@mkdir($homes . '/reseller/public_html', 0777, true);
@file_put_contents($homes . '/demo/public_html/index.html', "<h1>demo site</h1>\n");
@file_put_contents($homes . '/reseller/public_html/index.html', "<h1>reseller site</h1>\n");

$path = parse_url($_SERVER['REQUEST_URI'] ?? '/', PHP_URL_PATH) ?: '/';
$path = rawurldecode($path);

if ($path === '/health') {
    lab_health([
        'system' => 'hosting-panel',
        'group'  => 3,
        'group_name' => 'Hosting Control Panel',
        'port'   => $PORT,
        'product'=> APP_NAME . ' ' . APP_VER,
        'php'    => '7.4.33',
        'vuln'   => 'mime-only-upload-validation / role-header-trust',
    ]);
}

/* ------------------------- served tenant files ---------------------- */
if (preg_match('#^/home/([a-z0-9_]+)/public_html/(.+)$#i', $path, $m)) {
    lab_serve_stored($homes . '/' . $m[1] . '/public_html', $m[2]);
}

/* --------------- panel API: trust client role header (VULN) --------- */
if ($path === '/panel/api/accounts') {
    $role = $_SERVER['HTTP_X_ROLE'] ?? ($_SESSION['role'] ?? 'none');
    if (!in_array($role, ['reseller', 'root', 'admin'], true)) {
        lab_json(['error' => 'insufficient privileges', 'hint' => 'role is taken from X-Role header'], 403);
    }
    lab_json([
        'authenticated_as' => $role,
        'server' => 'srv-shared-01.example.internal',
        'accounts' => [
            ['user' => 'demo',    'plan' => 'starter', 'docroot' => '/home/demo/public_html',    'quota_mb' => 1024],
            ['user' => 'reseller','plan' => 'reseller','docroot' => '/home/reseller/public_html','quota_mb' => 20480],
            ['user' => 'billing', 'plan' => 'business','docroot' => '/home/billing/public_html', 'quota_mb' => 51200],
        ],
        'root_api_token' => 'WHM-LAB-9f2c41d7e0b8a63c',
        'note' => 'privilege decided by a client-supplied header (no server-side session check)',
    ]);
}

/* --------------------- file manager upload (VULN) --------------------
 * ตรวจแค่ $_FILES['file']['type'] ที่ client ส่งมา (ปลอมได้)
 * ไฟล์ถูกเก็บด้วยชื่อเดิมใน public_html ของ tenant -> .php รันได้
 * ------------------------------------------------------------------ */
if ($path === '/panel/filemanager/upload') {
    if ($_SERVER['REQUEST_METHOD'] !== 'POST') lab_json(['error' => 'method not allowed'], 405);
    $role = $_SERVER['HTTP_X_ROLE'] ?? ($_SESSION['role'] ?? 'demo');
    $tenant = preg_replace('/[^a-z0-9_]/i', '', $_POST['tenant'] ?? 'demo') ?: 'demo';
    if (empty($_FILES['file']['name'])) lab_json(['error' => 'missing file field "file"'], 400);

    $allowedMime = ['image/jpeg', 'image/png', 'image/gif'];
    $mime = $_FILES['file']['type'] ?? '';
    if (!in_array($mime, $allowedMime, true)) {
        lab_json(['error' => 'only images are allowed', 'received_type' => $mime], 415);
    }
    $dest = $homes . '/' . $tenant . '/public_html/' . basename($_FILES['file']['name']);
    move_uploaded_file($_FILES['file']['tmp_name'], $dest);
    @chmod($dest, 0666);
    lab_json([
        'tenant' => $tenant,
        'uploaded' => basename($dest),
        'detected_type' => $mime,
        'url' => 'http://' . ($_SERVER['HTTP_HOST'] ?? 'localhost:' . $PORT) . '/home/' . $tenant . '/public_html/' . rawurlencode(basename($dest)),
        'note' => 'validation used the spoofable client Content-Type only',
    ]);
}

/* ------------------------------- login ------------------------------ */
if ($path === '/login' && $_SERVER['REQUEST_METHOD'] === 'POST') {
    $u = $_POST['user'] ?? ''; $p = $_POST['pass'] ?? '';
    $known = ['demo' => 'demo', 'reseller' => 'reseller'];
    if (isset($known[$u]) && $known[$u] === $p) {
        $_SESSION['user'] = $u;
        $_SESSION['role'] = $u === 'reseller' ? 'reseller' : 'user';
        lab_json(['logged_in' => true, 'user' => $u, 'role' => $_SESSION['role']]);
    }
    lab_json(['error' => 'invalid login'], 401);
}

/* ------------------------------- homepage --------------------------- */
$demoFiles = lab_list_recent($homes . '/demo/public_html');
$rows = '';
foreach ($demoFiles as $f) {
    $rows .= '<tr><td class="mono">' . h($f['name']) . '</td><td>' . number_format($f['size']) . ' B</td><td>' . h($f['modified'])
           . '</td><td><a href="/home/demo/public_html/' . h(rawurlencode($f['name'])) . '">open</a></td></tr>';
}
if ($rows === '') $rows = '<tr><td colspan="4" style="color:#94a3b8">ว่าง</td></tr>';

lab_page(
    'HostAdmin ' . APP_VER . ' - Tenant Panel',
    'แผงควบคุมโฮสติ้งที่ทำงานด้วยสิทธิ์ระดับสูง: จัดการไฟล์ เว็บไซต์ และบัญชีผู้เช่า บนเซิร์ฟเวอร์แชร์',
    'TARGET #3 · กลุ่ม Hosting Control Panel · PORT 8083 · รันด้วยสิทธิ์ root',
    'amber',
    '<div class="card"><h2>Server</h2><div class="grid">
        <div class="tile"><b>Host</b>srv-shared-01</div>
        <div class="tile"><b>Panel</b>HostAdmin 110.0.24</div>
        <div class="tile"><b>Run as</b>root (www-data wrapper)</div>
        <div class="tile"><b>Tenants</b>demo, reseller, billing</div>
     </div></div>
     <div class="card"><h2>File manager &mdash; upload to /home/demo/public_html</h2>
       <form action="/panel/filemanager/upload" method="post" enctype="multipart/form-data">
         <p><input type="text" name="tenant" value="demo"></p>
         <p><input type="file" name="file"></p>
         <button>Upload</button>
       </form>
       <pre>POST /panel/filemanager/upload      (multipart: tenant=demo, file=@shell.php;type=image/png)
GET  /panel/api/accounts            X-Role: reseller</pre>
     </div>
     <div class="card"><h2>demo/public_html</h2>
       <table><thead><tr><th>File</th><th>Size</th><th>Modified</th><th></th></tr></thead><tbody>' . $rows . '</tbody></table></div>
     <div class="card"><h2>Endpoints</h2><table><tbody>
       <tr><td class="mono">POST /login</td><td>demo/demo, reseller/reseller</td></tr>
       <tr><td class="mono">POST /panel/filemanager/upload</td><td>อัปโหลดไฟล์ของผู้เช่า (ตรวจ MIME จาก client)</td></tr>
       <tr><td class="mono">GET /panel/api/accounts</td><td>รายชื่อบัญชี + root API token</td></tr>
       <tr><td class="mono">GET /home/&lt;tenant&gt;/public_html/&lt;file&gt;</td><td>เว็บของผู้เช่าแต่ละราย</td></tr>
     </tbody></table></div>'
);
