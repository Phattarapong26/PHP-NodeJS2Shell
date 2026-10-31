<?php
/**
 * LAB TARGET #8 - กลุ่มที่ 8: ระบบที่ผู้ให้บริการภายนอกดูแล (Shared / Managed Hosting)
 * Simulated product: "CloudShare Shared Hosting" - several tenants on one VM, one PHP pool
 * Weakness: tenants are not isolated (shared upload directory, no open_basedir, traversal in the
 *           download endpoint) so one compromised site can read/write another tenant's files.
 * LISTEN: 8088
 */
require __DIR__ . '/../../common/lab.php';

header('X-Powered-By: PHP/7.4.33');
header('Server: Apache/2.4.29 (Ubuntu)');
ini_set('display_errors', '1');
error_reporting(E_ALL);

const APP_NAME = 'CloudShare Hosting';
$PORT = 8088;
$root = __DIR__ . '/tenants';
$sharedUploads = __DIR__ . '/uploads';       // ทุก tenant ใช้โฟลเดอร์เดียวกัน
@mkdir($root . '/tenant_a', 0777, true);
@mkdir($root . '/tenant_b', 0777, true);
@mkdir($sharedUploads, 0777, true);

$path = parse_url($_SERVER['REQUEST_URI'] ?? '/', PHP_URL_PATH) ?: '/';
$path = rawurldecode($path);

if ($path === '/health') {
    lab_health([
        'system' => 'shared-hosting',
        'group'  => 8,
        'group_name' => 'ระบบที่ผู้ให้บริการภายนอกดูแล (Shared/Managed Hosting)',
        'port'   => $PORT,
        'product'=> APP_NAME . ' (shared pool, 2 tenants)',
        'php'    => '7.4.33',
        'vuln'   => 'cross-tenant-directory-traversal / shared-upload-dir',
    ]);
}

if (preg_match('#^/uploads/(.+)$#', $path, $m)) {
    lab_serve_stored($sharedUploads, $m[1]);
}

/* ---------------- tenant site (served from its own docroot) --------- */
if (preg_match('#^/site/([a-z0-9_]+)/?$#i', $path, $m)) {
    $tenant = strtolower($m[1]);
    $file = $root . '/' . $tenant . '/index.php';
    if (!is_file($file)) { http_response_code(404); echo 'tenant not found'; exit; }
    include $file;
    exit;
}

/* ------------- download endpoint: CROSS-TENANT TRAVERSAL (VULN) -----
 * $file ถูกต่อกับ docroot ของ tenant โดยไม่ตัด ../ และไม่มี open_basedir
 * ------------------------------------------------------------------ */
if ($path === '/download.php') {
    $tenant = preg_replace('/[^a-z0-9_]/i', '', $_GET['tenant'] ?? 'tenant_a') ?: 'tenant_a';
    $file   = $_GET['file'] ?? 'index.php';
    $target = $root . '/' . $tenant . '/' . $file;
    if (!is_file($target)) {
        lab_page('Download failed', 'ไม่พบไฟล์ที่ร้องขอ', 'TARGET #8 · SHARED HOSTING · PORT 8088', 'teal',
            '<div class="card"><p class="mono">' . h($target) . '</p><p class="sub">include path resolved without sanitisation (open_basedir = none)</p></div>');
    }
    $content = file_get_contents($target);
    header('Content-Type: text/plain; charset=utf-8');
    header('Content-Disposition: attachment; filename="' . basename($file) . '"');
    echo "### resolved: " . $target . "\n### size: " . strlen($content) . "\n\n" . $content;
    exit;
}

/* --------------- shared upload: no validation, shared dir ----------
 * เขียนได้ทั้งในโฟลเดอร์ uploads กลาง และทะลุไป docroot ของ tenant อื่น
 * ------------------------------------------------------------------ */
if ($path === '/upload.php') {
    if ($_SERVER['REQUEST_METHOD'] !== 'POST') lab_json(['error' => 'method not allowed'], 405);
    $tenant = preg_replace('/[^a-z0-9_]/i', '', $_POST['tenant'] ?? 'tenant_a') ?: 'tenant_a';
    if (empty($_FILES['file']['name'])) lab_json(['error' => 'missing file field "file"'], 400);
    $name = basename($_FILES['file']['name']);

    // path ที่สอง (ไม่บังคับ) ยอมให้เขียนข้าม tenant ผ่าน ../../
    $into = $_POST['dir'] ?? '';
    $dir  = $into !== '' ? ($root . '/' . $tenant . '/' . $into) : $sharedUploads;
    @mkdir($dir, 0777, true);
    move_uploaded_file($_FILES['file']['tmp_name'], $dir . '/' . $name);
    @chmod($dir . '/' . $name, 0666);

    $rel = str_replace(__DIR__, '', realpath($dir . '/' . $name));
    lab_json([
        'tenant' => $tenant,
        'stored' => $name,
        'path'   => $rel,
        'urls' => [
            'shared' => 'http://' . ($_SERVER['HTTP_HOST'] ?? 'localhost:' . $PORT) . '/uploads/' . rawurlencode($name),
            'tenant' => 'http://' . ($_SERVER['HTTP_HOST'] ?? 'localhost:' . $PORT) . '/site/' . $tenant . '/',
        ],
        'note' => 'one upload directory for every tenant; no extension check; no open_basedir',
    ]);
}

/* ------------------------------- homepage --------------------------- */
$files = lab_list_recent($sharedUploads);
$rows = '';
foreach ($files as $f) {
    $rows .= '<tr><td class="mono">' . h($f['name']) . '</td><td>' . number_format($f['size']) . ' B</td><td>' . h($f['modified'])
           . '</td><td><a href="/uploads/' . h(rawurlencode($f['name'])) . '">open</a></td></tr>';
}
if ($rows === '') $rows = '<tr><td colspan="4" style="color:#94a3b8">ยังไม่มีไฟล์ใน shared uploads</td></tr>';

lab_page(
    'CloudShare Hosting &mdash; customer site',
    'เว็บไซต์ของลูกค้าบนโฮสติ้งแบบแชร์ (ผู้ให้บริการภายนอกดูแล) &mdash; หลาย tenant อยู่บนเครื่องเดียวกัน',
    'TARGET #8 · SHARED HOSTING · PORT 8088 · หลาย tenant / pool เดียว',
    'teal',
    '<div class="card"><h2>This VM</h2><div class="grid">
        <div class="tile"><b>Plan</b>Shared Starter</div>
        <div class="tile"><b>Tenants</b>tenant_a, tenant_b</div>
        <div class="tile"><b>Uploads</b>/uploads (shared)</div>
        <div class="tile"><b>open_basedir</b>(not set)</div>
     </div></div>
     <div class="card"><h2>File download</h2>
       <form method="get" action="/download.php">
         <p><input type="text" name="tenant" value="tenant_a"></p>
         <p><input type="text" name="file" value="config.php"></p>
         <button>Download</button>
       </form>
       <pre>GET /download.php?tenant=tenant_a&amp;file=../tenant_b/config.php
GET /download.php?tenant=tenant_a&amp;file=../../../../etc/passwd</pre>
     </div>
     <div class="card"><h2>Upload to shared space</h2>
       <form action="/upload.php" method="post" enctype="multipart/form-data">
         <p><input type="text" name="tenant" value="tenant_a"></p>
         <p><input type="file" name="file"></p><button>Upload</button>
       </form>
       <table style="margin-top:12px"><thead><tr><th>File</th><th>Size</th><th>Modified</th><th></th></tr></thead><tbody>' . $rows . '</tbody></table>
     </div>
     <div class="card"><h2>Endpoints</h2><table><tbody>
       <tr><td class="mono">GET /site/tenant_a</td><td>เว็บของ tenant A</td></tr>
       <tr><td class="mono">GET /site/tenant_b</td><td>เว็บของ tenant B</td></tr>
       <tr><td class="mono">GET /download.php?tenant=&amp;file=</td><td>ดาวน์โหลดไฟล์ (path traversal ข้าม tenant)</td></tr>
       <tr><td class="mono">POST /upload.php</td><td>อัปโหลดเข้าโฟลเดอร์กลางที่ทุก tenant ใช้ร่วมกัน</td></tr>
     </tbody></table></div>'
);
