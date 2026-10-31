<?php
/**
 * LAB TARGET #1 - กลุ่มที่ 1: เว็บไซต์และระบบภายในองค์กร (CMS / Web Application สำเร็จรูป)
 * Simulated product: "CorpPress CMS 5.8.2 (WordPress-compatible)" on PHP 7.4.33
 * Weakness: unrestricted file upload in a third-party plugin -> PHP2Shell (web shell in webroot)
 * LISTEN: 8081
 */
require __DIR__ . '/../../common/lab.php';

// --- fingerprint เหมือน CMS จริง ---
header('X-Powered-By: PHP/7.4.33');
header('Server: Apache/2.4.41 (Ubuntu)');
ini_set('display_errors', '1');
error_reporting(E_ALL);

const APP_NAME = 'CorpPress CMS';
const APP_VER  = '5.8.2';
$PORT = 8081;
$uploads = __DIR__ . '/wp-content/uploads';
@mkdir($uploads, 0777, true);

$path = parse_url($_SERVER['REQUEST_URI'] ?? '/', PHP_URL_PATH) ?: '/';
$path = rawurldecode($path);

/* ------------------------------ health ------------------------------ */
if ($path === '/health') {
    lab_health([
        'system' => 'cms-corp',
        'group'  => 1,
        'group_name' => 'เว็บไซต์และระบบภายในองค์กร (CMS)',
        'port'   => $PORT,
        'product'=> APP_NAME . ' ' . APP_VER,
        'php'    => '7.4.33',
        'vuln'   => 'unrestricted-file-upload-plugin',
    ]);
}

/* --------------------------- uploaded files -------------------------- */
if (preg_match('#^/wp-content/uploads/(.+)$#', $path, $m)) {
    lab_serve_stored($uploads, $m[1]);
}

/* ------------------------- plugin upload (VULN) -----------------------
 * JVuln: third-party plugin "simple-media-upload" never validates extension
 * or MIME type; it keeps the client-supplied filename inside the webroot.
 * -------------------------------------------------------------------- */
if ($path === '/wp-content/plugins/simple-media-upload/upload.php' && $_SERVER['REQUEST_METHOD'] === 'POST') {
    if (empty($_FILES['file']['name'])) {
        lab_json(['error' => 'missing file field "file"'], 400);
    }
    $name = basename($_FILES['file']['name']);            // attacker-controlled
    $dest = $uploads . '/' . $name;
    if (!move_uploaded_file($_FILES['file']['tmp_name'], $dest)) {
        lab_json(['error' => 'upload failed'], 500);
    }
    @chmod($dest, 0666);
    lab_json([
        'uploaded' => $name,
        'bytes'    => filesize($dest),
        'url'      => 'http://' . ($_SERVER['HTTP_HOST'] ?? 'localhost:' . $PORT) . '/wp-content/uploads/' . $name,
        'plugin'   => 'simple-media-upload 1.0.3',
        'note'     => 'no extension / MIME validation applied',
    ]);
}

/* --------------------------- readme disclosure ---------------------- */
if ($path === '/readme.html') {
    header('Content-Type: text/html; charset=utf-8');
    echo "<h1>" . APP_NAME . "</h1><p>Version " . APP_VER . "</p><p>PHP 7.4.33 &middot; Apache/2.4.41 (Ubuntu)</p>";
    echo "<p>Active plugins: simple-media-upload 1.0.3, seo-toolkit 2.1, contact-form-lite 4.0</p>";
    exit;
}

/* ----------------------------- login + xmlrpc ----------------------- */
if ($path === '/wp-login.php') {
    if ($_SERVER['REQUEST_METHOD'] === 'POST') {
        $u = $_POST['log'] ?? ''; $p = $_POST['pwd'] ?? '';
        if ($u === 'admin' && $p === 'admin') {
            lab_json(['logged_in' => true, 'user' => 'admin', 'role' => 'administrator']);
        }
        lab_json(['error' => 'invalid credentials'], 401);
    }
    if (!empty($_GET['author'])) {
        // user enumeration
        lab_json(['author' => $_GET['author'], 'display_name' => 'Site Administrator', 'id' => 1]);
    }
    lab_page('CorpPress CMS - เข้าสู่ระบบ', 'ระบบจัดการเว็บไซต์ภายในองค์กร (Corporate CMS)', 'TARGET #1 · CMS · PORT 8081 · PHP 7.4.33', 'indigo',
    '<div class="card"><h2>Log in</h2><form method="post" action="/wp-login.php">
      <p><input type="text" name="log" placeholder="username หรืออีเมล"></p>
      <p><input type="password" name="pwd" placeholder="รหัสผ่าน"></p>
      <button>Log In</button></form></div>');
}

if ($path === '/xmlrpc.php') {
    header('Content-Type: text/xml; charset=utf-8');
    echo '<?xml version="1.0"?><methodResponse><params><param><value><array><data>'
       . '<value><string>wp.getUsersBlogs</string></value><value><string>system.multicall</string></value>'
       . '</data></array></value></param></params></methodResponse>';
    exit;
}

/* ------------------------------- homepage --------------------------- */
$files = lab_list_recent($uploads);
$rows = '';
foreach ($files as $f) {
    $rows .= '<tr><td class="mono">' . h($f['name']) . '</td><td>' . number_format($f['size']) . ' B</td><td>' . h($f['modified'])
           . '</td><td><a href="/wp-content/uploads/' . h(rawurlencode($f['name'])) . '">open</a></td></tr>';
}
if ($rows === '') $rows = '<tr><td colspan="4" style="color:#94a3b8">ยังไม่มีไฟล์ที่อัปโหลด</td></tr>';

lab_page(
    'CorpPress CMS 5.8.2 - Corporate Intranet',
    'เว็บไซต์และระบบภายในองค์กร: หน้าเว็บหลัก + ระบบจัดการเนื้อหา + ปลั๊กอัปโหลดมีเดียของ third-party',
    'TARGET #1 · กลุ่มเว็บไซต์/CMS · PORT 8081 · PHP 7.4.33',
    'indigo',
    '<div class="card"><h2>System profile</h2><div class="grid">
        <div class="tile"><b>Product</b>CorpPress CMS 5.8.2</div>
        <div class="tile"><b>Runtime</b>PHP 7.4.33 / Apache 2.4.41</div>
        <div class="tile"><b>Plugins</b>simple-media-upload 1.0.3</div>
        <div class="tile"><b>Webroot</b>/var/www/html</div>
     </div></div>
     <div class="card"><h2>Media upload (plugin)</h2>
       <p class="sub">อัปโหลดไฟล์มีเดียเข้าสู่ <code>/wp-content/uploads/</code> (endpoint สาธารณะของปลั๊กอิน)</p>
       <form action="/wp-content/plugins/simple-media-upload/upload.php" method="post" enctype="multipart/form-data" style="margin-top:10px">
         <p><input type="file" name="file"></p><button>Upload media</button>
       </form>
       <pre>POST /wp-content/plugins/simple-media-upload/upload.php
Content-Type: multipart/form-data; file=@shell.php</pre>
     </div>
     <div class="card"><h2>Uploaded files</h2>
       <table><thead><tr><th>File</th><th>Size</th><th>Modified</th><th></th></tr></thead><tbody>' . $rows . '</tbody></table>
     </div>
     <div class="card"><h2>Endpoints</h2><table><tbody>
       <tr><td class="mono">/wp-login.php</td><td>เข้าสู่ระบบผู้ดูแล</td></tr>
       <tr><td class="mono">/readme.html</td><td>เปิดเผยเวอร์ชันและปลั๊กอินที่ใช้งาน</td></tr>
       <tr><td class="mono">/xmlrpc.php</td><td>XML-RPC interface</td></tr>
       <tr><td class="mono">/wp-content/uploads/&lt;file&gt;</td><td>ไดเรกทอรีสาธารณะที่รัน PHP ได้</td></tr>
     </tbody></table></div>'
);
