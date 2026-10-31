<?php
/**
 * LAB TARGET #4 - กลุ่มที่ 4: ซอฟต์แวร์และอุปกรณ์สำเร็จรูป (Vendor Portal / Network Appliance / IoT)
 * Simulated product: "NetGuard Pro 3000" UTM appliance, firmware 2.4.1 (EOL, PHP 5.6-style code)
 * Weakness: web admin calls system commands with unescaped user input (command injection)
 *           and accepts firmware/package uploads into a runnable path.
 * LISTEN: 8084
 */
require __DIR__ . '/../../common/lab.php';

header('X-Powered-By: PHP/5.6.40');
header('Server: lighttpd/1.4.45');
ini_set('display_errors', '1');
error_reporting(E_ALL);

const APP_NAME = 'NetGuard Pro 3000';
const APP_VER  = '2.4.1 (EOL 2019)';
$PORT = 8084;
$fw = __DIR__ . '/firmware';
@mkdir($fw, 0777, true);

$path = parse_url($_SERVER['REQUEST_URI'] ?? '/', PHP_URL_PATH) ?: '/';
$path = rawurldecode($path);

if ($path === '/health') {
    lab_health([
        'system' => 'appliance',
        'group'  => 4,
        'group_name' => 'ซอฟต์แวร์และอุปกรณ์สำเร็จรูป (Appliance/IoT)',
        'port'   => $PORT,
        'product'=> APP_NAME . ' ' . APP_VER,
        'php'    => '5.6.40',
        'vuln'   => 'os-command-injection / unvalidated-firmware-upload',
    ]);
}

/* -------------------- served firmware / uploaded pkg ---------------- */
if (preg_match('#^/firmware/(.+)$#', $path, $m)) {
    lab_serve_stored($fw, $m[1]);
}

/* ------------------ diagnostics: ping (COMMAND INJECTION) -----------
 * $target ต่อเข้าไปในคำสั่ง shell โดยตรง ไม่ผ่าน escapeshellarg()
 * ------------------------------------------------------------------ */
if ($path === '/diag.php') {
    $target = $_GET['target'] ?? '127.0.0.1';
    $cmd = 'ping -c 1 -W 1 ' . $target . ' 2>&1';
    $out = shell_exec($cmd);
    if ($_SERVER['REQUEST_METHOD'] === 'POST' || isset($_GET['format'])) {
        lab_json(['command' => $cmd, 'output' => $out ?: '(no output)']);
    }
    lab_page('Network Diagnostics', 'เครื่องมือทดสอบการเชื่อมต่อจากหน้าเว็บผู้ดูแลอุปกรณ์', 'TARGET #4 · APPLIANCE · PORT 8084', 'amber',
        '<div class="card"><h2>Ping</h2>
          <form method="get" action="/diag.php">
            <p><input type="text" name="target" value="' . h($target) . '"></p>
            <button>Run ping</button>
          </form>
          <p class="sub" style="margin-top:10px">Command executed on device:</p>
          <pre>' . h($cmd) . "\n\n" . h($out ?: '(no output)') . '</pre>
          <p style="margin-top:8px"><a href="/diag.php?target=127.0.0.1%3Bid&format=json">view as JSON</a></p>
        </div>');
}

/* ------------------ CGi status endpoint (2nd injection) ------------ */
if ($path === '/cgi-bin/status.cgi') {
    $iface = $_GET['iface'] ?? 'eth0';
    $out = shell_exec('ifconfig ' . $iface . ' 2>&1');
    header('Content-Type: text/plain; charset=utf-8');
    echo "# ifconfig " . $iface . "\n" . ($out ?: '(no output)');
    exit;
}

/* ------------------ firmware upgrade (upload -> runnable) ----------
 * อัปโหลดแพ็กเกจโดยไม่ตรวจลายเซ็น/นามสกุล แล้วเก็บในไดเรกทอรีที่เว็บรันได้
 * ------------------------------------------------------------------ */
if ($path === '/firmware_upgrade' && $_SERVER['REQUEST_METHOD'] === 'POST') {
    if (empty($_FILES['pkg']['name'])) lab_json(['error' => 'missing file field "pkg"'], 400);
    $name = basename($_FILES['pkg']['name']);
    move_uploaded_file($_FILES['pkg']['tmp_name'], $fw . '/' . $name);
    @chmod($fw . '/' . $name, 0666);
    lab_json([
        'installed' => $name,
        'signature_verified' => false,
        'url' => 'http://' . ($_SERVER['HTTP_HOST'] ?? 'localhost:' . $PORT) . '/firmware/' . rawurlencode($name),
        'note' => 'no signature / extension check before storing in web-reachable path',
    ]);
}

/* --------------------------- config disclosure --------------------- */
if ($path === '/config_dump.php' || $path === '/backup/cfg.bin') {
    header('Content-Type: text/plain; charset=utf-8');
    echo "hostname=netguard-utm-01\nadmin_user=admin\nadmin_pass=Adm1n_N3tguard\n";
    echo "wan_ip=203.0.113.24\nvpn_psk=N3tguard-LAB-PSK-2024\nsnmp_community=public\n";
    exit;
}

if ($path === '/login' || $path === '/index.php') {
    if ($_SERVER['REQUEST_METHOD'] === 'POST') {
        $u = $_POST['user'] ?? ''; $p = $_POST['pass'] ?? '';
        if ($u === 'admin' && $p === 'admin') lab_json(['logged_in' => true, 'user' => 'admin', 'note' => 'default credentials']);
        lab_json(['error' => 'invalid login'], 401);
    }
}

/* ------------------------------- homepage --------------------------- */
$files = lab_list_recent($fw);
$rows = '';
foreach ($files as $f) {
    $rows .= '<tr><td class="mono">' . h($f['name']) . '</td><td>' . number_format($f['size']) . ' B</td><td>' . h($f['modified'])
           . '</td><td><a href="/firmware/' . h(rawurlencode($f['name'])) . '">open</a></td></tr>';
}
if ($rows === '') $rows = '<tr><td colspan="4" style="color:#94a3b8">ยังไม่มีแพ็กเกจ</td></tr>';

lab_page(
    APP_NAME . ' &mdash; Web Admin',
    'อุปกรณ์ความปลอดภัยเครือข่าย (UTM) ที่มีหน้าเว็บผู้ดูแลสำหรับตั้งค่าและวินิจฉัยระบบ เฟิร์มแวร์ค้างการอัปเดตตั้งแต่ปี 2019',
    'TARGET #4 · APPLIANCE / IoT · PORT 8084 · PHP 5.6.40 (EOL)',
    'amber',
    '<div class="card"><h2>Device</h2><div class="grid">
        <div class="tile"><b>Model</b>NetGuard Pro 3000</div>
        <div class="tile"><b>Firmware</b>2.4.1 (EOL)</div>
        <div class="tile"><b>Web server</b>lighttpd 1.4.45</div>
        <div class="tile"><b>Default login</b>admin / admin</div>
     </div></div>
     <div class="card"><h2>Diagnostics</h2>
       <form method="get" action="/diag.php"><p><input type="text" name="target" value="127.0.0.1"></p><button>Ping target</button></form>
       <pre>GET /diag.php?target=127.0.0.1;id
GET /cgi-bin/status.cgi?iface=eth0;id</pre>
     </div>
     <div class="card"><h2>Firmware package upload</h2>
       <form action="/firmware_upgrade" method="post" enctype="multipart/form-data">
         <p><input type="file" name="pkg"></p><button>Install package</button>
       </form>
       <table style="margin-top:12px"><thead><tr><th>Package</th><th>Size</th><th>Modified</th><th></th></tr></thead><tbody>' . $rows . '</tbody></table>
     </div>
     <div class="card"><h2>Endpoints</h2><table><tbody>
       <tr><td class="mono">GET /diag.php?target=</td><td>ping diagnostic (command injection)</td></tr>
       <tr><td class="mono">GET /cgi-bin/status.cgi?iface=</td><td>interface status (command injection)</td></tr>
       <tr><td class="mono">POST /firmware_upgrade</td><td>อัปโหลดแพ็กเกจไม่ตรวจลายเซ็น</td></tr>
       <tr><td class="mono">GET /config_dump.php</td><td>ค่าตั้งค่าอุปกรณ์และรหัสผ่าน admin</td></tr>
     </tbody></table></div>'
);
