<?php
/**
 * LAB TARGET #5 - กลุ่มที่ 5: Container และ Docker Image
 * Simulated product: containerised "Order API" (image corp/order-api:1.4.0, k8s pod order-api-7d9f)
 * Weakness: PHP app inside the image has an unrestricted attachment upload (container compromise)
 *           and the runtime is misconfigured (docker.sock mounted, privileged) -> escape path.
 * LISTEN: 8085
 */
require __DIR__ . '/../../common/lab.php';

header('X-Powered-By: PHP/8.1.2');
header('Server: Apache/2.4.52 (Debian)');
ini_set('display_errors', '1');
error_reporting(E_ALL);

const APP_NAME = 'Order API';
const IMAGE    = 'corp/order-api:1.4.0';
$PORT = 8085;
$public = __DIR__ . '/public/storage';
@mkdir($public, 0777, true);

$path = parse_url($_SERVER['REQUEST_URI'] ?? '/', PHP_URL_PATH) ?: '/';
$path = rawurldecode($path);
$host = gethostname() ?: 'order-api-7d9f2c-x4k1';

if ($path === '/health') {
    lab_health([
        'system' => 'container-app',
        'group'  => 5,
        'group_name' => 'Container และ Docker Image',
        'port'   => $PORT,
        'product'=> APP_NAME . ' (' . IMAGE . ')',
        'php'    => '8.1.2',
        'vuln'   => 'unrestricted-upload-in-image / container-misconfig',
    ]);
}

if (preg_match('#^/public/storage/(.+)$#', $path, $m)) {
    lab_serve_stored($public, $m[1]);
}

/* --------------------------- .env in the image ---------------------- */
if ($path === '/.env' || $path === '/app/.env') {
    header('Content-Type: text/plain; charset=utf-8');
    echo "APP_ENV=staging\nAPP_DEBUG=1\nAPP_URL=http://order-api.internal\n";
    echo "DB_HOST=postgres.orders.svc.cluster.local\nDB_USER=orders\nDB_PASS=0rders_Lab_P@ss\n";
    echo "PAYMENT_GATEWAY_KEY=sk_live_lab_51HxQ2exampleonly\n";
    echo "KUBERNETES_SERVICE_HOST=10.96.0.1\n";
    exit;
}

/* ------------------------ container metadata leak ------------------- */
if ($path === '/metrics') {
    header('Content-Type: text/plain; charset=utf-8');
    echo "# HELP order_api_container_info runtime info leaked to any caller\n";
    echo "order_api_container_info{image=\"" . IMAGE . "\",pod=\"$host\",namespace=\"orders\"} 1\n";
    echo "order_api_process_uid " . getmyuid() . "\n";
    echo "order_api_php_version_info{version=\"" . PHP_VERSION . "\"} 1\n";
    echo "order_api_env{APP_ENV=\"staging\",APP_DEBUG=\"1\"} 1\n";
    exit;
}

/* ---------------- Dockerfile / compose disclosure (escape risk) ----- */
if ($path === '/config/Dockerfile' || $path === '/config/docker-compose.yml') {
    header('Content-Type: text/plain; charset=utf-8');
    echo "# build context leaked through the config endpoint\n";
    echo "FROM php:8.1-apache\nRUN docker-php-ext-install pdo pdo_mysql\nCOPY . /var/www/html\nRUN chmod -R 777 /var/www/html/public\n";
    echo "USER root\n";
    echo "# --- docker-compose excerpt ---\n";
    echo "services:\n  order-api:\n    image: " . IMAGE . "\n    privileged: true\n    user: root\n";
    echo "    volumes:\n      - /var/run/docker.sock:/var/run/docker.sock\n      - ./uploads:/var/www/html/public/storage\n";
    exit;
}

/* ------------------ attachment upload (container compromise) -------
 * ไฟล์ที่อัปโหลดถูกเก็บใน public/storage ของอิมเมจและรันได้ทันที
 * volume ผูกกับ host -> เขียนทะลุออกนอกคอนเทนเนอร์ได้
 * ------------------------------------------------------------------ */
if ($path === '/api/upload/attachments') {
    if ($_SERVER['REQUEST_METHOD'] !== 'POST') lab_json(['error' => 'method not allowed'], 405);
    $name = isset($_FILES['file']['name']) ? basename($_FILES['file']['name'])
          : basename($_SERVER['HTTP_X_FILENAME'] ?? '');
    if ($name === '') lab_json(['error' => 'provide multipart field "file" or header X-Filename'], 400);
    $tmp = $_FILES['file']['tmp_name'] ?? null;
    if ($tmp) {
        move_uploaded_file($tmp, $public . '/' . $name);
    } else {
        file_put_contents($public . '/' . $name, file_get_contents('php://input'));
    }
    @chmod($public . '/' . $name, 0666);
    lab_json([
        'container' => $host,
        'stored'    => $name,
        'mount'     => '/var/www/html/public/storage -> ./uploads (host bind)',
        'url'       => 'http://' . ($_SERVER['HTTP_HOST'] ?? 'localhost:' . $PORT) . '/public/storage/' . rawurlencode($name),
        'note'      => 'upload lands on a host bind-mount, runs as root inside the image',
    ]);
}

if ($path === '/api/orders') {
    lab_json(['orders' => [
        ['id' => 'ORD-1001', 'status' => 'paid', 'amount' => 1290.00],
        ['id' => 'ORD-1002', 'status' => 'pending', 'amount' => 455.50],
    ], 'note' => 'no authentication required']);
}

/* ------------------------------- homepage --------------------------- */
$files = lab_list_recent($public);
$rows = '';
foreach ($files as $f) {
    $rows .= '<tr><td class="mono">' . h($f['name']) . '</td><td>' . number_format($f['size']) . ' B</td><td>' . h($f['modified'])
           . '</td><td><a href="/public/storage/' . h(rawurlencode($f['name'])) . '">open</a></td></tr>';
}
if ($rows === '') $rows = '<tr><td colspan="4" style="color:#94a3b8">ยังไม่มีไฟล์ใน volume</td></tr>';

lab_page(
    'Order API &mdash; container runtime',
    'บริการหลังบ้านที่รันในคอนเทนเนอร์: อัปโหลดไฟล์แนบคำสั่งซื้อ เก็บใน bind-mount ที่ผูกกับโฮสต์',
    'TARGET #5 · CONTAINER · PORT 8085 · image ' . IMAGE,
    'teal',
    '<div class="card"><h2>Runtime</h2><div class="grid">
        <div class="tile"><b>Image</b>' . IMAGE . '</div>
        <div class="tile"><b>Pod</b>' . h($host) . '</div>
        <div class="tile"><b>User</b>root (container)</div>
        <div class="tile"><b>Mount</b>/var/run/docker.sock</div>
     </div>
     <p class="sub" style="margin-top:10px">Image ใช้ <code>chmod 777 public</code> และรันเป็น root &mdash; ถ้าฝัง PHP shell ได้จะยึดคอนเทนเนอร์ และอาจไต่ต่อออก host ผ่าน docker.sock</p></div>
     <div class="card"><h2>Attachment upload</h2>
       <form action="/api/upload/attachments" method="post" enctype="multipart/form-data">
         <p><input type="file" name="file"></p><button>Upload attachment</button>
       </form>
       <pre>POST /api/upload/attachments      (multipart, file=@shell.php)
GET  /public/storage/shell.php?c=id</pre>
     </div>
     <div class="card"><h2>Volume contents (host bind mount)</h2>
       <table><thead><tr><th>File</th><th>Size</th><th>Modified</th><th></th></tr></thead><tbody>' . $rows . '</tbody></table></div>
     <div class="card"><h2>Endpoints</h2><table><tbody>
       <tr><td class="mono">GET /.env</td><td>env ของอิมเมจ (DB/PSP keys)</td></tr>
       <tr><td class="mono">GET /metrics</td><td>ข้อมูล runtime/pod/namespace</td></tr>
       <tr><td class="mono">GET /config/Dockerfile</td><td>Dockerfile + compose (privileged, docker.sock)</td></tr>
       <tr><td class="mono">POST /api/upload/attachments</td><td>อัปโหลดไฟล์แนบไม่จำกัดชนิด</td></tr>
     </tbody></table></div>'
);
