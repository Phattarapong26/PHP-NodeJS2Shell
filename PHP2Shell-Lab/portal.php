<?php
/**
 * OPScaner PHP2Shell Lab - portal (port 8080)
 * รวมรายการเป้าหมายทั้ง 8 ระบบ พร้อม health check
 */
require __DIR__ . '/common/lab.php';

const TARGETS = [
    1 => ['port' => 8081, 'group' => 'เว็บไซต์และระบบภายในองค์กร (CMS)',        'product' => 'CorpPress CMS 5.8.2',        'stack' => 'PHP 7.4.33 / Apache 2.4.41',  'vuln' => 'Unrestricted file upload (plugin) → web shell'],
    2 => ['port' => 8082, 'group' => 'ระบบหลังบ้านแอปมือถือและ API (Framework)', 'product' => 'FieldOps API v1.14.2',        'stack' => 'Laravel-compat / PHP 7.4.33', 'vuln' => 'unserialize() object injection + unvalidated upload'],
    3 => ['port' => 8083, 'group' => 'Hosting Control Panel',                   'product' => 'HostAdmin 110.0.24',          'stack' => 'PHP 7.4.33 / run as root',   'vuln' => 'MIME-only upload check + role header trust (priv-esc)'],
    4 => ['port' => 8084, 'group' => 'ซอฟต์แวร์/อุปกรณ์สำเร็จรูป (Appliance/IoT)','product' => 'NetGuard Pro 3000 fw 2.4.1',  'stack' => 'lighttpd / PHP 5.6.40',      'vuln' => 'OS command injection + unsigned firmware upload'],
    5 => ['port' => 8085, 'group' => 'Container และ Docker Image',              'product' => 'order-api:1.4.0',             'stack' => 'Apache / PHP 8.1.2',         'vuln' => 'Upload in image + docker.sock / privileged container'],
    6 => ['port' => 8086, 'group' => 'Windows + PHP (IIS/XAMPP)',               'product' => 'HR Portal on IIS 10',         'stack' => 'IIS 10 / PHP 7.4.33',        'vuln' => 'Windows filename parsing (shell.php;.jpg) + cmd injection'],
    7 => ['port' => 8087, 'group' => 'ระบบทดสอบ/เก่า/สำรอง (Dev/UAT/Staging)',   'product' => 'DMS Staging 2018.11.07',      'stack' => 'Apache / PHP 5.6.40',        'vuln' => 'debug + phpinfo + .git + LFI + session-upload-progress'],
    8 => ['port' => 8088, 'group' => 'ผู้ให้บริการภายนอกดูแล (Shared Hosting)',  'product' => 'CloudShare (2 tenants)',      'stack' => 'Apache / PHP 7.4.33',        'vuln' => 'Cross-tenant traversal + shared upload directory'],
];

function check(int $port, int $idx = 0): array {
    // ทำงานได้ทั้งแบบรันในเครื่องเดียว (127.0.0.1) และแบบ docker compose (ชื่อ service appN)
    $hosts = array_values(array_unique(array_filter([
        getenv('LAB_TARGET_HOST') ?: null,
        '127.0.0.1',
        'app' . $idx,
    ])));
    foreach ($hosts as $hst) {
        $ctx = stream_context_create(['http' => ['timeout' => 1.2, 'ignore_errors' => true]]);
        $t0 = microtime(true);
        $raw = @file_get_contents('http://' . $hst . ':' . $port . '/health', false, $ctx);
        $ms = (int)round((microtime(true) - $t0) * 1000);
        if ($raw !== false) {
            return ['up' => true, 'ms' => $ms, 'via' => $hst, 'meta' => json_decode($raw, true)];
        }
    }
    return ['up' => false, 'ms' => 0, 'via' => null, 'meta' => null];
}

$host = $_SERVER['HTTP_HOST'] ?? 'localhost:8080';
$hostOnly = explode(':', $host)[0];
$base = 'http://' . $hostOnly;

$rows = '';
$up = 0;
foreach (TARGETS as $n => $t) {
    $c = check($t['port'], $n);
    if ($c['up']) $up++;
    $status = $c['up']
        ? '<span class="pill" style="background:#ecfdf5;color:#047857;border-color:#a7f3d0">UP · ' . $c['ms'] . ' ms</span>'
        : '<span class="pill" style="background:#fef2f2;color:#b91c1c;border-color:#fecaca">DOWN</span>';
    $rows .= '<tr>'
        . '<td><b>#' . $n . '</b></td>'
        . '<td><a class="mono" href="' . $base . ':' . $t['port'] . '/">' . $t['port'] . '</a></td>'
        . '<td>' . h($t['group']) . '</td>'
        . '<td>' . h($t['product']) . '<br><span class="sub">' . h($t['stack']) . '</span></td>'
        . '<td>' . h($t['vuln']) . '</td>'
        . '<td>' . $status . '</td>'
        . '</tr>';
}

lab_page(
    'OPScaner PHP2Shell Lab &mdash; 8 simulated systems',
    'ระบบจำลองสำหรับวัดผลโปรแกรม VA: แต่ละพอร์ตคือหนึ่งกลุ่มระบบ พร้อมช่องโหว่ PHP2Shell ที่ใช้งานได้จริงในสภาพแวดล้อมปิด',
    'LAB PORTAL · PORT 8080 · ' . $up . '/8 systems up',
    'slate',
    '<div class="card"><h2>Targets</h2>
       <table><thead><tr><th>#</th><th>Port</th><th>กลุ่มระบบ</th><th>ผลิตภัณฑ์จำลอง</th><th>ช่องโหว่หลัก</th><th>Status</th></tr></thead>
       <tbody>' . $rows . '</tbody></table>
       <p class="sub" style="margin-top:12px">สแกนทั้งช่วงพอร์ต: <code class="mono">' . h($hostOnly) . ':8080-8088</code> &middot; health check: <code class="mono">/health</code> ทุกพอร์ต</p>
     </div>
     <div class="card"><h2>Quick check</h2>
       <pre>cd lab && ./verify_lab.sh          # ตรวจว่าทุกช่องโหว่ยังทำงาน (PASS/FAIL)
./stop_lab.sh                     # หยุดทุกบริการ</pre>
     </div>'
);
