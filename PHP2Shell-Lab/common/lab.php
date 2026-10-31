<?php
/**
 * OPScaner PHP2Shell Lab - shared helpers
 * Simulation target for VA / scanner validation only.
 * Everything here is intentionally vulnerable on purpose.
 */

function h($s): string { return htmlspecialchars((string)$s, ENT_QUOTES, 'UTF-8'); }

function lab_health(array $meta): void {
    header('Content-Type: application/json; charset=utf-8');
    echo json_encode(['status' => 'up'] + $meta, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_PRETTY_PRINT);
    exit;
}

function lab_json(array $data, int $code = 200): void {
    http_response_code($code);
    header('Content-Type: application/json; charset=utf-8');
    echo json_encode($data, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_PRETTY_PRINT);
    exit;
}

function lab_list_recent(string $dir, int $limit = 12): array {
    $out = [];
    if (!is_dir($dir)) return $out;
    $files = [];
    foreach (scandir($dir) as $f) {
        if ($f === '.' || $f === '..') continue;
        $files[$f] = filemtime("$dir/$f") ?: 0;
    }
    arsort($files);
    $i = 0;
    foreach ($files as $f => $t) {
        $out[] = [
            'name' => $f,
            'size' => filesize("$dir/$f"),
            'modified' => date('Y-m-d H:i:s', $t),
        ];
        if (++$i >= $limit) break;
    }
    return $out;
}

/** Serve a stored file. .php files are handed to the PHP engine (real execution). */
function lab_serve_stored(string $dir, string $name, string $type = null): void {
    $path = $dir . '/' . basename($name);
    if (!is_file($path)) {
        http_response_code(404);
        echo "404 Not Found";
        exit;
    }
    if (preg_match('/\.ph(p|tml|ar|ps|t)$/i', $path)) {
        header('Content-Type: text/html; charset=utf-8');
        include $path;   // by design: uploaded code is executed
        exit;
    }
    header('Content-Type: ' . ($type ?: 'application/octet-stream'));
    header('Content-Length: ' . filesize($path));
    readfile($path);
    exit;
}

function lab_download(string $path, string $type = 'text/plain; charset=utf-8'): void {
    if (!is_file($path)) { http_response_code(404); echo "Not found"; exit; }
    header('Content-Type: ' . $type);
    readfile($path);
    exit;
}

/**
 * Shared page template. $rows = [ [label, value, tone] ... ] shown as a spec grid,
 * $panels = 'html' free-form blocks.
 */
function lab_page(string $title, string $subtitle, string $badge, string $tone, string $panels, string $body_class = ''): void {
    $toneMap = [
        'red'    => ['#b91c1c', '#fef2f2', '#fecaca'],
        'amber'  => ['#b45309', '#fffbeb', '#fde68a'],
        'indigo' => ['#4338ca', '#eef2ff', '#c7d2fe'],
        'slate'  => ['#334155', '#f8fafc', '#e2e8f0'],
        'teal'   => ['#0f766e', '#f0fdfa', '#99f6e4'],
    ];
    [$fg, $bg, $bd] = $toneMap[$tone] ?? $toneMap['slate'];
    header('Content-Type: text/html; charset=utf-8');
    echo <<<HTML
<!DOCTYPE html>
<html lang="th"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{$title}</title>
<style>
  :root{--fg:#0f172a;--muted:#64748b;--bd:#e2e8f0;--bg:#f1f5f9}
  *{box-sizing:border-box}
  body{margin:0;font-family:"Segoe UI",Tahoma,system-ui,sans-serif;background:var(--bg);color:var(--fg);font-size:14px;line-height:1.55}
  .bar{background:{$bg};color:{$fg};border-bottom:1px solid {$bd};padding:10px 20px;font-weight:600;font-size:12.5px;display:flex;gap:10px;align-items:center}
  .dot{width:8px;height:8px;border-radius:50%;background:{$fg};display:inline-block}
  .wrap{max-width:1000px;margin:0 auto;padding:20px 16px 48px}
  .card{background:#fff;border:1px solid var(--bd);border-radius:12px;padding:18px 20px;margin-bottom:14px}
  h1{font-size:19px;margin:0 0 4px}
  h2{font-size:13px;text-transform:uppercase;letter-spacing:.06em;color:var(--muted);margin:0 0 10px}
  .sub{color:var(--muted);font-size:13px;margin:0}
  code,pre,.mono{font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace}
  code{background:#f1f5f9;padding:1px 5px;border-radius:4px;font-size:12.5px}
  pre{background:#0f172a;color:#e2e8f0;padding:12px 14px;border-radius:8px;overflow:auto;font-size:12.5px;line-height:1.6}
  pre .k{color:#fca5a5}
  table{width:100%;border-collapse:collapse;font-size:13px}
  th,td{text-align:left;padding:7px 8px;border-bottom:1px solid var(--bd);vertical-align:top}
  th{color:var(--muted);font-weight:600;font-size:11.5px;text-transform:uppercase;letter-spacing:.05em}
  .pill{display:inline-block;padding:2px 8px;border-radius:99px;font-size:11px;font-weight:600;background:#f1f5f9;color:#334155;border:1px solid var(--bd)}
  .grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(190px,1fr));gap:10px}
  .tile{background:#f8fafc;border:1px solid var(--bd);border-radius:10px;padding:10px 12px}
  .tile b{display:block;font-size:11px;text-transform:uppercase;letter-spacing:.05em;color:var(--muted);font-weight:600;margin-bottom:3px}
  input[type=text],input[type=file],input[type=password],textarea,select{width:100%;padding:8px 10px;border:1px solid var(--bd);border-radius:8px;font:inherit;background:#fff}
  button{background:#0f172a;color:#fff;border:0;border-radius:8px;padding:9px 16px;font:inherit;font-weight:600;cursor:pointer}
  a{color:#1d4ed8}
  .foot{text-align:center;color:#94a3b8;font-size:11.5px;margin-top:22px}
</style></head><body class="{$body_class}">
<div class="bar"><span class="dot"></span>{$badge}</div>
<div class="wrap">
  <div class="card"><h1>{$title}</h1><p class="sub">{$subtitle}</p></div>
  {$panels}
  <div class="foot">OPScaner PHP2Shell Lab &middot; simulated target for VA validation &middot; not production</div>
</div>
</body></html>
HTML;
    exit;
}
