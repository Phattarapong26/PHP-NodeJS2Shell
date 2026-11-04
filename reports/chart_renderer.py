"""
Vector Chart Renderer for ThaiCERT & NCSA Security Advisory Reports.
Generates pure, standalone SVG strings for:
1. ThaiCERT 8 Groups Spider/Radar Web Chart
2. Asset Distribution Lollipop Dot-Plot Chart
3. Top Detected CVEs Severity-Coded Frequency Bar Chart
"""

import math
import html
from typing import Dict, List, Any


THAICERT_GROUP_META = {
    1: {
        'id': 1,
        'code': 'ก.1',
        'name': 'เว็บไซต์และระบบภายในองค์กร (CMS)',
        'shortName': 'เว็บไซต์/CMS',
        'color': '#1d4ed8',        # Royal Ocean Blue
        'lightBg': 'rgba(29, 78, 216, 0.12)',
        'border': '#3b82f6'
    },
    2: {
        'id': 2,
        'code': 'ก.2',
        'name': 'ระบบหลังบ้านแอปมือถือ และ API',
        'shortName': 'แอป & API',
        'color': '#4338ca',        # Deep Cobalt Indigo
        'lightBg': 'rgba(67, 56, 202, 0.12)',
        'border': '#6366f1'
    },
    3: {
        'id': 3,
        'code': 'ก.3',
        'name': 'Hosting Control Panel',
        'shortName': 'Hosting Panel',
        'color': '#0e7490',        # Deep Cyan
        'lightBg': 'rgba(14, 116, 144, 0.12)',
        'border': '#06b6d4'
    },
    4: {
        'id': 4,
        'code': 'ก.4',
        'name': 'ซอฟต์แวร์และอุปกรณ์สำเร็จรูป (NAS/Appliance)',
        'shortName': 'อุปกรณ์/NAS',
        'color': '#0f766e',        # Oceanic Pine Teal
        'lightBg': 'rgba(15, 118, 110, 0.12)',
        'border': '#14b8a6'
    },
    5: {
        'id': 5,
        'code': 'ก.5',
        'name': 'Container และ Docker Image',
        'shortName': 'Container/K8s',
        'color': '#6d28d9',        # Royal Violet
        'lightBg': 'rgba(109, 40, 217, 0.12)',
        'border': '#8b5cf6'
    },
    6: {
        'id': 6,
        'code': 'ก.6',
        'name': 'Windows ที่มี PHP ติดตั้งอยู่',
        'shortName': 'Windows PHP',
        'color': '#0284c7',        # Cerulean Azure Sky
        'lightBg': 'rgba(2, 132, 199, 0.12)',
        'border': '#0ea5e9'
    },
    7: {
        'id': 7,
        'code': 'ก.7',
        'name': 'ระบบทดสอบ ระบบเก่า และระบบสำรอง',
        'shortName': 'Dev/UAT/สำรอง',
        'color': '#047857',        # Forest Mint Emerald
        'lightBg': 'rgba(4, 120, 87, 0.12)',
        'border': '#10b981'
    },
    8: {
        'id': 8,
        'code': 'ก.8',
        'name': 'ระบบที่ผู้ให้บริการภายนอกดูแล',
        'shortName': 'Cloud/ภายนอก',
        'color': '#475569',        # High-Tech Steel Slate
        'lightBg': 'rgba(71, 85, 105, 0.12)',
        'border': '#64748b'
    }
}


def extract_top_cves_from_hosts(hosts_list: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Extracts, aggregates and ranks detected CVEs and CWEs from hosts list."""
    cve_map: Dict[str, Dict[str, Any]] = {}
    for h in hosts_list:
        ip = str(h.get('ip') or h.get('target_id') or 'target')
        is_vuln = bool(h.get('vulnerability') and h.get('vulnerability') not in ('Secure', 'Review Needed'))
        cves = h.get('matched_cves') or []
        
        # Check active RCE proof / CWE-78
        rce_p = h.get('rce_proof') or (h.get('deep_audit') or {}).get('rce_proof') or {}
        if rce_p.get('is_rce_proved') or rce_p.get('proof_status') == 'RCE_CONFIRMED':
            cwe_id = 'CWE-78'
            if cwe_id not in cve_map:
                cve_map[cwe_id] = {
                    'id': cwe_id,
                    'severity': 'Critical',
                    'title': 'OS Command Injection (CWE-78)',
                    'count': 0,
                    'hosts': []
                }
            if ip not in cve_map[cwe_id]['hosts']:
                cve_map[cwe_id]['count'] += 1
                cve_map[cwe_id]['hosts'].append(ip)

        for c in cves:
            cve_id = c.get('id') or c.get('cve')
            if not cve_id:
                continue
            sev = c.get('severity') or 'Critical'
            if not is_vuln and c.get('confidence') == 'Conditional':
                continue
            if cve_id not in cve_map:
                cve_map[cve_id] = {
                    'id': cve_id,
                    'severity': sev,
                    'title': c.get('name') or c.get('title') or c.get('description') or 'Vulnerability Finding',
                    'count': 0,
                    'hosts': []
                }
            if ip not in cve_map[cve_id]['hosts']:
                cve_map[cve_id]['count'] += 1
                cve_map[cve_id]['hosts'].append(ip)

    res = list(cve_map.values())
    # Sort critical first, then by count descending
    res.sort(key=lambda x: (0 if str(x.get('severity', '')).lower() == 'critical' else 1, -x.get('count', 0)))
    return res


def build_group_stats(hosts_list: List[Dict[str, Any]], thaicert_summary: Dict[str, Any] = None) -> Dict[int, Dict[str, Any]]:
    """Builds unified stats for groups 1..8 based on hosts and scan summary."""
    stats = {}
    for g in range(1, 9):
        meta = THAICERT_GROUP_META[g]
        stats[g] = {
            'id': g,
            'code': meta['code'],
            'name': meta['name'],
            'shortName': meta['shortName'],
            'color': meta['color'],
            'lightBg': meta['lightBg'],
            'border': meta['border'],
            'total': 0,
            'vuln': 0,
            'secure': 0
        }

    # If thaicert_summary exists and populated, use it
    if thaicert_summary and isinstance(thaicert_summary, dict):
        for k, v in thaicert_summary.items():
            try:
                gid = int(k)
                if gid in stats and isinstance(v, dict):
                    stats[gid]['total'] = int(v.get('total', 0))
                    stats[gid]['vuln'] = int(v.get('vuln', 0))
                    stats[gid]['secure'] = int(v.get('secure', 0))
            except (ValueError, TypeError):
                continue
    else:
        # Fallback: calculate from hosts_list
        def is_h_vuln(h):
            if not h: return False
            v = h.get('vulnerability') or ''
            if v in ('Critical', 'High', 'Lifecycle Risk (EOL)', 'Outdated', 'Warning'): return True
            if h.get('matched_cves') and len(h.get('matched_cves')) > 0: return True
            if h.get('is_rce_proved') or (h.get('rce_proof', {}).get('is_rce_proved')): return True
            pv = str(h.get('phpVersion', '') or h.get('php_version', ''))
            if any(ver in pv for ver in ('5.', '7.', '8.0', '8.1')): return True
            return False

        for h in hosts_list:
            groups = h.get('thaicert_groups') or []
            is_v = is_h_vuln(h)
            for g in groups:
                if isinstance(g, int) and g in stats:
                    stats[g]['total'] += 1
                    if is_v:
                        stats[g]['vuln'] += 1
                    else:
                        stats[g]['secure'] += 1

    return stats


def render_radar_svg(stats: Dict[int, Dict[str, Any]]) -> str:
    """Generates pure SVG for Radar Web (กระจาย 8 กลุ่ม)."""
    cx, cy = 250, 155
    R = 104
    num_axes = 8

    max_val = max([stats[g]['total'] for g in range(1, 9)] + [1])
    if max_val > 20:
        scale_max = math.ceil(max_val / 5) * 5
    elif max_val > 10:
        scale_max = 20
    elif max_val > 5:
        scale_max = 10
    else:
        scale_max = max(5, max_val)

    angles = [-math.pi / 2 + (i * 2 * math.pi / num_axes) for i in range(num_axes)]

    svg_parts = [
        '<svg viewBox="10 10 480 295" width="100%" height="100%" xmlns="http://www.w3.org/2000/svg" style="display: block; overflow: visible;">'
    ]

    # 1. Concentric Regular Octagons (Grid Rings)
    levels = [0.25, 0.5, 0.75, 1.0]
    for idx, lvl in enumerate(levels):
        r = R * lvl
        pts = " ".join([f"{cx + r * math.cos(a):.1f},{cy + r * math.sin(a):.1f}" for a in angles])
        fill_attr = 'fill="rgba(248, 250, 252, 0.75)"' if idx == 3 else 'fill="none"'
        dash_attr = 'stroke-dasharray="2 2"' if idx < 3 else ''
        svg_parts.append(f'<polygon points="{pts}" {fill_attr} stroke="#cbd5e1" stroke-width="1.1" {dash_attr} />')
        
        tick_val = int(round(scale_max * lvl))
        ty = cy - r + 4.0
        svg_parts.append(f'<text x="{cx + 6}" y="{ty:.1f}" font-size="11.5" font-family="monospace" fill="#64748b" font-weight="700">{tick_val}</text>')

    # 2. Radial Axis Lines
    for idx, a in enumerate(angles):
        g = idx + 1
        meta = stats.get(g, THAICERT_GROUP_META[g])
        x2 = cx + R * math.cos(a)
        y2 = cy + R * math.sin(a)
        svg_parts.append(f'<line x1="{cx}" y1="{cy}" x2="{x2:.1f}" y2="{y2:.1f}" stroke="{meta["border"]}" stroke-width="1.1" opacity="0.45" />')

    # 3. Data Polygon
    data_points = []
    for g in range(1, 9):
        a = angles[g - 1]
        val = stats[g]['total']
        r = (val / scale_max) * R if val > 0 else 2.5
        data_points.append({
            'x': cx + r * math.cos(a),
            'y': cy + r * math.sin(a),
            'group': g,
            'val': val,
            'vuln': stats[g]['vuln'],
            'meta': stats[g]
        })

    poly_pts = " ".join([f"{p['x']:.1f},{p['y']:.1f}" for p in data_points])
    svg_parts.append(f'<polygon points="{poly_pts}" fill="rgba(37, 99, 235, 0.16)" stroke="#2563eb" stroke-width="2.2" />')

    # 4. Vertex Points & Halos
    for p in data_points:
        has_vuln = p['vuln'] > 0
        dot_color = '#e11d48' if has_vuln else p['meta']['color']
        r_dot = 7.0 if p['val'] > 0 else 4.0

        if p['val'] > 0:
            halo_color = 'rgba(225, 29, 72, 0.22)' if has_vuln else p['meta']['lightBg']
            halo_stroke = '#f43f5e' if has_vuln else p['meta']['border']
            svg_parts.append(f'<circle cx="{p["x"]:.1f}" cy="{p["y"]:.1f}" r="{r_dot + 4.0}" fill="{halo_color}" stroke="{halo_stroke}" stroke-width="1.1" />')

        svg_parts.append(f'<circle cx="{p["x"]:.1f}" cy="{p["y"]:.1f}" r="{r_dot}" fill="{dot_color}" stroke="#ffffff" stroke-width="2.0" />')

    # 5. Axis Labels
    for g in range(1, 9):
        a = angles[g - 1]
        meta = stats[g]
        label_dist = R + 22
        lx = cx + label_dist * math.cos(a)
        ly = cy + label_dist * math.sin(a)

        anchor = "middle"
        cos_a = math.cos(a)
        if cos_a > 0.25:
            anchor = "start"
        elif cos_a < -0.25:
            anchor = "end"

        dy = 3
        sin_a = math.sin(a)
        if sin_a < -0.6:
            dy = -4
        elif sin_a > 0.6:
            dy = 13

        has_vuln = meta['vuln'] > 0
        v_sub = f" · {meta['vuln']} เสี่ยง" if has_vuln else ""
        sub_color = '#e11d48' if has_vuln else '#64748b'

        svg_parts.append(f'''
        <g>
          <text x="{lx:.1f}" y="{(ly + dy - 6):.1f}" text-anchor="{anchor}" font-size="14" font-weight="700" fill="{meta['color']}">{meta['code']} {html.escape(meta['shortName'])}</text>
          <text x="{lx:.1f}" y="{(ly + dy + 10):.1f}" text-anchor="{anchor}" font-size="12" font-weight="600" font-family="monospace" fill="{sub_color}">{meta['total']} เครื่อง{v_sub}</text>
        </g>
        ''')

    svg_parts.append('</svg>')
    return "".join(svg_parts)


def render_lollipop_svg(stats: Dict[int, Dict[str, Any]]) -> str:
    """Generates pure SVG for Lollipop Dot-Plot ranking by quantity."""
    items = [stats[g] for g in range(1, 9)]
    items.sort(key=lambda x: x['total'], reverse=True)

    max_val = max([it['total'] for it in items] + [1])
    if max_val > 20:
        scale_max = math.ceil(max_val / 5) * 5
    elif max_val > 10:
        scale_max = 20
    elif max_val > 5:
        scale_max = 10
    else:
        scale_max = max(5, max_val)

    x_start = 145
    x_end = 430
    W = x_end - x_start
    y_start = 22
    row_h = 32

    svg_parts = [
        '<svg viewBox="10 5 475 305" width="100%" height="100%" xmlns="http://www.w3.org/2000/svg" style="display: block; overflow: visible;">'
    ]

    # 1. Gridlines and scale ticks
    num_ticks = 4
    for t in range(num_ticks + 1):
        frac = t / num_ticks
        x = x_start + frac * W
        tick_val = int(round(scale_max * frac))
        svg_parts.append(f'<line x1="{x:.1f}" y1="{y_start - 6}" x2="{x:.1f}" y2="{y_start + 7 * row_h + 10}" stroke="#f1f5f9" stroke-width="1.2" />')
        svg_parts.append(f'<line x1="{x:.1f}" y1="{y_start + 7 * row_h + 10}" x2="{x:.1f}" y2="{y_start + 7 * row_h + 15}" stroke="#cbd5e1" stroke-width="1.2" />')
        svg_parts.append(f'<text x="{x:.1f}" y="{y_start + 7 * row_h + 26}" font-size="11.5" font-family="monospace" fill="#64748b" text-anchor="middle" font-weight="700">{tick_val}</text>')

    # Baseline
    svg_parts.append(f'<line x1="{x_start}" y1="{y_start + 7 * row_h + 10}" x2="{x_end}" y2="{y_start + 7 * row_h + 10}" stroke="#cbd5e1" stroke-width="1.4" />')
    svg_parts.append(f'<text x="{x_end + 25}" y="{y_start + 7 * row_h + 26}" font-size="11.5" font-weight="700" fill="#64748b" text-anchor="end">เครื่อง</text>')

    # 2. Lollipop Rows
    for idx, item in enumerate(items):
        y = y_start + idx * row_h
        val_frac = (item['total'] / scale_max) if scale_max > 0 else 0
        dot_x = x_start + val_frac * W
        has_vuln = item['vuln'] > 0
        dot_color = '#e11d48' if has_vuln else item['color']
        v_sub = f' <tspan font-size="11" font-weight="bold" fill="#e11d48">({item["vuln"]} เสี่ยง)</tspan>' if has_vuln else ''

        svg_parts.append(f'''
        <g>
          <!-- Category Label on Left -->
          <text x="{x_start - 12}" y="{y + 4.5}" text-anchor="end" font-size="13.5" font-weight="700" fill="{item['color']}">{item['code']} {html.escape(item['shortName'])}</text>
          
          <!-- Horizontal Stick Line -->
          <line x1="{x_start}" y1="{y}" x2="{dot_x:.1f}" y2="{y}" stroke="{item['border']}" stroke-width="2.2" stroke-linecap="round" />
        ''')

        if has_vuln:
            svg_parts.append(f'<circle cx="{dot_x:.1f}" cy="{y}" r="11.5" fill="rgba(225, 29, 72, 0.2)" stroke="#f43f5e" stroke-width="1.2" />')

        svg_parts.append(f'''
          <circle cx="{dot_x:.1f}" cy="{y}" r="7.8" fill="{dot_color}" stroke="#ffffff" stroke-width="2.0" />
          <text x="{dot_x + 12:.1f}" y="{y + 4.5}" font-size="13" font-weight="800" font-family="monospace" fill="{dot_color}">{item['total']}{v_sub}</text>
        </g>
        ''')

    svg_parts.append('</svg>')
    return "".join(svg_parts)


def render_top_cves_svg(cves_list: List[Dict[str, Any]]) -> str:
    """Generates pure SVG for Top Detected CVEs Bar Chart."""
    if not cves_list:
        return '''
        <div style="height: 190px; display: flex; flex-direction: column; align-items: center; justify-content: center; background-color: #f8fafc; border-radius: 12px; border: 1px dashed #cbd5e1; text-align: center; padding: 20px;">
          <div style="font-size: 26pt; margin-bottom: 4px;">🛡️</div>
          <div style="font-size: 14pt; font-weight: bold; color: #047857;">ไม่พบช่องโหว่ความเสี่ยงระดับวิกฤต/สูงตามฐานข้อมูลสากล</div>
          <div style="font-size: 11pt; color: #64748b; margin-top: 2px;">ทุกพอร์ตบริการในวงเครือข่ายปลอดภัยจากรายการ CVE ที่ระบุในมาตรฐาน</div>
        </div>
        '''

    # Take top 6
    top_cves = cves_list[:6]
    max_count = max([c.get('count', 1) for c in top_cves] + [1])
    scale_max = math.ceil(max_count / 5) * 5 if max_count > 5 else 5

    x_start = 140
    x_end = 430
    W = x_end - x_start
    y_start = 24
    row_h = 36

    svg_parts = [
        f'<svg viewBox="0 0 495 {y_start + len(top_cves) * row_h + 30}" width="100%" height="100%" xmlns="http://www.w3.org/2000/svg" style="display: block; overflow: visible;">'
    ]

    # Gridlines
    num_ticks = 4
    for t in range(num_ticks + 1):
        frac = t / num_ticks
        x = x_start + frac * W
        tick_val = int(round(scale_max * frac))
        svg_parts.append(f'<line x1="{x:.1f}" y1="12" x2="{x:.1f}" y2="{y_start + len(top_cves) * row_h + 5}" stroke="#f1f5f9" stroke-width="1.2" />')
        svg_parts.append(f'<text x="{x:.1f}" y="{y_start + len(top_cves) * row_h + 19}" font-size="11" font-family="monospace" fill="#64748b" text-anchor="middle" font-weight="700">{tick_val}</text>')

    # Baseline
    svg_parts.append(f'<line x1="{x_start}" y1="{y_start + len(top_cves) * row_h + 5}" x2="{x_end}" y2="{y_start + len(top_cves) * row_h + 5}" stroke="#cbd5e1" stroke-width="1.2" />')
    svg_parts.append(f'<text x="{x_end + 25}" y="{y_start + len(top_cves) * row_h + 19}" font-size="11" font-weight="700" fill="#64748b" text-anchor="end">เครื่อง</text>')

    # Bars
    for idx, cve in enumerate(top_cves):
        y = y_start + idx * row_h
        cnt = cve.get('count', 1)
        bar_w = max(14.0, (cnt / scale_max) * W)
        sev = str(cve.get('severity', 'Critical')).capitalize()
        if sev == 'Critical':
            bar_color = '#e11d48'
        elif sev == 'High':
            bar_color = '#ea580c'
        else:
            bar_color = '#d97706'

        c_id = html.escape(str(cve.get('id') or cve.get('cve') or 'CVE-UNKNOWN'))

        svg_parts.append(f'''
        <g>
          <!-- CVE ID Label -->
          <text x="{x_start - 10}" y="{y + 14}" font-size="12" font-weight="700" font-family="monospace" fill="#1e293b" text-anchor="end">{c_id}</text>
          
          <!-- Track bar -->
          <rect x="{x_start}" y="{y}" width="{W}" height="20" rx="5" fill="#f8fafc" stroke="#e2e8f0" stroke-width="1" />
          
          <!-- Filled bar -->
          <rect x="{x_start}" y="{y}" width="{bar_w:.1f}" height="20" rx="5" fill="{bar_color}" />
          
          <!-- Count text -->
          <text x="{x_start + bar_w + 7:.1f}" y="{y + 14}" font-size="12" font-weight="800" font-family="monospace" fill="{bar_color}">{cnt}</text>
        </g>
        ''')

    svg_parts.append('</svg>')
    return "".join(svg_parts)


def build_visual_analytics_dashboard_html(stats: Dict[int, Dict[str, Any]], cves_list: List[Dict[str, Any]]) -> str:
    """
    Renders complete Visual Risk Analytics Dashboard section for A4 report.
    Presents 3 tone-coordinated cards matching 1:1 with the OP Scanner UI.
    """
    radar_svg = render_radar_svg(stats)
    lollipop_svg = render_lollipop_svg(stats)
    cve_svg = render_top_cves_svg(cves_list)

    # Crisp vector icons
    globe_icon = '''<svg width="17" height="17" viewBox="0 0 24 24" fill="none" stroke="#1d4ed8" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round" style="display:inline-block; vertical-align:-2px;"><circle cx="12" cy="12" r="10"></circle><line x1="2" y1="12" x2="22" y2="12"></line><path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z"></path></svg>'''
    lollipop_icon = '''<svg width="17" height="17" viewBox="0 0 24 24" fill="none" stroke="#4338ca" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round" style="display:inline-block; vertical-align:-2px;"><line x1="18" y1="20" x2="18" y2="10"></line><line x1="12" y1="20" x2="12" y2="4"></line><line x1="6" y1="20" x2="6" y2="14"></line></svg>'''
    shield_icon = '''<svg width="17" height="17" viewBox="0 0 24 24" fill="none" stroke="#e11d48" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round" style="display:inline-block; vertical-align:-2px;"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"></path></svg>'''

    return f"""
    <div class="adv-visual-dashboard" style="margin-top: 6px; margin-bottom: 12px; break-inside: avoid; page-break-inside: avoid;">

      <!-- Top Row: Radar & Lollipop Dual Layout (Side-by-Side) -->
      <table style="width: 100%; border-collapse: separate; border-spacing: 12px 0; margin-bottom: 12px; table-layout: fixed;">
        <tr>
          <!-- Card 1: Radar Web -->
          <td style="width: 50%; vertical-align: top; background: #ffffff; border: 1.2px solid #e2e8f0; border-radius: 14px; padding: 12px 14px; box-shadow: 0 1px 3px rgba(0,0,0,0.03);">
            <div style="display: flex; justify-content: space-between; align-items: center; border-bottom: 1px solid #f1f5f9; padding-bottom: 6px; margin-bottom: 8px;">
              <div style="font-weight: bold; font-size: 13.5pt; color: #1e293b; display: flex; align-items: center; gap: 6px;">
                {globe_icon} <span>Radar Web (กระจาย 8 กลุ่ม)</span>
              </div>
              <div style="font-size: 10.5pt; color: #64748b; font-weight: 600;">
                สเกลเครื่อง
              </div>
            </div>
            <div style="height: 275px; display: flex; align-items: center; justify-content: center;">
              {radar_svg}
            </div>
          </td>

          <!-- Card 2: Lollipop Dot Plot -->
          <td style="width: 50%; vertical-align: top; background: #ffffff; border: 1.2px solid #e2e8f0; border-radius: 14px; padding: 12px 14px; box-shadow: 0 1px 3px rgba(0,0,0,0.03);">
            <div style="display: flex; justify-content: space-between; align-items: center; border-bottom: 1px solid #f1f5f9; padding-bottom: 6px; margin-bottom: 8px;">
              <div style="font-weight: bold; font-size: 13.5pt; color: #1e293b; display: flex; align-items: center; gap: 6px;">
                {lollipop_icon} <span>Lollipop (จัดอันดับตามปริมาณ)</span>
              </div>
              <div style="font-size: 10.5pt; color: #64748b; font-weight: 600;">
                Dot Plot
              </div>
            </div>
            <div style="height: 275px; display: flex; align-items: center; justify-content: center;">
              {lollipop_svg}
            </div>
          </td>
        </tr>
      </table>

      <!-- Bottom Card: Top CVEs Frequency Bar Chart -->
      <div style="background: #ffffff; border: 1.2px solid #e2e8f0; border-radius: 14px; padding: 12px 16px; box-shadow: 0 1px 3px rgba(0,0,0,0.03);">
        <div style="display: flex; justify-content: space-between; align-items: center; border-bottom: 1px solid #f1f5f9; padding-bottom: 6px; margin-bottom: 8px;">
          <div style="font-weight: bold; font-size: 13.5pt; color: #1e293b; display: flex; align-items: center; gap: 6px;">
            {shield_icon} <span>Top CVEs (ความถี่ช่องโหว่ความมั่นคงปลอดภัยที่ตรวจพบ)</span>
          </div>
          <div style="font-size: 10.5pt; display: flex; align-items: center; gap: 8px;">
            <span style="color: #e11d48; font-weight: bold;">● วิกฤต (Critical)</span>
            <span style="color: #ea580c; font-weight: bold;">● สูง (High)</span>
          </div>
        </div>
        <div style="width: 100%;">
          {cve_svg}
        </div>
      </div>
    </div>
    """
