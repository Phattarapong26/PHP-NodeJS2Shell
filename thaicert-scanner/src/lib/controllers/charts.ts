import { appState } from './state';

// Global Tooltip for ThaiCERT Security Assessment
export function initThaiCertTooltip() {
  const tip = document.getElementById('globalThaiCertTooltip');
  const tipTarget = document.getElementById('tipTarget');
  const tipNote = document.getElementById('tipNote');
  const tipSevPill = document.getElementById('tipSevPill');
  const tipCveSection = document.getElementById('tipCveSection');
  const tipCveList = document.getElementById('tipCveList');

  if (!tip) return;

  document.addEventListener('mouseover', (e) => {
    const wrap = (e.target as Element).closest('.thaicert-badge-wrap');
    if (!wrap) return;

    const target = wrap.getAttribute('data-target') || '';
    const note = decodeURIComponent(wrap.getAttribute('data-note') || '');
    const sev = wrap.getAttribute('data-sev') || 'SECURE';
    const sevClass = wrap.getAttribute('data-sev-class') || 'bg-emerald-950 text-emerald-300 border-emerald-800';
    let cves = [];
    try {
      cves = JSON.parse(decodeURIComponent(wrap.getAttribute('data-cves') || '[]'));
    } catch (_) {}

    tipTarget.textContent = target;
    tipNote.textContent = note;
    tipSevPill.textContent = sev;
    tipSevPill.className = `px-2 py-0.5 rounded text-[10px] font-mono font-bold border ${sevClass}`;

    if (cves && cves.length > 0) {
      tipCveSection.classList.remove('hidden');
      tipCveList.innerHTML = cves.map(c => {
        const id = c.cve || c.id || 'CVE';
        const s = c.severity || 'Medium';
        let bg = 'bg-rose-900/70 text-rose-200 border-rose-700';
        if (s === 'High') bg = 'bg-orange-900/70 text-orange-200 border-orange-700';
        else if (s === 'Medium') bg = 'bg-amber-900/70 text-amber-200 border-amber-700';
        return `<span class="px-1.5 py-0.5 rounded text-[10px] font-mono border ${bg}">${id}</span>`;
      }).join('');
    } else {
      tipCveSection.classList.add('hidden');
      tipCveList.innerHTML = '';
    }

    tip.classList.remove('hidden');
    tip.classList.add('flex');

    const rect = wrap.getBoundingClientRect();
    const tipW = tip.offsetWidth || 340;
    const tipH = tip.offsetHeight || 130;

    let left = rect.left + (rect.width / 2) - (tipW / 2);
    if (left < 12) left = 12;
    if (left + tipW > window.innerWidth - 12) left = window.innerWidth - tipW - 12;

    let top = rect.top - tipH - 8;
    if (top < 10) {
      // Flip below the badge if near top of window
      top = rect.bottom + 8;
    }

    tip.style.left = `${left}px`;
    tip.style.top = `${top}px`;
  });

  document.addEventListener('mouseout', (e) => {
    const wrap = (e.target as Element).closest('.thaicert-badge-wrap');
    if (!wrap) return;
    const related = e.relatedTarget;
    if (related && wrap.contains(related as Node)) return;
    tip.classList.add('hidden');
    tip.classList.remove('flex');
  });
}

// ==========================================
// THAICERT 8 GROUPS DUAL CHARTS (RADAR & LOLLIPOP)
// ==========================================
export const THAICERT_GROUP_META = {
  1: { id: 1, code: 'ก.1', name: 'เว็บไซต์ / CMS', shortName: 'เว็บไซต์/CMS', note: 'WordPress, Drupal, Joomla, Moodle, CMS', icon: 'ph-globe' },
  2: { id: 2, code: 'ก.2', name: 'แอป & API', shortName: 'แอป & API', note: 'Laravel, Symfony, Node.js REST API', icon: 'ph-code' },
  3: { id: 3, code: 'ก.3', name: 'Control Panel', shortName: 'Hosting Panel', note: 'cPanel, Plesk, DirectAdmin, Webmin', icon: 'ph-gauge' },
  4: { id: 4, code: 'ก.4', name: 'อุปกรณ์ & NAS', shortName: 'อุปกรณ์/NAS', note: 'Network Appliance, NAS Synology/QNAP', icon: 'ph-hard-drives' },
  5: { id: 5, code: 'ก.5', name: 'Container / K8s', shortName: 'Container/K8s', note: 'Docker, Podman, Kubernetes Node', icon: 'ph-package' },
  6: { id: 6, code: 'ก.6', name: 'Windows PHP', shortName: 'Windows PHP', note: 'Windows IIS, XAMPP, Laragon (CVE-2024-4577)', icon: 'ph-microsoft-windows-logo' },
  7: { id: 7, code: 'ก.7', name: 'Dev / UAT / สำรอง', shortName: 'Dev/UAT/สำรอง', note: 'Development, Staging, DR, Shadow IT', icon: 'ph-clock-counter-clockwise' },
  8: { id: 8, code: 'ก.8', name: 'Cloud / ภายนอก', shortName: 'Cloud/ภายนอก', note: 'Shared Hosting, Cloud VM, Outsourced', icon: 'ph-cloud' }
};

export function getThaiCertGroupStats() {
  const stats = {};
  const allHosts = appState.allHosts || [];
  for (let g = 1; g <= 8; g++) {
    const groupHosts = allHosts.filter(h => (h.thaicert_groups || []).includes(g));
    const total = groupHosts.length;
    const vuln = groupHosts.filter(h => (h.is_php || h.is_node) && (h.vulnerability === 'Critical' || h.vulnerability === 'Outdated' || h.vulnerability === 'Warning')).length;
    stats[g] = {
      ...THAICERT_GROUP_META[g],
      total: total,
      vuln: vuln,
      secure: Math.max(0, total - vuln)
    };
  }
  return stats;
}

export function renderRadarChart(stats) {
  const svg = document.getElementById('radarChartSvg');
  if (!svg) return;

  const cx = 230, cy = 205;
  const R = 120;
  const numAxes = 8;

  let maxVal = 0;
  for (let g = 1; g <= 8; g++) {
    if (stats[g].total > maxVal) maxVal = stats[g].total;
  }
  let scaleMax = 5;
  if (maxVal > 20) scaleMax = Math.ceil(maxVal / 5) * 5;
  else if (maxVal > 10) scaleMax = 20;
  else if (maxVal > 5) scaleMax = 10;
  else scaleMax = 5;

  const angles = [];
  for (let i = 0; i < numAxes; i++) {
    angles.push(-Math.PI / 2 + (i * 2 * Math.PI / numAxes));
  }

  let html = '';

  // 1. Concentric Regular Octagons (Grid Rings)
  const levels = [0.25, 0.5, 0.75, 1.0];
  levels.forEach((lvl, idx) => {
    const r = R * lvl;
    const pts = angles.map(a => `${(cx + r * Math.cos(a)).toFixed(1)},${(cy + r * Math.sin(a)).toFixed(1)}`).join(' ');
    html += `<polygon points="${pts}" fill="none" stroke="#e2e8f0" stroke-width="1.2" stroke-dasharray="${idx < 3 ? '2 2' : 'none'}" />`;
    
    const tickVal = Math.round(scaleMax * lvl);
    const ty = cy - r + 3;
    html += `<text x="${cx + 6}" y="${ty.toFixed(1)}" font-size="9" font-family="monospace" fill="#94a3b8" font-weight="600">${tickVal}</text>`;
  });

  // 2. Radial Axis Lines
  angles.forEach((a) => {
    const x2 = cx + R * Math.cos(a);
    const y2 = cy + R * Math.sin(a);
    html += `<line x1="${cx}" y1="${cy}" x2="${x2.toFixed(1)}" y2="${y2.toFixed(1)}" stroke="#cbd5e1" stroke-width="1" />`;
  });

  // 3. Data Polygon (Teal fill matching reference image)
  const dataPoints = [];
  for (let g = 1; g <= 8; g++) {
    const a = angles[g - 1];
    const val = stats[g].total;
    const r = val > 0 ? (val / scaleMax) * R : 2;
    dataPoints.push({
      x: cx + r * Math.cos(a),
      y: cy + r * Math.sin(a),
      group: g,
      val: val,
      vuln: stats[g].vuln
    });
  }

  const polyPointsStr = dataPoints.map(p => `${p.x.toFixed(1)},${p.y.toFixed(1)}`).join(' ');
  html += `<polygon points="${polyPointsStr}" fill="rgba(94, 161, 161, 0.45)" stroke="#3d8383" stroke-width="2.2" class="transition-all duration-300" />`;

  // 4. Vertex Points
  dataPoints.forEach(p => {
    const isSelected = appState.activeGroupFilter === p.group;
    const hasVuln = p.vuln > 0;
    const dotColor = hasVuln ? '#e11d48' : '#3d8383';
    const rDot = isSelected ? 6.5 : (p.val > 0 ? 5 : 3.5);
    const strokeColor = isSelected ? '#3b82f6' : '#ffffff';
    const strokeWidth = isSelected ? 2.5 : 1.8;

    html += `
      <circle 
        cx="${p.x.toFixed(1)}" 
        cy="${p.y.toFixed(1)}" 
        r="${rDot}" 
        fill="${dotColor}" 
        stroke="${strokeColor}" 
        stroke-width="${strokeWidth}" 
        class="cursor-pointer transition-all duration-150 hover:scale-150 chart-radar-dot"
        data-group="${p.group}"
        data-action="toggleGroupFilter" data-arg="${p.group}"
      />
    `;
  });

  // 5. Axis Labels (Group Names & Counts)
  for (let g = 1; g <= 8; g++) {
    const a = angles[g - 1];
    const meta = stats[g];
    const labelDist = R + 26;
    const lx = cx + labelDist * Math.cos(a);
    const ly = cy + labelDist * Math.sin(a);

    let anchor = "middle";
    const cosA = Math.cos(a);
    if (cosA > 0.25) anchor = "start";
    else if (cosA < -0.25) anchor = "end";

    let dy = 4;
    const sinA = Math.sin(a);
    if (sinA < -0.6) dy = -4;
    else if (sinA > 0.6) dy = 12;

    const isSelected = appState.activeGroupFilter === g;
    const textFill = isSelected ? '#1d4ed8' : '#334155';
    const badgeFill = isSelected ? '#2563eb' : (meta.vuln > 0 ? '#e11d48' : '#64748b');

    html += `
      <g class="cursor-pointer chart-group-label" data-group="${g}" data-action="toggleGroupFilter" data-arg="${g}">
        <text 
          x="${lx.toFixed(1)}" 
          y="${(ly + dy - 6).toFixed(1)}" 
          text-anchor="${anchor}" 
          font-size="10.5" 
          font-weight="${isSelected ? '800' : '700'}" 
          fill="${textFill}"
          class="transition-colors hover:fill-blue-600 select-none"
        >${meta.code} ${meta.shortName}</text>
        <text 
          x="${lx.toFixed(1)}" 
          y="${(ly + dy + 7).toFixed(1)}" 
          text-anchor="${anchor}" 
          font-size="9" 
          font-weight="600" 
          font-family="monospace"
          fill="${badgeFill}"
          class="select-none"
        >(${meta.total} เครื่อง${meta.vuln > 0 ? ` · ${meta.vuln} เสี่ยง` : ''})</text>
      </g>
    `;
  }

  svg.innerHTML = html;
}

export function renderLollipopChart(stats) {
  const svg = document.getElementById('lollipopChartSvg');
  if (!svg) return;

  const items = [];
  for (let g = 1; g <= 8; g++) {
    items.push(stats[g]);
  }
  // Sort descending by count, matching reference image
  items.sort((a, b) => b.total - a.total);

  let maxVal = 0;
  items.forEach(it => { if (it.total > maxVal) maxVal = it.total; });

  let scaleMax = 5;
  if (maxVal > 20) scaleMax = Math.ceil(maxVal / 5) * 5;
  else if (maxVal > 10) scaleMax = 20;
  else if (maxVal > 5) scaleMax = 10;
  else scaleMax = 5;

  const xStart = 145;
  const xEnd = 450;
  const W = xEnd - xStart;
  const yStart = 32;
  const rowH = 32;

  let html = '';

  // 1. Vertical Gridlines & Scale Ticks at bottom
  const numTicks = 4;
  for (let t = 0; t <= numTicks; t++) {
    const frac = t / numTicks;
    const x = xStart + frac * W;
    const tickVal = Math.round(scaleMax * frac);
    
    html += `<line x1="${x.toFixed(1)}" y1="${yStart - 10}" x2="${x.toFixed(1)}" y2="${yStart + 7 * rowH + 12}" stroke="#f1f5f9" stroke-width="1.2" />`;
    html += `<line x1="${x.toFixed(1)}" y1="${yStart + 7 * rowH + 12}" x2="${x.toFixed(1)}" y2="${yStart + 7 * rowH + 17}" stroke="#cbd5e1" stroke-width="1.2" />`;
    html += `<text x="${x.toFixed(1)}" y="${yStart + 7 * rowH + 28}" font-size="9" font-family="monospace" fill="#94a3b8" text-anchor="middle" font-weight="600">${tickVal}</text>`;
  }
  // Bottom baseline
  html += `<line x1="${xStart}" y1="${yStart + 7 * rowH + 12}" x2="${xEnd}" y2="${yStart + 7 * rowH + 12}" stroke="#cbd5e1" stroke-width="1.2" />`;
  html += `<text x="${xEnd + 26}" y="${yStart + 7 * rowH + 28}" font-size="9" fill="#94a3b8" text-anchor="end">เครื่อง</text>`;

  // 2. Lollipop Rows
  items.forEach((item, idx) => {
    const y = yStart + idx * rowH;
    const isSelected = appState.activeGroupFilter === item.id;
    const valFrac = scaleMax > 0 ? (item.total / scaleMax) : 0;
    const dotX = xStart + valFrac * W;

    const hasVuln = item.vuln > 0;
    // Dot color: teal (#5ea1a1) if normal, or rose/red (#e11d48) if vulnerable
    const dotColor = hasVuln ? '#e11d48' : '#5ea1a1';
    const rowBg = isSelected ? 'rgba(59, 130, 246, 0.08)' : 'transparent';

    html += `
      <g class="cursor-pointer chart-lollipop-row" data-group="${item.id}" data-action="toggleGroupFilter" data-arg="${item.id}">
        <!-- Hover/Selection background highlight -->
        <rect x="10" y="${y - 12}" width="${xEnd - 5}" height="${rowH - 4}" rx="8" fill="${rowBg}" class="transition-colors hover:fill-blue-50/70" />
        
        <!-- Category Label on Left -->
        <text 
          x="${xStart - 12}" 
          y="${y + 4}" 
          text-anchor="end" 
          font-size="11" 
          font-weight="${isSelected ? '800' : '600'}" 
          fill="${isSelected ? '#1d4ed8' : '#334155'}"
          class="select-none"
        >${item.code} ${item.shortName}</text>
        
        <!-- Horizontal Stick Line -->
        <line 
          x1="${xStart}" 
          y1="${y}" 
          x2="${dotX.toFixed(1)}" 
          y2="${y}" 
          stroke="${isSelected ? '#3b82f6' : '#cbd5e1'}" 
          stroke-width="${isSelected ? 2.5 : 1.8}" 
          class="transition-all duration-200"
        />

        <!-- Circle Dot (Bubble matching reference image) -->
        <circle 
          cx="${dotX.toFixed(1)}" 
          cy="${y}" 
          r="${isSelected ? 8.5 : 7}" 
          fill="${dotColor}" 
          stroke="#ffffff" 
          stroke-width="2" 
          class="transition-transform duration-150 hover:scale-125"
        />

        <!-- Value Counter Label right beside dot -->
        <text 
          x="${(dotX + 11).toFixed(1)}" 
          y="${y + 4}" 
          font-size="11" 
          font-weight="bold" 
          font-family="monospace" 
          fill="${hasVuln ? '#e11d48' : (isSelected ? '#1d4ed8' : '#0f766e')}"
          class="select-none"
        >${item.total}${hasVuln ? `<tspan font-size="9" font-weight="normal" fill="#e11d48"> (${item.vuln} เสี่ยง)</tspan>` : ''}</text>
      </g>
    `;
  });

  svg.innerHTML = html;
}

export function getTopDetectedCves() {
  const cveMap = {};
  const allHosts = appState.allHosts || [];

  allHosts.forEach(h => {
    (h.matched_cves || []).forEach(c => {
      const cveId = c.cve || c.id || 'CVE-UNKNOWN';
      if (!cveMap[cveId]) {
        cveMap[cveId] = {
          id: cveId,
          severity: c.severity || 'Critical',
          title: c.title || c.description || 'ช่องโหว่ความเสี่ยงระดับสูงที่ตรวจพบ',
          count: 0,
          hosts: []
        };
      }
      cveMap[cveId].count += 1;
      if (!cveMap[cveId].hosts.includes(h.ip)) {
        cveMap[cveId].hosts.push(h.ip);
      }
    });

    if (h.kernel_audit && h.kernel_audit.cve) {
      const cveId = h.kernel_audit.cve;
      if (!cveMap[cveId]) {
        cveMap[cveId] = {
          id: cveId,
          severity: 'High',
          title: h.kernel_audit.note || 'Linux Kernel Network Vulnerability',
          count: 0,
          hosts: []
        };
      }
      cveMap[cveId].count += 1;
      if (!cveMap[cveId].hosts.includes(h.ip)) {
        cveMap[cveId].hosts.push(h.ip);
      }
    }
  });

  const list = Object.values(cveMap);
  list.sort((a: any, b: any) => b.count - a.count);
  return list;
}

export function renderCveBarChart(cves) {
  const svg = document.getElementById('cveBarChartSvg');
  const overlay = document.getElementById('cveEmptyOverlay');
  if (!svg) return;

  if (!cves || cves.length === 0) {
    if (overlay) {
      overlay.classList.remove('hidden');
      overlay.classList.add('flex');
    }

    // Draw ghost bars matching user reference image
    const ghostData = [
      { label: 'Top 1', val: 3900 },
      { label: '', val: 2500 },
      { label: 'Top 2', val: 3200 },
      { label: '', val: 1700 },
      { label: 'Top 3', val: 2200 },
      { label: '', val: 1200 }
    ];
    const maxVal = 4000;
    const xStart = 55, xEnd = 450, W = 395;
    const yStart = 26, rowH = 38;

    let html = '';
    [0, 1000, 2000, 3000, 4000].forEach(tick => {
      const x = xStart + (tick / maxVal) * W;
      html += `<line x1="${x.toFixed(1)}" y1="16" x2="${x.toFixed(1)}" y2="250" stroke="#cbd5e1" stroke-width="0.8" opacity="0.35" />`;
      html += `<text x="${x.toFixed(1)}" y="270" font-size="9" font-family="monospace" fill="#94a3b8" text-anchor="middle" font-weight="600">${tick === 0 ? '0' : tick.toLocaleString()}</text>`;
    });

    ghostData.forEach((d, idx) => {
      const y = yStart + idx * rowH;
      const barW = (d.val / maxVal) * W;
      if (d.label) {
        html += `<text x="${xStart - 10}" y="${y + 16}" font-size="10" font-weight="700" fill="#94a3b8" text-anchor="end">${d.label}</text>`;
      }
      html += `<rect x="${xStart}" y="${y}" width="${barW.toFixed(1)}" height="24" rx="6" fill="#78716c" opacity="0.4" />`;
    });

    svg.innerHTML = html;
    return;
  }

  // CVEs found: Render real frequency bars
  if (overlay) {
    overlay.classList.add('hidden');
    overlay.classList.remove('flex');
  }

  const topCves = cves.slice(0, 6);
  let maxCount = 0;
  topCves.forEach(c => { if (c.count > maxCount) maxCount = c.count; });
  const scaleMax = maxCount > 5 ? Math.ceil(maxCount / 5) * 5 : 5;

  const xStart = 135, xEnd = 430, W = 295;
  const yStart = 28, rowH = 42;

  let html = '';

  // Grid lines
  const numTicks = 4;
  for (let t = 0; t <= numTicks; t++) {
    const frac = t / numTicks;
    const x = xStart + frac * W;
    const tickVal = Math.round(scaleMax * frac);
    html += `<line x1="${x.toFixed(1)}" y1="16" x2="${x.toFixed(1)}" y2="${yStart + topCves.length * rowH + 6}" stroke="#f1f5f9" stroke-width="1.2" />`;
    html += `<text x="${x.toFixed(1)}" y="${yStart + topCves.length * rowH + 22}" font-size="9" font-family="monospace" fill="#94a3b8" text-anchor="middle" font-weight="600">${tickVal}</text>`;
  }
  html += `<line x1="${xStart}" y1="${yStart + topCves.length * rowH + 6}" x2="${xEnd}" y2="${yStart + topCves.length * rowH + 6}" stroke="#cbd5e1" stroke-width="1.2" />`;
  html += `<text x="${xEnd + 26}" y="${yStart + topCves.length * rowH + 22}" font-size="9" fill="#94a3b8" text-anchor="end">เครื่อง</text>`;

  topCves.forEach((cve, idx) => {
    const y = yStart + idx * rowH;
    const barW = Math.max(14, (cve.count / scaleMax) * W);
    
    let barColor = '#e11d48'; // Critical
    if (cve.severity === 'High') barColor = '#ea580c';
    else if (cve.severity === 'Medium') barColor = '#d97706';

    html += `
      <g class="cursor-pointer chart-cve-bar" data-cve="${cve.id}">
        <!-- CVE ID Label -->
        <text x="${xStart - 10}" y="${y + 16}" font-size="10.5" font-weight="700" font-family="monospace" fill="#1e293b" text-anchor="end" class="select-none">${cve.id}</text>
        
        <!-- Track bar -->
        <rect x="${xStart}" y="${y}" width="${W}" height="24" rx="6" fill="#f8fafc" stroke="#e2e8f0" stroke-width="1" />

        <!-- Filled bar -->
        <rect x="${xStart}" y="${y}" width="${barW.toFixed(1)}" height="24" rx="6" fill="${barColor}" class="transition-all duration-300 hover:opacity-90" />

        <!-- Count text -->
        <text x="${(xStart + barW + 8).toFixed(1)}" y="${y + 16}" font-size="10.5" font-weight="bold" font-family="monospace" fill="${barColor}">${cve.count}</text>
      </g>
    `;
  });

  svg.innerHTML = html;
}

export function attachChartTooltips(stats, cves) {
  const tip = document.getElementById('chartHoverTooltip');
  const badge = document.getElementById('chartTipBadge');
  const title = document.getElementById('chartTipTitle');
  const riskPill = document.getElementById('chartTipRiskPill');
  const totalLabel = document.getElementById('chartTipTotalLabel');
  const totalEl = document.getElementById('chartTipTotal');
  const vulnRow = document.getElementById('chartTipVulnRow');
  const vulnEl = document.getElementById('chartTipVuln');
  const noteEl = document.getElementById('chartTipNote');
  const actionText = document.getElementById('chartTipActionText');

  if (!tip) return;

  function handleGroupEnter(e) {
    const target = e.target.closest('[data-group]');
    if (!target) return;
    const g = parseInt(target.getAttribute('data-group'), 10);
    const meta = stats[g];
    if (!meta) return;

    badge.textContent = meta.code;
    badge.className = "font-bold text-[10px] font-mono px-1.5 py-0.5 rounded bg-teal-500/20 text-teal-300 border border-teal-400/40 flex-shrink-0";
    title.textContent = meta.name;
    if (totalLabel) totalLabel.textContent = "จำนวนเครื่องที่ตรวจพบ:";
    totalEl.textContent = `${meta.total} เครื่อง`;
    noteEl.textContent = `เกณฑ์การตรวจ: ${meta.note}`;
    if (actionText) actionText.textContent = "คลิกเพื่อกรองอุปกรณ์เฉพาะกลุ่มนี้";

    if (meta.vuln > 0) {
      riskPill.textContent = `${meta.vuln} VULNERABLE`;
      riskPill.className = "px-2 py-0.5 rounded text-[10px] font-mono font-bold border border-rose-500/60 bg-rose-500/20 text-rose-300 flex-shrink-0";
      vulnRow.classList.remove('hidden');
      vulnRow.classList.add('flex');
      vulnEl.textContent = `${meta.vuln} เครื่อง`;
    } else {
      riskPill.textContent = "SECURE";
      riskPill.className = "px-2 py-0.5 rounded text-[10px] font-mono font-bold border border-emerald-400/60 bg-emerald-500/10 text-emerald-300 flex-shrink-0";
      vulnRow.classList.add('hidden');
      vulnRow.classList.remove('flex');
    }

    tip.classList.remove('hidden');
    tip.classList.add('flex');
  }

  function handleCveEnter(e) {
    const target = e.target.closest('[data-cve]');
    if (!target) return;
    const cveId = target.getAttribute('data-cve');
    const cve = (cves || []).find(x => x.id === cveId);
    if (!cve) return;

    badge.textContent = cve.severity.toUpperCase();
    badge.className = "font-bold text-[10px] font-mono px-1.5 py-0.5 rounded bg-rose-500/20 text-rose-300 border border-rose-400/40 flex-shrink-0";
    title.textContent = cve.id;
    if (totalLabel) totalLabel.textContent = "จำนวนโฮสต์ที่ได้รับผลกระทบ:";
    totalEl.textContent = `${cve.count} เครื่อง`;
    vulnRow.classList.add('hidden');
    noteEl.textContent = cve.title;
    if (actionText) {
      actionText.textContent = `พบที่ IP: ${cve.hosts.slice(0, 3).join(', ')}${cve.hosts.length > 3 ? ` และอีก ${cve.hosts.length - 3} เครื่อง` : ''}`;
    }

    riskPill.textContent = cve.severity.toUpperCase();
    riskPill.className = "px-2 py-0.5 rounded text-[10px] font-mono font-bold border border-rose-500/60 bg-rose-500/20 text-rose-300 flex-shrink-0";

    tip.classList.remove('hidden');
    tip.classList.add('flex');
  }

  function handleEmptyOverlayEnter() {
    badge.textContent = "CLEAN";
    badge.className = "font-bold text-[10px] font-mono px-1.5 py-0.5 rounded bg-emerald-500/20 text-emerald-300 border border-emerald-400/40 flex-shrink-0";
    title.textContent = "สถานะความมั่นคงปลอดภัย";
    if (totalLabel) totalLabel.textContent = "ช่องโหว่ CVE ที่ตรวจพบ:";
    totalEl.textContent = "0 รายการ (ปลอดภัย 100%)";
    vulnRow.classList.add('hidden');
    noteEl.textContent = "ไม่พบช่องโหว่ความเสี่ยงระดับสูงหรือร้ายแรงในบรรดาอุปกรณ์ที่ตรวจสอบรอบนี้";
    if (actionText) actionText.textContent = "สอดคล้องตามเกณฑ์มาตรฐาน ThaiCERT / สกมช.";

    riskPill.textContent = "SECURE";
    riskPill.className = "px-2 py-0.5 rounded text-[10px] font-mono font-bold border border-emerald-400/60 bg-emerald-500/10 text-emerald-300 flex-shrink-0";

    tip.classList.remove('hidden');
    tip.classList.add('flex');
  }

  function handleMove(e) {
    if (tip.classList.contains('hidden')) return;
    const tipW = tip.offsetWidth || 230;
    const tipH = tip.offsetHeight || 110;
    let left = e.clientX + 14;
    let top = e.clientY + 14;

    if (left + tipW > window.innerWidth - 12) {
      left = e.clientX - tipW - 14;
    }
    if (top + tipH > window.innerHeight - 12) {
      top = e.clientY - tipH - 14;
    }
    tip.style.left = `${left}px`;
    tip.style.top = `${top}px`;
  }

  function handleLeave() {
    tip.classList.add('hidden');
    tip.classList.remove('flex');
  }

  document.querySelectorAll('.chart-radar-dot, .chart-group-label, .chart-lollipop-row').forEach(el => {
    el.addEventListener('mouseenter', handleGroupEnter);
    el.addEventListener('mousemove', handleMove);
    el.addEventListener('mouseleave', handleLeave);
  });

  document.querySelectorAll('.chart-cve-bar').forEach(el => {
    el.addEventListener('mouseenter', handleCveEnter);
    el.addEventListener('mousemove', handleMove);
    el.addEventListener('mouseleave', handleLeave);
  });

  const overlay = document.getElementById('cveEmptyOverlay');
  if (overlay) {
    overlay.addEventListener('mouseenter', handleEmptyOverlayEnter);
    overlay.addEventListener('mousemove', handleMove);
    overlay.addEventListener('mouseleave', handleLeave);
  }
}

export function renderThaiCertDualCharts() {
  const stats = getThaiCertGroupStats();
  renderRadarChart(stats);
  renderLollipopChart(stats);

  const cves = getTopDetectedCves();
  renderCveBarChart(cves);

  attachChartTooltips(stats, cves);
}

export const renderThaiCertVisualCharts = renderThaiCertDualCharts;

export function initThaiCertChartsControls() {
  const btnViewCharts = document.getElementById('btnViewCharts');
  const btnViewCards = document.getElementById('btnViewCards');
  const thaicertChartsContainer = document.getElementById('thaicertChartsContainer');
  const thaicertGroupGrid = document.getElementById('thaicertGroupGrid');

  if (btnViewCharts && btnViewCards && thaicertChartsContainer && thaicertGroupGrid) {
    btnViewCharts.addEventListener('click', () => {
      thaicertChartsContainer.classList.remove('hidden');
      thaicertGroupGrid.classList.add('hidden');
      btnViewCharts.className = "px-2.5 py-1 rounded-lg bg-white text-teal-800 shadow-xs font-bold transition flex items-center gap-1.5 cursor-pointer";
      btnViewCards.className = "px-2.5 py-1 rounded-lg text-slate-500 hover:text-slate-800 transition flex items-center gap-1.5 cursor-pointer";
      renderThaiCertDualCharts();
    });

    btnViewCards.addEventListener('click', () => {
      thaicertChartsContainer.classList.add('hidden');
      thaicertGroupGrid.classList.remove('hidden');
      btnViewCards.className = "px-2.5 py-1 rounded-lg bg-white text-blue-700 shadow-xs font-bold transition flex items-center gap-1.5 cursor-pointer";
      btnViewCharts.className = "px-2.5 py-1 rounded-lg text-slate-500 hover:text-slate-800 transition flex items-center gap-1.5 cursor-pointer";
    });
  }
}