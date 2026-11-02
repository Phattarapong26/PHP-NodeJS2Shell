import { escapeHtml } from './utils';
import { renderThaiCertDualCharts } from './charts';
import { badgeFilteredCount, emptyStateDesc, emptyStateTitle, mainSubnetInput, resultsEmptyState, resultsModal, resultsTableBody, resultsTableContainer } from './dom';
import { getWebTargetUrl } from './network';
import { appState } from './state';
import { showToast } from './ui';

// Step 5: Render and Filter Results Table
export function renderResultsTable() {
  const totalAllOnline = appState.allHosts.length;
  const totalPhp = appState.foundPhpHosts.length;
  const totalNode = appState.foundNodeHosts.length;
  const totalVuln = appState.allHosts.filter(h => (h.is_php || h.is_node) && (h.vulnerability === 'Critical' || h.vulnerability === 'Outdated' || h.vulnerability === 'Warning')).length;
  const totalWorkstations = appState.allHosts.filter(h => !h.is_php && !h.is_node).length;

  // Update badge in modal header
  if (badgeFilteredCount) {
    if (totalVuln > 0) {
      badgeFilteredCount.className = "text-xs bg-rose-50 text-rose-700 px-3 py-1 rounded-full border border-rose-200 font-semibold shadow-2xs inline-flex items-center gap-1.5";
      badgeFilteredCount.innerHTML = `<span class="w-2 h-2 rounded-full bg-rose-500 animate-pulse flex-shrink-0"></span><span>พบความเสี่ยง ${totalVuln} เครื่อง</span> <span class="opacity-75 font-normal font-mono">(PHP ${totalPhp} · Node ${totalNode})</span>`;
    } else if (totalPhp > 0 || totalNode > 0) {
      badgeFilteredCount.className = "text-xs bg-emerald-50 text-emerald-700 px-3 py-1 rounded-full border border-emerald-200 font-semibold shadow-2xs inline-flex items-center gap-1.5";
      badgeFilteredCount.innerHTML = `<span class="w-2 h-2 rounded-full bg-emerald-500 flex-shrink-0"></span><span>ปลอดภัยตามเกณฑ์</span> <span class="opacity-75 font-normal font-mono">(PHP ${totalPhp} · Node ${totalNode})</span>`;
    } else {
      badgeFilteredCount.className = "text-xs bg-blue-50 text-blue-700 px-3 py-1 rounded-full border border-blue-200 font-semibold shadow-2xs inline-flex items-center gap-1.5";
      badgeFilteredCount.innerHTML = `<span class="w-2 h-2 rounded-full bg-blue-500 flex-shrink-0"></span><span>ออนไลน์ ${totalAllOnline} เครื่อง</span>`;
    }
  }

  // Update Tab Counts
  const elAllOnline = document.getElementById('countTabAllOnline');
  const elPhp = document.getElementById('countTabPhp');
  const elNode = document.getElementById('countTabNode');
  const elVuln = document.getElementById('countTabVuln');
  const elWorkstation = document.getElementById('countTabWorkstation');
  const emptyAllCount = document.getElementById('emptyAllCount');

  if (elAllOnline) elAllOnline.textContent = String(totalAllOnline);
  if (elPhp) elPhp.textContent = String(totalPhp);
  if (elNode) elNode.textContent = String(totalNode);
  if (elVuln) elVuln.textContent = String(totalVuln);
  if (elWorkstation) elWorkstation.textContent = String(totalWorkstations);
  if (emptyAllCount) emptyAllCount.textContent = String(totalAllOnline);

  // Update Notification Banner
  const banner = document.getElementById('resultsStatusBanner');
  const bannerIconWrap = document.getElementById('bannerStatusIconWrap');
  const bannerIcon = document.getElementById('bannerStatusIcon');
  const bannerText = document.getElementById('bannerStatusText');

  if (banner && bannerText) {
    const targetBadge = document.getElementById('bannerScannedTargetText');
    const targetSub = mainSubnetInput ? mainSubnetInput.value : appState.subnet;
    if (targetBadge && targetSub) targetBadge.textContent = `เป้าหมาย: ${targetSub}`;

    if (totalVuln > 0) {
      banner.className = "px-6 py-2.5 bg-gradient-to-r from-rose-50/95 via-rose-50/60 to-white/90 border-b border-rose-200/70 flex items-center justify-between text-xs text-rose-950 backdrop-blur-sm transition-all duration-200";
      if (bannerIconWrap) bannerIconWrap.className = "w-6 h-6 rounded-lg bg-rose-100 border border-rose-200 flex items-center justify-center flex-shrink-0 text-rose-600 shadow-2xs";
      if (bannerIcon) bannerIcon.className = "ph-bold ph-shield-warning text-sm";
      bannerText.innerHTML = `<span class="font-bold text-rose-900">ตรวจพบข้อควรระวังความปลอดภัย ${totalVuln} เครื่อง:</span> <span class="text-rose-700 font-normal">มีรันไทม์ที่ต้องปรับปรุงแพตช์ (CVE-2024-4577 หรือ Node2Shell) ควรตรวจสอบการตั้งค่า</span>`;
    } else if (totalPhp > 0 || totalNode > 0) {
      banner.className = "px-6 py-2.5 bg-gradient-to-r from-blue-50/95 via-blue-50/60 to-white/90 border-b border-blue-200/70 flex items-center justify-between text-xs text-blue-950 backdrop-blur-sm transition-all duration-200";
      if (bannerIconWrap) bannerIconWrap.className = "w-6 h-6 rounded-lg bg-blue-100 border border-blue-200 flex items-center justify-center flex-shrink-0 text-blue-600 shadow-2xs";
      if (bannerIcon) bannerIcon.className = "ph-bold ph-shield-check text-sm";
      bannerText.innerHTML = `<span class="font-bold text-blue-900">ตรวจพบเซิร์ฟเวอร์ PHP (${totalPhp}) / Node.js (${totalNode}):</span> <span class="text-blue-700 font-normal">ได้รับการปรับปรุงแพตช์ความปลอดภัยเรียบร้อยแล้ว ปลอดภัยตามเกณฑ์ ThaiCERT</span>`;
    } else if (totalAllOnline > 0) {
      banner.className = "px-6 py-2.5 bg-gradient-to-r from-emerald-50/95 via-emerald-50/60 to-white/90 border-b border-emerald-200/70 flex items-center justify-between text-xs text-emerald-950 backdrop-blur-sm transition-all duration-200";
      if (bannerIconWrap) bannerIconWrap.className = "w-6 h-6 rounded-lg bg-emerald-100 border border-emerald-200 flex items-center justify-center flex-shrink-0 text-emerald-600 shadow-2xs";
      if (bannerIcon) bannerIcon.className = "ph-bold ph-check-circle text-sm";
      bannerText.innerHTML = `<span class="font-bold text-emerald-900">ระบบในเครือข่ายปลอดภัย:</span> <span class="text-emerald-700 font-normal">ตรวจพบอุปกรณ์ออนไลน์ ${totalAllOnline} เครื่อง เป็นเครื่องลูกข่ายทั่วไป ปลอดภัย 100%</span>`;
    } else {
      banner.className = "px-6 py-2.5 bg-gradient-to-r from-slate-100 via-slate-50 to-white border-b border-slate-200 flex items-center justify-between text-xs text-slate-700 backdrop-blur-sm transition-all duration-200";
      if (bannerIconWrap) bannerIconWrap.className = "w-6 h-6 rounded-lg bg-slate-200 border border-slate-300 flex items-center justify-center flex-shrink-0 text-slate-600 shadow-2xs";
      if (bannerIcon) bannerIcon.className = "ph-bold ph-info text-sm";
      bannerText.textContent = `สแกนเสร็จสิ้น — ไม่พบเครื่องที่ตอบสนองในวง ${targetSub || ''}`;
    }
  }

  // Update ThaiCERT 8 Groups Matrix Cards
  for (let g = 1; g <= 8; g++) {
    const groupHosts = appState.allHosts.filter(h => (h.thaicert_groups || []).includes(g));
    const gTotal = groupHosts.length;
    const gVuln = groupHosts.filter(h => (h.is_php || h.is_node) && (h.vulnerability === 'Critical' || h.vulnerability === 'Outdated' || h.vulnerability === 'Warning')).length;
    
    const countBadge = document.getElementById(`badgeGroupCount${g}`);
    if (countBadge) {
      if (gTotal === 0) {
        countBadge.innerHTML = `<span class="font-mono text-slate-300 font-bold text-xs">0</span>`;
      } else if (gVuln > 0) {
        countBadge.innerHTML = `<span class="text-rose-600 font-bold font-mono text-xs bg-rose-50 px-1.5 py-0.5 rounded border border-rose-200 shadow-2xs">${gTotal} <span class="text-[9px] font-semibold text-rose-500">(${gVuln} เสี่ยง)</span></span>`;
      } else {
        countBadge.innerHTML = `<span class="text-emerald-700 font-bold font-mono text-xs bg-emerald-50 px-1.5 py-0.5 rounded border border-emerald-200 shadow-2xs">${gTotal}</span>`;
      }
    }

    const card = document.querySelector(`.group-card[data-group="${g}"]`);
    if (card) {
      if (appState.activeGroupFilter === g) {
        card.classList.add('ring-2', 'ring-blue-500', 'bg-blue-50/90', 'border-blue-400', 'shadow-sm');
        card.classList.remove('bg-white/90', 'border-slate-200/80');
      } else {
        card.classList.remove('ring-2', 'ring-blue-500', 'bg-blue-50/90', 'border-blue-400', 'shadow-sm');
        card.classList.add('bg-white/90', 'border-slate-200/80');
      }
    }
  }

  // Render Dual Visual Charts (Radar & Lollipop Charts)
  if (typeof renderThaiCertDualCharts === 'function') {
    renderThaiCertDualCharts();
  }

  // Update active group filter indicator
  const groupTag = document.getElementById('activeGroupFilterTag');
  const groupTagName = document.getElementById('activeGroupFilterName');
  if (groupTag && groupTagName) {
    if (appState.activeGroupFilter) {
      const gNames = {
        1: 'กลุ่ม 1: เว็บไซต์/CMS',
        2: 'กลุ่ม 2: แอป & API',
        3: 'กลุ่ม 3: Hosting Panel',
        4: 'กลุ่ม 4: ซอฟต์แวร์/อุปกรณ์',
        5: 'กลุ่ม 5: Container/K8s',
        6: 'กลุ่ม 6: Windows PHP (CVE-2024-4577)',
        7: 'กลุ่ม 7: Dev/UAT/สำรอง',
        8: 'กลุ่ม 8: Cloud/ภายนอก'
      };
      groupTagName.textContent = gNames[appState.activeGroupFilter] || `กลุ่ม ${appState.activeGroupFilter}`;
      groupTag.classList.remove('hidden');
      groupTag.classList.add('inline-flex');
    } else {
      groupTag.classList.add('hidden');
      groupTag.classList.remove('inline-flex');
    }
  }

  // Filter data
  let filteredList = getFilteredResultsList();

  resultsTableBody.innerHTML = '';

  if (filteredList.length === 0) {
    resultsTableContainer.classList.add('hidden');
    resultsEmptyState.classList.remove('hidden');

    const targetVal = mainSubnetInput ? mainSubnetInput.value : (appState.subnetPrefix + '0/24');
    if (emptyStateTitle) {
      if (appState.activeFilter === 'node_only' && totalNode === 0) {
        emptyStateTitle.textContent = `ไม่พบเซิร์ฟเวอร์ Node.js ในวง ${targetVal}`;
      } else if (appState.activeFilter === 'php_only' && totalPhp === 0) {
        emptyStateTitle.textContent = `ไม่พบเซิร์ฟเวอร์ PHP ในวง ${targetVal}`;
      } else if (appState.activeFilter === 'vulnerable' && totalVuln === 0) {
        emptyStateTitle.textContent = `ยอดเยี่ยม! ไม่พบอุปกรณ์ที่มีความเสี่ยงในวง ${targetVal}`;
      } else if (totalAllOnline === 0) {
        emptyStateTitle.textContent = `ไม่พบอุปกรณ์ที่ตอบสนองในวง ${targetVal}`;
      } else {
        emptyStateTitle.textContent = `ไม่พบรายการในหมวดที่เลือก`;
      }
    }
    if (emptyStateDesc) {
      if (appState.activeFilter === 'node_only' && totalNode === 0) {
        emptyStateDesc.textContent = `พบอุปกรณ์ออนไลน์ทั้งหมด ${totalAllOnline} เครื่อง แต่ไม่มีเครื่องใดเปิดบริการ Node.js (ปลอดภัยจาก Node2Shell / CVE-2026-111497)`;
      } else if (appState.activeFilter === 'php_only' && totalPhp === 0) {
        emptyStateDesc.textContent = `พบอุปกรณ์ออนไลน์ทั้งหมด ${totalAllOnline} เครื่อง แต่ไม่มีเครื่องใดเปิดบริการ Web Server PHP (ปลอดภัยจาก php2shell / CVE-2024-4577)`;
      } else if (appState.activeFilter === 'vulnerable' && totalVuln === 0) {
        emptyStateDesc.textContent = `ทุกเครื่องในเครือข่ายได้รับการอัปเดตเวอร์ชันปลอดภัย ปลอดภัยจาก php2shell และ Node2Shell เรียบร้อย`;
      } else if (totalAllOnline === 0) {
        emptyStateDesc.textContent = `ระบบส่งคำขอตรวจสอบครบถ้วนแล้ว แต่ไม่มีเครื่องใดตอบสนอง โปรดตรวจสอบการเชื่อมต่อเครือข่าย`;
      } else {
        emptyStateDesc.textContent = `ไม่มีเครื่องที่ตรงกับตัวกรองที่เลือกในขณะนี้ ลองสลับแท็บ "อุปกรณ์ออนไลน์ทั้งหมด" เพื่อดูเครื่องที่พบ`;
      }
    }
    return;
  }

  resultsTableContainer.classList.remove('hidden');
  resultsEmptyState.classList.add('hidden');

  filteredList.forEach(item => {
    const row = document.createElement('tr');
    row.className = "hover:bg-blue-50/50 transition-colors border-b border-slate-100";

    // Determine concise ThaiCERT Security Status label and detailed tooltip
    let shortStatus = "ปลอดภัย (ทั่วไป)";
    let shortStatusIcon = "ph-shield";
    let statusBadgeStyle = "bg-slate-100/90 text-slate-600 border-slate-200/90 hover:bg-slate-200/90";
    let sevPill = "SECURE";
    let sevPillClass = "bg-emerald-950 text-emerald-300 border-emerald-800";

    const deep = item.deep_audit || {};
    const nginxSev = (deep.nginx_audit || {}).severity;
    const isCrit = item.vulnerability === "Critical" || item.vulnerabilityNode === "Critical" || nginxSev === "Critical";
    const isHigh = item.vulnerability === "High" || item.vulnerabilityNode === "High" || nginxSev === "High";
    const isWarn = item.vulnerability === "Warning" || item.vulnerability === "Outdated" || item.vulnerabilityNode === "Warning";

    const rceProof = item.rce_proof || deep.rce_proof || {};
    const isRceProved = item.is_rce_proved || !!rceProof.is_rce_proved;

    if (isRceProved) {
      shortStatusIcon = "ph-terminal-window";
      statusBadgeStyle = "bg-rose-100 text-rose-900 border-rose-400 hover:bg-rose-200 shadow-xs font-bold";
      sevPill = "CRITICAL";
      sevPillClass = "bg-rose-950 text-rose-300 border-rose-800";
      shortStatus = "🔥 ยืนยัน RCE สำเร็จ (PoC)";
    } else if (isCrit) {
      shortStatusIcon = "ph-warning-octagon";
      statusBadgeStyle = "bg-rose-50 text-rose-700 border-rose-300 hover:bg-rose-100 shadow-2xs font-bold";
      sevPill = "CRITICAL";
      sevPillClass = "bg-rose-950 text-rose-300 border-rose-800";
      if (item.matched_cves && item.matched_cves.length > 0) {
        const topCve = item.matched_cves[0].cve || item.matched_cves[0].id;
        shortStatus = `เสี่ยง ${topCve}`;
      } else if (item.is_php) {
        shortStatus = "เสี่ยง php2shell (RCE)";
      } else if (item.is_node) {
        shortStatus = "เสี่ยง Node2Shell (RCE)";
      } else {
        shortStatus = "เสี่ยงระดับวิกฤต";
      }
    } else if (isHigh) {
      shortStatusIcon = "ph-shield-warning";
      statusBadgeStyle = "bg-orange-50 text-orange-700 border-orange-300 hover:bg-orange-100 shadow-2xs font-bold";
      sevPill = "HIGH";
      sevPillClass = "bg-orange-950 text-orange-300 border-orange-800";
      if (item.matched_cves && item.matched_cves.length > 0) {
        const topCve = item.matched_cves[0].cve || item.matched_cves[0].id;
        shortStatus = `เสี่ยง ${topCve}`;
      } else {
        shortStatus = "เสี่ยงระดับสูง (High)";
      }
    } else if (item.vulnerability === "Outdated") {
      shortStatus = "เวอร์ชันเก่า (EOL)";
      shortStatusIcon = "ph-clock-countdown";
      statusBadgeStyle = "bg-amber-50 text-amber-800 border-amber-300 hover:bg-amber-100 shadow-2xs font-semibold";
      sevPill = "OUTDATED";
      sevPillClass = "bg-amber-950 text-amber-300 border-amber-800";
    } else if (isWarn) {
      shortStatus = "ควรตรวจสอบ (Warning)";
      shortStatusIcon = "ph-warning";
      statusBadgeStyle = "bg-amber-50 text-amber-800 border-amber-300 hover:bg-amber-100 shadow-2xs font-semibold";
      sevPill = "WARNING";
      sevPillClass = "bg-amber-950 text-amber-300 border-amber-800";
    } else if (item.vulnerability === "Review Needed") {
      shortStatus = "ควรตรวจซ้ำ (Review)";
      shortStatusIcon = "ph-info";
      statusBadgeStyle = "bg-amber-50 text-amber-800 border-amber-300 hover:bg-amber-100 shadow-2xs font-semibold";
      sevPill = "REVIEW";
      sevPillClass = "bg-amber-950 text-amber-300 border-amber-800";
    } else if (item.is_php) {
      shortStatus = "ปลอดภัย (PHP Patched)";
      shortStatusIcon = "ph-shield-check";
      statusBadgeStyle = "bg-emerald-50 text-emerald-700 border-emerald-300 hover:bg-emerald-100 shadow-2xs font-semibold";
      sevPill = "SECURE";
      sevPillClass = "bg-emerald-950 text-emerald-300 border-emerald-800";
    } else if (item.is_node) {
      shortStatus = "ปลอดภัย (Node Patched)";
      shortStatusIcon = "ph-shield-check";
      statusBadgeStyle = "bg-emerald-50 text-emerald-700 border-emerald-300 hover:bg-emerald-100 shadow-2xs font-semibold";
      sevPill = "SECURE";
      sevPillClass = "bg-emerald-950 text-emerald-300 border-emerald-800";
    } else if (item.webServer && item.webServer !== "ไม่มี Web Service" && !(item.device_name && item.device_name.includes("LAN Client"))) {
      shortStatus = "ปลอดภัย (Web Service)";
      shortStatusIcon = "ph-check-circle";
      statusBadgeStyle = "bg-emerald-50 text-emerald-700 border-emerald-300 hover:bg-emerald-100 shadow-2xs font-semibold";
      sevPill = "SECURE";
      sevPillClass = "bg-emerald-950 text-emerald-300 border-emerald-800";
    }

    const ports = Array.isArray(item.ports) && item.ports.length > 0 ? item.ports : [];
    const isPhp = !!item.is_php;
    const isNode = !!item.is_node;
    const isGw = item.ip === appState.gateway || (item.device_name && item.device_name.includes("Gateway"));
    const isMobile = item.is_mobile || (item.device_name && item.device_name.includes("Private Wi-Fi"));

    let deviceIcon = "ph-desktop";
    let deviceIconColor = "text-slate-500";
    if (isNode) {
      deviceIcon = "ph-brackets-curly";
      deviceIconColor = "text-emerald-600";
    } else if (isPhp) {
      deviceIcon = "ph-file-php";
      deviceIconColor = "text-indigo-600";
    } else if (isGw) {
      deviceIcon = "ph-router";
      deviceIconColor = "text-blue-600";
    } else if (isMobile) {
      deviceIcon = "ph-device-mobile";
      deviceIconColor = "text-purple-600";
    } else if (item.device_name && item.device_name.toLowerCase().includes("apple")) {
      deviceIcon = "ph-laptop";
      deviceIconColor = "text-slate-700";
    } else if (item.device_name && (item.device_name.toLowerCase().includes("printer") || item.device_name.toLowerCase().includes("canon") || item.device_name.toLowerCase().includes("epson"))) {
      deviceIcon = "ph-printer";
      deviceIconColor = "text-amber-600";
    }

    // Dot indicator
    let dotColor = 'bg-slate-400';
    if (isNode && isPhp) {
      dotColor = 'bg-purple-600 animate-pulse';
    } else if (isNode) {
      dotColor = 'bg-emerald-500 animate-pulse';
    } else if (isPhp) {
      dotColor = 'bg-indigo-600 animate-pulse';
    } else if (item.is_online) {
      dotColor = 'bg-emerald-400';
    }

    // Runtime Column
    let runtimeHtml = '';
    if (isNode && isPhp) {
      runtimeHtml = `
        <div class="flex flex-col gap-1">
          <span class="font-mono px-2 py-0.5 rounded font-bold text-[10px] bg-indigo-50 text-indigo-700 border border-indigo-200 inline-flex items-center gap-1">
            <i class="ph-bold ph-file-php"></i> ${item.phpVersion || 'PHP'}
          </span>
          <span class="font-mono px-2 py-0.5 rounded font-bold text-[10px] bg-emerald-50 text-emerald-700 border border-emerald-200 inline-flex items-center gap-1">
            <i class="ph-bold ph-brackets-curly"></i> ${item.nodeVersion || item.runtime_version}
            ${item.has_brotli ? '<span class="ml-1 text-[8px] bg-emerald-200 text-emerald-800 px-1 py-0.2 rounded font-semibold">br</span>' : ''}
          </span>
        </div>
      `;
    } else if (isNode) {
      runtimeHtml = `
        <span class="font-mono px-2 py-0.5 rounded font-bold text-[11px] bg-emerald-50 text-emerald-700 border border-emerald-200 inline-flex items-center gap-1">
          <i class="ph-bold ph-brackets-curly"></i> ${item.nodeVersion || item.runtime_version}
          ${item.has_brotli ? '<span class="ml-1 text-[9px] bg-emerald-200 text-emerald-800 px-1 py-0.2 rounded font-semibold">br</span>' : ''}
        </span>
      `;
    } else if (isPhp) {
      runtimeHtml = `
        <span class="font-mono px-2 py-0.5 rounded font-bold text-[11px] bg-indigo-50 text-indigo-700 border border-indigo-200 inline-flex items-center gap-1">
          <i class="ph-bold ph-file-php"></i> ${item.phpVersion}
        </span>
      `;
    } else {
      runtimeHtml = `
        <span class="font-mono px-2 py-0.5 rounded font-medium text-[11px] bg-slate-100 text-slate-500 border border-slate-200">
          ไม่มี Web Service
        </span>
      `;
    }

    const isActionInspect = isPhp || isNode || (item.matched_cves && item.matched_cves.length > 0) || (item.deep_audit && item.deep_audit.kernel_audit);
    const targetPort = item.port || (item.ports && item.ports[0]) || null;
    const targetId = item.target_id || (targetPort ? `${item.ip}:${targetPort}` : item.ip);
    const webUrl = getWebTargetUrl(item, targetPort);
    const hasWebOrPorts = targetPort || ports.length > 0 || isPhp || isNode;

    row.innerHTML = `
      <td class="py-3 px-3 font-mono font-semibold text-slate-800">
        <div class="flex items-center gap-1.5 flex-wrap">
          <span class="w-2 h-2 rounded-full ${dotColor}"></span>
          ${hasWebOrPorts ? `
            <a href="${webUrl}" target="_blank" title="เปิดหน้าเว็บ ${webUrl}" class="hover:underline hover:text-blue-600 inline-flex items-center gap-1 text-slate-800">
              <span>${item.ip}</span>
              ${targetPort ? `<span class="px-1.5 py-0.5 rounded text-[10px] font-bold font-mono bg-blue-100/90 text-blue-700 border border-blue-200">:${targetPort}</span>` : ''}
              <i class="ph-bold ph-arrow-square-out text-[11px] text-slate-400"></i>
            </a>
          ` : `<span>${item.ip}</span>`}
        </div>
      </td>
      <td class="py-3 px-3 text-slate-700">
        <div class="flex items-start gap-2">
          <div class="w-7 h-7 rounded-lg outer-dish flex items-center justify-center flex-shrink-0 mt-0.5 ${deviceIconColor}">
            <i class="ph ${deviceIcon} text-base"></i>
          </div>
          <div class="flex flex-col min-w-0">
            <span class="font-bold text-slate-800 text-xs">${item.device_name || item.webServer}</span>
            <span class="text-[10px] text-slate-400 font-mono">${item.mac ? 'MAC: ' + item.mac : 'DHCP Host'}</span>
            <div class="flex flex-wrap gap-1 mt-1">
              ${(item.thaicert_groups && item.thaicert_groups.length > 0 ? item.thaicert_groups : [4]).map(g => {
                const titles = {
                  1: "ก.1 เว็บไซต์/CMS",
                  2: "ก.2 แอป & API",
                  3: "ก.3 Hosting Panel",
                  4: "ก.4 ซอฟต์แวร์/อุปกรณ์",
                  5: "ก.5 Container/K8s",
                  6: "ก.6 Windows PHP ⚠️",
                  7: "ก.7 Dev/UAT/สำรอง",
                  8: "ก.8 Cloud/ภายนอก"
                };
                const isG6 = g === 6;
                const isV = item.vulnerability === 'Critical' || item.vulnerability === 'Warning';
                const bgCls = isG6 ? (isV ? 'bg-rose-100 text-rose-800 border-rose-300 font-bold' : 'bg-amber-100 text-amber-800 border-amber-300') : 'bg-slate-100 text-slate-600 border-slate-200';
                return `<span class="px-1.5 py-0.2 rounded text-[9px] border ${bgCls}">${titles[g] || 'ก.' + g}</span>`;
              }).join('')}
            </div>
          </div>
        </div>
      </td>
      <td class="py-3 px-3">
        ${runtimeHtml}
      </td>
      <td class="py-3 px-3">
        ${targetPort ? `
          <div class="flex items-center gap-1">
            <a href="${webUrl}" target="_blank" title="เปิดบริการบนพอร์ต ${targetPort} (${webUrl})" class="bg-blue-50 hover:bg-blue-600 hover:text-white text-blue-700 border border-blue-200 px-2 py-0.5 rounded text-[11px] font-mono font-bold inline-flex items-center gap-1 transition">
              <i class="ph-bold ph-plug text-xs"></i>
              <span>${targetPort}</span>
              <i class="ph-bold ph-arrow-square-out text-[9px] opacity-70"></i>
            </a>
          </div>
        ` : `<span class="text-slate-400 font-mono text-[10px]">พอร์ตปิด (Firewall)</span>`}
      </td>
      <td class="py-3 px-3 font-mono text-slate-600 text-[11px]">${item.latency || '< 5 ms'}</td>
      <td class="py-2.5 px-3">
        <div class="thaicert-badge-wrap inline-block"
             data-target="${item.ip}${targetPort ? ':' + targetPort : ''}"
             data-status="${encodeURIComponent(shortStatus)}"
             data-sev="${sevPill}"
             data-sev-class="${sevPillClass}"
             data-note="${encodeURIComponent(item.cveNote || '')}"
             data-cves="${encodeURIComponent(JSON.stringify(item.matched_cves || []))}">
          <div class="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full border text-[11px] cursor-pointer transition-all duration-150 hover:scale-[1.02] ${statusBadgeStyle}">
            <i class="ph-bold ${shortStatusIcon} text-xs flex-shrink-0"></i>
            <span class="whitespace-nowrap font-medium">${shortStatus}</span>
            <i class="ph-bold ph-info text-[10px] opacity-60"></i>
          </div>
          ${isRceProved ? `
            <div class="mt-1 flex items-center gap-1">
              <span class="px-2 py-0.5 rounded text-[9.5px] font-mono font-bold bg-rose-600 text-white shadow-2xs inline-flex items-center gap-1">
                <i class="ph-bold ph-terminal-window"></i> RCE ยืนยันผล
              </span>
            </div>
          ` : ''}
        </div>
      </td>
      <td class="py-3 px-3 text-right">
        <div class="inline-flex items-center justify-end gap-1.5">
          ${hasWebOrPorts ? `
            <a href="${webUrl}" target="_blank" title="เปิดดูหน้าเว็บจริง (${webUrl})" class="px-2 py-1 rounded-lg bg-emerald-50 hover:bg-emerald-600 hover:text-white text-emerald-700 border border-emerald-200 transition text-[11px] font-semibold inline-flex items-center gap-1">
              <i class="ph-bold ph-arrow-square-out"></i>
              <span>เปิดเว็บ</span>
            </a>
          ` : ''}
          <button data-action="inspectHost" data-arg="${escapeHtml(targetId)}" class="px-2.5 py-1 rounded-lg ${isActionInspect ? 'bg-blue-50 hover:bg-blue-600 hover:text-white text-blue-700 border border-blue-200' : 'bg-slate-100 hover:bg-slate-200 text-slate-700 border border-slate-200'} transition text-[11px] font-semibold">
            ${isActionInspect ? 'ตรวจเจาะลึก' : 'ข้อมูล Host'}
          </button>
        </div>
      </td>
    `;
    resultsTableBody.appendChild(row);
  });
}

export function getFilteredResultsList() {
  const term = ((document.getElementById('inputSearchHost') as HTMLInputElement | null)?.value || '').trim().toLowerCase();
  let baseList = [];
  if (appState.activeFilter === 'all_online') {
    baseList = appState.allHosts;
  } else if (appState.activeFilter === 'php_only') {
    baseList = appState.allHosts.filter(h => h.is_php);
  } else if (appState.activeFilter === 'node_only') {
    baseList = appState.allHosts.filter(h => h.is_node);
  } else if (appState.activeFilter === 'vulnerable') {
    baseList = appState.allHosts.filter(h => (h.is_php || h.is_node) && (h.vulnerability === 'Critical' || h.vulnerability === 'Outdated' || h.vulnerability === 'Warning'));
  } else if (appState.activeFilter === 'workstations') {
    baseList = appState.allHosts.filter(h => !h.is_php && !h.is_node);
  } else {
    baseList = appState.allHosts;
  }

  // ThaiCERT 8 Groups Filter
  if (appState.activeGroupFilter) {
    baseList = baseList.filter(item => (item.thaicert_groups || []).includes(appState.activeGroupFilter));
  }

  // Enterprise Scope Presets Filter
  if (appState.scopePreset === 'windows') {
    baseList = baseList.filter(item => (item.thaicert_groups || []).includes(6));
  } else if (appState.scopePreset === 'web_api') {
    baseList = baseList.filter(item => {
      const g = item.thaicert_groups || [];
      return g.includes(1) || g.includes(2);
    });
  } else if (appState.scopePreset === 'dev_shadow') {
    baseList = baseList.filter(item => (item.thaicert_groups || []).includes(7));
  }

  if (term) {
    baseList = baseList.filter(item => 
      (item.ip && item.ip.toLowerCase().includes(term)) ||
      (item.port && String(item.port).includes(term)) ||
      (item.target_id && item.target_id.toLowerCase().includes(term)) ||
      (item.webServer && item.webServer.toLowerCase().includes(term)) ||
      (item.primary_group && item.primary_group.toLowerCase().includes(term)) ||
      (item.group_labels && item.group_labels.some(l => l.toLowerCase().includes(term))) ||
      (item.phpVersion && item.phpVersion.toLowerCase().includes(term)) ||
      (item.nodeVersion && item.nodeVersion.toLowerCase().includes(term)) ||
      (item.runtime_version && item.runtime_version.toLowerCase().includes(term)) ||
      (item.cveNote && item.cveNote.toLowerCase().includes(term))
    );
  }
  return baseList;
}

export function toggleGroupFilter(g) {
  if (appState.activeGroupFilter === g) {
    appState.activeGroupFilter = null;
  } else {
    appState.activeGroupFilter = g;
  }
  renderResultsTable();
}

export function clearGroupFilter() {
  appState.activeGroupFilter = null;
  renderResultsTable();
}

export function onScopePresetChange(preset) {
  appState.scopePreset = preset;
  renderResultsTable();
  const presetNames = {
    all: "ตรวจสอบครบทั้ง 8 กลุ่มระบบ",
    windows: "เน้นกลุ่ม 6: Windows + PHP",
    web_api: "เน้นกลุ่ม 1 & 2: เว็บไซต์และ API ภายใน",
    dev_shadow: "เน้นกลุ่ม 7: ระบบทดสอบ / เก่า / สำรอง"
  };
  showToast(`ขอบเขต: ${presetNames[preset] || preset}`);
}

export function switchFilterToAll() {
  appState.activeFilter = 'all_online';
  document.querySelectorAll('.filter-tab').forEach(t => {
    t.classList.toggle('active', t.getAttribute('data-filter') === 'all_online');
  });
  renderResultsTable();
}

// Export CSV feature
export function exportToCsv() {
  const listToExport = getFilteredResultsList();
  if (!listToExport || listToExport.length === 0) {
    showToast("ไม่พบข้อมูลที่จะส่งออก");
    return;
  }
  let csvContent = "\uFEFFIP Address,Device Type,Runtime / Version,Open Ports,Latency,ThaiCERT Groups,Primary Group,Security Chains Status,Security Assessment,Remediation Advice\n";
  listToExport.forEach(item => {
    const portsStr = Array.isArray(item.ports) && item.ports.length > 0 ? item.ports.join(';') : 'Closed';
    const runtimeVal = item.runtime_version || item.phpVersion || 'ไม่มี Web Service';
    const groupsStr = (item.thaicert_groups || []).join(';');
    const primaryG = item.primary_group || 'กลุ่ม 4: ซอฟต์แวร์/อุปกรณ์ทั่วไป';
    const secChains = item.security_chains || (item.deep_audit && item.deep_audit.security_chains) || {};
    const chainsStatus = secChains.overall_status || (item.is_php ? 'Hardened' : 'N/A');
    const remedy = item.vulnerability === 'Critical' 
      ? 'อัปเกรด PHP เป็น 8.2.20+ / 8.3.8+ ด่วน หรือตั้งค่า session.upload_progress.enabled = Off'
      : (item.is_php ? 'ตั้งค่า session.use_strict_mode = 1 และ expose_php = Off' : 'ระบบปกติ');
    csvContent += `"${item.ip}","${item.device_name || item.webServer}","${runtimeVal}","${portsStr}","${item.latency || '1ms'}","${groupsStr}","${primaryG}","${chainsStatus}","${item.cveNote}","${remedy}"\n`;
  });
  const blob = new Blob([csvContent], { type: 'text/csv;charset=utf-8;' });
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.setAttribute("href", url);
  link.setAttribute("download", `ThaiCERT_Network_Scan_${appState.subnetPrefix || 'scan_'}report.csv`);
  document.body.appendChild(link);
  link.click();
  document.body.removeChild(link);
  URL.revokeObjectURL(url);
  showToast(`ส่งออกรายงาน CSV สำเร็จ (${listToExport.length} รายการ)`);
}

// Modal Control Functions
export function openResultsModal() {
  resultsModal.classList.remove('opacity-0', 'pointer-events-none');
  const bodyEl = document.getElementById('resultsModalBody');
  if (bodyEl) bodyEl.scrollTop = 0;
  if (typeof renderThaiCertDualCharts === 'function') {
    renderThaiCertDualCharts();
  }
}

export function closeResultsModal() {
  resultsModal.classList.add('opacity-0', 'pointer-events-none');
}