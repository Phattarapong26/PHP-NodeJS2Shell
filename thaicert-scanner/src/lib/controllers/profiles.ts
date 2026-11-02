import { apiFetch } from './api';
import { renderThaiCertVisualCharts } from './charts';
import { badgeFilteredCount, btnCancelProfileForm, btnClearCustomHeaders, btnCloseDetailDrawerBottom, btnCloseProfileDetailDrawer, btnCloseProfileFormModal, btnDetailActivateProfile, btnDetailEditProfile, btnDrawerAutoDetect, btnDrawerCreateProfile, btnEmptyCreateProfile, btnFormDetectNetwork, btnHeaderPresetProxy, btnHeaderPresetRef, btnHeaderPresetXff, btnHeaderProfile, btnOpenCreateProfileFromList, btnPresetSpeedBalanced, btnPresetSpeedStealth, btnPresetSpeedTurbo, headerProfileName, mainSubnetInput, profileDetailDrawer, profileDrawerBackdrop, profileEmptyState, profileForm, profileFormConcurrency, profileFormConcurrencyDisplay, profileFormCustomHeaders, profileFormCustomPorts, profileFormCustomPortsWrapper, profileFormCustomUa, profileFormCustomUaWrapper, profileFormDesc, profileFormHeading, profileFormId, profileFormNetwork, profileFormSetActive, profileFormTimeout, profileFormTimeoutDisplay, profileFormTitle, profileFormUaPreset, profileSelectDrawer, profilesListContainer, quickPhpCount, scanElapsedDuration } from './dom';
import { autoDetectLocalNetwork, recalculateSubnet } from './network';
import { WIDE_PORTS_COLLECTION } from './ports';
import { openResultsModal, renderResultsTable } from './results';
import { closeProfileDrawer, closeProfileModal, openProfileModal } from './shell';
import { appState } from './state';
import { showToast } from './ui';
import { escapeHtml } from './utils';

// ==========================================
// SCAN PROFILE & SYSTEM UPDATE LOGIC
// ==========================================
export const UA_PRESETS = {
  chrome: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
  edge: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36 Edg/124.0.0.0",
  safari: "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Safari/605.1.15",
  ios: "Mozilla/5.0 (iPhone; CPU iPhone OS 17_4 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Mobile/15E148 Safari/604.1",
  googlebot: "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
  official: "ThaiCERT-OPScaner/2.0 (LAN Discovery & Security Audit)",
  custom: ""
};

export function getUaKeyFromString(ua) {
  if (!ua) return 'chrome';
  for (const [k, v] of Object.entries(UA_PRESETS)) {
    if (k !== 'custom' && v === ua) return k;
  }
  return 'custom';
}

export function getUaDisplayLabel(ua) {
  if (!ua) return 'Chrome Desktop';
  for (const [k, v] of Object.entries(UA_PRESETS)) {
    if (k !== 'custom' && v === ua) {
      if (k === 'chrome') return 'Chrome Desktop';
      if (k === 'edge') return 'Microsoft Edge';
      if (k === 'safari') return 'Apple Safari macOS';
      if (k === 'ios') return 'Safari iPhone / iOS';
      if (k === 'googlebot') return 'Googlebot Web Crawler';
      if (k === 'official') return 'ThaiCERT Official Agent';
    }
  }
  return 'Custom User-Agent';
}

export async function loadProfiles() {
  try {
    const res = await apiFetch('/api/profiles');
    const data = await res.json();
    if (data.status === 'ok') {
      appState.profilesList = data.profiles || [];
      if (data.active_profile) {
        syncProfileToAppState(data.active_profile);
      } else {
        appState.activeProfile = null;
        updateHeaderProfileUI();
      }
      renderProfileList();
    }
  } catch (err) {
    console.warn('Failed to load profiles:', err);
  }
}

export function updateHeaderProfileUI() {
  if (!headerProfileName) return;
  if (appState.activeProfile) {
    headerProfileName.textContent = appState.activeProfile.title;
    headerProfileName.className = "font-bold text-blue-700 max-w-[170px] truncate";
    if (btnHeaderProfile) {
      btnHeaderProfile.classList.add('bg-blue-50/90', 'border-blue-300');
      btnHeaderProfile.classList.remove('bg-white/70', 'border-slate-200/90', 'bg-amber-50/80', 'border-amber-300');
      btnHeaderProfile.title = `Profile ปัจจุบัน: ${appState.activeProfile.title} (${appState.activeProfile.network_target || 'IP อัตโนมัติ'})`;
    }
    // Sync settings to active profile
    if (appState.activeProfile.network_target && mainSubnetInput) {
      mainSubnetInput.value = appState.activeProfile.network_target;
      recalculateSubnet(appState.activeProfile.network_target);
    }
    if (appState.activeProfile.concurrency) {
      appState.concurrency = parseInt(appState.activeProfile.concurrency, 10);
    }
  } else {
    headerProfileName.textContent = "ยังไม่ได้เลือก Profile";
    headerProfileName.className = "font-bold text-amber-700 max-w-[170px] truncate";
    if (btnHeaderProfile) {
      btnHeaderProfile.classList.remove('bg-blue-50/90', 'border-blue-300');
      btnHeaderProfile.classList.add('bg-amber-50/80', 'border-amber-300');
      btnHeaderProfile.title = "⚠️ ยังไม่ได้เลือก Profile (คลิกเพื่อเลือก)";
    }
  }
}

export function renderProfileList() {
  if (!profilesListContainer || !profileEmptyState) return;

  const profiles = appState.profilesList || [];
  if (profiles.length === 0) {
    profileEmptyState.classList.remove('hidden');
    profilesListContainer.classList.add('hidden');
    return;
  }

  profileEmptyState.classList.add('hidden');
  profilesListContainer.classList.remove('hidden');

  profilesListContainer.innerHTML = profiles.map(p => {
    const isActive = appState.activeProfile && appState.activeProfile.id === p.id;
    const targetDisplay = p.network_target ? escapeHtml(p.network_target) : 'IP เครื่องปัจจุบัน (Auto)';
    const descDisplay = p.description ? escapeHtml(p.description) : 'ไม่มีคำอธิบายเพิ่มเติม';
    const concurrencyVal = p.concurrency || 60;
    const timeoutVal = p.timeout || 2.2;
    const uaLabel = getUaDisplayLabel(p.user_agent);
    const portModeLabel = p.port_mode === 'wide' ? 'พอร์ตกว้าง (Top 100)' : (p.port_mode === 'custom' ? 'พอร์ตกำหนดเอง' : 'มาตรฐาน Dev (23 พอร์ต)');
    
    return `
      <div class="p-3.5 rounded-2xl border transition-all ${isActive ? 'bg-blue-50/80 border-blue-400 shadow-sm ring-1 ring-blue-400/40' : 'bg-white border-slate-200 hover:border-slate-300 shadow-xs'} flex flex-col gap-2.5">
        <div class="flex items-start justify-between gap-3">
          <div class="flex-1 min-w-0">
            <div class="flex items-center gap-2 mb-1">
              <span class="font-bold text-sm text-slate-800 truncate">${escapeHtml(p.title)}</span>
              ${isActive ? '<span class="px-2 py-0.5 rounded-md bg-emerald-100 text-emerald-800 text-[10px] font-bold border border-emerald-300 flex items-center gap-1 flex-shrink-0"><i class="ph-bold ph-check text-xs"></i> ใช้งานอยู่</span>' : ''}
            </div>
            <div class="flex items-center gap-2 text-xs text-slate-500 mb-1">
              <span class="inline-flex items-center gap-1 font-mono text-[11px] bg-slate-100 px-2 py-0.5 rounded text-slate-700">
                <i class="ph-bold ph-target text-blue-600"></i> ${targetDisplay}
              </span>
            </div>
            <p class="text-[11px] text-slate-500 line-clamp-1">${descDisplay}</p>
          </div>

          <div class="flex items-center gap-1.5 flex-shrink-0">
            ${!isActive ? `
              <button type="button" data-action="handleSelectProfile" data-arg="${p.id}" class="px-2.5 py-1.5 rounded-xl bg-blue-600 hover:bg-blue-700 text-white font-bold text-xs shadow-xs transition flex items-center gap-1 cursor-pointer" title="เลือกใช้งาน Profile นี้">
                <i class="ph-bold ph-check"></i>
                <span>เลือก</span>
              </button>
            ` : ''}
            <button type="button" data-action="openProfileDetailDrawer" data-arg="${p.id}" class="px-2.5 py-1.5 rounded-xl bg-indigo-50 hover:bg-indigo-100 text-indigo-700 border border-indigo-200 font-bold text-xs shadow-xs transition flex items-center gap-1 cursor-pointer" title="ดูข้อมูลการตั้งค่าและประวัติการสแกนย้อนหลัง">
              <i class="ph-bold ph-eye text-sm"></i>
              <span>ดูข้อมูล & ประวัติ</span>
            </button>
            <button type="button" data-action="handleEditProfile" data-arg="${p.id}" class="w-8 h-8 rounded-xl bg-slate-100 hover:bg-slate-200 text-slate-600 flex items-center justify-center transition cursor-pointer" title="แก้ไข Profile">
              <i class="ph-bold ph-pencil-simple text-sm"></i>
            </button>
            <button type="button" data-action="handleDeleteProfile" data-arg="${p.id}" class="w-8 h-8 rounded-xl bg-rose-50 hover:bg-rose-100 text-rose-600 flex items-center justify-center transition cursor-pointer" title="ลบ Profile">
              <i class="ph-bold ph-trash text-sm"></i>
            </button>
          </div>
        </div>

        <!-- Profile Spec Tags -->
        <div class="flex flex-wrap items-center gap-1.5 pt-2 border-t border-slate-200/60 text-[10px]">
          <span class="px-2 py-0.5 rounded-md bg-amber-50 text-amber-900 border border-amber-200 font-mono font-semibold flex items-center gap-1">
            <i class="ph-bold ph-lightning text-amber-600"></i> ${concurrencyVal} reqs (${timeoutVal}s)
          </span>
          <span class="px-2 py-0.5 rounded-md bg-indigo-50 text-indigo-900 border border-indigo-200 font-semibold flex items-center gap-1">
            <i class="ph-bold ph-mask-happy text-indigo-600"></i> ${uaLabel}
          </span>
          <span class="px-2 py-0.5 rounded-md bg-slate-100 text-slate-700 font-semibold">
            ${portModeLabel}
          </span>
          ${p.custom_headers ? '<span class="px-1.5 py-0.5 rounded bg-emerald-50 text-emerald-800 border border-emerald-200 font-semibold">Custom Headers</span>' : ''}
        </div>
      </div>
    `;
  }).join('');
}

export async function handleSelectProfile(profileId) {
  try {
    const res = await apiFetch(`/api/profiles/${profileId}/select`, { method: 'POST' });
    const data = await res.json();
    if (data.status === 'ok') {
      syncProfileToAppState(data.active_profile);
      renderProfileList();
      showToast(`เลือกใช้งาน Profile: ${data.active_profile.title}`);
      closeProfileDrawer();
      closeProfileDetailDrawer();
    } else {
      showToast(data.message || 'เกิดข้อผิดพลาดในการเลือก Profile');
    }
  } catch (err) {
    showToast('ไม่สามารถเชื่อมต่อเซิร์ฟเวอร์ได้');
  }
}

// ==========================================
// 80% WIDTH PROFILE DETAIL & HISTORY DRAWER
// ==========================================
export async function openProfileDetailDrawer(profileId) {
  try {
    const resProf = await apiFetch(`/api/profiles/${profileId}`);
    const dataProf = await resProf.json();
    if (dataProf.status !== 'ok') {
      showToast(dataProf.message || 'ไม่พบข้อมูล Profile');
      return;
    }
    const profile = dataProf.profile;

    // Render Profile Specs in Header
    const detailProfileTitle = document.getElementById('detailProfileTitle');
    const detailProfileDesc = document.getElementById('detailProfileDesc');
    const detailProfileIdBadge = document.getElementById('detailProfileIdBadge');
    const detailProfileActiveBadge = document.getElementById('detailProfileActiveBadge');

    if (detailProfileTitle) detailProfileTitle.textContent = profile.title;
    if (detailProfileDesc) detailProfileDesc.textContent = profile.description || 'ไม่มีคำอธิบายเพิ่มเติมสำหรับ Profile นี้';
    if (detailProfileIdBadge) detailProfileIdBadge.textContent = `ID: ${profile.id}`;

    if (detailProfileActiveBadge) {
      if (profile.is_active) {
        detailProfileActiveBadge.classList.remove('hidden');
      } else {
        detailProfileActiveBadge.classList.add('hidden');
      }
    }

    if (btnDetailActivateProfile) {
      if (profile.is_active) {
        btnDetailActivateProfile.classList.add('hidden');
      } else {
        btnDetailActivateProfile.classList.remove('hidden');
        btnDetailActivateProfile.onclick = () => handleSelectProfile(profile.id);
      }
    }

    if (btnDetailEditProfile) {
      btnDetailEditProfile.onclick = () => handleEditProfile(profile.id);
    }

    // Render Config Matrix
    const detailConfigTarget = document.getElementById('detailConfigTarget');
    const detailConfigConcurrency = document.getElementById('detailConfigConcurrency');
    const detailConfigTimeout = document.getElementById('detailConfigTimeout');
    const detailConfigUaName = document.getElementById('detailConfigUaName');
    const detailConfigHeadersCount = document.getElementById('detailConfigHeadersCount');
    const detailConfigPortMode = document.getElementById('detailConfigPortMode');
    const detailConfigScope = document.getElementById('detailConfigScope');
    const detailFullUserAgent = document.getElementById('detailFullUserAgent');
    const detailCustomHeadersText = document.getElementById('detailCustomHeadersText');

    if (detailConfigTarget) detailConfigTarget.textContent = profile.network_target || 'IP เครื่องปัจจุบัน (Auto)';
    if (detailConfigConcurrency) detailConfigConcurrency.textContent = `${profile.concurrency || 60} reqs`;
    if (detailConfigTimeout) detailConfigTimeout.textContent = `Timeout ${profile.timeout || 2.2}s`;
    if (detailConfigUaName) detailConfigUaName.textContent = getUaDisplayLabel(profile.user_agent);

    const customHdrStr = profile.custom_headers ? profile.custom_headers.trim() : "";
    const customHdrLines = customHdrStr ? customHdrStr.split('\n').filter(l => l.trim().length > 0) : [];
    if (detailConfigHeadersCount) {
      detailConfigHeadersCount.textContent = customHdrLines.length > 0 
        ? `กำหนด Headers อำพราง ${customHdrLines.length} ค่า` 
        : 'ไม่ได้กำหนด Headers เพิ่มเติม';
    }

    let portModeText = "มาตรฐาน Dev (23 พอร์ต)";
    if (profile.port_mode === 'wide') portModeText = "สแกนกว้าง (Top 100 พอร์ต)";
    else if (profile.port_mode === 'custom') portModeText = `กำหนดเอง: ${profile.custom_ports || '80, 443'}`;
    if (detailConfigPortMode) detailConfigPortMode.textContent = portModeText;

    let scopeText = "ครอบคลุม 8 กลุ่มระบบ (Enterprise)";
    if (profile.scope_preset === 'windows') scopeText = "เน้นกลุ่ม 6: Windows IIS + PHP";
    else if (profile.scope_preset === 'web_api') scopeText = "เน้นกลุ่ม 1 & 2: Web & API";
    else if (profile.scope_preset === 'dev_shadow') scopeText = "เน้นกลุ่ม 7: Dev / Shadow IT";
    if (detailConfigScope) detailConfigScope.textContent = scopeText;

    if (detailFullUserAgent) {
      detailFullUserAgent.textContent = profile.user_agent || UA_PRESETS.chrome;
    }
    if (detailCustomHeadersText) {
      detailCustomHeadersText.textContent = customHdrStr || "ไม่มีการกำหนด Header เพิ่มเติม";
    }

    // Fetch & Render Scan History Timeline
    await renderProfileScanHistory(profile.id);

    // Slide Open Detail Drawer (80% Width)
    if (profileDrawerBackdrop) {
      profileDrawerBackdrop.classList.remove('pointer-events-none', 'opacity-0');
    }
    if (profileDetailDrawer) {
      profileDetailDrawer.classList.remove('invisible');
      requestAnimationFrame(() => {
        profileDetailDrawer.classList.remove('translate-x-full');
      });
    }
  } catch (err) {
    showToast('เกิดข้อผิดพลาดในการโหลดรายละเอียด Profile');
  }
}

export async function renderProfileScanHistory(profileId) {
  const detailHistoryCountBadge = document.getElementById('detailHistoryCountBadge');
  const detailHistoryEmptyState = document.getElementById('detailHistoryEmptyState');
  const detailHistoryListContainer = document.getElementById('detailHistoryListContainer');

  if (!detailHistoryListContainer) return;

  try {
    const res = await apiFetch(`/api/profiles/${profileId}/history`);
    const data = await res.json();
    const historyList = (data.status === 'ok') ? (data.history || []) : [];

    if (detailHistoryCountBadge) {
      detailHistoryCountBadge.textContent = `${historyList.length} รอบ`;
    }

    if (historyList.length === 0) {
      if (detailHistoryEmptyState) detailHistoryEmptyState.classList.remove('hidden');
      detailHistoryListContainer.classList.add('hidden');
      detailHistoryListContainer.innerHTML = '';
      return;
    }

    if (detailHistoryEmptyState) detailHistoryEmptyState.classList.add('hidden');
    detailHistoryListContainer.classList.remove('hidden');

    detailHistoryListContainer.innerHTML = historyList.map(h => {
      const vulnBadge = (h.vuln_hosts > 0)
        ? `<span class="px-2 py-0.5 rounded-md bg-rose-100 text-rose-800 border border-rose-300 font-bold flex items-center gap-1"><i class="ph-bold ph-warning text-xs"></i> เสี่ยง ${h.vuln_hosts} เครื่อง</span>`
        : `<span class="px-2 py-0.5 rounded-md bg-emerald-100 text-emerald-800 border border-emerald-300 font-bold flex items-center gap-1"><i class="ph-bold ph-shield-check text-xs"></i> ปลอดภัย (0 ช่องโหว่)</span>`;

      return `
        <div class="p-4 rounded-2xl bg-white border border-slate-200 shadow-xs flex flex-col gap-2.5 hover:border-blue-300 transition">
          <div class="flex items-center justify-between gap-3">
            <div class="flex items-center gap-2">
              <div class="w-7 h-7 rounded-lg bg-blue-50 text-blue-700 flex items-center justify-center font-bold text-xs">
                <i class="ph-bold ph-calendar-check"></i>
              </div>
              <div>
                <span class="font-bold text-slate-800 text-xs">${escapeHtml(h.created_at)}</span>
                <span class="font-mono text-[10px] text-slate-500 bg-slate-100 px-1.5 py-0.2 rounded ml-1 border border-slate-200">${escapeHtml(h.target_subnet || '-')}</span>
              </div>
            </div>

            <div class="flex items-center gap-2">
              <button type="button" data-action="handleRestoreScanHistory" data-arg="${h.id}" class="neu-pill-btn active px-3 py-1.5 rounded-xl text-white font-bold text-xs shadow-xs flex items-center gap-1.5 cursor-pointer hover:scale-[1.01] transition" title="โหลดผลสแกนและกราฟสถิติของรอบนี้ขึ้นมาแสดง">
                <i class="ph-bold ph-chart-polar text-sm"></i>
                <span>ดูผลสแกนรอบนี้ย้อนหลัง</span>
              </button>
              <button type="button" data-action="handleDeleteScanHistory" data-arg="${h.id}" data-arg2="${profileId}" class="w-7 h-7 rounded-lg bg-slate-100 hover:bg-rose-100 text-slate-400 hover:text-rose-600 flex items-center justify-center transition cursor-pointer" title="ลบประวัติการสแกนรอบนี้">
                <i class="ph-bold ph-trash text-xs"></i>
              </button>
            </div>
          </div>

          <!-- Metrics Row -->
          <div class="flex flex-wrap items-center gap-2 text-[10.5px] pt-1 border-t border-slate-100">
            <span class="px-2 py-0.5 rounded bg-slate-100 text-slate-700 font-mono">
              สแกนรวม <b>${h.total_hosts || 0}</b> เครื่อง (${h.elapsed_seconds || 0}s)
            </span>
            <span class="px-2 py-0.5 rounded bg-blue-50 text-blue-800 font-mono">
              🐘 PHP: <b>${h.php_hosts || 0}</b> เครื่อง
            </span>
            <span class="px-2 py-0.5 rounded bg-emerald-50 text-emerald-800 font-mono">
              🟢 Node.js: <b>${h.node_hosts || 0}</b> เครื่อง
            </span>
            ${vulnBadge}
          </div>

          ${h.scan_summary ? `<p class="text-[10px] text-slate-400 italic">${escapeHtml(h.scan_summary)}</p>` : ''}
        </div>
      `;
    }).join('');

  } catch (err) {
    console.warn('Failed to load history:', err);
  }
}

export function closeProfileDetailDrawer() {
  if (profileDetailDrawer) {
    profileDetailDrawer.classList.add('translate-x-full');
  }
  if (!profileSelectDrawer || profileSelectDrawer.classList.contains('translate-x-full')) {
    if (profileDrawerBackdrop) {
      profileDrawerBackdrop.classList.add('opacity-0', 'pointer-events-none');
    }
  }
  setTimeout(() => {
    if (profileDetailDrawer) profileDetailDrawer.classList.add('invisible');
  }, 300);
}

export async function handleRestoreScanHistory(historyId) {
  try {
    const res = await apiFetch(`/api/scan-history/${historyId}/restore`, { method: 'POST' });
    const data = await res.json();
    if (data.status !== 'ok' || !data.history_record) {
      showToast(data.message || 'ไม่สามารถโหลดผลสแกนย้อนหลังได้');
      return;
    }

    const record = data.history_record;
    let resultJson = null;
    try {
      resultJson = JSON.parse(record.scan_result_json);
    } catch (e) {
      showToast('รูปแบบข้อมูลผลสแกนไม่สมบูรณ์');
      return;
    }

    // Restore into appState
    appState.allHosts = resultJson.hosts || [];
    appState.foundPhpHosts = resultJson.php_hosts || [];
    appState.foundNodeHosts = resultJson.node_hosts || [];
    appState.totalHosts = resultJson.total_hosts || appState.allHosts.length;
    appState.totalPhpFound = resultJson.php_count || appState.foundPhpHosts.length;
    appState.totalNodeFound = resultJson.node_count || appState.foundNodeHosts.length;
    appState.totalVulnFound = resultJson.vuln_count || 0;
    appState.thaicertSummary = resultJson.thaicert_groups || {};

    if (quickPhpCount) quickPhpCount.textContent = appState.totalPhpFound;
    if (badgeFilteredCount) badgeFilteredCount.textContent = appState.allHosts.length;
    if (scanElapsedDuration) scanElapsedDuration.textContent = record.elapsed_seconds ? `${record.elapsed_seconds} วินาที` : "-";

    // Close drawers & open results modal
    closeProfileDetailDrawer();
    closeProfileDrawer();

    openResultsModal();
    renderThaiCertVisualCharts();
    renderResultsTable();

    showToast(`โหลดผลสแกนย้อนหลังของวันที่ ${record.created_at} เรียบร้อยแล้ว`);
  } catch (err) {
    showToast('เกิดข้อผิดพลาดในการโหลดผลสแกนย้อนหลัง');
  }
}

export async function handleDeleteScanHistory(historyId, profileId) {
  if (!confirm('ยืนยันการลบประวัติการสแกนรอบนี้หรือไม่?')) return;
  try {
    const res = await apiFetch(`/api/scan-history/${historyId}`, { method: 'DELETE' });
    const data = await res.json();
    if (data.status === 'ok') {
      showToast('ลบประวัติการสแกนสำเร็จ');
      await renderProfileScanHistory(profileId);
    } else {
      showToast(data.message || 'ไม่สามารถลบประวัติได้');
    }
  } catch (err) {
    showToast('เกิดข้อผิดพลาดในการเชื่อมต่อ');
  }
}

// ==========================================
// PROFILE FORM MODAL CONTROLS (Create / Edit)
// ==========================================
export function openProfileFormModal() {
  const modal = document.getElementById('profileFormModal');
  if (modal) {
    modal.classList.remove('opacity-0', 'pointer-events-none', 'hidden');
    modal.classList.add('opacity-100');
    modal.style.display = 'flex';
    modal.style.opacity = '1';
    modal.style.pointerEvents = 'auto';
    modal.style.visibility = 'visible';
  }
}

export function closeProfileFormModal() {
  const modal = document.getElementById('profileFormModal');
  if (modal) {
    modal.classList.add('opacity-0', 'pointer-events-none');
    modal.classList.remove('opacity-100');
    modal.style.opacity = '0';
    modal.style.pointerEvents = 'none';
    setTimeout(() => {
      modal.style.display = 'none';
    }, 150);
  }
}

// ==========================================
// COMPREHENSIVE PROFILE FORM CONTROLS & SYNC
// ==========================================
export function syncProfileToAppState(profile) {
  if (!profile) return;
  appState.activeProfile = profile;

  // 1. Target Subnet Sync
  if (profile.network_target && profile.network_target.trim()) {
    const net = profile.network_target.trim();
    appState.subnet = net;
    if (mainSubnetInput) {
      mainSubnetInput.value = net;
    }
    if (typeof recalculateSubnet === 'function') {
      recalculateSubnet(net);
    }
  }

  // 2. Concurrency & Timeout
  if (profile.concurrency) {
    appState.concurrency = parseInt(profile.concurrency, 10);
  }
  if (profile.timeout) {
    appState.scanTimeout = parseFloat(profile.timeout);
  }

  // 3. Port Mode & Port List
  const pMode = profile.port_mode || 'standard';
  appState.portMode = pMode;
  if (pMode === 'standard') {
    appState.selectedPorts = [80, 443, 8080, 8081, 8082, 8083, 8084, 8085, 8086, 8087, 8088, 8443, 8000, 8888, 3000, 5000, 5173, 4000, 18080, 9000, 5050, 8880, 9090];
  } else if (pMode === 'wide') {
    appState.selectedPorts = WIDE_PORTS_COLLECTION.slice(0, 100);
  } else if (pMode === 'custom') {
    const customStr = profile.custom_ports || '';
    const parsed = customStr.split(',').map(s => parseInt(s.trim(), 10)).filter(n => !isNaN(n) && n >= 1 && n <= 65535);
    appState.selectedPorts = parsed.length > 0 ? parsed : [80, 443, 8080, 8000, 18080];
  }

  const portCountBadge = document.getElementById('portCountBadge');
  if (portCountBadge && appState.selectedPorts) {
    portCountBadge.textContent = `${appState.selectedPorts.length} พอร์ตที่เลือก`;
  }

  // 4. Scope Preset
  appState.scopePreset = profile.scope_preset || 'all';

  // 5. User-Agent & Custom Headers
  appState.customUserAgent = profile.user_agent || UA_PRESETS.chrome;
  appState.customHeaders = profile.custom_headers || '';

  // 6. Header Profile UI
  updateHeaderProfileUI();
}

export function applySpeedPreset(preset) {
  const btnStealth = document.getElementById('btnPresetSpeedStealth');
  const btnBalanced = document.getElementById('btnPresetSpeedBalanced');
  const btnTurbo = document.getElementById('btnPresetSpeedTurbo');

  const presets = {
    stealth: { el: btnStealth, conc: 20, tout: 5.0 },
    balanced: { el: btnBalanced, conc: 60, tout: 2.2 },
    turbo: { el: btnTurbo, conc: 120, tout: 1.2 }
  };

  Object.entries(presets).forEach(([key, cfg]) => {
    if (!cfg.el) return;
    if (key === preset) {
      cfg.el.className = "speed-preset-btn px-2.5 py-1 rounded-lg border text-[10px] font-bold text-blue-700 bg-blue-100 border-blue-400 shadow-inner cursor-pointer transition-all";
      if (profileFormConcurrency) {
        profileFormConcurrency.value = cfg.conc;
        if (profileFormConcurrencyDisplay) profileFormConcurrencyDisplay.textContent = `${cfg.conc} workers`;
      }
      if (profileFormTimeout) {
        profileFormTimeout.value = cfg.tout;
        if (profileFormTimeoutDisplay) profileFormTimeoutDisplay.textContent = `${cfg.tout.toFixed(1)}s`;
      }
    } else {
      cfg.el.className = "speed-preset-btn px-2.5 py-1 rounded-lg border text-[10px] font-semibold text-slate-600 bg-white hover:bg-slate-50 border-slate-200 cursor-pointer transition-all";
    }
  });

  if (preset === 'custom') {
    Object.values(presets).forEach(cfg => {
      if (cfg.el) {
        cfg.el.className = "speed-preset-btn px-2.5 py-1 rounded-lg border text-[10px] font-semibold text-slate-600 bg-white hover:bg-slate-50 border-slate-200 cursor-pointer transition-all";
      }
    });
  }
}

export function checkSpeedPresetMatch() {
  if (!profileFormConcurrency || !profileFormTimeout) return;
  const conc = parseInt(profileFormConcurrency.value, 10);
  const tout = parseFloat(profileFormTimeout.value);
  if (conc === 20 && Math.abs(tout - 5.0) < 0.2) {
    applySpeedPreset('stealth');
  } else if (conc === 60 && Math.abs(tout - 2.2) < 0.2) {
    applySpeedPreset('balanced');
  } else if (conc === 120 && Math.abs(tout - 1.2) < 0.2) {
    applySpeedPreset('turbo');
  } else {
    applySpeedPreset('custom');
  }
}

export function applyPortMode(mode) {
  const radio = document.querySelector(`input[name="profile_port_mode"][value="${mode}"]`) as HTMLInputElement | null;
  if (radio) radio.checked = true;

  document.querySelectorAll('.port-mode-card').forEach(card => {
    const cardMode = card.getAttribute('data-port-mode');
    const titleSpan = card.querySelector('.port-card-title') || card.querySelector('span');
    if (cardMode === mode) {
      card.className = "port-mode-card flex flex-col p-2.5 rounded-xl border border-blue-500 bg-blue-50/70 shadow-xs cursor-pointer transition ring-1 ring-blue-400/40";
      if (titleSpan) {
        titleSpan.className = "font-bold text-blue-900 text-[11px] port-card-title";
      }
    } else {
      card.className = "port-mode-card flex flex-col p-2.5 rounded-xl border border-slate-200 bg-white hover:border-blue-300 cursor-pointer transition";
      if (titleSpan) {
        titleSpan.className = "font-semibold text-slate-700 text-[11px] port-card-title";
      }
    }
  });

  if (profileFormCustomPortsWrapper) {
    if (mode === 'custom') {
      profileFormCustomPortsWrapper.classList.remove('hidden');
      if (profileFormCustomPorts && !profileFormCustomPorts.value.trim()) {
        profileFormCustomPorts.value = "80, 443, 8080, 8000, 18080";
      }
      if (profileFormCustomPorts) profileFormCustomPorts.focus();
    } else {
      profileFormCustomPortsWrapper.classList.add('hidden');
    }
  }
}

export function applyScopePreset(scope) {
  const radio = document.querySelector(`input[name="profile_scope_preset"][value="${scope}"]`) as HTMLInputElement | null;
  if (radio) radio.checked = true;

  document.querySelectorAll('.scope-preset-card').forEach(card => {
    const cardScope = card.getAttribute('data-scope-preset');
    if (cardScope === scope) {
      card.className = "scope-preset-card flex items-center gap-2 p-2 rounded-xl border border-indigo-500 bg-indigo-50/70 ring-1 ring-indigo-400/40 text-indigo-950 font-bold cursor-pointer transition shadow-xs";
    } else {
      card.className = "scope-preset-card flex items-center gap-2 p-2 rounded-xl border border-slate-200 bg-white hover:border-indigo-300 text-slate-700 font-medium cursor-pointer transition";
    }
  });
}

export function applyCidrPreset(cidr) {
  if (!profileFormNetwork) return;
  let raw = profileFormNetwork.value.trim();
  if (!raw) {
    raw = appState.subnet || appState.hostIp || '192.168.1.0';
  }
  let baseIp = raw.replace(/\/\d+$/, '').trim();
  if (baseIp.includes(':')) {
    baseIp = baseIp.split(':')[0];
  }
  const parts = baseIp.split('.');
  let result = `${baseIp}/${cidr}`;
  if (parts.length === 4 && parts.every(p => !isNaN(parseInt(p, 10)))) {
    if (cidr === '24') {
      parts[3] = '0';
      result = `${parts.join('.')}/24`;
    } else if (cidr === '28') {
      const fourth = parseInt(parts[3], 10) || 0;
      const block = Math.floor(fourth / 16) * 16;
      parts[3] = block.toString();
      result = `${parts.join('.')}/28`;
    } else if (cidr === '32') {
      result = `${parts.join('.')}/32`;
    }
  }
  profileFormNetwork.value = result;

  document.querySelectorAll('.cidr-preset-btn').forEach(btn => {
    const c = btn.getAttribute('data-cidr');
    if (c === cidr) {
      btn.className = "cidr-preset-btn px-2.5 py-0.5 rounded-lg border border-blue-400 bg-blue-100 text-blue-800 font-mono text-[10px] font-bold shadow-xs cursor-pointer transition-all";
    } else {
      btn.className = "cidr-preset-btn px-2.5 py-0.5 rounded-lg border border-slate-200 bg-slate-50 hover:bg-blue-50 text-slate-700 font-mono text-[10px] font-semibold cursor-pointer transition-all";
    }
  });
}

export function appendCustomHeader(line) {
  if (!profileFormCustomHeaders) return;
  const current = profileFormCustomHeaders.value.trim();
  const headerKey = line.split(':')[0].trim();
  if (!current) {
    profileFormCustomHeaders.value = line;
    showToast(`เพิ่ม Header: ${headerKey} เรียบร้อย`);
  } else if (current.toLowerCase().includes(headerKey.toLowerCase() + ':')) {
    showToast(`มี Header "${headerKey}" อยู่ในรายการแล้ว`);
  } else {
    profileFormCustomHeaders.value = current + '\n' + line;
    showToast(`เพิ่ม Header: ${headerKey} เรียบร้อย`);
  }
}

export function clearCustomHeaders() {
  if (profileFormCustomHeaders) {
    profileFormCustomHeaders.value = '';
    showToast("ล้าง Custom Headers เรียบร้อย");
  }
}

export function handleOpenCreateProfile() {
  try {
    if (profileFormHeading) profileFormHeading.textContent = "เพิ่ม Profile การสแกน";
    if (profileFormId) profileFormId.value = "";
    if (profileFormTitle) profileFormTitle.value = "";
    if (profileFormNetwork) profileFormNetwork.value = appState.subnet || "";
    if (profileFormDesc) profileFormDesc.value = "";
    
    // Speed
    applySpeedPreset('balanced');

    // User-Agent
    if (profileFormUaPreset) profileFormUaPreset.value = "chrome";
    if (profileFormCustomUaWrapper) profileFormCustomUaWrapper.classList.add('hidden');
    if (profileFormCustomUa) profileFormCustomUa.value = "";

    // Headers
    if (profileFormCustomHeaders) profileFormCustomHeaders.value = "";

    // Port Mode
    applyPortMode('standard');
    if (profileFormCustomPorts) profileFormCustomPorts.value = "";

    // Scope
    applyScopePreset('all');

    // Active Toggle
    if (profileFormSetActive) profileFormSetActive.checked = true;

    // CIDR active highlight check
    if (profileFormNetwork && profileFormNetwork.value) {
      const match = profileFormNetwork.value.match(/\/(\d+)$/);
      if (match) applyCidrPreset(match[1]);
    }

    openProfileFormModal();
  } catch (err) {
    console.error('Error in handleOpenCreateProfile:', err);
    openProfileFormModal();
  }
}

export function handleEditProfile(profileId) {
  try {
    const p = appState.profilesList.find(x => x.id === profileId);
    if (!p) return;
    if (profileFormHeading) profileFormHeading.textContent = "แก้ไข Profile การสแกน";
    if (profileFormId) profileFormId.value = p.id;
    if (profileFormTitle) profileFormTitle.value = p.title || "";
    if (profileFormNetwork) profileFormNetwork.value = p.network_target || "";
    if (profileFormDesc) profileFormDesc.value = p.description || "";

    // Speed
    const conc = p.concurrency || 60;
    const tout = p.timeout || 2.2;
    if (profileFormConcurrency) {
      profileFormConcurrency.value = conc;
      if (profileFormConcurrencyDisplay) profileFormConcurrencyDisplay.textContent = `${conc} workers`;
    }
    if (profileFormTimeout) {
      profileFormTimeout.value = tout;
      if (profileFormTimeoutDisplay) profileFormTimeoutDisplay.textContent = `${tout}s`;
    }
    checkSpeedPresetMatch();

    // User-Agent
    const uaKey = getUaKeyFromString(p.user_agent);
    if (profileFormUaPreset) profileFormUaPreset.value = uaKey;
    if (uaKey === 'custom') {
      if (profileFormCustomUaWrapper) profileFormCustomUaWrapper.classList.remove('hidden');
      if (profileFormCustomUa) profileFormCustomUa.value = p.user_agent || "";
    } else {
      if (profileFormCustomUaWrapper) profileFormCustomUaWrapper.classList.add('hidden');
      if (profileFormCustomUa) profileFormCustomUa.value = "";
    }

    // Custom Headers
    if (profileFormCustomHeaders) profileFormCustomHeaders.value = p.custom_headers || "";

    // Port Mode
    const pMode = p.port_mode || 'standard';
    applyPortMode(pMode);
    if (profileFormCustomPorts) profileFormCustomPorts.value = p.custom_ports || "";

    // Scope
    const sMode = p.scope_preset || 'all';
    applyScopePreset(sMode);

    // CIDR Highlight
    if (p.network_target) {
      const match = p.network_target.match(/\/(\d+)$/);
      if (match) applyCidrPreset(match[1]);
    }

    if (profileFormSetActive) profileFormSetActive.checked = Boolean(p.is_active);
    openProfileFormModal();
  } catch (err) {
    console.error('Error in handleEditProfile:', err);
    openProfileFormModal();
  }
}

export async function handleDeleteProfile(profileId) {
  const p = appState.profilesList.find(x => x.id === profileId);
  const title = p ? p.title : `ID ${profileId}`;
  if (!confirm(`ยืนยันการลบ Scan Profile: "${title}" หรือไม่?`)) return;

  try {
    const res = await apiFetch(`/api/profiles/${profileId}`, { method: 'DELETE' });
    const data = await res.json();
    if (data.status === 'ok') {
      showToast(`ลบ Profile สำเร็จ`);
      closeProfileDetailDrawer();
      await loadProfiles();
    } else {
      showToast(data.message || 'ลบ Profile ไม่สำเร็จ');
    }
  } catch (err) {
    showToast('เกิดข้อผิดพลาดในการเชื่อมต่อ');
  }
}

export async function handleSaveProfile(e) {
  if (e) e.preventDefault();
  const pid = profileFormId ? profileFormId.value.trim() : "";
  const title = profileFormTitle ? profileFormTitle.value.trim() : "";
  const network_target = profileFormNetwork ? profileFormNetwork.value.trim() : "";
  const description = profileFormDesc ? profileFormDesc.value.trim() : "";
  const set_active = profileFormSetActive ? profileFormSetActive.checked : true;

  const concurrency = profileFormConcurrency ? parseInt(profileFormConcurrency.value, 10) : 60;
  const timeout = profileFormTimeout ? parseFloat(profileFormTimeout.value) : 2.2;

  // User-Agent resolution
  let user_agent = UA_PRESETS.chrome;
  const uaPresetVal = profileFormUaPreset ? profileFormUaPreset.value : 'chrome';
  if (uaPresetVal === 'custom') {
    user_agent = profileFormCustomUa ? profileFormCustomUa.value.trim() : "";
    if (!user_agent) user_agent = UA_PRESETS.chrome;
  } else {
    user_agent = UA_PRESETS[uaPresetVal] || UA_PRESETS.chrome;
  }

  const custom_headers = profileFormCustomHeaders ? profileFormCustomHeaders.value.trim() : "";

  const portModeEl = document.querySelector('input[name="profile_port_mode"]:checked') as HTMLInputElement | null;
  const port_mode = portModeEl ? portModeEl.value : 'standard';
  const custom_ports = profileFormCustomPorts ? profileFormCustomPorts.value.trim() : "";

  const scopeEl = document.querySelector('input[name="profile_scope_preset"]:checked') as HTMLInputElement | null;
  const scope_preset = scopeEl ? scopeEl.value : 'all';

  if (!title) {
    showToast("กรุณากรอกชื่อ Profile");
    return;
  }

  try {
    const url = pid ? `/api/profiles/${pid}` : '/api/profiles';
    const method = pid ? 'PUT' : 'POST';
    const res = await apiFetch(url, {
      method: method,
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        title,
        network_target,
        description,
        concurrency,
        timeout,
        user_agent,
        custom_headers,
        port_mode,
        custom_ports,
        scope_preset,
        set_active
      })
    });
    const data = await res.json();
    if (data.status === 'ok' || data.status === 201) {
      showToast(data.message || 'บันทึก Profile เรียบร้อย');
      closeProfileFormModal();
      await loadProfiles();
      if (set_active && data.profile) {
        syncProfileToAppState(data.profile);
      }
      if (pid) {
        await openProfileDetailDrawer(pid);
      }
    } else {
      showToast(data.message || 'ไม่สามารถบันทึกได้');
    }
  } catch (err) {
    showToast('เกิดข้อผิดพลาดในการเชื่อมต่อเซิร์ฟเวอร์');
  }
}

/** Wires DOM event listeners for this domain. Called once from bootstrap after the DOM is mounted. */
export function initProfiles() {
  // Bind Profile Form Interactive Events
  if (profileFormConcurrency) {
    profileFormConcurrency.addEventListener('input', () => {
      if (profileFormConcurrencyDisplay) {
        profileFormConcurrencyDisplay.textContent = `${profileFormConcurrency.value} workers`;
      }
      checkSpeedPresetMatch();
    });
  }

  if (profileFormTimeout) {
    profileFormTimeout.addEventListener('input', () => {
      if (profileFormTimeoutDisplay) {
        profileFormTimeoutDisplay.textContent = `${parseFloat(profileFormTimeout.value).toFixed(1)}s`;
      }
      checkSpeedPresetMatch();
    });
  }

  if (btnPresetSpeedStealth) {
    btnPresetSpeedStealth.addEventListener('click', () => applySpeedPreset('stealth'));
  }

  if (btnPresetSpeedBalanced) {
    btnPresetSpeedBalanced.addEventListener('click', () => applySpeedPreset('balanced'));
  }

  if (btnPresetSpeedTurbo) {
    btnPresetSpeedTurbo.addEventListener('click', () => applySpeedPreset('turbo'));
  }

  if (profileFormUaPreset) {
    profileFormUaPreset.addEventListener('change', () => {
      if (profileFormUaPreset.value === 'custom') {
        if (profileFormCustomUaWrapper) {
          profileFormCustomUaWrapper.classList.remove('hidden');
          if (profileFormCustomUa && !profileFormCustomUa.value) {
            profileFormCustomUa.value = UA_PRESETS.chrome;
          }
          if (profileFormCustomUa) profileFormCustomUa.focus();
        }
      } else {
        if (profileFormCustomUaWrapper) profileFormCustomUaWrapper.classList.add('hidden');
        if (profileFormCustomUa) {
          profileFormCustomUa.value = UA_PRESETS[profileFormUaPreset.value] || "";
        }
      }
    });
  }

  if (btnHeaderPresetXff) {
    btnHeaderPresetXff.addEventListener('click', () => appendCustomHeader('X-Forwarded-For: 127.0.0.1'));
  }

  if (btnHeaderPresetRef) {
    btnHeaderPresetRef.addEventListener('click', () => appendCustomHeader('Referer: https://internal.company.corp/'));
  }

  if (btnHeaderPresetProxy) {
    btnHeaderPresetProxy.addEventListener('click', () => {
      appendCustomHeader('X-Real-IP: 10.0.0.1');
      appendCustomHeader('X-Originating-IP: 127.0.0.1');
    });
  }

  if (btnClearCustomHeaders) {
    btnClearCustomHeaders.addEventListener('click', clearCustomHeaders);
  }

  // CIDR Presets in Profile Form
  document.querySelectorAll('.cidr-preset-btn').forEach(btn => {
    btn.addEventListener('click', () => {
      const cidr = btn.getAttribute('data-cidr');
      applyCidrPreset(cidr);
    });
  });

  if (profileFormNetwork) {
    profileFormNetwork.addEventListener('input', () => {
      const val = profileFormNetwork.value.trim();
      const match = val.match(/\/(\d+)$/);
      document.querySelectorAll('.cidr-preset-btn').forEach(btn => {
        const c = btn.getAttribute('data-cidr');
        if (match && match[1] === c) {
          btn.className = "cidr-preset-btn px-2.5 py-0.5 rounded-lg border border-blue-400 bg-blue-100 text-blue-800 font-mono text-[10px] font-bold shadow-xs cursor-pointer transition-all";
        } else {
          btn.className = "cidr-preset-btn px-2.5 py-0.5 rounded-lg border border-slate-200 bg-slate-50 hover:bg-blue-50 text-slate-700 font-mono text-[10px] font-semibold cursor-pointer transition-all";
        }
      });
    });
  }

  if (btnFormDetectNetwork) {
    btnFormDetectNetwork.addEventListener('click', () => {
      if (profileFormNetwork) {
        const detected = appState.subnet || appState.hostIp || '192.168.1.0/24';
        profileFormNetwork.value = detected;
        const match = detected.match(/\/(\d+)$/);
        if (match) applyCidrPreset(match[1]);
        showToast(`ใช้เป้าหมายเครือข่ายปัจจุบัน: ${detected}`);
      }
    });
  }

  // Port Mode Selection Cards Click
  document.querySelectorAll('.port-mode-card').forEach(card => {
    card.addEventListener('click', () => {
      const mode = card.getAttribute('data-port-mode');
      if (mode) applyPortMode(mode);
    });
  });

  document.querySelectorAll('input[name="profile_port_mode"]').forEach(r => {
    r.addEventListener('change', () => applyPortMode((r as HTMLInputElement).value));
  });

  // Scope Selection Cards Click
  document.querySelectorAll('.scope-preset-card').forEach(card => {
    card.addEventListener('click', () => {
      const scope = card.getAttribute('data-scope-preset');
      if (scope) applyScopePreset(scope);
    });
  });

  document.querySelectorAll('input[name="profile_scope_preset"]').forEach(r => {
    r.addEventListener('change', () => applyScopePreset((r as HTMLInputElement).value));
  });

  if (btnDrawerAutoDetect) {
    btnDrawerAutoDetect.addEventListener('click', () => {
      autoDetectLocalNetwork();
      showToast("รีเซ็ตตรวจจับเครือข่ายเครื่องใหม่เรียบร้อย");
    });
  }

  // Drawer Buttons Wiring
  if (btnOpenCreateProfileFromList) btnOpenCreateProfileFromList.addEventListener('click', handleOpenCreateProfile);

  if (btnDrawerCreateProfile) btnDrawerCreateProfile.addEventListener('click', handleOpenCreateProfile);

  if (btnCloseProfileDetailDrawer) btnCloseProfileDetailDrawer.addEventListener('click', closeProfileDetailDrawer);

  if (btnCloseDetailDrawerBottom) btnCloseDetailDrawerBottom.addEventListener('click', closeProfileDetailDrawer);

  // Bind Profile & Update Events
  if (btnHeaderProfile) btnHeaderProfile.addEventListener('click', () => openProfileModal(false));

  // NOTE: the old btnCloseProfileModal / btnDoneProfileModal / profileSelectModal ids no longer
  // exist in the markup (superseded by ProfileSelectDrawer), so the dead bindings were dropped.

  if (btnEmptyCreateProfile) btnEmptyCreateProfile.addEventListener('click', handleOpenCreateProfile);

  if (btnOpenCreateProfileFromList) btnOpenCreateProfileFromList.addEventListener('click', handleOpenCreateProfile);

  if (btnDrawerCreateProfile) btnDrawerCreateProfile.addEventListener('click', handleOpenCreateProfile);

  if (btnCloseProfileFormModal) btnCloseProfileFormModal.addEventListener('click', closeProfileFormModal);

  if (btnCancelProfileForm) btnCancelProfileForm.addEventListener('click', closeProfileFormModal);

  if (profileForm) profileForm.addEventListener('submit', handleSaveProfile);
}
