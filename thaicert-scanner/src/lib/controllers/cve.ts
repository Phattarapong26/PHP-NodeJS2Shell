import { apiFetch } from './api';
import { btnCloseCveCatalog, btnOpenCveCatalog, cveCatalogContainer, cveDatabaseModal, inputSearchCveCatalog } from './dom';
import { escapeHtml } from './utils';
import { showToast } from './ui';

// ═══════════════════════════════════════════════════════════════════════
// MULTI-STACK CVE DATABASE & DYNAMIC STANDARD RULES CONTROLLER
// ═══════════════════════════════════════════════════════════════════════

export let cveCatalogDatabase: any[] = [];
export let dynamicRulesDatabase: any[] = [];
export let currentCatalogMode: 'dynamic' | 'builtin' = 'dynamic';
export let currentCveCategory = 'ALL';

const THAICERT_GROUP_NAMES: Record<number, string> = {
  1: 'Web Interface & Attack Surface',
  2: 'API & Microservices',
  3: 'Internal Services & DBs',
  4: 'Mobile & IoT Devices',
  5: 'Cloud & Container Infrastructure',
  6: 'Critical Application Vulnerabilities',
  7: 'Network & OS Infrastructure',
  8: 'Auxiliary & Unknown Assets'
};

export async function loadBuiltinDatabase() {
  try {
    const res = await apiFetch('/api/cve-database');
    if (res.ok) {
      const data = await res.json();
      if (data && data.database) {
        cveCatalogDatabase = data.database;
        if (currentCatalogMode === 'builtin') renderCveCatalog();
      }
    }
  } catch (e) {
    console.warn("Failed to load /api/cve-database", e);
  }
}

export async function loadDynamicRules() {
  try {
    const res = await apiFetch('/api/cve/rules');
    if (res.ok) {
      const data = await res.json();
      if (data && data.rules) {
        dynamicRulesDatabase = data.rules;
        const countBadge = document.getElementById('cveRulesCountBadge');
        if (countBadge) {
          countBadge.textContent = `${dynamicRulesDatabase.length} กฎมาตรฐาน`;
        }
        if (currentCatalogMode === 'dynamic') renderCveCatalog();
      }
    }
  } catch (e) {
    console.warn("Failed to load /api/cve/rules", e);
  }
}

export function renderCveCatalog() {
  if (!cveCatalogContainer) return;
  const term = (inputSearchCveCatalog?.value || '').trim().toLowerCase();

  if (currentCatalogMode === 'dynamic') {
    renderDynamicRules(term);
  } else {
    renderBuiltinRules(term);
  }
}

function renderDynamicRules(term: string) {
  let filtered = dynamicRulesDatabase.filter(item => {
    const matchCat = (currentCveCategory === 'ALL' || item.target_type === currentCveCategory);
    if (!matchCat) return false;
    if (!term) return true;
    const text = `${item.rule_id} ${item.cve_id} ${item.name} ${item.description} ${item.target_type} ${item.severity} ${item.cwe}`.toLowerCase();
    return text.includes(term);
  });

  if (filtered.length === 0) {
    cveCatalogContainer.innerHTML = `
      <div class="text-center py-10 text-slate-400">
        <i class="ph ph-magnifying-glass text-3xl mb-2 text-slate-300"></i>
        <p>ไม่พบกฎช่องโหว่ภาษากลางที่ตรงกับเงื่อนไข</p>
      </div>
    `;
    return;
  }

  cveCatalogContainer.innerHTML = filtered.map(rule => {
    const isCrit = rule.severity === 'Critical';
    const isHigh = rule.severity === 'High';
    const sevClass = isCrit 
      ? 'bg-rose-100 text-rose-800 border-rose-300' 
      : (isHigh ? 'bg-amber-100 text-amber-800 border-amber-300' : 'bg-blue-100 text-blue-800 border-blue-300');

    const groupLabel = THAICERT_GROUP_NAMES[rule.thaicert_group] || `กลุ่ม ${rule.thaicert_group}`;
    const trigger = rule.trigger || {};
    const triggerText = rule.target_type === 'web' 
      ? `${trigger.method || 'GET'} ${trigger.path || '/'}` 
      : (rule.target_type === 'android' ? `พอร์ต ${trigger.target_port || 5555} (ADB/TCP)` : `ตรวจคุณสมบัติ: ${trigger.feature_check || 'TCP Probe'}`);

    const isEnabled = Boolean(rule.is_enabled);

    return `
      <div class="p-4 rounded-2xl bg-white border ${isEnabled ? 'border-slate-200/90' : 'border-slate-200 opacity-60 bg-slate-50'} shadow-2xs hover:border-blue-400 transition space-y-2.5">
        <div class="flex items-center justify-between gap-2 flex-wrap">
          <div class="flex items-center gap-2 flex-wrap">
            <span class="px-2.5 py-0.5 rounded-md font-mono font-bold text-xs border ${sevClass}">${escapeHtml(rule.rule_id)}</span>
            <span class="font-bold text-slate-800 text-sm">${escapeHtml(rule.name)}</span>
            <span class="text-[11px] font-mono text-slate-500 font-semibold">(${escapeHtml(rule.cve_id)})</span>
          </div>
          <div class="flex items-center gap-2 text-xs">
            <span class="px-2 py-0.5 rounded-md bg-indigo-50 text-indigo-700 font-semibold border border-indigo-200 text-[11px]">
              กลุ่ม ${rule.thaicert_group}: ${escapeHtml(groupLabel)}
            </span>
            <span class="px-2 py-0.5 rounded-md bg-slate-100 text-slate-700 font-bold font-mono text-[11px]">
              CVSS ${rule.cvss_score || '5.0'}
            </span>
            <button type="button" class="btn-toggle-rule px-2 py-0.5 rounded-md text-[11px] font-semibold transition cursor-pointer ${isEnabled ? 'bg-emerald-100 text-emerald-800 border border-emerald-300' : 'bg-slate-200 text-slate-600'}" data-rule-id="${escapeHtml(rule.rule_id)}" data-enabled="${isEnabled ? '1' : '0'}">
              ${isEnabled ? 'เปิดใช้งาน' : 'ปิดการใช้งาน'}
            </button>
            <button type="button" class="btn-delete-rule text-slate-400 hover:text-rose-600 p-1 rounded-md transition cursor-pointer" data-rule-id="${escapeHtml(rule.rule_id)}" title="ลบกฎนี้">
              <i class="ph-bold ph-trash text-sm"></i>
            </button>
          </div>
        </div>

        <p class="text-xs text-slate-600 leading-relaxed">${escapeHtml(rule.description || '')}</p>

        <div class="grid grid-cols-1 sm:grid-cols-2 gap-2 text-[11px] pt-2 border-t border-slate-100 bg-slate-50/70 p-2.5 rounded-xl">
          <div>
            <span class="text-slate-400 font-semibold">เวกเตอร์ทดสอบ (Trigger):</span> 
            <span class="font-mono text-slate-800 font-bold block sm:inline truncate">${escapeHtml(triggerText)}</span>
          </div>
          <div>
            <span class="text-slate-400 font-semibold">ประเภทเป้าหมาย (Target):</span> 
            <span class="font-semibold text-blue-700 font-mono uppercase">${escapeHtml(rule.target_type)}</span>
          </div>
          ${rule.remediation ? `
          <div class="sm:col-span-2 pt-1 text-slate-600">
            <span class="text-slate-400 font-semibold">คำแนะนำการแก้ไข (Remediation):</span> 
            <span class="text-emerald-700 font-medium">${escapeHtml(rule.remediation)}</span>
          </div>` : ''}
        </div>
      </div>
    `;
  }).join('');

  // Attach dynamic card event handlers
  cveCatalogContainer.querySelectorAll('.btn-toggle-rule').forEach(btn => {
    btn.addEventListener('click', async (e) => {
      e.stopPropagation();
      const el = btn as HTMLElement;
      const ruleId = el.getAttribute('data-rule-id');
      const isCurrentlyEnabled = el.getAttribute('data-enabled') === '1';
      if (!ruleId) return;
      try {
        const res = await apiFetch(`/api/cve/rules/${encodeURIComponent(ruleId)}/toggle`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ is_enabled: !isCurrentlyEnabled })
        });
        if (res.ok) {
          showToast(`เปลี่ยนสถานะกฎ ${ruleId} เรียบร้อย`);
          await loadDynamicRules();
        }
      } catch (err) {
        showToast('ไม่สามารถเปลี่ยนสถานะกฎได้');
      }
    });
  });

  cveCatalogContainer.querySelectorAll('.btn-delete-rule').forEach(btn => {
    btn.addEventListener('click', async (e) => {
      e.stopPropagation();
      const el = btn as HTMLElement;
      const ruleId = el.getAttribute('data-rule-id');
      if (!ruleId) return;
      if (!confirm(`คุณต้องการลบกฎ ${ruleId} ออกจากฐานข้อมูลใช่หรือไม่?`)) return;
      try {
        const res = await apiFetch(`/api/cve/rules/${encodeURIComponent(ruleId)}`, {
          method: 'DELETE'
        });
        if (res.ok) {
          showToast(`ลบกฎ ${ruleId} เรียบร้อยแล้ว`);
          await loadDynamicRules();
        }
      } catch (err) {
        showToast('เกิดข้อผิดพลาดในการลบกฎ');
      }
    });
  });
}

function renderBuiltinRules(term: string) {
  let filtered = cveCatalogDatabase.filter(item => {
    const matchCat = (currentCveCategory === 'ALL' || item.category === currentCveCategory);
    if (!matchCat) return false;
    if (!term) return true;
    const text = `${item.id} ${item.name} ${item.desc} ${item.category} ${item.severity}`.toLowerCase();
    return text.includes(term);
  });

  if (filtered.length === 0) {
    cveCatalogContainer.innerHTML = `
      <div class="text-center py-8 text-slate-400">
        <i class="ph ph-magnifying-glass text-3xl mb-2 text-slate-300"></i>
        <p>ไม่พบรายการช่องโหว่ที่ตรงกับคำค้นหา</p>
      </div>
    `;
    return;
  }

  cveCatalogContainer.innerHTML = filtered.map(cve => {
    const isCrit = cve.severity === 'Critical';
    const isHigh = cve.severity === 'High';
    const sevClass = isCrit 
      ? 'bg-rose-100 text-rose-800 border-rose-300' 
      : (isHigh ? 'bg-amber-100 text-amber-800 border-amber-300' : 'bg-blue-100 text-blue-800 border-blue-300');
    
    const catBadge = cve.category === 'PHP' 
      ? 'bg-indigo-50 text-indigo-700 border-indigo-200'
      : (cve.category === 'NGINX' ? 'bg-emerald-50 text-emerald-700 border-emerald-200' : 'bg-purple-50 text-purple-700 border-purple-200');

    return `
      <div class="p-3.5 rounded-2xl bg-white border border-slate-200/90 shadow-2xs hover:border-blue-400 transition space-y-2">
        <div class="flex items-center justify-between gap-2 flex-wrap">
          <div class="flex items-center gap-2">
            <span class="px-2.5 py-0.5 rounded-md font-mono font-bold text-xs border ${sevClass}">${escapeHtml(cve.id)}</span>
            <span class="font-bold text-slate-800 text-sm">${escapeHtml(cve.name)}</span>
          </div>
          <div class="flex items-center gap-1.5 text-[11px] font-mono">
            <span class="px-2 py-0.5 rounded-md border font-semibold ${catBadge}">${escapeHtml(cve.category)}</span>
            <span class="px-2 py-0.5 rounded-md bg-slate-100 text-slate-600 font-bold">CVSS ${cve.cvss || '9.0+'}</span>
          </div>
        </div>

        <p class="text-xs text-slate-600 leading-relaxed">${escapeHtml(cve.desc)}</p>

        <div class="grid grid-cols-1 sm:grid-cols-2 gap-2 text-[11px] pt-1 border-t border-slate-100">
          <div>
            <span class="text-slate-400 font-semibold">เกณฑ์แพตช์ปลอดภัย:</span> 
            <span class="text-emerald-700 font-semibold block sm:inline font-mono">${escapeHtml(cve.patched)}</span>
          </div>
          <div>
            <span class="text-slate-400 font-semibold">คำสั่งตรวจเช็ค (Host Check):</span>
            <div class="mt-0.5 p-1.5 rounded-lg bg-slate-900 text-slate-200 font-mono text-[10px] flex items-center justify-between">
              <span class="truncate"><code>${escapeHtml(cve.host_check || 'N/A')}</code></span>
              <button type="button" class="ml-2 text-indigo-400 hover:text-indigo-200 font-bold flex-shrink-0 cursor-pointer" data-action="copyText" data-copy="${escapeHtml(cve.host_check || '')}" data-toast="คัดลอกคำสั่งเรียบร้อย">คัดลอก</button>
            </div>
          </div>
        </div>
      </div>
    `;
  }).join('');
}

/** Wires DOM event listeners for this domain. Called once from bootstrap after the DOM is mounted. */
export function initCve() {
  if (btnOpenCveCatalog) {
    btnOpenCveCatalog.addEventListener('click', () => {
      loadDynamicRules();
      loadBuiltinDatabase();
      if (cveDatabaseModal) {
        cveDatabaseModal.classList.remove('opacity-0', 'pointer-events-none');
        const content = document.getElementById('cveDatabaseContent');
        if (content) content.classList.remove('scale-95');
      }
    });
  }

  if (btnCloseCveCatalog) {
    btnCloseCveCatalog.addEventListener('click', () => {
      if (cveDatabaseModal) {
        cveDatabaseModal.classList.add('opacity-0', 'pointer-events-none');
        const content = document.getElementById('cveDatabaseContent');
        if (content) content.classList.add('scale-95');
      }
    });
  }

  if (cveDatabaseModal) {
    cveDatabaseModal.addEventListener('click', (e) => {
      if (e.target === cveDatabaseModal) {
        cveDatabaseModal.classList.add('opacity-0', 'pointer-events-none');
        const content = document.getElementById('cveDatabaseContent');
        if (content) content.classList.add('scale-95');
      }
    });
  }

  // View Mode Tabs Switcher
  const tabDynamic = document.getElementById('tabModeDynamic');
  const tabBuiltin = document.getElementById('tabModeBuiltin');

  if (tabDynamic && tabBuiltin) {
    tabDynamic.addEventListener('click', () => {
      currentCatalogMode = 'dynamic';
      tabDynamic.className = 'px-3 py-1 rounded-lg font-bold text-xs bg-white text-blue-700 shadow-xs transition cursor-pointer';
      tabBuiltin.className = 'px-3 py-1 rounded-lg font-semibold text-xs text-slate-600 hover:text-slate-900 transition cursor-pointer';
      currentCveCategory = 'ALL';
      updateFilterButtonsUI();
      renderCveCatalog();
    });

    tabBuiltin.addEventListener('click', () => {
      currentCatalogMode = 'builtin';
      tabBuiltin.className = 'px-3 py-1 rounded-lg font-bold text-xs bg-white text-blue-700 shadow-xs transition cursor-pointer';
      tabDynamic.className = 'px-3 py-1 rounded-lg font-semibold text-xs text-slate-600 hover:text-slate-900 transition cursor-pointer';
      currentCveCategory = 'ALL';
      updateFilterButtonsUI();
      renderCveCatalog();
    });
  }

  // Category Filter Buttons
  document.querySelectorAll('.cve-cat-filter').forEach(btn => {
    btn.addEventListener('click', () => {
      currentCveCategory = btn.getAttribute('data-category') || 'ALL';
      updateFilterButtonsUI();
      renderCveCatalog();
    });
  });

  function updateFilterButtonsUI() {
    document.querySelectorAll('.cve-cat-filter').forEach(b => {
      const cat = b.getAttribute('data-category') || 'ALL';
      if (cat === currentCveCategory) {
        b.className = 'cve-cat-filter px-2.5 py-1 rounded-full font-semibold bg-blue-600 text-white shadow-xs transition cursor-pointer';
      } else {
        b.className = 'cve-cat-filter px-2.5 py-1 rounded-full font-semibold neu-pill-btn text-slate-600 hover:text-blue-600 transition cursor-pointer';
      }
    });
  }

  if (inputSearchCveCatalog) {
    inputSearchCveCatalog.addEventListener('input', () => {
      renderCveCatalog();
    });
  }

  // Export JSON Button
  const btnExport = document.getElementById('btnExportCveRules');
  if (btnExport) {
    btnExport.addEventListener('click', () => {
      window.location.href = '/api/cve/export';
      showToast('กำลังดาวน์โหลดไฟล์กฎช่องโหว่ (JSON)...');
    });
  }

  // Import JSON Button & File Picker
  const btnImport = document.getElementById('btnImportCveRules');
  const inputImport = document.getElementById('inputImportCveJson') as HTMLInputElement | null;
  if (btnImport && inputImport) {
    btnImport.addEventListener('click', () => {
      inputImport.value = '';
      inputImport.click();
    });

    inputImport.addEventListener('change', async () => {
      const file = inputImport.files?.[0];
      if (!file) return;

      const reader = new FileReader();
      reader.onload = async (e) => {
        try {
          const content = e.target?.result as string;
          const parsed = JSON.parse(content);

          const res = await apiFetch('/api/cve/import?overwrite=true', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(parsed)
          });
          const resData = await res.json();
          if (res.ok && resData.status === 'ok') {
            const s = resData.summary;
            showToast(`นำเข้าสำเร็จ: ${s.imported} รายการ, อัปเดต: ${s.updated} รายการ`);
            await loadDynamicRules();
          } else {
            showToast(`นำเข้าล้มเหลว: ${resData.message || 'โครงสร้าง JSON ไม่ถูกต้อง'}`);
          }
        } catch (err: any) {
          showToast(`เกิดข้อผิดพลาดในการอ่านไฟล์: ${err.message}`);
        }
      };
      reader.readAsText(file);
    });
  }

  // Preload databases
  loadDynamicRules();
  loadBuiltinDatabase();
}
