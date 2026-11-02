import { apiFetch } from './api';
import { btnCloseCveCatalog, btnOpenCveCatalog, cveCatalogContainer, cveDatabaseModal, inputSearchCveCatalog } from './dom';
import { escapeHtml } from './utils';

// ═══════════════════════════════════════════════════════════════════════
// MULTI-STACK CVE DATABASE CATALOG CONTROLLER (ThaiCERT & NCSA)
// ═══════════════════════════════════════════════════════════════════════
export let cveCatalogDatabase = [];

export let currentCveCategory = 'ALL';

export async function loadCveDatabase() {
  try {
    const res = await apiFetch('/api/cve-database');
    if (res.ok) {
      const data = await res.json();
      if (data && data.database) {
        cveCatalogDatabase = data.database;
        renderCveCatalog();
        return;
      }
    }
  } catch (e) {
    console.warn("Failed to load /api/cve-database", e);
  }
}

export function renderCveCatalog() {
  if (!cveCatalogContainer) return;
  const term = (inputSearchCveCatalog?.value || '').trim().toLowerCase();
  
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
      if (cveCatalogDatabase.length === 0) {
        loadCveDatabase();
      }
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

  // Category Filter Buttons
  document.querySelectorAll('.cve-cat-filter').forEach(btn => {
    btn.addEventListener('click', () => {
      document.querySelectorAll('.cve-cat-filter').forEach(b => {
        b.className = 'cve-cat-filter px-3 py-1 rounded-full font-semibold neu-pill-btn text-slate-600 hover:text-blue-600 transition cursor-pointer';
      });
      btn.className = 'cve-cat-filter px-3 py-1 rounded-full font-semibold bg-blue-600 text-white shadow-xs transition cursor-pointer';
      currentCveCategory = btn.getAttribute('data-category') || 'ALL';
      renderCveCatalog();
    });
  });

  if (inputSearchCveCatalog) {
    inputSearchCveCatalog.addEventListener('input', () => {
      renderCveCatalog();
    });
  }

  // Preload CVE Catalog Database
  loadCveDatabase();
}
