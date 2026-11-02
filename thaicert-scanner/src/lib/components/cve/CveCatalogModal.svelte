<!--
  @component CveCatalogModal
  Dynamic Standard Vulnerability & Payload Catalog Modal (ภาษากลาง JSON)
  Supports viewing, searching, filtering, importing, and exporting standard CVE detection rules.
-->
<div id="cveDatabaseModal" class="fixed inset-0 bg-slate-900/40 backdrop-blur-sm z-[60] opacity-0 pointer-events-none transition-all duration-300 flex items-center justify-center p-4">
  <div class="neu-modal-surface text-slate-700 w-full max-w-5xl rounded-3xl p-6 shadow-2xl max-h-[92vh] flex flex-col overflow-hidden border border-white/90 transform scale-95 transition-transform duration-200" id="cveDatabaseContent">
    
    <!-- Header -->
    <div class="flex items-center justify-between pb-3 border-b border-slate-200/70">
      <div class="flex items-center gap-3">
        <div class="w-10 h-10 rounded-2xl outer-dish flex items-center justify-center text-blue-600 shadow-sm">
          <i class="ph-bold ph-shield-check text-xl"></i>
        </div>
        <div>
          <div class="flex items-center gap-2">
            <h3 class="font-bold text-slate-800 text-base sm:text-lg">คลังกฎช่องโหว่และเพย์โหลดมาตรฐาน (Standard CVE & Payload Catalog)</h3>
            <span id="cveRulesCountBadge" class="text-xs bg-blue-100 text-blue-800 px-2.5 py-0.5 rounded-full font-bold border border-blue-200">ภาษากลาง JSON</span>
          </div>
          <p class="text-xs text-slate-500">มาตรฐานกฎภาษากลางสำหรับ Web, Network L4, Linux OS, และ Android ตามกรอบ 8 กลุ่ม ThaiCERT / สกมช.</p>
        </div>
      </div>
      <div class="flex items-center gap-2">
        <input type="file" id="inputImportCveJson" accept=".json" class="hidden" />
        <button id="btnImportCveRules" class="px-3 py-1.5 rounded-xl neu-pill-btn text-xs font-semibold text-slate-700 hover:text-blue-600 flex items-center gap-1.5 transition cursor-pointer" title="นำเข้าไฟล์กฎ .json">
          <i class="ph-bold ph-upload-simple text-sm text-blue-600"></i>
          <span>นำเข้า JSON</span>
        </button>
        <button id="btnExportCveRules" class="px-3 py-1.5 rounded-xl neu-pill-btn text-xs font-semibold text-slate-700 hover:text-emerald-600 flex items-center gap-1.5 transition cursor-pointer" title="ส่งออกคลังกฎเป็น .json">
          <i class="ph-bold ph-download-simple text-sm text-emerald-600"></i>
          <span>ส่งออก JSON</span>
        </button>
        <button id="btnCloseCveCatalog" aria-label="ปิดหน้าต่างคลังกฎช่องโหว่" class="w-8 h-8 rounded-full neu-pill-btn text-slate-400 hover:text-slate-700 flex items-center justify-center transition cursor-pointer">
          <i class="ph-bold ph-x text-base"></i>
        </button>
      </div>
    </div>

    <!-- Mode Selector & Filter bar -->
    <div class="py-3 flex flex-wrap items-center justify-between gap-2 border-b border-slate-200/60 text-xs">
      <div class="flex items-center gap-2">
        <!-- Catalog View Tabs -->
        <div class="inline-flex rounded-xl p-0.5 bg-slate-200/60 text-slate-700">
          <button id="tabModeDynamic" class="px-3 py-1 rounded-lg font-bold text-xs bg-white text-blue-700 shadow-xs transition cursor-pointer">
            <i class="ph-bold ph-code text-xs mr-1"></i> กฎภาษากลาง (Dynamic Rules)
          </button>
          <button id="tabModeBuiltin" class="px-3 py-1 rounded-lg font-semibold text-xs text-slate-600 hover:text-slate-900 transition cursor-pointer">
            <i class="ph-bold ph-cpu text-xs mr-1"></i> SemVer Built-in (16)
          </button>
        </div>

        <!-- Dynamic Category Pills -->
        <div class="flex items-center gap-1" id="cveFilterTabs">
          <button class="cve-cat-filter px-2.5 py-1 rounded-full font-semibold bg-blue-600 text-white shadow-xs transition cursor-pointer" data-category="ALL">ทั้งหมด</button>
          <button class="cve-cat-filter px-2.5 py-1 rounded-full font-semibold neu-pill-btn text-slate-600 hover:text-blue-600 transition cursor-pointer" data-category="web">Web</button>
          <button class="cve-cat-filter px-2.5 py-1 rounded-full font-semibold neu-pill-btn text-slate-600 hover:text-blue-600 transition cursor-pointer" data-category="linux_os">Linux OS</button>
          <button class="cve-cat-filter px-2.5 py-1 rounded-full font-semibold neu-pill-btn text-slate-600 hover:text-blue-600 transition cursor-pointer" data-category="android">Android</button>
          <button class="cve-cat-filter px-2.5 py-1 rounded-full font-semibold neu-pill-btn text-slate-600 hover:text-blue-600 transition cursor-pointer" data-category="network_l4">Network L4</button>
        </div>
      </div>

      <div class="relative w-48 sm:w-64">
        <input id="inputSearchCveCatalog" type="text" placeholder="ค้นหา Rule ID / CVE / คำอธิบาย..." class="w-full pl-7 pr-3 py-1 rounded-full neu-pill-inset text-xs text-slate-700 placeholder-slate-400 focus:outline-none">
        <i class="ph ph-magnifying-glass absolute left-2.5 top-1/2 -translate-y-1/2 text-slate-400 text-xs"></i>
      </div>
    </div>

    <!-- Scrollable CVE List Cards -->
    <div class="mt-3 flex-1 overflow-y-auto space-y-2.5 pr-1 max-h-[60vh]" id="cveCatalogContainer">
      <!-- Rendered dynamically via JavaScript -->
    </div>

    <!-- Footer -->
    <div class="pt-3 border-t border-slate-200/70 flex items-center justify-between text-xs text-slate-500">
      <span class="flex items-center gap-1.5">
        <i class="ph-bold ph-shield-check text-emerald-600 text-sm"></i>
        สอดคล้องตามมาตรฐาน CVE JSON 5.0 / NVD API 2.0 / CSAF 2.0 และ ThaiCERT 8-Group Model
      </span>
      <span class="font-mono text-[11px] text-slate-400 bg-slate-100 px-2 py-0.5 rounded">Dynamic Engine + Negative Canary</span>
    </div>
  </div>
</div>
