<!--
  @component CveCatalogModal
  Markup ported 1:1 from the original GUI.html (lines 778-829).
  Element ids are preserved: the controllers in src/lib/controllers bind to them.
-->
<!-- CVE DATABASE CATALOG MODAL (Multi-Stack 16 CVEs: PHP, NGINX, Node.js) -->
<div id="cveDatabaseModal" class="fixed inset-0 bg-slate-900/40 backdrop-blur-sm z-50 opacity-0 pointer-events-none transition-all duration-300 flex items-center justify-center p-4">
  <div class="neu-modal-surface text-slate-700 w-full max-w-4xl rounded-3xl p-6 shadow-2xl max-h-[90vh] flex flex-col overflow-hidden border border-white/90 transform scale-95 transition-transform duration-200" id="cveDatabaseContent">
    
    <!-- Header -->
    <div class="flex items-center justify-between pb-3 border-b border-slate-200/70">
      <div class="flex items-center gap-3">
        <div class="w-10 h-10 rounded-2xl outer-dish flex items-center justify-center text-blue-600 shadow-sm">
          <i class="ph-bold ph-database text-xl"></i>
        </div>
        <div>
          <div class="flex items-center gap-2">
            <h3 class="font-bold text-slate-800 text-base sm:text-lg">ฐานข้อมูลช่องโหว่ความเสี่ยง (CVE Knowledge Base)</h3>
            <span class="text-xs bg-blue-100 text-blue-800 px-2.5 py-0.5 rounded-full font-bold border border-blue-200">16 รายการ Multi-Stack</span>
          </div>
          <p class="text-xs text-slate-500">ระบบตรวจสอบช่องโหว่อัตโนมัติด้วย SemVer Range Matching (PHP, NGINX, Node.js)</p>
        </div>
      </div>
      <button id="btnCloseCveCatalog" class="w-8 h-8 rounded-full neu-pill-btn text-slate-400 hover:text-slate-700 flex items-center justify-center transition cursor-pointer">
        <i class="ph-bold ph-x text-base"></i>
      </button>
    </div>

    <!-- Filter bar -->
    <div class="py-3 flex flex-wrap items-center justify-between gap-2 border-b border-slate-200/60 text-xs">
      <div class="flex items-center gap-1.5" id="cveFilterTabs">
        <button class="cve-cat-filter px-3 py-1 rounded-full font-semibold bg-blue-600 text-white shadow-xs transition cursor-pointer" data-category="ALL">ทั้งหมด (16)</button>
        <button class="cve-cat-filter px-3 py-1 rounded-full font-semibold neu-pill-btn text-slate-600 hover:text-blue-600 transition cursor-pointer" data-category="PHP">PHP (6)</button>
        <button class="cve-cat-filter px-3 py-1 rounded-full font-semibold neu-pill-btn text-slate-600 hover:text-blue-600 transition cursor-pointer" data-category="NGINX">NGINX (6)</button>
        <button class="cve-cat-filter px-3 py-1 rounded-full font-semibold neu-pill-btn text-slate-600 hover:text-blue-600 transition cursor-pointer" data-category="Node.js">Node.js (4)</button>
      </div>
      <div class="relative w-48 sm:w-64">
        <input id="inputSearchCveCatalog" type="text" placeholder="ค้นหา CVE-ID / คำอธิบาย..." class="w-full pl-7 pr-3 py-1 rounded-full neu-pill-inset text-xs text-slate-700 placeholder-slate-400 focus:outline-none">
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
        สอดคล้องตามเกณฑ์มาตรฐานความมั่นคงปลอดภัยสากล (ThaiCERT & NCSA Thailand Framework)
      </span>
      <span class="font-mono text-[11px] text-slate-400 bg-slate-100 px-2 py-0.5 rounded">SemVer Range Engine</span>
    </div>
  </div>
</div>
