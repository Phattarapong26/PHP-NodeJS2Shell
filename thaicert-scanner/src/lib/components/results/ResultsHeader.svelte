<!--
  @component ResultsHeader
  Markup ported 1:1 from the original GUI.html (lines 476-511).
  Element ids are preserved: the controllers in src/lib/controllers bind to them.
-->
<!-- Results Header matching Neumorphic Aesthetic (Fixed at Top) -->
<div class="px-6 py-4 bg-gradient-to-r from-white via-slate-50/90 to-blue-50/50 border-b border-slate-200/70 flex items-center justify-between gap-4 flex-shrink-0 z-10">
  <div class="flex items-center gap-3.5 min-w-0">
    <div id="resultsHeaderIcon" class="w-11 h-11 rounded-2xl bg-gradient-to-br from-blue-600 to-indigo-600 text-white flex items-center justify-center shadow-md flex-shrink-0">
      <i class="ph-bold ph-shield-check text-2xl"></i>
    </div>
    <div class="min-w-0">
      <div class="flex items-center gap-2.5 flex-wrap">
        <h2 class="text-base sm:text-lg font-extrabold text-slate-900 tracking-tight">ผลการสแกนและตรวจสอบอุปกรณ์ในเครือข่าย</h2>
        <span id="badgeFilteredCount" class="text-xs bg-blue-50 text-blue-700 px-2.5 py-0.5 rounded-full border border-blue-200 font-semibold shadow-2xs inline-flex items-center gap-1.5">
          <span class="w-1.5 h-1.5 rounded-full bg-blue-500"></span>
          <span>พบ 0 เครื่อง</span>
        </span>
      </div>
      <p id="resultsSubHeader" class="text-xs text-slate-500 mt-0.5 truncate">ตรวจพบอุปกรณ์ออนไลน์จาก DHCP และคัดกรองความปลอดภัยตามเกณฑ์ ThaiCERT / สกมช.</p>
    </div>
  </div>
  
  <div class="flex items-center gap-2 flex-shrink-0">
    <button id="btnExportAmberPdfModal" class="px-3.5 py-2 rounded-xl text-xs font-bold text-amber-950 bg-gradient-to-r from-amber-400 via-amber-400 to-amber-500 hover:from-amber-500 hover:to-amber-600 border border-amber-400/80 shadow-xs hover:shadow transition-all duration-150 flex items-center gap-1.5 cursor-pointer active:scale-95" title="ออกรายงานความมั่นคงปลอดภัยตามมาตรฐาน สกมช. (TLP:AMBER PDF)">
      <i class="ph-fill ph-file-pdf text-base text-amber-950"></i>
      <span>ออกรายงาน TLP:AMBER (PDF)</span>
    </button>
    <button id="btnExportEvidenceBundleModal" class="px-3.5 py-2 rounded-xl text-xs font-bold text-white bg-emerald-600 hover:bg-emerald-700 border border-emerald-700 shadow-xs hover:shadow transition-all duration-150 flex items-center gap-1.5 cursor-pointer active:scale-95" title="ดาวน์โหลด Forensic Evidence Bundle (.ZIP) พร้อมดิจิทัลซิกเนเจอร์ SHA-256">
      <i class="ph-fill ph-archive text-base text-white"></i>
      <span>Forensic Bundle (.ZIP)</span>
    </button>
    <button id="btnExportReport" class="px-3 py-2 rounded-xl bg-white hover:bg-slate-50 border border-slate-200 text-xs font-semibold flex items-center gap-1.5 transition text-slate-700 hover:text-blue-600 shadow-2xs active:scale-95 cursor-pointer" title="ส่งออกรายงานเป็นไฟล์ CSV">
      <i class="ph-bold ph-download-simple text-blue-600"></i>
      <span class="hidden sm:inline">Export CSV</span>
    </button>
    <button id="btnCloseResults" class="w-9 h-9 rounded-xl bg-slate-100 hover:bg-slate-200 text-slate-500 hover:text-slate-800 flex items-center justify-center transition active:scale-95 cursor-pointer" title="ปิดหน้าต่าง">
      <i class="ph-bold ph-x text-base"></i>
    </button>
  </div>
</div>
