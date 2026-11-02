<!--
  @component AuditHeader
  Markup ported 1:1 from the original GUI.html (lines 835-862).
  Element ids are preserved: the controllers in src/lib/controllers bind to them.
-->
<!-- Header -->
<div class="px-6 py-4 bg-gradient-to-r from-white via-slate-50 to-blue-50/60 border-b border-slate-200/70 flex items-center justify-between">
  <div class="flex items-center gap-3">
    <div class="w-9 h-9 rounded-xl outer-dish flex items-center justify-center text-blue-600">
      <i class="ph-bold ph-shield-check text-xl"></i>
    </div>
    <div>
      <h3 class="font-bold text-slate-800 text-sm sm:text-base flex items-center gap-2">
        <span>ผลการตรวจสอบเชิงรับ & สภาพแวดล้อมความปลอดภัย</span>
        <span id="auditTargetBadge" class="text-xs font-mono font-normal bg-blue-100 text-blue-800 px-2 py-0.5 rounded-full"></span>
      </h3>
      <p class="text-[11px] text-slate-500">Defensive Security Posture & Patch Verification Guidance</p>
    </div>
  </div>
  <div class="flex items-center gap-2">
    <button id="btnExportHostPdf" class="neu-pill-btn px-3 py-1.5 rounded-xl text-xs font-bold text-amber-950 bg-amber-400 hover:bg-amber-500 border border-amber-500 shadow-sm transition flex items-center gap-1.5 cursor-pointer" title="ออกรายงาน PDF เฉพาะเครื่องนี้ตามมาตรฐาน สกมช. (TLP:AMBER)">
      <i class="ph-bold ph-file-pdf text-sm text-amber-950"></i>
      <span>ออกรายงาน TLP:AMBER (PDF)</span>
    </button>
    <a id="auditTargetOpenWebBtn" href="#" target="_blank" class="neu-pill-btn px-3 py-1.5 rounded-xl text-xs font-semibold text-emerald-700 hover:text-emerald-800 flex items-center gap-1.5 border border-emerald-300 bg-emerald-50/70 shadow-sm transition">
      <i class="ph-bold ph-arrow-square-out text-sm text-emerald-600"></i>
      <span>เปิดดูหน้าเว็บจริง</span>
    </a>
    <button id="btnCloseDeepAudit" class="w-8 h-8 rounded-full neu-pill-btn text-slate-400 hover:text-slate-700 flex items-center justify-center cursor-pointer">
      <i class="ph-bold ph-x text-base"></i>
    </button>
  </div>
</div>
