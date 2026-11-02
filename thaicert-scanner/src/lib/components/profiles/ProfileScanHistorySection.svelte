<!--
  @component ProfileScanHistorySection
  Markup ported 1:1 from the original GUI.html (lines 1523-1551).
  Element ids are preserved: the controllers in src/lib/controllers bind to them.
-->
<!-- SECTION 2: Scan History Timeline for this Profile -->
<div class="space-y-3 pt-2">
  <div class="flex items-center justify-between border-b border-slate-200/60 pb-2">
    <div class="flex items-center gap-2">
      <span class="font-bold text-slate-800 text-xs flex items-center gap-1.5">
        <i class="ph-bold ph-clock-counter-clockwise text-blue-600"></i>
        <span>ประวัติการสแกนภายใต้ Profile นี้ (Scan History Timeline)</span>
      </span>
      <span id="detailHistoryCountBadge" class="font-mono text-[10px] font-bold px-2 py-0.5 rounded-full bg-blue-100 text-blue-800 border border-blue-200">0 รอบ</span>
    </div>
    <span class="text-[10px] text-slate-400">บันทึกผลการตรวจสอบย้อนหลังทุกรอบการรัน</span>
  </div>

  <!-- Empty History State -->
  <div id="detailHistoryEmptyState" class="py-12 px-6 flex flex-col items-center justify-center text-center rounded-2xl border-2 border-dashed border-slate-200 bg-white/60">
    <div class="w-12 h-12 rounded-2xl bg-slate-100 text-slate-400 flex items-center justify-center mb-2">
      <i class="ph-duotone ph-hourglass-empty text-2xl"></i>
    </div>
    <h4 class="text-xs font-bold text-slate-700 mb-1">ยังไม่มีประวัติการสแกน</h4>
    <p class="text-[11px] text-slate-400 max-w-sm leading-relaxed">
      เมื่อเริ่มต้นการสแกนโดยเลือก Profile นี้ ข้อมูลสรุปและผลการตรวจสอบช่องโหว่จะถูกบันทึกไว้ในประวัตินี้โดยอัตโนมัติ เพื่อให้สามารถเปิดดูย้อนหลังได้ตลอดเวลา
    </p>
  </div>

  <!-- History Table / Cards Container -->
  <div id="detailHistoryListContainer" class="flex flex-col gap-2.5">
    <!-- Dynamically populated via JS -->
  </div>
</div>
