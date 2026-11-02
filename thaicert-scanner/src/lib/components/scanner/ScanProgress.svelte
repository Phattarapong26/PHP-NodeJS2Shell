<!--
  @component ScanProgress
  Markup ported 1:1 from the original GUI.html (lines 413-433).
  Element ids are preserved: the controllers in src/lib/controllers bind to them.
-->
<!-- Live Scan Progress Subtitle & Step Tracker -->
<div class="mt-8 text-center max-w-md w-full">
  <div id="currentStepBadge" class="inline-flex items-center gap-2 px-4 py-1.5 rounded-full bg-white/70 border border-slate-200/90 text-xs font-semibold text-slate-700 shadow-sm transition-all">
    <i id="stepBadgeIcon" class="ph-bold ph-magnifying-glass text-blue-600"></i>
    <span id="stepBadgeText">กดปุ่ม Scan เพื่อเริ่มค้นหาเครื่อง PHP ในวง LAN</span>
  </div>

  <!-- Mini Progress Bar (Appears during scan) -->
  <div id="scanProgressWrapper" class="mt-3 opacity-0 transition-opacity duration-300">
    <div class="w-full bg-slate-200/80 rounded-full h-2 overflow-hidden border border-white/80">
      <div id="scanProgressBar" class="bg-gradient-to-r from-blue-500 to-indigo-600 h-2 rounded-full w-0 transition-all duration-150"></div>
    </div>
    <div class="flex justify-between items-center text-[11px] text-slate-500 mt-1.5 px-1">
      <span id="scanProgressStats">สแกน 0 / 254 เครื่อง</span>
      <button id="btnCancelScan" type="button" class="inline-flex items-center gap-1 text-rose-600 hover:text-rose-700 font-semibold px-2 py-0.5 rounded bg-rose-50 hover:bg-rose-100 transition-colors cursor-pointer">
        <i class="ph-bold ph-x-circle"></i> หยุดสแกน
      </button>
      <span id="scanSpeedStat">ความเร็ว: ~65 host/s</span>
    </div>
  </div>
</div>
