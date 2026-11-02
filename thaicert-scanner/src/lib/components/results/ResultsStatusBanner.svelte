<!--
  @component ResultsStatusBanner
  Markup ported 1:1 from the original GUI.html (lines 516-527).
  Element ids are preserved: the controllers in src/lib/controllers bind to them.
-->
<!-- Dynamic Status Notification Banner -->
<div id="resultsStatusBanner" class="px-6 py-2.5 bg-gradient-to-r from-emerald-50/95 via-emerald-50/60 to-white/90 border-b border-emerald-200/70 flex items-center justify-between text-xs text-emerald-950 backdrop-blur-sm transition-all duration-200">
  <div class="flex items-center gap-2.5 min-w-0 pr-3">
    <div id="bannerStatusIconWrap" class="w-6 h-6 rounded-lg bg-emerald-100 border border-emerald-200 flex items-center justify-center flex-shrink-0 text-emerald-600 shadow-2xs">
      <i id="bannerStatusIcon" class="ph-bold ph-check-circle text-sm"></i>
    </div>
    <span id="bannerStatusText" class="font-medium truncate sm:whitespace-normal">ผลการสแกนเครือข่ายความปลอดภัย</span>
  </div>
  <div class="flex items-center gap-2 flex-shrink-0">
    <span class="text-[11px] font-semibold text-slate-600 font-mono bg-white/90 px-2.5 py-0.5 rounded-lg border border-slate-200/80 shadow-2xs" id="bannerScannedTargetText"></span>
  </div>
</div>
