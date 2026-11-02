<!--
  @component ResultsFooter
  Markup ported 1:1 from the original GUI.html (lines 684-694).
  Element ids are preserved: the controllers in src/lib/controllers bind to them.
-->
<!-- Results Footer (Fixed at Bottom) -->
<div class="px-6 py-3.5 bg-white/95 border-t border-slate-200/70 flex items-center justify-between text-xs text-slate-500 flex-shrink-0 z-10 backdrop-blur-sm">
  <div class="flex items-center gap-2">
    <span class="w-2 h-2 rounded-full bg-emerald-500"></span>
    <span>เสร็จสิ้นใน <span id="scanElapsedDuration" class="font-bold text-slate-700">3.42 วินาที</span> (Concurrent Workers: 50)</span>
  </div>
  <button id="btnRescanFromModal" class="neu-pill-btn px-3 py-1 rounded-xl text-blue-600 font-bold hover:text-blue-700 flex items-center gap-1.5 transition">
    <i class="ph-bold ph-arrows-clockwise text-blue-600"></i>
    <span>สแกนใหม่อีกครั้ง</span>
  </button>
</div>
