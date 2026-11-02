<!--
  @component FormSpeedConcurrency
  Markup ported 1:1 from the original GUI.html (lines 1645-1683).
  Element ids are preserved: the controllers in src/lib/controllers bind to them.
-->
<!-- Row 3: Speed & Concurrency Settings -->
<div class="p-3.5 rounded-2xl neu-concave-card border border-slate-200 bg-white/70 space-y-3">
  <div class="flex items-center justify-between">
    <label class="font-bold text-slate-800 text-xs flex items-center gap-1.5">
      <i class="ph-bold ph-lightning text-amber-500"></i>
      <span>กำหนดความเร็วการสแกน (Speed & Concurrency)</span>
    </label>
    <div class="flex items-center gap-1.5">
      <button type="button" id="btnPresetSpeedStealth" class="speed-preset-btn px-2.5 py-1 rounded-lg border text-[10px] font-semibold text-slate-600 bg-white hover:bg-slate-50 border-slate-200 cursor-pointer transition-all">Stealth (20 reqs)</button>
      <button type="button" id="btnPresetSpeedBalanced" class="speed-preset-btn px-2.5 py-1 rounded-lg border text-[10px] font-bold text-blue-700 bg-blue-100 border-blue-400 shadow-inner cursor-pointer transition-all">มาตรฐาน (60 reqs)</button>
      <button type="button" id="btnPresetSpeedTurbo" class="speed-preset-btn px-2.5 py-1 rounded-lg border text-[10px] font-semibold text-slate-600 bg-white hover:bg-slate-50 border-slate-200 cursor-pointer transition-all">Turbo (120 reqs)</button>
    </div>
  </div>

  <div class="grid grid-cols-1 sm:grid-cols-2 gap-3 pt-1">
    <div>
      <div class="flex justify-between items-center mb-1 text-[11px]">
        <span class="text-slate-600 font-semibold">Async Workers Concurrency:</span>
        <span id="profileFormConcurrencyDisplay" class="font-bold font-mono text-blue-600 bg-blue-50 px-1.5 py-0.2 rounded border border-blue-200">60 workers</span>
      </div>
      <input id="profileFormConcurrency" type="range" min="10" max="200" value="60" class="w-full accent-blue-600 cursor-pointer">
      <div class="flex justify-between text-[9px] text-slate-400 font-mono">
        <span>10 (เงียบ ปลอดภัย)</span>
        <span>200 (สูงสุด)</span>
      </div>
    </div>
    <div>
      <div class="flex justify-between items-center mb-1 text-[11px]">
        <span class="text-slate-600 font-semibold">Request Timeout (วินาที):</span>
        <span id="profileFormTimeoutDisplay" class="font-bold font-mono text-blue-600 bg-blue-50 px-1.5 py-0.2 rounded border border-blue-200">2.2s</span>
      </div>
      <input id="profileFormTimeout" type="range" min="0.5" max="10.0" step="0.1" value="2.2" class="w-full accent-blue-600 cursor-pointer">
      <div class="flex justify-between text-[9px] text-slate-400 font-mono">
        <span>0.5s (เร็ว)</span>
        <span>10.0s (รองรับเน็ตช้า)</span>
      </div>
    </div>
  </div>
</div>
