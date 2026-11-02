<!--
  @component AppFooter
  Markup ported 1:1 from the original GUI.html (lines 438-470).
  Element ids are preserved: the controllers in src/lib/controllers bind to them.
-->
<!-- Bottom Footer Quick Network Info -->
<footer class="w-full px-6 py-3 bg-white/40 border-t border-slate-200/60 flex flex-wrap items-center justify-between text-xs text-slate-600 z-10 backdrop-blur-sm gap-2">
  <div class="flex items-center gap-3">
    <!-- Live System Status (Preserves statusIndicatorDot and statusPillText for JS) -->
    <div class="flex items-center gap-1.5 px-2.5 py-1 rounded-full bg-white/70 border border-slate-200/70 shadow-xs">
      <span id="statusIndicatorDot" class="w-2 h-2 rounded-full bg-emerald-500 animate-pulse"></span>
      <span id="statusPillText" class="font-medium text-slate-700">System Ready · LAN Discovery Idle</span>
    </div>
    <div class="hidden lg:flex items-center gap-1.5 text-slate-400">|</div>
    <div class="flex items-center gap-1.5">
      <i class="ph-fill ph-wifi-high text-blue-600"></i>
      <span class="font-medium text-slate-800">LAN Host IP:</span>
      <span id="detectedHostIp" class="font-mono bg-white/80 px-2 py-0.5 rounded border border-slate-200 font-semibold text-blue-600">กำลังตรวจจับ...</span>
    </div>
    <div class="hidden md:flex items-center gap-1.5">
      <span class="text-slate-400">|</span>
      <span class="font-medium text-slate-800">ขอบเขต Subnet:</span>
      <span id="detectedSubnetRange" class="font-mono bg-white/80 px-2 py-0.5 rounded border border-slate-200 text-slate-700">กำลังคำนวณ...</span>
    </div>
  </div>

  <div class="flex items-center gap-2">
    <span class="text-slate-500">ผลการสแกนล่าสุด:</span>
    <button id="btnOpenResultsQuick" class="font-bold text-blue-600 hover:text-blue-800 flex items-center gap-1.5 px-3 py-1 rounded-md bg-blue-50 hover:bg-blue-100/70 border border-blue-200 transition cursor-pointer">
      <span id="quickPhpCount">ยังไม่ได้สแกน</span>
      <i class="ph-bold ph-caret-right"></i>
    </button>
    <button id="btnFooterExportAmberPdf" class="font-bold text-amber-950 bg-amber-400 hover:bg-amber-500 border border-amber-500 flex items-center gap-1.5 px-3 py-1 rounded-md shadow-sm transition cursor-pointer text-xs" title="ดาวน์โหลดรายงานความมั่นคงปลอดภัย TLP:AMBER (PDF)">
      <i class="ph-bold ph-file-pdf text-sm"></i>
      <span>รายงาน TLP:AMBER (PDF)</span>
    </button>
  </div>
</footer>
