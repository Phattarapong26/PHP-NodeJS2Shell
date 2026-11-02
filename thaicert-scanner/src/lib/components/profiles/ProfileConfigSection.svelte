<!--
  @component ProfileConfigSection
  Stealth Configuration Matrix with 4 interactive cards and stealth specs.
  Ported and styled 1:1 against the OP Scanner enterprise design.
-->
<div class="rounded-3xl bg-white border border-slate-200/80 p-5 shadow-xs space-y-4">
  <!-- Section Header -->
  <div class="flex items-center justify-between border-b border-slate-100 pb-3">
    <div class="flex items-center gap-2.5">
      <div class="w-8 h-8 rounded-xl bg-blue-50 border border-blue-200/60 flex items-center justify-center text-blue-600 shadow-2xs">
        <i class="ph-bold ph-stack text-base"></i>
      </div>
      <div>
        <h3 class="font-bold text-slate-800 text-sm tracking-tight">การตั้งค่าการสแกน &amp; การจำพรางตัว (Stealth Configuration)</h3>
      </div>
    </div>
    <button id="btnConfigSectionEdit" type="button" class="neu-pill-btn px-3 py-1.5 rounded-xl bg-blue-50 hover:bg-blue-100 text-blue-700 border border-blue-200 text-xs font-semibold flex items-center gap-1.5 cursor-pointer transition">
      <i class="ph-bold ph-gear"></i>
      <span>ตั้งค่าการสแกน</span>
    </button>
  </div>

  <!-- 4 Interactive Configuration Cards -->
  <div class="grid grid-cols-1 sm:grid-cols-2 xl:grid-cols-4 gap-3.5">
    <!-- Card 1: Network Target -->
    <div class="p-3.5 rounded-2xl bg-white border border-slate-200/80 hover:border-blue-300 shadow-2xs hover:shadow-xs transition flex items-center justify-between gap-2 group cursor-pointer" id="cardConfigTarget">
      <div class="flex items-start gap-3">
        <div class="w-9 h-9 rounded-xl bg-blue-50 text-blue-600 flex items-center justify-center shrink-0 mt-0.5">
          <i class="ph-bold ph-tree-structure text-lg"></i>
        </div>
        <div>
          <div class="text-[11px] text-slate-400 font-medium">Network Target</div>
          <div id="detailConfigTarget" class="font-mono font-bold text-slate-800 text-sm tracking-tight">192.168.1.0/24</div>
          <div id="detailConfigTargetSub" class="text-[10px] text-slate-400">ขอบเขตเป้าหมายเครือข่าย</div>
        </div>
      </div>
      <i class="ph-bold ph-caret-right text-slate-300 group-hover:text-blue-500 transition"></i>
    </div>

    <!-- Card 2: Timeout & Concurrency -->
    <div class="p-3.5 rounded-2xl bg-white border border-slate-200/80 hover:border-blue-300 shadow-2xs hover:shadow-xs transition flex items-center justify-between gap-2 group cursor-pointer" id="cardConfigSpeed">
      <div class="flex items-start gap-3">
        <div class="w-9 h-9 rounded-xl bg-amber-50 text-amber-600 flex items-center justify-center shrink-0 mt-0.5">
          <i class="ph-bold ph-clock text-lg"></i>
        </div>
        <div>
          <div class="text-[11px] text-slate-400 font-medium">ค่า Timeout &amp; Concurrency</div>
          <div class="flex items-center gap-1.5 font-bold text-slate-800 text-xs">
            <span id="detailConfigConcurrency" class="font-mono text-slate-800">20 reqs</span>
            <span class="text-slate-300">•</span>
            <span id="detailConfigTimeout" class="font-mono text-slate-800">Timeout 5s</span>
          </div>
          <div class="text-[10px] text-slate-400">Non-blocking Async I/O</div>
        </div>
      </div>
      <i class="ph-bold ph-caret-right text-slate-300 group-hover:text-blue-500 transition"></i>
    </div>

    <!-- Card 3: Stealth & Headers -->
    <div class="p-3.5 rounded-2xl bg-white border border-slate-200/80 hover:border-blue-300 shadow-2xs hover:shadow-xs transition flex items-center justify-between gap-2 group cursor-pointer" id="cardConfigStealth">
      <div class="flex items-start gap-3">
        <div class="w-9 h-9 rounded-xl bg-purple-50 text-purple-600 flex items-center justify-center shrink-0 mt-0.5">
          <i class="ph-bold ph-shield-check text-lg"></i>
        </div>
        <div>
          <div class="text-[11px] text-slate-400 font-medium">การตั้งค่าหัวเว็บ (Stealth)</div>
          <div id="detailConfigUaName" class="font-bold text-slate-800 text-xs truncate max-w-[140px]">Chrome Desktop</div>
          <div id="detailConfigHeadersCount" class="text-[10px] text-slate-400 font-medium">กำหนด Headers ตัวพราง 4 ค่า</div>
        </div>
      </div>
      <i class="ph-bold ph-caret-right text-slate-300 group-hover:text-blue-500 transition"></i>
    </div>

    <!-- Card 4: Ports & Scope -->
    <div class="p-3.5 rounded-2xl bg-white border border-slate-200/80 hover:border-blue-300 shadow-2xs hover:shadow-xs transition flex items-center justify-between gap-2 group cursor-pointer" id="cardConfigScope">
      <div class="flex items-start gap-3">
        <div class="w-9 h-9 rounded-xl bg-emerald-50 text-emerald-600 flex items-center justify-center shrink-0 mt-0.5">
          <i class="ph-bold ph-rocket-launch text-lg"></i>
        </div>
        <div>
          <div class="text-[11px] text-slate-400 font-medium">พอร์ต &amp; ขอบเขต ThaiCERT</div>
          <div id="detailConfigPortMode" class="font-bold text-slate-800 text-xs truncate max-w-[140px]">สแกนทั้งหมด (Top 100 พอร์ต)</div>
          <div id="detailConfigScope" class="text-[10px] text-slate-400">ครอบคลุม 8 กลุ่มระบบ (Enterprise)</div>
        </div>
      </div>
      <i class="ph-bold ph-caret-right text-slate-300 group-hover:text-blue-500 transition"></i>
    </div>
  </div>

  <!-- Stealth Specifications Preview Strip -->
  <div class="pt-2 border-t border-slate-100 flex flex-col md:flex-row items-center justify-between gap-2 text-[11px] text-slate-500">
    <div class="flex items-center gap-2 truncate w-full">
      <span class="font-semibold text-slate-600 shrink-0">User-Agent:</span>
      <span id="detailFullUserAgent" class="font-mono text-[10px] text-slate-600 bg-slate-50 px-2.5 py-0.5 rounded-lg border border-slate-200 truncate select-all">ThaiCERT-OPScaner/2.0</span>
    </div>
    <div class="shrink-0 flex items-center gap-2">
      <span class="font-semibold text-slate-600">Headers:</span>
      <span id="detailCustomHeadersText" class="font-mono text-[10px] text-slate-600 bg-slate-50 px-2.5 py-0.5 rounded-lg border border-slate-200">ไม่มีการกำหนด Header เพิ่มเติม</span>
    </div>
  </div>
</div>
