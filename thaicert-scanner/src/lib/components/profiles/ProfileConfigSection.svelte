<!--
  @component ProfileConfigSection
  Markup ported 1:1 from the original GUI.html (lines 1448-1521).
  Element ids are preserved: the controllers in src/lib/controllers bind to them.
-->
<!-- SECTION 1: Profile Configuration & Stealth Specifications -->
<div class="space-y-3">
  <div class="flex items-center justify-between border-b border-slate-200/60 pb-2">
    <span class="font-bold text-slate-800 text-xs flex items-center gap-1.5">
      <i class="ph-bold ph-sliders-horizontal text-blue-600"></i>
      <span>การตั้งค่าการสแกน & การอำพรางตัว (Stealth Configuration)</span>
    </span>
    <span class="text-[10px] text-slate-400 font-mono">Config Matrix</span>
  </div>

  <div class="grid grid-cols-1 md:grid-cols-4 gap-3">
    <!-- Target Card -->
    <div class="p-3.5 rounded-2xl bg-white border border-slate-200 shadow-xs space-y-1">
      <div class="text-[10.5px] text-slate-400 font-semibold flex items-center gap-1">
        <i class="ph-bold ph-target text-blue-600"></i>
        <span>Network Target</span>
      </div>
      <div id="detailConfigTarget" class="font-mono font-bold text-slate-800 text-sm">192.168.1.0/24</div>
      <div id="detailConfigTargetSub" class="text-[10px] text-slate-400">ขอบเขตเป้าหมายเครือข่าย</div>
    </div>

    <!-- Speed & Concurrency Card -->
    <div class="p-3.5 rounded-2xl bg-white border border-slate-200 shadow-xs space-y-1">
      <div class="text-[10.5px] text-slate-400 font-semibold flex items-center gap-1">
        <i class="ph-bold ph-lightning text-amber-500"></i>
        <span>ความเร็ว & Concurrency</span>
      </div>
      <div class="flex items-center gap-2">
        <span id="detailConfigConcurrency" class="font-mono font-bold text-blue-700 text-sm">100 reqs</span>
        <span class="text-slate-300">/</span>
        <span id="detailConfigTimeout" class="font-mono text-slate-600 text-xs">Timeout 2.2s</span>
      </div>
      <div class="text-[10px] text-slate-400">Non-blocking Async I/O</div>
    </div>

    <!-- Stealth & Headers Card -->
    <div class="p-3.5 rounded-2xl bg-white border border-slate-200 shadow-xs space-y-1">
      <div class="text-[10.5px] text-slate-400 font-semibold flex items-center gap-1">
        <i class="ph-bold ph-mask-happy text-indigo-600"></i>
        <span>การอำพรางตัว (Stealth)</span>
      </div>
      <div id="detailConfigUaName" class="font-semibold text-slate-800 text-xs truncate">Chrome Desktop</div>
      <div id="detailConfigHeadersCount" class="text-[10px] text-emerald-700 font-semibold">กำหนด Headers อำพราง 2 ค่า</div>
    </div>

    <!-- Ports & Scope Card -->
    <div class="p-3.5 rounded-2xl bg-white border border-slate-200 shadow-xs space-y-1">
      <div class="text-[10.5px] text-slate-400 font-semibold flex items-center gap-1">
        <i class="ph-bold ph-plugs text-teal-600"></i>
        <span>พอร์ต & ขอบเขต ThaiCERT</span>
      </div>
      <div id="detailConfigPortMode" class="font-bold text-slate-800 text-xs">มาตรฐาน Dev (23 พอร์ต)</div>
      <div id="detailConfigScope" class="text-[10px] text-indigo-700 font-medium">ครอบคลุม 8 กลุ่มระบบ</div>
    </div>
  </div>

  <!-- Stealth Details Expanded Box -->
  <div class="p-3.5 rounded-2xl bg-slate-50/80 border border-slate-200/80 space-y-2">
    <div class="flex items-center justify-between text-[11px] font-semibold text-slate-700">
      <span class="flex items-center gap-1.5">
        <i class="ph-bold ph-identification-badge text-indigo-600"></i>
        <span>User-Agent String ที่ส่งออกไป:</span>
      </span>
      <span class="text-[10px] font-mono text-slate-400 bg-white px-2 py-0.5 rounded border border-slate-200">HTTP Request Header</span>
    </div>
    <div id="detailFullUserAgent" class="font-mono text-[10.5px] text-slate-700 bg-white p-2 rounded-xl border border-slate-200 break-all select-all">
      ThaiCERT-OPScaner/2.0 (LAN Discovery & Security Audit)
    </div>
    <div id="detailCustomHeadersSection" class="pt-1">
      <span class="text-[10.5px] font-semibold text-slate-600 block mb-1">Custom Request Headers:</span>
      <pre id="detailCustomHeadersText" class="font-mono text-[10px] text-slate-700 bg-white p-2 rounded-xl border border-slate-200 overflow-x-auto whitespace-pre-wrap">ไม่มีการกำหนด Header เพิ่มเติม</pre>
    </div>
  </div>
</div>
