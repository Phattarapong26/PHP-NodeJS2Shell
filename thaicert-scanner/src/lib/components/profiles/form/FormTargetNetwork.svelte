<!--
  @component FormTargetNetwork
  Markup ported 1:1 from the original GUI.html (lines 1614-1643).
  Element ids are preserved: the controllers in src/lib/controllers bind to them.
-->
<!-- Row 2: Target Network & CIDR Presets -->
<div class="p-3.5 rounded-2xl neu-concave-card border border-blue-200/80 bg-white/70 space-y-2.5">
  <div class="flex items-center justify-between">
    <label class="font-bold text-slate-800 text-xs flex items-center gap-1.5">
      <i class="ph-bold ph-target text-blue-600"></i>
      <span>เป้าหมายเครือข่าย (Network Target / CIDR)</span>
    </label>
    <button id="btnFormDetectNetwork" type="button" class="neu-pill-btn px-2.5 py-1 rounded-lg text-blue-600 text-[10px] font-semibold flex items-center gap-1 cursor-pointer">
      <i class="ph-bold ph-crosshair text-xs"></i>
      <span>ใช้ IP ปัจจุบัน</span>
    </button>
  </div>
  <input 
    id="profileFormNetwork" 
    type="text" 
    placeholder="เช่น 192.168.1.0/24 (เว้นว่างเพื่อตรวจจับอัตโนมัติ)" 
    class="w-full px-3 py-2 rounded-xl border border-slate-300 focus:border-blue-500 focus:ring-1 focus:ring-blue-500 focus:outline-none bg-white font-mono text-xs font-bold text-slate-800"
  />
  <div class="flex items-center gap-2">
    <span class="text-[10px] text-slate-400">ทางลัด CIDR:</span>
    <button type="button" id="btnCidr24" class="cidr-preset-btn px-2.5 py-0.5 rounded-lg border border-slate-200 bg-slate-50 hover:bg-blue-50 text-slate-700 font-mono text-[10px] font-semibold cursor-pointer transition-all" data-cidr="24">/24 (254 Hosts)</button>
    <button type="button" id="btnCidr28" class="cidr-preset-btn px-2.5 py-0.5 rounded-lg border border-slate-200 bg-slate-50 hover:bg-blue-50 text-slate-700 font-mono text-[10px] font-semibold cursor-pointer transition-all" data-cidr="28">/28 (14 Hosts)</button>
    <button type="button" id="btnCidr32" class="cidr-preset-btn px-2.5 py-0.5 rounded-lg border border-slate-200 bg-slate-50 hover:bg-blue-50 text-slate-700 font-mono text-[10px] font-semibold cursor-pointer transition-all" data-cidr="32">/32 (เครื่องเดียว)</button>
  </div>
  <!-- VPN Reminder inside form -->
  <div class="p-2 rounded-xl bg-amber-50 border border-amber-200/70 text-amber-900 text-[10.5px] flex items-start gap-1.5">
    <i class="ph-bold ph-warning text-amber-600 text-sm flex-shrink-0 mt-0.5"></i>
    <span><b>คำเตือน VPN:</b> หากต่อ VPN อยู่ ให้ระบุวง Subnet กายภาพจริงในช่องนี้ เพื่อไม่ให้ผลสแกนคลาดเคลื่อนไปที่ช่องทาง VPN</span>
  </div>
</div>
