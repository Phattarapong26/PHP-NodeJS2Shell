<!--
  @component FormPortMode
  Markup ported 1:1 from the original GUI.html (lines 1738-1775).
  Element ids are preserved: the controllers in src/lib/controllers bind to them.
-->
<!-- Row 5: Port Mode Selection -->
<div class="p-3.5 rounded-2xl neu-concave-card border border-slate-200 bg-white/70 space-y-2.5">
  <label class="font-bold text-slate-800 text-xs flex items-center gap-1.5">
    <i class="ph-bold ph-plugs text-blue-600"></i>
    <span>รูปแบบพอร์ตการตรวจสอบ (Port Mode)</span>
  </label>
  <div class="grid grid-cols-3 gap-2">
    <label id="cardPortStandard" data-port-mode="standard" class="port-mode-card flex flex-col p-2.5 rounded-xl border border-blue-500 bg-blue-50/70 shadow-xs cursor-pointer transition ring-1 ring-blue-400/40">
      <div class="flex items-center gap-1.5 mb-1">
        <input type="radio" name="profile_port_mode" value="standard" checked class="accent-blue-600 cursor-pointer">
        <span class="font-bold text-blue-900 text-[11px] port-card-title">มาตรฐาน Dev</span>
      </div>
      <span class="text-[10px] text-slate-500">23 พอร์ตยอดนิยม (80, 443, 8080, 8000, 3000, ฯลฯ)</span>
    </label>
    <label id="cardPortWide" data-port-mode="wide" class="port-mode-card flex flex-col p-2.5 rounded-xl border border-slate-200 bg-white hover:border-blue-300 cursor-pointer transition">
      <div class="flex items-center gap-1.5 mb-1">
        <input type="radio" name="profile_port_mode" value="wide" class="accent-blue-600 cursor-pointer">
        <span class="font-semibold text-slate-700 text-[11px] port-card-title">สแกนกว้าง (Wide)</span>
      </div>
      <span class="text-[10px] text-slate-400">Top 100 พอร์ตบริการทั่วไป</span>
    </label>
    <label id="cardPortCustom" data-port-mode="custom" class="port-mode-card flex flex-col p-2.5 rounded-xl border border-slate-200 bg-white hover:border-blue-300 cursor-pointer transition">
      <div class="flex items-center gap-1.5 mb-1">
        <input type="radio" name="profile_port_mode" value="custom" class="accent-blue-600 cursor-pointer">
        <span class="font-semibold text-slate-700 text-[11px] port-card-title">กำหนดเอง (Custom)</span>
      </div>
      <span class="text-[10px] text-slate-400">ระบุหมายเลขพอร์ตเฉพาะ</span>
    </label>
  </div>
  <div id="profileFormCustomPortsWrapper" class="hidden">
    <input 
      id="profileFormCustomPorts" 
      type="text" 
      placeholder="ระบุพอร์ต เช่น 80, 443, 8080, 9000, 18080" 
      class="w-full px-3 py-1.5 rounded-xl border border-slate-300 font-mono text-xs bg-white focus:outline-none focus:ring-1 focus:ring-blue-500"
    />
  </div>
</div>
