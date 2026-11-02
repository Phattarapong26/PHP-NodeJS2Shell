<!--
  @component FormEnterpriseScope
  Markup ported 1:1 from the original GUI.html (lines 1777-1801).
  Element ids are preserved: the controllers in src/lib/controllers bind to them.
-->
<!-- Row 6: ThaiCERT Enterprise Scope -->
<div class="p-3.5 rounded-2xl neu-concave-card border border-indigo-200/80 bg-white/70 space-y-2">
  <label class="font-bold text-slate-800 text-xs flex items-center gap-1.5 text-indigo-950">
    <i class="ph-bold ph-shield-check text-indigo-600"></i>
    <span>ขอบเขตการประเมิน (ThaiCERT Enterprise Scope)</span>
  </label>
  <div class="grid grid-cols-2 gap-2 text-[11px]">
    <label id="cardScopeAll" data-scope-preset="all" class="scope-preset-card flex items-center gap-2 p-2 rounded-xl border border-indigo-500 bg-indigo-50/70 ring-1 ring-indigo-400/40 text-indigo-950 font-bold cursor-pointer transition shadow-xs">
      <input type="radio" name="profile_scope_preset" value="all" checked class="accent-indigo-600 cursor-pointer">
      <span>🌟 ครบทั้ง 8 กลุ่มระบบ</span>
    </label>
    <label id="cardScopeWindows" data-scope-preset="windows" class="scope-preset-card flex items-center gap-2 p-2 rounded-xl border border-slate-200 bg-white hover:border-indigo-300 text-slate-700 font-medium cursor-pointer transition">
      <input type="radio" name="profile_scope_preset" value="windows" class="accent-indigo-600 cursor-pointer">
      <span>🪟 เน้นกลุ่ม 6: Windows IIS/PHP</span>
    </label>
    <label id="cardScopeWebApi" data-scope-preset="web_api" class="scope-preset-card flex items-center gap-2 p-2 rounded-xl border border-slate-200 bg-white hover:border-indigo-300 text-slate-700 font-medium cursor-pointer transition">
      <input type="radio" name="profile_scope_preset" value="web_api" class="accent-indigo-600 cursor-pointer">
      <span>🌐 เน้นกลุ่ม 1 & 2: Web & API</span>
    </label>
    <label id="cardScopeDevShadow" data-scope-preset="dev_shadow" class="scope-preset-card flex items-center gap-2 p-2 rounded-xl border border-slate-200 bg-white hover:border-indigo-300 text-slate-700 font-medium cursor-pointer transition">
      <input type="radio" name="profile_scope_preset" value="dev_shadow" class="accent-indigo-600 cursor-pointer">
      <span>🕒 เน้นกลุ่ม 7: Dev/Shadow IT</span>
    </label>
  </div>
</div>
