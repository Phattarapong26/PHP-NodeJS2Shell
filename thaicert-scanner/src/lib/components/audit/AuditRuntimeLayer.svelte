<!--
  @component AuditRuntimeLayer
  Markup ported 1:1 from the original GUI.html (lines 987-1001).
  Element ids are preserved: the controllers in src/lib/controllers bind to them.
-->
<!-- Layer 2: Application & Runtime Hardening -->
<div class="p-4 rounded-2xl bg-white/70 border border-slate-200/80 shadow-sm space-y-2">
  <div class="flex items-center justify-between text-xs font-bold text-slate-800">
    <span class="flex items-center gap-1.5 text-indigo-700">
      <i class="ph-bold ph-cpu"></i> 2. สภาพแวดล้อมภาษาและระบบ (Application & Runtime)
    </span>
    <span id="auditHardeningBadge" class="px-2 py-0.5 rounded-md font-medium text-[11px] bg-emerald-50 text-emerald-700 border border-emerald-200"></span>
  </div>
  <div class="grid grid-cols-2 gap-2 text-[11px] pt-1 border-t border-slate-100">
    <div><span class="text-slate-400">CMS / Framework:</span> <b id="auditCmsName" class="text-slate-800 block"></b></div>
    <div><span class="text-slate-400">Web Server Engine:</span> <b id="auditServerName" class="text-slate-800 block"></b></div>
    <div><span class="text-slate-400">การเปิดเผยเวอร์ชัน (expose_php):</span> <b id="auditExposeStatus" class="text-slate-800 block"></b></div>
    <div><span class="text-slate-400">พอร์ตที่เปิดให้บริการ:</span> <b id="auditOpenPorts" class="text-slate-800 block"></b></div>
  </div>
</div>
