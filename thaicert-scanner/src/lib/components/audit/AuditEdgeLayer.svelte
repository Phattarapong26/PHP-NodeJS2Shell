<!--
  @component AuditEdgeLayer
  Markup ported 1:1 from the original GUI.html (lines 973-985).
  Element ids are preserved: the controllers in src/lib/controllers bind to them.
-->
<!-- Layer 1: Edge & Network Security -->
<div class="p-4 rounded-2xl bg-white/70 border border-slate-200/80 shadow-sm space-y-2">
  <div class="flex items-center justify-between text-xs font-bold text-slate-800">
    <span class="flex items-center gap-1.5 text-blue-700">
      <i class="ph-bold ph-globe"></i> 1. การป้องกันระดับหน้าบ้าน (Edge & WAF)
    </span>
    <span id="auditWafBadge" class="px-2 py-0.5 rounded-md font-mono text-[11px] bg-slate-100 text-slate-700"></span>
  </div>
  <div class="grid grid-cols-2 gap-2 text-[11px] pt-1 border-t border-slate-100">
    <div><span class="text-slate-400">Web Application Firewall:</span> <b id="auditWafName" class="text-slate-800 block"></b></div>
    <div><span class="text-slate-400">Transport Security (HSTS):</span> <b id="auditHsts" class="text-slate-800 block"></b></div>
  </div>
</div>
