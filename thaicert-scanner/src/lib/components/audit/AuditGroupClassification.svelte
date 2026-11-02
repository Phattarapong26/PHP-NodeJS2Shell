<!--
  @component AuditGroupClassification
  Markup ported 1:1 from the original GUI.html (lines 936-957).
  Element ids are preserved: the controllers in src/lib/controllers bind to them.
-->
<!-- ThaiCERT 8 Groups Target Classification -->
<div class="p-3.5 rounded-2xl bg-gradient-to-r from-blue-50/90 via-indigo-50/70 to-slate-50/80 border border-blue-200/80 shadow-sm space-y-1.5">
  <div class="flex items-center justify-between text-xs font-bold text-slate-800">
    <span class="flex items-center gap-1.5 text-blue-900">
      <i class="ph-bold ph-squares-four text-base text-blue-600"></i> การจำแนกตาม 8 กลุ่มระบบ ThaiCERT / สกมช.
    </span>
    <span id="auditGroupPrimaryBadge" class="px-2 py-0.5 rounded-md font-semibold text-[11px] bg-blue-100 text-blue-800 border border-blue-200 font-mono">กำลังประเมิน...</span>
  </div>
  <div id="auditGroupList" class="flex flex-wrap gap-1.5 pt-1">
    <!-- Injected group badges -->
  </div>
  <!-- Architectural Exploit Chain Matrix container -->
  <div id="auditArchMatrixWrapper" class="hidden mt-2 pt-2 border-t border-blue-200/60 text-[11px]">
    <div class="font-bold text-slate-700 mb-1 flex items-center justify-between">
      <span><i class="ph-bold ph-git-branch text-indigo-600"></i> สถาปัตยกรรม & Exploit Chain Matrix (8 กลุ่ม ThaiCERT):</span>
      <span class="text-[10px] text-slate-400 font-normal">SAPI · Worker Model · Prerequisites</span>
    </div>
    <div id="auditArchMatrixList" class="space-y-1.5 overflow-x-auto">
      <!-- Injected architectural cards -->
    </div>
  </div>
</div>
