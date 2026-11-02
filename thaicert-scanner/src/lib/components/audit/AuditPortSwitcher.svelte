<!--
  @component AuditPortSwitcher
  Markup ported 1:1 from the original GUI.html (lines 867-876).
  Element ids are preserved: the controllers in src/lib/controllers bind to them.
-->
<!-- Target Service Port Selector (When multiple ports exist on IP) -->
<div id="auditPortSwitcherWrapper" class="hidden p-3 rounded-2xl bg-indigo-50/80 border border-indigo-200/80 shadow-xs flex flex-col sm:flex-row sm:items-center justify-between gap-2">
  <div class="flex items-center gap-1.5 text-xs text-indigo-950 font-bold">
    <i class="ph-bold ph-plugs-connected text-indigo-600 text-sm"></i>
    <span>เลือกสลับดูผลตามพอร์ตบนเครื่องนี้:</span>
  </div>
  <div id="auditPortSwitcherList" class="flex items-center gap-1.5 flex-wrap">
    <!-- Injected port switch buttons -->
  </div>
</div>
