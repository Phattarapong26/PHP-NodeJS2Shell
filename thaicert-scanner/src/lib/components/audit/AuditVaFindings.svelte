<!--
  @component AuditVaFindings
  Markup ported 1:1 from the original GUI.html (lines 1039-1053).
  Element ids are preserved: the controllers in src/lib/controllers bind to them.
-->
<!-- Discovered VA Findings & Configuration State (ค่าของการ VA ที่ตรวจพบจริง) -->
<div class="pt-3 border-t border-slate-200/60 space-y-2.5">
  <div class="flex items-center justify-between flex-wrap gap-2">
    <span class="font-bold text-slate-800 text-xs sm:text-sm flex items-center gap-1.5">
      <i class="ph-bold ph-magnifying-glass-plus text-indigo-600 text-base"></i>
      ค่าทางเทคนิคและสถานะที่ตรวจพบจากการทำ VA (Audited Vulnerability Assessment Findings):
    </span>
    <span class="text-[10px] text-slate-400 font-mono">Real-time Audited Parameter Values</span>
  </div>

  <!-- 2-Column Responsive Grid for Discovered VA Findings -->
  <div class="grid grid-cols-1 md:grid-cols-2 gap-3.5" id="vaDiscoveredCardsContainer">
    <!-- Dynamically populated via renderVaDiscoveredCards(host) -->
  </div>
</div>
