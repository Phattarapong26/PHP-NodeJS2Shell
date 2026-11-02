<!--
  @component AuditMatchedCves
  Markup ported 1:1 from the original GUI.html (lines 959-971).
  Element ids are preserved: the controllers in src/lib/controllers bind to them.
-->
<!-- Mapped CVE Vulnerability Warnings (ThaiCERT & NCSA Catalog) -->
<div id="auditMatchedCvesWrapper" class="hidden p-3.5 rounded-2xl bg-rose-50/90 border border-rose-200/90 shadow-sm space-y-2">
  <div class="flex items-center justify-between text-xs font-bold text-rose-950">
    <span class="flex items-center gap-1.5">
      <i class="ph-bold ph-shield-warning text-rose-600 text-base"></i>
      <span>ช่องโหว่ CVE ที่ตรวจพบความเสี่ยงบนระบบนี้ (Mapped CVEs):</span>
    </span>
    <span id="auditMatchedCvesCountBadge" class="px-2 py-0.5 rounded-full text-[10px] font-bold bg-rose-200 text-rose-800 font-mono">0 ช่องโหว่</span>
  </div>
  <div id="auditMatchedCvesList" class="space-y-2 pt-1">
    <!-- Rendered dynamic CVE cards -->
  </div>
</div>
