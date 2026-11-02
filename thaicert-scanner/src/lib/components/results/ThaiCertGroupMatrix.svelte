<!--
  @component ThaiCertGroupMatrix
  Markup ported 1:1 from the original GUI.html (lines 529-610).
  Element ids are preserved: the controllers in src/lib/controllers bind to them.
-->
<script lang="ts">
  import AnalyticsCharts from './AnalyticsCharts.svelte';
  import { clearGroupFilter } from '../../controllers/results';
</script>

<!-- ThaiCERT 8 Groups Inspection Matrix (NCSA Guidelines) -->
<div class="px-6 py-3 bg-gradient-to-r from-slate-50/90 via-blue-50/30 to-slate-50/90 border-b border-slate-200/70">
  <div class="flex items-center justify-between mb-2">
    <div class="flex items-center gap-2">
      <div class="w-6 h-6 rounded-lg bg-teal-600 text-white flex items-center justify-center text-xs font-bold shadow-xs">
        <i class="ph-bold ph-chart-polar"></i>
      </div>
      <span class="font-bold text-slate-800 text-xs sm:text-sm">การจำแนก 8 กลุ่มระบบความมั่นคงปลอดภัย (เกณฑ์ ThaiCERT / สกมช.)</span>
      <span class="text-[11px] text-slate-400 hidden sm:inline">· กราฟวิเคราะห์เรดาร์ & แผนภูมิ Lollipop & Top CVEs (ชี้เพื่อดูรายละเอียด / คลิกเพื่อกรอง)</span>
    </div>
    <div class="flex items-center gap-2">
      <span id="activeGroupFilterTag" class="hidden px-2.5 py-0.5 rounded-full text-[11px] font-semibold bg-blue-100 text-blue-700 border border-blue-300 items-center gap-1.5 cursor-pointer transition hover:bg-blue-200 shadow-2xs" onclick={() => clearGroupFilter()} title="คลิกเพื่อยกเลิกตัวกรอง">
        <span id="activeGroupFilterName">กลุ่ม 1</span>
        <i class="ph-bold ph-x text-xs"></i>
      </span>
    </div>
  </div>
  
  <AnalyticsCharts />
</div>
