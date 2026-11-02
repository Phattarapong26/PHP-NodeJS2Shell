<!--
  @component ResultsTable
  Results Table & Centered Empty State.
  Engineered 1:1 against ThaiCERT enterprise security operations.
-->
<script lang="ts">
  import { closeResultsModal, switchFilterToAll } from '../../controllers/results';
</script>

<!-- Results Table Area -->
<div class="p-4 sm:p-6 bg-slate-50/40 flex-1 min-h-[250px] flex flex-col justify-center">
  <div id="resultsTableContainer" class="rounded-2xl border border-white/80 bg-white/70 shadow-sm p-1 overflow-x-auto">
    <table class="w-full text-left border-collapse">
      <thead>
        <tr class="border-b border-slate-200/80 text-[11px] font-bold uppercase tracking-wider text-slate-400 bg-slate-100/50">
          <th class="py-2.5 px-3">IP Address : Port</th>
          <th class="py-2.5 px-3">ประเภทอุปกรณ์ / บริการ</th>
          <th class="py-2.5 px-3">รันไทม์ (Runtime / Version)</th>
          <th class="py-2.5 px-3">Port</th>
          <th class="py-2.5 px-3">Latency</th>
          <th class="py-2.5 px-3">การประเมินความปลอดภัย (ThaiCERT)</th>
          <th class="py-2.5 px-3 text-right">Action</th>
        </tr>
      </thead>
      <tbody id="resultsTableBody" class="divide-y divide-slate-100/90 text-xs">
        <!-- Injected via JavaScript -->
      </tbody>
    </table>
  </div>

  <!-- Empty state when no scan done yet or no host found (Centered with mx-auto & flex) -->
  <div id="resultsEmptyState" class="hidden flex flex-col items-center justify-center py-12 px-6 text-center w-full mx-auto my-auto">
    <div id="emptyStateIconWrap" class="w-16 h-16 rounded-full outer-dish flex items-center justify-center text-emerald-500 mb-4 shadow-sm mx-auto">
      <i id="emptyStateIcon" class="ph-bold ph-shield-check text-3xl text-emerald-500"></i>
    </div>
    <h3 id="emptyStateTitle" class="font-bold text-slate-800 text-base text-center mx-auto tracking-tight">สแกนเสร็จสิ้น — ไม่พบเครื่องที่รันบริการ PHP</h3>
    <p id="emptyStateDesc" class="text-xs text-slate-500 mt-2 max-w-md text-center mx-auto leading-relaxed">
      ระบบส่งคำขอตรวจสอบความปลอดภัยครบทุก Host ในวง Subnet เรียบร้อย ไม่พบบริการ PHP ที่เปิดใช้งาน (เครือข่ายปลอดภัยจากช่องโหว่ php2shell / CVE-2024-4577)
    </p>
    <div class="mt-6 flex flex-wrap items-center justify-center gap-3 mx-auto">
      <button id="btnEmptyShowAll" onclick={() => switchFilterToAll()} class="px-4 py-2 rounded-xl neu-pill-btn text-xs font-semibold text-blue-700 border border-blue-200 flex items-center gap-1.5 cursor-pointer hover:bg-blue-50 transition shadow-2xs">
        <i class="ph-bold ph-broadcast text-blue-600"></i>
        <span>ดูอุปกรณ์ออนไลน์ทั้งหมด (<span id="emptyAllCount">0</span> เครื่อง)</span>
      </button>
      <button onclick={() => closeResultsModal()} class="px-4 py-2 rounded-xl neu-pill-btn text-xs font-semibold text-slate-700 hover:text-slate-900 cursor-pointer transition shadow-2xs">
        เปลี่ยนเป้าหมาย Subnet อื่น
      </button>
    </div>
  </div>
</div>
