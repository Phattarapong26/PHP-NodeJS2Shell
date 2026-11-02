<!--
  @component ProfileScanHistorySection
  Scan History Timeline with circular success percentage rings and latest report card.
  Styled 1:1 against the OP Scanner enterprise design.
-->
<div class="rounded-3xl bg-white border border-slate-200/80 p-5 shadow-xs space-y-4">
  <!-- Section Header -->
  <div class="flex items-center justify-between border-b border-slate-100 pb-3">
    <div class="flex items-center gap-2.5">
      <div class="w-8 h-8 rounded-full bg-blue-50 border border-blue-200/70 flex items-center justify-center text-blue-600 shadow-2xs">
        <i class="ph-bold ph-clock text-base"></i>
      </div>
      <div class="flex items-center gap-2">
        <h3 class="font-bold text-slate-800 text-xs md:text-sm tracking-tight">
          ประวัติการสแกน (Scan History Timeline)
        </h3>
        <span id="detailHistoryCountBadge" class="font-bold text-[11px] px-2.5 py-0.5 rounded-full bg-blue-50 text-blue-700 border border-blue-200/80">
          0 รายการล่าสุด
        </span>
      </div>
    </div>

    <!-- Dropdown Selector: Show Latest N Items -->
    <div class="relative inline-flex items-center">
      <select id="detailHistoryLimitSelect" class="text-xs font-semibold text-slate-700 bg-white border border-slate-200 rounded-xl px-3 py-1.5 pr-7 shadow-2xs hover:border-blue-400 focus:outline-none focus:ring-2 focus:ring-blue-100 cursor-pointer appearance-none transition-all">
        <option value="5" selected>แสดงล่าสุด 5 รายการ</option>
        <option value="10">แสดงล่าสุด 10 รายการ</option>
        <option value="20">แสดงล่าสุด 20 รายการ</option>
        <option value="50">แสดงทั้งหมด</option>
      </select>
      <i class="ph-bold ph-caret-down text-slate-400 absolute right-2.5 pointer-events-none text-[10px]"></i>
    </div>
  </div>

  <!-- Empty History State -->
  <div id="detailHistoryEmptyState" class="py-12 px-6 flex flex-col items-center justify-center text-center rounded-2xl border-2 border-dashed border-slate-200 bg-white/60">
    <div class="w-12 h-12 rounded-2xl bg-slate-100 text-slate-400 flex items-center justify-center mb-2">
      <i class="ph-duotone ph-hourglass-empty text-2xl"></i>
    </div>
    <h4 class="text-xs font-bold text-slate-700 mb-1">ยังไม่มีประวัติการสแกน</h4>
    <p class="text-[11px] text-slate-400 max-w-sm leading-relaxed">
      เมื่อเริ่มต้นการสแกนโดยเลือก Profile นี้ ข้อมูลสรุปและผลการตรวจสอบช่องโหว่จะถูกบันทึกไว้ในประวัตินี้โดยอัตโนมัติ เพื่อให้สามารถเปิดดูย้อนหลังได้ตลอดเวลา
    </p>
  </div>

  <!-- Vertical Timeline Wrapper -->
  <div id="detailHistoryTimelineWrapper" class="relative hidden pl-7 space-y-3">
    <!-- Continuous Vertical Track Line -->
    <div class="absolute left-[11px] top-3 bottom-5 w-0.5 bg-blue-100 pointer-events-none"></div>

    <!-- History Cards Container -->
    <div id="detailHistoryListContainer" class="flex flex-col gap-3">
      <!-- Dynamically populated via renderProfileScanHistory() in profiles.ts -->
    </div>

    <!-- Timeline Footer: + ดูประวัติเพิ่มเติม -->
    <div id="detailHistoryFooter" class="relative flex items-center gap-3 pt-2">
      <div class="absolute -left-7 w-6 flex items-center justify-center">
        <div class="w-2.5 h-2.5 rounded-full bg-slate-300 ring-4 ring-slate-50"></div>
      </div>
      <button type="button" id="btnLoadMoreHistory" class="neu-pill-btn px-3.5 py-1.5 rounded-xl bg-slate-100 hover:bg-slate-200/80 border border-slate-200 text-slate-700 text-xs font-semibold flex items-center gap-1.5 cursor-pointer shadow-2xs transition">
        <i class="ph-bold ph-plus text-xs"></i>
        <span>ดูประวัติเพิ่มเติม</span>
      </button>
    </div>
  </div>

  <!-- Bottom Card: รายงานล่าสุด (Latest Scan Summary Banner) -->
  <div id="detailLatestScanSummaryCard" class="hidden mt-4 rounded-2xl border border-blue-200/90 bg-gradient-to-r from-blue-50/80 via-indigo-50/40 to-blue-50/80 p-4 shadow-xs flex flex-col md:flex-row items-center justify-between gap-4">
    <!-- Left: 3D Shield Graphic with Sparkles -->
    <div class="relative flex items-center justify-center shrink-0 w-16 h-16">
      <div class="absolute inset-0 bg-blue-400/20 rounded-full blur-lg"></div>
      <div class="relative w-12 h-12 rounded-2xl bg-gradient-to-br from-blue-500 via-blue-600 to-indigo-600 shadow-md shadow-blue-500/30 flex items-center justify-center text-white text-2xl border border-blue-300/40">
        <i class="ph-fill ph-shield-check"></i>
      </div>
      <span class="absolute -top-1 -left-1 text-xs select-none">✨</span>
      <span class="absolute -top-1 -right-1 text-xs select-none">✨</span>
      <div class="absolute -bottom-1 w-10 h-2 bg-blue-900/10 rounded-full blur-xs"></div>
    </div>

    <!-- Center: 4-Column Metric Summary Grid -->
    <div class="flex-1 w-full">
      <div class="grid grid-cols-2 lg:grid-cols-4 gap-3 text-xs">
        <div>
          <div class="text-[11px] text-slate-500 flex items-center gap-1">📅 รายงานล่าสุด</div>
          <div class="font-bold text-slate-800 mt-0.5 tracking-tight" id="detailLatestSummaryDateTime">-</div>
          <div class="mt-1">
            <span class="inline-flex items-center gap-1 px-2 py-0.2 rounded-full bg-emerald-100/80 text-emerald-800 text-[10px] font-bold">
              <i class="ph-bold ph-check text-[10px]"></i> สำเร็จ
            </span>
          </div>
        </div>
        <div>
          <div class="text-[11px] text-slate-500 flex items-center gap-1">⏱️ ระยะเวลาสแกน</div>
          <div class="font-bold text-slate-800 mt-0.5" id="detailLatestSummaryElapsed">-</div>
        </div>
        <div>
          <div class="text-[11px] text-slate-500 flex items-center gap-1">💻 จำนวนเครื่องที่สแกน</div>
          <div class="font-bold text-slate-800 mt-0.5" id="detailLatestSummaryTotalHosts">-</div>
        </div>
        <div>
          <div class="text-[11px] text-slate-500 flex items-center gap-1">🛡️ ผลการสแกน</div>
          <div class="font-bold mt-0.5 flex items-center gap-1.5" id="detailLatestSummaryVerdict">
            <span class="w-2 h-2 rounded-full bg-emerald-500 inline-block"></span>
            <span class="text-emerald-700">ไม่พบช่องโหว่</span>
          </div>
        </div>
      </div>
    </div>

    <!-- Right: Quick Action Button -->
    <div class="shrink-0">
      <button id="btnLatestScanAction" type="button" class="neu-pill-btn active px-4 py-2.5 rounded-xl text-white font-bold text-xs shadow-xs flex items-center gap-2 cursor-pointer hover:scale-[1.02] transition">
        <i class="ph-bold ph-download-simple text-sm"></i>
        <span>ดาวน์โหลดรายงาน</span>
      </button>
    </div>
  </div>
</div>
