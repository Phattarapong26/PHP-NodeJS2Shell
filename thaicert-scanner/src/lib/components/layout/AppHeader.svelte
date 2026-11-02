<!--
  @component AppHeader
  Markup ported 1:1 from the original GUI.html (lines 239-296).
  Element ids are preserved: the controllers in src/lib/controllers bind to them.
-->
<!-- Top System Window Bar -->
<header class="w-full px-6 py-3.5 flex items-center justify-between z-20 select-none border-b border-slate-200/40 bg-white/30 backdrop-blur-sm">
  <!-- Traffic lights / Window controls + Current Profile Selector Button -->
  <div class="flex items-center gap-3">
    <div class="flex items-center gap-2 select-none pointer-events-none">
      <span class="w-3.5 h-3.5 rounded-full bg-red-400/90 shadow-sm inline-block opacity-85"></span>
      <span class="w-3.5 h-3.5 rounded-full bg-amber-400/90 shadow-sm inline-block opacity-85"></span>
      <span class="w-3.5 h-3.5 rounded-full bg-emerald-400/90 shadow-sm inline-block opacity-85"></span>
    </div>

    <!-- Left Current Profile Pill / Button -->
    <button id="btnHeaderProfile" type="button" class="flex items-center gap-2 px-3 py-1 rounded-xl border text-xs font-semibold shadow-xs transition hover:shadow-sm cursor-pointer bg-white/70 border-slate-200/90 text-slate-700 hover:bg-white hover:border-blue-400 hover:text-blue-700" title="คลิกเพื่อจัดการและเลือก Scan Profile">
      <i class="ph-bold ph-identification-card text-blue-600 text-sm"></i>
      <span class="text-slate-400 font-normal">Profile:</span>
      <span id="headerProfileName" class="font-bold text-slate-800 max-w-[170px] truncate">ยังไม่ได้เลือก Profile</span>
      <i class="ph ph-caret-down text-slate-400 text-[10px]"></i>
    </button>
  </div>

  <!-- Right Window Actions -->
  <div class="flex items-center gap-2.5 text-slate-400 text-sm">
    <!-- Git Update Notification Badge -->
    <button id="btnHeaderUpdateBadge" type="button" class="hidden hover:opacity-95 transition flex items-center gap-1.5 text-xs font-bold px-2.5 py-1 rounded-lg bg-gradient-to-r from-emerald-600 to-teal-600 text-white border border-emerald-600 shadow-sm cursor-pointer animate-pulse" title="ระบบมีการอัปเดตใหม่บน Git คลิกเพื่อดูรายละเอียดและอัปเดต">
      <i class="ph-bold ph-arrow-circle-up text-sm"></i>
      <span>มีอัปเดตใหม่</span>
      <span id="headerUpdateTag" class="text-[10px] bg-white/20 px-1 py-0.2 rounded font-mono">Git</span>
    </button>

    <button id="btnExportAmberPdf" class="hover:opacity-90 transition flex items-center gap-1.5 text-xs font-bold px-2.5 py-1 rounded-lg bg-amber-400 text-amber-950 border border-amber-500 shadow-sm cursor-pointer" title="ดาวน์โหลดรายงานความมั่นคงปลอดภัยมาตรฐาน สกมช. (TLP:AMBER PDF)">
      <i class="ph-bold ph-file-pdf text-sm text-amber-950"></i>
      <span>รายงาน TLP:AMBER (PDF)</span>
    </button>
    <button id="btnExportEvidenceBundle" class="hover:opacity-90 transition flex items-center gap-1.5 text-xs font-bold px-2.5 py-1 rounded-lg bg-emerald-600 text-white border border-emerald-700 shadow-sm cursor-pointer" title="ดาวน์โหลด Forensic Evidence Bundle (.ZIP) พร้อม SHA-256 Digest">
      <i class="ph-bold ph-archive text-sm"></i>
      <span>Forensic Bundle (.ZIP)</span>
    </button>
    <button id="btnOpenCveCatalog" class="hover:text-blue-700 transition flex items-center gap-1.5 text-xs font-semibold px-2.5 py-1 rounded-lg bg-blue-50/90 text-blue-700 border border-blue-200/70 shadow-sm cursor-pointer" title="เปิดฐานข้อมูลช่องโหว่ CVE Multi-Stack (PHP, NGINX, Node.js)">
      <i class="ph-bold ph-database text-sm"></i>
      <span>ฐานข้อมูล CVE (16 รายการ)</span>
    </button>
    <a href="/diagram" target="_blank" class="hover:text-indigo-600 transition flex items-center gap-1.5 text-xs font-semibold px-2.5 py-1 rounded-lg bg-indigo-50/90 text-indigo-700 border border-indigo-200/70 shadow-sm" title="เปิดแผนผังสถาปัตยกรรมและข้อจำกัดระบบ (หน้าเต็ม)">
      <i class="ph-bold ph-git-fork text-sm"></i>
      <span>ผังสถาปัตยกรรม & ขอบเขต</span>
    </a>
    <button id="btnToggleSettings" class="hover:text-slate-700 transition" title="Network Config">
      <i class="ph ph-gear text-lg"></i>
    </button>
    <button id="btnToggleWorkflow" class="hover:text-blue-600 transition flex items-center gap-1.5 text-xs font-semibold px-2.5 py-1 rounded-lg bg-blue-50/80 text-blue-600 border border-blue-200/60" title="ดูขั้นตอนการทำงาน">
      <i class="ph ph-tree-structure text-sm"></i>
      <span>Diagram Flow</span>
    </button>
    <div class="flex items-center gap-3 pl-2 border-l border-slate-300/60">
      <button class="hover:text-slate-700 transition" title="ย่อ"><i class="ph ph-minus"></i></button>
      <button id="btnMaximize" class="hover:text-slate-700 transition" title="ขยายเต็มจอ"><i class="ph ph-square"></i></button>
      <button class="hover:text-slate-700 transition" title="ปิด"><i class="ph ph-x"></i></button>
    </div>
  </div>
</header>
