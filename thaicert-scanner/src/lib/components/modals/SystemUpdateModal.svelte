<!--
  @component SystemUpdateModal
  Markup ported 1:1 from the original GUI.html (lines 1826-1882).
  Element ids are preserved: the controllers in src/lib/controllers bind to them.
-->
<!-- SYSTEM UPDATE MODAL (Git Version Check & 1-Click Update) -->
<div id="systemUpdateModal" class="fixed inset-0 bg-slate-900/40 backdrop-blur-sm z-50 opacity-0 pointer-events-none transition-all duration-300 flex items-center justify-center p-4">
  <div class="neu-modal-surface text-slate-700 w-full max-w-lg rounded-3xl p-6 shadow-2xl flex flex-col">
    
    <div class="flex items-center justify-between pb-3 border-b border-slate-200/70">
      <div class="flex items-center gap-3">
        <div class="w-10 h-10 rounded-2xl outer-dish flex items-center justify-center text-emerald-600">
          <i class="ph-bold ph-git-pull-request text-xl"></i>
        </div>
        <div>
          <h3 class="font-bold text-slate-800 text-base">ระบบอัปเดตเวอร์ชัน (Version Update)</h3>
          <p class="text-xs text-slate-400">ตรวจสอบความเปลี่ยนแปลงล่าสุดจาก Remote Git</p>
        </div>
      </div>
      <button id="btnCloseUpdateModal" class="w-8 h-8 rounded-full neu-pill-btn text-slate-400 hover:text-slate-600 flex items-center justify-center">
        <i class="ph-bold ph-x text-base"></i>
      </button>
    </div>

    <div class="my-4 flex flex-col gap-3 text-xs">
      <!-- Commit Info Box -->
      <div class="p-4 rounded-2xl bg-white border border-slate-200 shadow-xs flex flex-col gap-2">
        <div class="flex items-center justify-between">
          <span class="text-slate-500 font-medium">เวอร์ชันปัจจุบัน (Local Commit):</span>
          <span id="updateLocalCommit" class="font-mono font-bold text-slate-800 bg-slate-100 px-2 py-0.5 rounded">--</span>
        </div>
        <div class="flex items-center justify-between">
          <span class="text-slate-500 font-medium">เวอร์ชันบน Git (Remote Commit):</span>
          <span id="updateRemoteCommit" class="font-mono font-bold text-blue-700 bg-blue-50 px-2 py-0.5 rounded">--</span>
        </div>
        <div class="flex items-center justify-between">
          <span class="text-slate-500 font-medium">สถานะอัปเดต:</span>
          <span id="updateStatusText" class="font-bold text-emerald-700">กำลังตรวจสอบ...</span>
        </div>
        <div class="flex items-center justify-between pt-1 border-t border-slate-100">
          <span class="text-slate-400">สภาพแวดล้อม:</span>
          <span id="updateEnvBadge" class="text-[11px] font-semibold text-slate-600 bg-slate-100 px-2 py-0.5 rounded-md">ตรวจจับอัตโนมัติ</span>
        </div>
      </div>

      <!-- Update Log / Status Box -->
      <div id="updateLogBox" class="hidden p-3 rounded-2xl bg-slate-900 text-slate-200 font-mono text-[11px] max-h-36 overflow-y-auto whitespace-pre-wrap"></div>
    </div>

    <div class="pt-3 border-t border-slate-200/70 flex items-center justify-between">
      <button id="btnCheckUpdateManual" type="button" class="neu-pill-btn px-3 py-1.5 rounded-xl text-slate-600 hover:text-blue-700 text-xs font-semibold flex items-center gap-1.5">
        <i class="ph-bold ph-arrows-clockwise text-sm"></i>
        <span>ตรวจสอบซ้ำ</span>
      </button>
      <button id="btnApplyUpdateNow" type="button" class="neu-pill-btn active px-4 py-2 rounded-xl text-xs font-bold text-white shadow-md flex items-center gap-1.5 hover:scale-[1.01] transition cursor-pointer">
        <i class="ph-bold ph-cloud-arrow-down text-base"></i>
        <span id="btnApplyUpdateText">อัปเดตระบบเดี๋ยวนี้ (Git Pull)</span>
      </button>
    </div>

  </div>
</div>
