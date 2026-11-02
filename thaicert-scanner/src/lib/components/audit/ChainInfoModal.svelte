<!--
  @component ChainInfoModal
  Markup ported 1:1 from the original GUI.html (lines 1239-1302).
  Element ids are preserved: the controllers in src/lib/controllers bind to them.
-->
<script lang="ts">
  import { closeChainInfoModal } from '../../controllers/audit';
</script>

<!-- Chain Deep Info & Remediation Modal (เมื่อกด icon info มุมขวา) -->
<div id="chainInfoModal" class="fixed inset-0 bg-slate-950/70 backdrop-blur-sm z-[60] opacity-0 pointer-events-none transition-all duration-200 flex items-center justify-center p-4">
  <div class="neu-modal-surface w-full max-w-xl rounded-3xl overflow-hidden shadow-2xl flex flex-col border border-white/90 transform scale-95 transition-transform duration-200" id="chainInfoContent">
    <!-- Header -->
    <div class="px-5 py-4 bg-gradient-to-r from-slate-900 via-slate-800 to-indigo-950 text-white flex items-center justify-between border-b border-slate-700/60">
      <div class="flex items-center gap-2.5">
        <div class="w-8 h-8 rounded-xl bg-amber-500/20 text-amber-400 border border-amber-500/40 flex items-center justify-center shadow-xs">
          <i class="ph-bold ph-info text-lg"></i>
        </div>
        <div>
          <h4 id="chainInfoTitle" class="font-bold text-xs sm:text-sm text-white">รายละเอียดทางเทคนิคและผลกระทบของความเสี่ยง</h4>
          <span id="chainInfoTagBadge" class="text-[10px] font-mono text-cyan-300">Security Chain Telemetry</span>
        </div>
      </div>
      <button onclick={() => closeChainInfoModal()} class="w-7 h-7 rounded-full bg-slate-800 text-slate-400 hover:text-white flex items-center justify-center transition cursor-pointer">
        <i class="ph-bold ph-x text-sm"></i>
      </button>
    </div>
    <!-- Body -->
    <div class="p-5 space-y-3.5 text-xs overflow-y-auto max-h-[70vh] bg-slate-50">
      <!-- ปัญหาที่ตรวจพบ -->
      <div class="p-3.5 rounded-2xl bg-white border border-slate-200/90 shadow-2xs space-y-1.5">
        <div class="flex items-center gap-2 text-amber-900 font-bold text-xs">
          <i class="ph-bold ph-warning-circle text-amber-600 text-base"></i>
          <span>ปัญหาที่ตรวจพบ (Detected Risk & Mechanism):</span>
        </div>
        <p id="chainInfoProblem" class="text-slate-700 leading-relaxed pl-6 text-[11.5px]"></p>
      </div>

      <!-- ผลกระทบต่อระบบ -->
      <div class="p-3.5 rounded-2xl bg-white border border-slate-200/90 shadow-2xs space-y-1.5">
        <div class="flex items-center gap-2 text-rose-900 font-bold text-xs">
          <i class="ph-bold ph-shield-warning text-rose-600 text-base"></i>
          <span>ผลกระทบต่อระบบ (Security Impact & Severity):</span>
        </div>
        <p id="chainInfoImpact" class="text-slate-700 leading-relaxed pl-6 text-[11.5px]"></p>
      </div>

      <!-- สิ่งที่จะกลายเป็นช่องโหว่ -->
      <div class="p-3.5 rounded-2xl bg-white border border-slate-200/90 shadow-2xs space-y-1.5">
        <div class="flex items-center gap-2 text-indigo-900 font-bold text-xs">
          <i class="ph-bold ph-lock-key-open text-indigo-600 text-base"></i>
          <span>สิ่งที่จะกลายเป็นช่องโหว่ (Vulnerability Vector & Preconditions):</span>
        </div>
        <p id="chainInfoVector" class="text-slate-700 leading-relaxed pl-6 text-[11.5px]"></p>
      </div>

      <!-- แนวทางป้องกันและแก้ไข -->
      <div class="p-3.5 rounded-2xl bg-white border border-slate-200/90 shadow-2xs space-y-1.5">
        <div class="flex items-center gap-2 text-emerald-900 font-bold text-xs">
          <i class="ph-bold ph-shield-check text-emerald-600 text-base"></i>
          <span>แนวทางป้องกันและแก้ไข (Defensive Mitigation & Hardening):</span>
        </div>
        <p id="chainInfoMitigation" class="text-slate-700 leading-relaxed pl-6 text-[11.5px]"></p>
      </div>
    </div>
    <!-- Footer -->
    <div class="px-5 py-3 bg-white border-t border-slate-200 flex justify-end">
      <button onclick={() => closeChainInfoModal()} class="px-4 py-1.5 rounded-xl bg-slate-800 hover:bg-slate-900 text-white text-xs font-semibold cursor-pointer transition">
        ปิดหน้าต่าง
      </button>
    </div>
  </div>
</div>
