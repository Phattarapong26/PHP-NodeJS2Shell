<!--
  @component AuditRceProof
  Markup ported 1:1 from the original GUI.html (lines 878-934).
  Element ids are preserved: the controllers in src/lib/controllers bind to them.
-->
<script lang="ts">
  import { runLiveRceAudit } from '../../controllers/audit';
</script>

<!-- Empirical Live RCE Proof Indicator (Active PoC Execution) -->
<div id="auditRceProofWrapper" class="hidden p-3.5 rounded-2xl bg-gradient-to-r from-rose-950 via-slate-900 to-black border-2 border-rose-500 shadow-md text-white space-y-2">
  <div class="flex items-center justify-between text-xs font-bold">
    <span class="flex items-center gap-2 text-rose-300">
      <span class="w-2.5 h-2.5 rounded-full bg-rose-500 animate-ping flex-shrink-0"></span>
      <i class="ph-bold ph-terminal-window text-base text-rose-400 flex-shrink-0"></i>
      <span id="auditRceProofTitle">หลักฐานเชิงประจักษ์ยืนยันการรันคำสั่งควบคุมระบบ (Live RCE Proof)</span>
    </span>
    <span id="auditRceProofStatusBadge" class="px-2.5 py-0.5 rounded-full font-mono text-[10px] font-bold bg-rose-900/80 text-rose-200 border border-rose-600">VERIFIED EXPLOITABLE</span>
  </div>
  <div id="auditRceProofDesc" class="text-xs text-rose-200/90 leading-relaxed font-sans">
    <!-- Description -->
  </div>
  <div class="p-2.5 bg-black/90 rounded-xl border border-rose-900/60 font-mono text-xs space-y-1.5">
    <div class="text-slate-400 text-[11px] flex items-center justify-between flex-wrap gap-1">
      <span><b>เทคนิคการเจาะระบบ:</b> <span id="auditRceProofTechnique" class="text-amber-300">-</span></span>
      <span id="auditRceProofPrivilege" class="text-rose-400 font-semibold font-mono">-</span>
    </div>
    <div class="text-slate-300 text-[11px] pt-1">
      <span class="text-emerald-400 font-bold">$</span> <span id="auditRceProofCommand" class="text-slate-100 font-bold">id</span>
    </div>
    <div id="auditRceProofOutput" class="p-2 bg-slate-950 rounded-lg text-emerald-400 text-[11px] overflow-x-auto whitespace-pre-wrap font-bold border border-emerald-950/40 select-all">
      <!-- Terminal Output -->
    </div>
    <div id="auditRceProofCurlWrapper" class="pt-1 text-[10px] text-slate-400 space-y-1">
      <div class="flex items-center justify-between">
        <span><b>คำสั่งทดสอบจริง (CLI Reproduction):</b></span>
        <button id="btnCopyRceCurl" type="button" class="text-blue-400 hover:text-blue-300 underline cursor-pointer">คัดลอกคำสั่ง curl</button>
      </div>
      <div id="auditRceProofCurl" class="p-1.5 bg-slate-900 rounded text-sky-300 text-[10px] overflow-x-auto font-mono select-all">
        <!-- curl command -->
      </div>
    </div>
    <div id="auditRceTrailWrapper" class="hidden pt-1.5 border-t border-slate-800 text-[10px] text-slate-400 font-mono space-y-0.5">
      <div class="text-cyan-400 font-semibold flex items-center gap-1">
        <i class="ph-bold ph-seal-check text-xs"></i> Tamper-Evident Evidence Digest (SHA-256 Integrity Verification)
      </div>
      <div><span class="text-slate-500">Operator:</span> <span id="auditRceTrailOperator" class="text-slate-300">-</span> | <span class="text-slate-500">Time (UTC):</span> <span id="auditRceTrailTime" class="text-slate-300">-</span></div>
      <div class="truncate"><span class="text-slate-500">Evidence SHA-256:</span> <span id="auditRceTrailSha" class="text-emerald-400 select-all font-bold">-</span></div>
    </div>
  </div>

  <!-- Action Button for On-Demand Active RCE Verification -->
  <div id="auditRceActionBox" class="pt-1.5 flex flex-col sm:flex-row items-center justify-between gap-2 border-t border-rose-900/50">
    <span class="text-[11px] text-slate-400 flex items-center gap-1">
      <i class="ph-bold ph-shield-check text-emerald-400"></i> Safety Gate: โหมดทดสอบ Canary ปลอดภัย (Non-destructive)
    </span>
    <button 
      id="btnTriggerActiveRce" 
      type="button" 
      onclick={() => runLiveRceAudit()} 
      class="w-full sm:w-auto px-3.5 py-1.5 rounded-xl bg-gradient-to-r from-rose-600 to-red-600 hover:from-rose-500 hover:to-red-500 text-white font-bold text-xs flex items-center justify-center gap-1.5 shadow-md transition cursor-pointer">
      <i class="ph-bold ph-lightning text-sm text-amber-300"></i>
      <span id="btnTriggerActiveRceText">ทดสอบ Active RCE PoC บนโฮสต์นี้</span>
    </button>
  </div>
</div>
