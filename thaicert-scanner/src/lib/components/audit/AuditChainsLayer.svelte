<!--
  @component AuditChainsLayer
  Markup ported 1:1 from the original GUI.html (lines 1003-1225).
  Element ids are preserved: the controllers in src/lib/controllers bind to them.
-->
<script lang="ts">
  import AuditVaFindings from './AuditVaFindings.svelte';
  import AuditHardeningIni from './AuditHardeningIni.svelte';
  import AsanDiagnostic from './AsanDiagnostic.svelte';
  import ProbeInspectionLog from './ProbeInspectionLog.svelte';
  import { switchAuditChain } from '../../controllers/audit';
</script>

<!-- Layer 3: Deep Security Chains Analysis (Chains A ถึง E) -->
<div class="p-4 rounded-2xl bg-white/90 border border-slate-200/80 shadow-sm space-y-3" id="auditLayerSecurityChains">
  <div class="flex items-center justify-between text-xs font-bold text-slate-800 border-b border-slate-100 pb-2">
    <span class="flex items-center gap-1.5 text-indigo-900">
      <i class="ph-bold ph-terminal-window text-indigo-600 text-base"></i> 3. การประเมินกลไกความเสี่ยง 5 สายเจาะลึก (Security Chains Audit - Chains A ถึง E)
    </span>
    <span id="auditChainsOverallBadge" class="px-2 py-0.5 rounded-md font-semibold text-[11px] bg-emerald-50 text-emerald-700 border border-emerald-200">Defensively Hardened</span>
  </div>

  <!-- Chain Selection Tabs -->
  <div class="flex items-center gap-1.5 border-b border-slate-100 pb-2 flex-wrap">
    <button id="tabBtnChainAll" class="chain-tab px-3 py-1 rounded-lg text-[11px] font-semibold bg-slate-900 text-cyan-300 border border-cyan-500/50 cursor-pointer transition shadow-xs" onclick={() => switchAuditChain('all')}>
      All Chains (Console View)
    </button>
    <button id="tabBtnChainA" class="chain-tab px-3 py-1 rounded-lg text-[11px] font-semibold bg-slate-100 text-slate-600 hover:bg-slate-200 border border-transparent cursor-pointer transition" onclick={() => switchAuditChain('chain_a')}>
      [A] Upload Progress
    </button>
    <button id="tabBtnChainB" class="chain-tab px-3 py-1 rounded-lg text-[11px] font-semibold bg-slate-100 text-slate-600 hover:bg-slate-200 border border-transparent cursor-pointer transition" onclick={() => switchAuditChain('chain_b')}>
      [B] INI Leak
    </button>
    <button id="tabBtnChainC" class="chain-tab px-3 py-1 rounded-lg text-[11px] font-semibold bg-slate-100 text-slate-600 hover:bg-slate-200 border border-transparent cursor-pointer transition" onclick={() => switchAuditChain('chain_c')}>
      [C] Serializer Mismatch
    </button>
    <button id="tabBtnChainD" class="chain-tab px-3 py-1 rounded-lg text-[11px] font-semibold bg-slate-100 text-slate-600 hover:bg-slate-200 border border-transparent cursor-pointer transition" onclick={() => switchAuditChain('chain_d')}>
      [D] OOM Cleanup
    </button>
    <button id="tabBtnChainE" class="chain-tab px-3 py-1 rounded-lg text-[11px] font-semibold bg-slate-100 text-slate-600 hover:bg-slate-200 border border-transparent cursor-pointer transition" onclick={() => switchAuditChain('chain_e')}>
      [E] Worker Reuse
    </button>
  </div>

  <!-- Active Chain Stages Content (High-contrast CLI console cards) -->
  <div id="chainDetailContainer" class="space-y-2">
    <!-- Dynamically populated with CLI console cards & summary table -->
  </div>

  <AuditVaFindings />

  <AuditHardeningIni />

  <AsanDiagnostic />

  <ProbeInspectionLog />
</div>
