<!--
  @component DeepAuditModal
  Markup ported 1:1 from the original GUI.html (lines 831-1237).
  Element ids are preserved: the controllers in src/lib/controllers bind to them.
-->
<script lang="ts">
  import AuditHeader from './AuditHeader.svelte';
  import AuditPortSwitcher from './AuditPortSwitcher.svelte';
  import AuditRceProof from './AuditRceProof.svelte';
  import AuditGroupClassification from './AuditGroupClassification.svelte';
  import AuditMatchedCves from './AuditMatchedCves.svelte';
  import AuditEdgeLayer from './AuditEdgeLayer.svelte';
  import AuditRuntimeLayer from './AuditRuntimeLayer.svelte';
  import AuditChainsLayer from './AuditChainsLayer.svelte';
  import AuditFooter from './AuditFooter.svelte';
</script>

<!-- MODAL: Deep Security Posture Audit & Credentialed Host Check (Elevated z-[110] above Results) -->
<div id="deepAuditModal" class="fixed inset-0 bg-slate-900/60 backdrop-blur-sm z-[110] opacity-0 pointer-events-none transition-all duration-200 flex items-center justify-center p-4">
  <div class="neu-modal-surface w-full max-w-4xl rounded-3xl overflow-hidden shadow-2xl flex flex-col border border-white/90 transform scale-95 transition-transform duration-200" id="deepAuditContent">
    
    <AuditHeader />

    <!-- Body -->
    <div class="p-6 space-y-4 text-xs overflow-y-auto max-h-[75vh]">
      
      <AuditPortSwitcher />
      
      <AuditRceProof />
      
      <AuditGroupClassification />

      <AuditMatchedCves />

      <AuditEdgeLayer />

      <AuditRuntimeLayer />

      <AuditChainsLayer />

    </div>

    <AuditFooter />

  </div>
</div>
