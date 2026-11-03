<!--
  @component App
  Root shell. Mirrors the original <body> wrapper (lines 234-1892 of GUI.html)
  and owns the one-time controller bootstrap that used to run on window.onload.
-->
<script lang="ts">
  import { onMount } from 'svelte';
  import AppHeader from '$lib/components/layout/AppHeader.svelte';
  import AppFooter from '$lib/components/layout/AppFooter.svelte';
  import ScannerView from '$lib/components/scanner/ScannerView.svelte';
  import ResultsModal from '$lib/components/results/ResultsModal.svelte';
  import CveCatalogModal from '$lib/components/cve/CveCatalogModal.svelte';
  import DeepAuditModal from '$lib/components/audit/DeepAuditModal.svelte';
  import ChainInfoModal from '$lib/components/audit/ChainInfoModal.svelte';
  import ProfileDrawerBackdrop from '$lib/components/profiles/ProfileDrawerBackdrop.svelte';
  import ProfileSelectDrawer from '$lib/components/profiles/ProfileSelectDrawer.svelte';
  import ProfileDetailDrawer from '$lib/components/profiles/ProfileDetailDrawer.svelte';
  import ProfileFormModal from '$lib/components/profiles/ProfileFormModal.svelte';
  import SystemUpdateModal from '$lib/components/modals/SystemUpdateModal.svelte';
  import Toast from '$lib/components/common/Toast.svelte';
  import Tooltips from '$lib/components/common/Tooltips.svelte';
  import { bootstrap } from '$lib/controllers/bootstrap';

  let dispose: (() => void) | null = null;

  // Controllers bind to the real DOM elements by id, so they must start after mount.
  onMount(() => {
    dispose = bootstrap();
    return () => dispose?.();
  });
</script>

<div class="app-viewport w-full h-full max-w-full max-h-full flex flex-col relative overflow-hidden">
  <AppHeader />

  <ScannerView />

  <AppFooter />

  <!-- Layer 1: Profile Drawers & Backdrop (Slide-in from Right) -->
  <ProfileDrawerBackdrop />
  <ProfileSelectDrawer />
  <ProfileDetailDrawer />

  <!-- Layer 2: Main Utility & Progress Modals -->
  <CveCatalogModal />
  <SystemUpdateModal />

  <!-- Layer 3: Results Modal (Foreground Scan Inspection Surface) -->
  <ResultsModal />

  <!-- Layer 4: Deep Audit & Attack Chain Modals (Mounted above Results) -->
  <DeepAuditModal />
  <ChainInfoModal />

  <!-- Layer 5: Profile Form Modal (Create & Edit Dialog) -->
  <ProfileFormModal />

  <!-- Layer 6: Notifications & Feedback -->
  <Toast />
</div>

<!-- Floating chart tooltips (fixed position) -->
<Tooltips />
