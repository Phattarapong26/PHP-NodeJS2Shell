<!--
  @component ScannerView
  Markup ported 1:1 from the original GUI.html (lines 298-436).
  Element ids are preserved: the controllers in src/lib/controllers bind to them.
-->
<script lang="ts">
  import HeroSearch from './HeroSearch.svelte';
  import RadarDisk from './RadarDisk.svelte';
  import ScanProgress from './ScanProgress.svelte';
</script>

<!-- Main Content Area -->
<main class="flex-1 flex flex-col items-center justify-center relative px-4 z-10 overflow-y-auto overflow-x-hidden w-full max-w-full">
  
  <!-- Ambient Decorative Blurred Glows (Strictly Clipped) -->
  <div class="absolute inset-0 overflow-hidden pointer-events-none z-0">
    <div class="absolute -top-12 -left-12 w-80 h-80 rounded-full bg-blue-100/60 blur-3xl"></div>
    <div class="absolute -bottom-16 -right-16 w-96 h-96 rounded-full bg-indigo-100/50 blur-3xl"></div>
  </div>

  <!-- VIEW 1: MANUAL SCAN INTERFACE -->
  <div id="viewManualScan" class="w-full flex-1 flex flex-col items-center justify-center transition-all duration-300">
    
    <HeroSearch />

    <RadarDisk />

    <ScanProgress />
  </div> <!-- /#viewManualScan -->

</main>
