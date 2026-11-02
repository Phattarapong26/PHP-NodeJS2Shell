<!--
  @component ResultsModal
  Markup ported 1:1 from the original GUI.html (lines 472-697).
  Element ids are preserved: the controllers in src/lib/controllers bind to them.
-->
<script lang="ts">
  import ResultsHeader from './ResultsHeader.svelte';
  import ResultsStatusBanner from './ResultsStatusBanner.svelte';
  import ThaiCertGroupMatrix from './ThaiCertGroupMatrix.svelte';
  import ResultsFilterBar from './ResultsFilterBar.svelte';
  import ResultsTable from './ResultsTable.svelte';
  import ResultsFooter from './ResultsFooter.svelte';
</script>

<!-- SLIDE-UP MODAL: Results Panel (Step 5 of Diagram) -->
<div id="resultsModal" class="fixed inset-0 bg-slate-900/50 backdrop-blur-sm z-[60] opacity-0 pointer-events-none transition-all duration-300 flex items-end sm:items-center justify-center p-0 sm:p-4 overflow-y-auto">
  <div class="neu-modal-surface w-full max-w-7xl max-h-[92vh] sm:max-h-[90vh] rounded-t-3xl sm:rounded-3xl flex flex-col overflow-hidden transform translate-y-8 transition-transform duration-300 my-auto shadow-2xl">
    
    <ResultsHeader />

    <!-- Scrollable Modal Body (Contains Status Banner, 3 Visual Charts, Filter Bar, and Device Table) -->
    <div id="resultsModalBody" class="flex-1 overflow-y-auto overflow-x-hidden flex flex-col min-h-0 scroll-smooth">

    <ResultsStatusBanner />

    <ThaiCertGroupMatrix />

    <ResultsFilterBar />

    <ResultsTable />

    </div> <!-- End #resultsModalBody (Full Scrollable Content) -->

    <ResultsFooter />

  </div>
</div>
