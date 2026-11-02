<!--
  @component Toast
  Markup ported 1:1 from the original GUI.html (lines 1884-1888).
  Element ids are preserved: the controllers in src/lib/controllers bind to them.
-->
<!-- Notification Toast (Top-level Feedback z-[9999]) -->
<div id="toastMessage" class="fixed bottom-8 left-1/2 transform -translate-x-1/2 neu-modal-surface text-slate-800 text-xs px-4 py-2.5 rounded-full shadow-lg border border-white flex items-center gap-2 opacity-0 pointer-events-none transition-all duration-300 z-[9999]">
  <i class="ph-bold ph-info text-blue-600"></i>
  <span id="toastText">การตั้งค่าเรียบร้อยแล้ว</span>
</div>
