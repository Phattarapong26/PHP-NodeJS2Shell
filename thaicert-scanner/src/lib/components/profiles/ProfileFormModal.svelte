<!--
  @component ProfileFormModal
  Markup ported 1:1 from the original GUI.html (lines 1567-1824).
  Element ids are preserved: the controllers in src/lib/controllers bind to them.
-->
<script lang="ts">
  import FormBasicInfo from './form/FormBasicInfo.svelte';
  import FormTargetNetwork from './form/FormTargetNetwork.svelte';
  import FormSpeedConcurrency from './form/FormSpeedConcurrency.svelte';
  import FormStealthHeaders from './form/FormStealthHeaders.svelte';
  import FormPortMode from './form/FormPortMode.svelte';
  import FormEnterpriseScope from './form/FormEnterpriseScope.svelte';
  import FormActiveToggle from './form/FormActiveToggle.svelte';
  import { closeProfileFormModal } from '../../controllers/profiles';
</script>

<!-- 3. PROFILE CREATE / EDIT MODAL (Comprehensive Scan & Stealth Config) -->
<div id="profileFormModal" onclick={(event) => { if (event.target === event.currentTarget) closeProfileFormModal(); }} class="fixed inset-0 bg-slate-900/60 backdrop-blur-sm z-[9999] opacity-0 pointer-events-none transition-all duration-200 flex items-center justify-center p-4">
  <div class="neu-modal-surface text-slate-700 w-full max-w-2xl rounded-3xl p-6 shadow-2xl max-h-[92vh] flex flex-col">
    
    <!-- Form Header -->
    <div class="flex items-center justify-between pb-3 border-b border-slate-200/70 flex-shrink-0 mb-3">
      <div class="flex items-center gap-2.5">
        <div class="w-8 h-8 rounded-xl outer-dish flex items-center justify-center text-blue-600">
          <i class="ph-bold ph-pencil-simple text-base"></i>
        </div>
        <div>
          <h3 id="profileFormHeading" class="font-bold text-slate-800 text-sm">เพิ่ม Profile การสแกน</h3>
          <p class="text-[10px] text-slate-400">กำหนดเป้าหมายเครือข่าย, ความเร็ว, และ Header อำพรางตัว</p>
        </div>
      </div>
      <button id="btnCloseProfileFormModal" type="button" onclick={() => closeProfileFormModal()} class="w-7 h-7 rounded-full neu-pill-btn text-slate-400 hover:text-slate-600 flex items-center justify-center cursor-pointer">
        <i class="ph-bold ph-x text-sm"></i>
      </button>
    </div>

    <!-- Scrollable Form Body -->
    <form id="profileForm" class="flex-1 overflow-y-auto pr-1 space-y-4 text-xs">
      <input type="hidden" id="profileFormId" value="">

      <FormBasicInfo />

      <FormTargetNetwork />

      <FormSpeedConcurrency />

      <FormStealthHeaders />

      <FormPortMode />

      <FormEnterpriseScope />

      <FormActiveToggle />

      <!-- Form Buttons -->
      <div class="flex items-center justify-end gap-2 pt-3 border-t border-slate-200/70">
        <button id="btnCancelProfileForm" type="button" onclick={() => closeProfileFormModal()} class="neu-pill-btn px-4 py-2 rounded-xl text-slate-600 hover:text-slate-800 font-semibold cursor-pointer">
          ยกเลิก
        </button>
        <button id="btnSaveProfileForm" type="submit" class="neu-pill-btn active px-5 py-2 rounded-xl text-white font-bold shadow-sm flex items-center gap-1.5 cursor-pointer">
          <i class="ph-bold ph-check text-sm"></i>
          <span>บันทึก Profile</span>
        </button>
      </div>
    </form>

  </div>
</div>
