<!--
  @component ProfileFormModal
  Profile Create / Edit Modal with Main Views (Basic Info, Target Network, Port Mode)
  and Collapsible Advanced Settings (Speed & Concurrency, Stealth Headers).
-->
<script lang="ts">
  import FormBasicInfo from './form/FormBasicInfo.svelte';
  import FormTargetNetwork from './form/FormTargetNetwork.svelte';
  import FormPortMode from './form/FormPortMode.svelte';
  import FormSpeedConcurrency from './form/FormSpeedConcurrency.svelte';
  import FormStealthHeaders from './form/FormStealthHeaders.svelte';
  import FormActiveToggle from './form/FormActiveToggle.svelte';
  import { closeProfileFormModal } from '../../controllers/profiles';

  let showAdvanced = $state(false);
</script>

<!-- 3. PROFILE CREATE / EDIT MODAL (Comprehensive Scan & Stealth Config - Elevated z-[130] above Results) -->
<div id="profileFormModal" onclick={(event) => { if (event.target === event.currentTarget) closeProfileFormModal(); }} class="fixed inset-0 bg-slate-900/60 backdrop-blur-sm z-[130] opacity-0 pointer-events-none transition-all duration-200 flex items-center justify-center p-4">
  <div class="neu-modal-surface text-slate-700 w-full max-w-2xl rounded-3xl p-6 shadow-2xl max-h-[92vh] flex flex-col">
    
    <!-- Form Header -->
    <div class="flex items-center justify-between pb-3 border-b border-slate-200/70 flex-shrink-0 mb-3">
      <div class="flex items-center gap-2.5">
        <div class="w-8 h-8 rounded-xl outer-dish flex items-center justify-center text-blue-600">
          <i class="ph-bold ph-pencil-simple text-base"></i>
        </div>
        <div>
          <h3 id="profileFormHeading" class="font-bold text-slate-800 text-sm">เพิ่ม Profile การสแกน</h3>
          <p class="text-[10px] text-slate-400">กำหนดเป้าหมายเครือข่าย, รูปแบบพอร์ต, และการตั้งค่าขั้นสูง</p>
        </div>
      </div>
      <button id="btnCloseProfileFormModal" type="button" aria-label="ปิดหน้าต่างตั้งค่า Profile" onclick={() => closeProfileFormModal()} class="w-7 h-7 rounded-full neu-pill-btn text-slate-400 hover:text-slate-600 flex items-center justify-center cursor-pointer">
        <i class="ph-bold ph-x text-sm"></i>
      </button>
    </div>

    <!-- Scrollable Form Body -->
    <form id="profileForm" class="flex-1 overflow-y-auto pr-1 space-y-4 text-xs">
      <input type="hidden" id="profileFormId" value="">
      <!-- Default ThaiCERT scope: All 8 groups assessed without partitioning -->
      <input type="hidden" name="profile_scope_preset" value="all" checked>

      <!-- 1. Basic Info (Title & Description) -->
      <FormBasicInfo />

      <!-- 2. Target Network (Subnet / IP Range) -->
      <FormTargetNetwork />

      <!-- 3. Port Mode (Main View - Not hidden in Advanced Settings) -->
      <FormPortMode />

      <!-- 4. Advanced Settings Dropdown / Collapsible Accordion -->
      <div class="rounded-2xl border border-slate-200/90 bg-white/50 overflow-hidden shadow-2xs">
        <button
          type="button"
          onclick={() => { showAdvanced = !showAdvanced; }}
          class="w-full flex items-center justify-between p-3.5 bg-slate-50/70 hover:bg-slate-100/70 transition cursor-pointer text-xs"
        >
          <div class="flex items-center gap-2.5 text-left">
            <div class="w-7 h-7 rounded-xl bg-blue-100/80 text-blue-700 flex items-center justify-center font-bold shadow-2xs">
              <i class="ph-bold ph-sliders text-sm"></i>
            </div>
            <div>
              <div class="flex items-center gap-2">
                <span class="font-bold text-slate-800 text-xs">การตั้งค่าขั้นสูง (Advanced Settings)</span>
                <span class="text-[9.5px] px-2 py-0.2 rounded-full font-semibold bg-slate-200/80 text-slate-600">ความเร็ว & Header</span>
              </div>
              <p class="text-[10px] text-slate-400">กำหนดความเร็วการสแกน (Speed & Concurrency) และ Header อำพรางตัว (Stealth Headers)</p>
            </div>
          </div>
          <div class="flex items-center gap-1.5 text-slate-400">
            <span class="text-[10px] font-semibold hidden sm:inline">{showAdvanced ? 'ซ่อนการตั้งค่า' : 'กดเพื่อตั้งค่า'}</span>
            <i class="ph-bold ph-caret-down text-sm transition-transform duration-200 {showAdvanced ? 'rotate-180 text-blue-600' : ''}"></i>
          </div>
        </button>

        <!-- Dropdown Body containing Speed Concurrency & Stealth Headers -->
        <div class="p-3.5 space-y-3.5 border-t border-slate-200/70 bg-white {showAdvanced ? 'block' : 'hidden'}">
          <FormSpeedConcurrency />
          <FormStealthHeaders />
        </div>
      </div>

      <!-- 5. Active Profile Toggle -->
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
