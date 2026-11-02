<!--
  @component ProfileDetailDrawer
  Markup ported 1:1 from the original GUI.html (lines 1409-1564).
  Element ids are preserved: the controllers in src/lib/controllers bind to them.
-->
<script lang="ts">
  import ProfileConfigSection from './ProfileConfigSection.svelte';
  import ProfileScanHistorySection from './ProfileScanHistorySection.svelte';
</script>

<!-- 2. PROFILE DETAIL & SCAN HISTORY DRAWER (80% Width Slide-over from Right) -->
<div id="profileDetailDrawer" class="fixed top-0 right-0 w-full sm:w-[80vw] max-w-full h-full neu-modal-surface shadow-2xl border-l border-white/80 z-50 transform translate-x-full transition-transform duration-300 flex flex-col justify-between invisible">
  
  <!-- Drawer Header -->
  <div class="p-5 pb-3 border-b border-slate-200/70 flex items-center justify-between flex-shrink-0 bg-white/70">
    <div class="flex items-center gap-3">
      <div class="w-10 h-10 rounded-2xl outer-dish flex items-center justify-center text-blue-600 flex-shrink-0">
        <i class="ph-bold ph-article text-xl"></i>
      </div>
      <div>
        <div class="flex items-center gap-2">
          <h2 id="detailProfileTitle" class="font-extrabold text-slate-800 text-base">ชื่อ Profile</h2>
          <span id="detailProfileActiveBadge" class="hidden px-2 py-0.5 rounded-full bg-emerald-100 text-emerald-800 text-[10px] font-bold border border-emerald-300 flex items-center gap-1">
            <i class="ph-bold ph-check text-xs"></i> ใช้งานอยู่
          </span>
          <span id="detailProfileIdBadge" class="px-2 py-0.5 rounded-md bg-slate-100 text-slate-600 font-mono text-[10px]">ID: 1</span>
        </div>
        <p id="detailProfileDesc" class="text-xs text-slate-500 mt-0.5">คำอธิบาย Profile...</p>
      </div>
    </div>

    <div class="flex items-center gap-2">
      <button id="btnDetailActivateProfile" type="button" class="neu-pill-btn px-3 py-1.5 rounded-xl text-xs font-bold text-blue-700 bg-blue-50 hover:bg-blue-100 border border-blue-200 flex items-center gap-1.5 cursor-pointer">
        <i class="ph-bold ph-check-circle"></i>
        <span>เลือกใช้งาน Profile นี้</span>
      </button>
      <button id="btnDetailEditProfile" type="button" class="neu-pill-btn px-3 py-1.5 rounded-xl text-xs font-semibold text-slate-700 hover:text-slate-900 border border-slate-200 flex items-center gap-1.5 cursor-pointer">
        <i class="ph-bold ph-pencil-simple"></i>
        <span>แก้ไขการตั้งค่า</span>
      </button>
      <button id="btnCloseProfileDetailDrawer" class="w-8 h-8 rounded-full neu-pill-btn text-slate-400 hover:text-slate-600 flex items-center justify-center cursor-pointer">
        <i class="ph-bold ph-x text-base"></i>
      </button>
    </div>
  </div>

  <!-- Scrollable Drawer Body -->
  <div class="p-6 flex-1 overflow-y-auto space-y-6 text-xs">
    
    <ProfileConfigSection />

    <ProfileScanHistorySection />

  </div>

  <!-- Drawer Footer -->
  <div class="p-4 border-t border-slate-200/70 flex items-center justify-between flex-shrink-0 bg-slate-50/70">
    <span class="text-[11px] text-slate-500">
      💡 คลิก <b>"ดูผลสแกนรอบนี้ย้อนหลัง"</b> เพื่อโหลดผลลัพธ์ทั้งหมด กราฟสถิติ และรายงาน PDF ของรอบนั้นขึ้นมาแสดง
    </span>
    <button id="btnCloseDetailDrawerBottom" type="button" class="neu-pill-btn px-4 py-2 rounded-xl text-xs font-bold text-slate-600 hover:text-slate-800 transition cursor-pointer">
      ปิด
    </button>
  </div>
</div>
