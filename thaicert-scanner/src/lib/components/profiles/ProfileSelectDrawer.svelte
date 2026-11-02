<!--
  @component ProfileSelectDrawer
  Markup ported 1:1 from the original GUI.html (lines 1307-1406).
  Element ids are preserved: the controllers in src/lib/controllers bind to them.
-->
<script lang="ts">
  import { handleOpenCreateProfile } from '../../controllers/profiles';
</script>

<!-- 1. PROFILE SELECTION & MANAGEMENT DRAWER (Slides from Right, ~520px) -->
<div id="profileSelectDrawer" class="fixed top-0 right-0 w-full sm:w-[520px] max-w-full h-full neu-modal-surface shadow-2xl border-l border-white/80 z-40 transform translate-x-full transition-transform duration-300 flex flex-col justify-between invisible">
  
  <!-- Drawer Header -->
  <div class="p-5 pb-3 border-b border-slate-200/70 flex items-center justify-between flex-shrink-0">
    <div class="flex items-center gap-3">
      <div class="w-9 h-9 rounded-2xl outer-dish flex items-center justify-center text-blue-600">
        <i class="ph-bold ph-identification-card text-lg"></i>
      </div>
      <div>
        <h3 class="font-bold text-slate-800 text-sm">จัดการและเลือก Scan Profile</h3>
        <span class="text-[10px] text-slate-400">Network Subnet, Speed, Stealth & Scan History</span>
      </div>
    </div>
    <button id="btnCloseProfileDrawer" class="w-7 h-7 rounded-full neu-pill-btn text-slate-400 hover:text-slate-600 flex items-center justify-center cursor-pointer">
      <i class="ph-bold ph-x text-sm"></i>
    </button>
  </div>

  <!-- Scrollable Drawer Body -->
  <div class="p-5 flex-1 overflow-y-auto space-y-4 text-xs">

    <!-- Alert Banner (shown when scan attempted without active profile) -->
    <div id="profileScanWarningBanner" class="hidden p-3 rounded-2xl bg-amber-500/10 border border-amber-300/80 text-amber-900 text-xs font-semibold flex items-center gap-2">
      <i class="ph-bold ph-warning-circle text-amber-600 text-lg flex-shrink-0"></i>
      <span>กรุณาเลือก Profile ที่ต้องการจะสแกนก่อนเริ่มต้นการตรวจหา</span>
    </div>

    <!-- VPN Warning Notice (Always visible) -->
    <div class="p-3 rounded-2xl bg-blue-50/80 border border-blue-200/70 text-slate-700 text-xs flex items-start gap-2.5">
      <i class="ph-bold ph-shield-warning text-amber-600 text-base flex-shrink-0 mt-0.5"></i>
      <div class="leading-relaxed">
        <span class="font-bold text-slate-900">⚠️ ข้อควรระวังเมื่อเปิดใช้งาน VPN:</span> หากเปิดใช้งาน VPN และไม่ได้ระบุ Network Target ใน Profile ให้ชัดเจน ระบบอาจตรวจหาผ่านช่องทางเสมือนของ VPN ซึ่งทำให้ไม่เห็นอุปกรณ์ภายใต้ Subnet กายภาพจริงของคุณ
      </div>
    </div>

    <!-- Quick Summary of Detected Machine Subnet -->
    <div class="p-3 rounded-xl neu-concave-card border border-blue-200/70 bg-white/70 flex items-center justify-between">
      <div class="flex items-center gap-2">
        <span class="w-2.5 h-2.5 rounded-full bg-emerald-500 animate-pulse"></span>
        <div>
          <div class="text-[10px] text-slate-400 font-medium">เครือข่ายปัจจุบันของเครื่องสแกนเนอร์:</div>
          <div class="font-mono font-bold text-blue-700 text-xs flex items-center gap-2">
            <span id="drawerDetectedIp">-</span>
            <span class="text-slate-300">|</span>
            <span id="drawerDetectedSubnet" class="text-slate-700">-</span>
          </div>
        </div>
      </div>
      <button id="btnDrawerAutoDetect" type="button" class="neu-pill-btn px-2.5 py-1.5 rounded-xl text-blue-600 text-xs font-semibold flex items-center gap-1 cursor-pointer" title="รีเฟรชตรวจจับเครือข่ายใหม่">
        <i class="ph-bold ph-arrows-clockwise text-xs"></i>
        <span>รีเฟรช</span>
      </button>
    </div>

    <!-- Section Heading & Add Button -->
    <div class="flex items-center justify-between pt-1">
      <span class="font-bold text-slate-800 text-xs flex items-center gap-1.5">
        <i class="ph-bold ph-cards text-blue-600"></i>
        <span>รายการ Profile ทั้งหมด</span>
      </span>
      <button id="btnOpenCreateProfileFromList" type="button" onclick={() => handleOpenCreateProfile()} class="neu-pill-btn active px-3 py-1.5 rounded-xl text-white font-bold text-[11px] shadow-xs flex items-center gap-1 hover:scale-[1.02] transition cursor-pointer">
        <i class="ph-bold ph-plus text-xs"></i>
        <span>เพิ่ม Profile ใหม่</span>
      </button>
    </div>

    <!-- Empty State -->
    <div id="profileEmptyState" class="hidden py-10 px-6 flex flex-col items-center justify-center text-center rounded-2xl border-2 border-dashed border-slate-200 bg-slate-50/60">
      <div class="w-14 h-14 rounded-2xl bg-blue-100/60 text-blue-600 flex items-center justify-center mb-3 shadow-inner">
        <i class="ph-duotone ph-folder-dashed text-2xl"></i>
      </div>
      <h4 class="text-sm font-bold text-slate-800 mb-1">ยังไม่มี Profile ในระบบ</h4>
      <p class="text-xs text-slate-500 max-w-xs mb-3 leading-relaxed">
        กรุณาสร้าง Profile สำหรับกำหนดวง Subnet เป้าหมาย ความเร็ว และ Header อำพรางตัว
      </p>
      <button id="btnEmptyCreateProfile" type="button" onclick={() => handleOpenCreateProfile()} class="neu-pill-btn active px-3.5 py-2 rounded-xl text-xs font-bold text-white shadow-md flex items-center gap-1.5 hover:scale-[1.02] transition cursor-pointer">
        <i class="ph-bold ph-plus-circle text-sm"></i>
        <span>+ สร้าง Profile แรก</span>
      </button>
    </div>

    <!-- Profiles List Container -->
    <div id="profilesListContainer" class="flex flex-col gap-3">
      <!-- Dynamically populated via JS -->
    </div>

  </div>

  <!-- Drawer Footer -->
  <div class="p-4 border-t border-slate-200/70 flex items-center justify-between flex-shrink-0 bg-slate-50/50">
    <button id="btnDrawerCreateProfile" type="button" onclick={() => handleOpenCreateProfile()} class="neu-pill-btn active px-4 py-2 rounded-xl text-xs font-bold text-white shadow-sm flex items-center gap-1.5 cursor-pointer">
      <i class="ph-bold ph-plus text-xs"></i>
      <span>+ เพิ่ม Profile ใหม่</span>
    </button>
    <button id="btnDoneProfileDrawer" type="button" class="neu-pill-btn px-4 py-2 rounded-xl text-xs font-bold text-slate-600 hover:text-slate-800 transition cursor-pointer">
      ปิดหน้าต่าง
    </button>
  </div>
</div>
