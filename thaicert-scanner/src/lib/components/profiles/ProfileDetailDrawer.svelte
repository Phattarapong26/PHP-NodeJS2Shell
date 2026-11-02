<!--
  @component ProfileDetailDrawer
  Modal Popup / Slide Drawer for Profile Inspection & Quick Scanning (80% Width).
  Engineered 1:1 against the OP Scanner enterprise design mockup.
-->
<script lang="ts">
  import ProfileConfigSection from './ProfileConfigSection.svelte';
  import ProfileScanHistorySection from './ProfileScanHistorySection.svelte';
</script>

<!-- 2. PROFILE DETAIL & SCAN HISTORY DRAWER (80% Width Slide-over from Right) -->
<div id="profileDetailDrawer" class="fixed top-0 right-0 w-full sm:w-[88vw] xl:w-[80vw] max-w-full h-full bg-[#f4f7fa] shadow-2xl border-l border-slate-200/80 z-50 transform translate-x-full transition-transform duration-300 flex flex-col justify-between invisible">
  
  <!-- Drawer Header -->
  <div class="px-6 py-4 border-b border-slate-200/80 flex items-center justify-between flex-shrink-0 bg-white/90 backdrop-blur-md">
    <div class="flex items-center gap-3">
      <div>
        <div class="flex items-center gap-2.5">
          <h2 id="detailProfileTitle" class="font-black text-slate-800 text-xl tracking-tight">OP Scanner</h2>
          <span id="detailProfileActiveBadge" class="px-2.5 py-0.5 rounded-full bg-emerald-50 text-emerald-700 text-xs font-bold border border-emerald-200 flex items-center gap-1 shadow-2xs">
            <i class="ph-bold ph-check text-xs"></i>
            <span>พร้อมใช้งาน</span>
          </span>
          <span id="detailProfileIdBadge" class="px-2.5 py-0.5 rounded-md bg-slate-100 text-slate-600 font-mono text-[11px] font-semibold border border-slate-200/80">ID: 1</span>
        </div>
        <p id="detailProfileDesc" class="text-xs text-slate-500 mt-1">สแกนและตรวจสอบความปลอดภัยของเครือข่าย ได้อย่างรวดเร็วและแม่นยำ</p>
      </div>
    </div>

    <!-- Header Actions -->
    <div class="flex items-center gap-2">
      <button id="btnDetailActivateProfile" type="button" class="neu-pill-btn px-3.5 py-1.5 rounded-xl text-xs font-bold text-blue-700 bg-blue-50 hover:bg-blue-100 border border-blue-200 flex items-center gap-1.5 cursor-pointer transition">
        <i class="ph-bold ph-check-circle"></i>
        <span>เลือกใช้งาน Profile นี้</span>
      </button>
      <button id="btnDetailEditProfile" type="button" class="neu-pill-btn px-3.5 py-1.5 rounded-xl text-xs font-semibold text-slate-700 hover:text-slate-900 border border-slate-200 flex items-center gap-1.5 cursor-pointer transition">
        <i class="ph-bold ph-pencil-simple"></i>
        <span>แก้ไขการตั้งค่า</span>
      </button>
      <button id="btnCloseProfileDetailDrawer" type="button" class="w-8 h-8 rounded-full neu-pill-btn text-slate-400 hover:text-slate-700 flex items-center justify-center cursor-pointer transition ml-1" title="ปิดหน้าต่าง">
        <i class="ph-bold ph-x text-base"></i>
      </button>
    </div>
  </div>

  <!-- Scrollable Drawer Body -->
  <div class="p-6 flex-1 overflow-y-auto space-y-5 text-xs">
    
    <!-- Top Section: Stealth Configuration Matrix -->
    <ProfileConfigSection />

    <!-- Main Two-Column Layout -->
    <div class="grid grid-cols-1 lg:grid-cols-12 gap-5 items-start">
      
      <!-- Left Column: Scan History Timeline (8/12) -->
      <div class="lg:col-span-8 space-y-4">
        <ProfileScanHistorySection />
      </div>

      <!-- Right Column: Quick Scan Launcher & Tips (4/12) -->
      <div class="lg:col-span-4 space-y-4">
        
        <!-- Card 1: เริ่มการสแกนได้ทันที -->
        <div class="rounded-3xl bg-white border border-slate-200/80 p-5 shadow-xs flex flex-col items-center text-center space-y-4">
          <!-- Card Header -->
          <div class="w-full flex items-center justify-start gap-2 text-xs font-bold text-slate-800">
            <i class="ph-bold ph-lightning text-blue-600 text-sm"></i>
            <span>เริ่มการสแกนได้ทันที</span>
          </div>

          <!-- Giant 3D Circular Scan Button -->
          <div class="py-2">
            <button id="btnProfileQuickScan" type="button" class="group relative w-28 h-28 rounded-full bg-gradient-to-b from-blue-500 via-blue-600 to-indigo-600 shadow-xl shadow-blue-500/30 text-white flex flex-col items-center justify-center gap-1 cursor-pointer hover:scale-105 active:scale-95 transition-all duration-200 ring-8 ring-blue-100/60" title="คลิกเพื่อเริ่มสแกนด้วย Profile นี้ทันที">
              <i class="ph-fill ph-play text-3xl ml-1 group-hover:scale-110 transition-transform"></i>
              <span class="text-xs font-extrabold tracking-wider">Scan</span>
            </button>
          </div>

          <!-- Status Indicator -->
          <div class="flex items-center gap-1.5 text-xs font-semibold text-slate-600">
            <span class="w-2 h-2 rounded-full bg-emerald-500"></span>
            <span>พร้อมใช้งานสำหรับการสแกน</span>
          </div>

          <!-- Sub-card: Scan Profile ที่เลือกใช้ -->
          <div class="w-full p-3 rounded-2xl bg-slate-50/80 border border-slate-200/80 text-left space-y-2">
            <div class="flex items-center justify-between text-[11px]">
              <span class="font-bold text-slate-700">Scan Profile ที่เลือกใช้</span>
              <button id="btnSidebarEditProfile" type="button" class="text-blue-600 font-semibold hover:underline cursor-pointer">แก้ไข</button>
            </div>
            <div class="flex items-center justify-between p-2.5 rounded-xl bg-white border border-slate-200/80 cursor-pointer hover:border-blue-300 transition" id="sidebarProfileCard">
              <div class="flex items-center gap-2.5">
                <div class="w-8 h-8 rounded-lg bg-blue-50 text-blue-600 flex items-center justify-center font-bold text-base">
                  <i class="ph-bold ph-globe"></i>
                </div>
                <div>
                  <div id="detailSidebarProfileUa" class="font-bold text-slate-800 text-xs">Chrome Desktop</div>
                  <div id="detailSidebarProfileHeaders" class="text-[10px] text-slate-400">Headers: 4 รายการ</div>
                </div>
              </div>
              <i class="ph-bold ph-caret-right text-slate-300"></i>
            </div>
          </div>
        </div>

        <!-- Card 2: แนะนำ (Recommendation Tips) -->
        <div class="rounded-3xl bg-amber-50/60 border border-amber-200/80 p-4 shadow-2xs space-y-1.5 cursor-pointer hover:bg-amber-50 transition" id="cardProfileRecommendation">
          <div class="flex items-center gap-1.5 text-xs font-bold text-amber-900">
            <span class="text-sm">💡</span>
            <span>แนะนำ</span>
          </div>
          <div class="flex items-center justify-between text-xs text-amber-900/90 leading-relaxed">
            <span>ปรับเพิ่มความครอบคลุม โดยเลือกสแกน Top 100 พอร์ต</span>
            <i class="ph-bold ph-caret-right text-amber-400 shrink-0 ml-2"></i>
          </div>
        </div>

      </div>
    </div>

  </div>

  <!-- Drawer Footer -->
  <div class="px-6 py-3 border-t border-slate-200/80 flex items-center justify-between flex-shrink-0 bg-white/80">
    <span class="text-[11px] text-slate-500">
      💡 คลิก <b>"ดูรายละเอียด"</b> เพื่อโหลดผลลัพธ์ทั้งหมด กราฟสถิติ และรายงานของรอบนั้นขึ้นมาแสดง
    </span>
    <button id="btnCloseDetailDrawerBottom" type="button" class="neu-pill-btn px-4 py-1.5 rounded-xl text-xs font-bold text-slate-600 hover:text-slate-800 transition cursor-pointer">
      ปิด
    </button>
  </div>
</div>
