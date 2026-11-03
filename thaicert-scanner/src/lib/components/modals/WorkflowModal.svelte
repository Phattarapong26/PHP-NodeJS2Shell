<!--
  @component WorkflowModal
  Markup ported 1:1 from the original GUI.html (lines 699-776).
  Element ids are preserved: the controllers in src/lib/controllers bind to them.
-->
<!-- WORKFLOW DIAGRAM MODAL (Interactive viewer matching soft Neumorphic Look - z-[60]) -->
<div id="workflowModal" class="fixed inset-0 bg-slate-900/40 backdrop-blur-md z-[60] opacity-0 pointer-events-none transition-all duration-300 flex items-center justify-center p-4">
  <div class="neu-modal-surface text-slate-700 w-full max-w-xl rounded-3xl p-6 shadow-2xl max-h-[90vh] overflow-y-auto">
    
    <div class="flex items-center justify-between pb-4 border-b border-slate-200/70">
      <div class="flex items-center gap-3">
        <div class="w-9 h-9 rounded-2xl outer-dish flex items-center justify-center text-blue-600">
          <i class="ph-bold ph-git-fork text-lg"></i>
        </div>
        <div>
          <h3 class="font-bold text-slate-800 text-base">ลำดับขั้นตอนการทำงาน (Workflow Logic)</h3>
          <p class="text-xs text-slate-400">ระบบทำงานอัตโนมัติตาม Flowchart ที่กำหนด</p>
        </div>
      </div>
      <div class="flex items-center gap-2">
        <button id="btnCloseWorkflow" class="w-8 h-8 rounded-full neu-pill-btn text-slate-400 hover:text-slate-600 flex items-center justify-center">
          <i class="ph-bold ph-x text-base"></i>
        </button>
      </div>
    </div>

    <!-- Workflow Visual Vertical Steps (Matched to soft neumorphic style) -->
    <div class="mt-6 flex flex-col items-center gap-2 text-xs sm:text-sm">
      
      <!-- Box: Button Click -->
      <div id="flowStep0" class="neu-step-box w-full max-w-md p-3.5 rounded-2xl text-center font-medium flex items-center justify-center gap-2">
        <i class="ph-bold ph-magnifying-glass text-blue-600"></i>
        <span>ผู้ใช้กดปุ่ม 'สแกนวง LAN หาเครื่อง PHP / Node.js'</span>
      </div>
      <i class="ph-bold ph-arrow-down text-slate-400 text-sm"></i>

      <!-- Box 1 -->
      <div id="flowStep1" class="neu-step-box w-full max-w-md p-3.5 rounded-2xl text-center">
        <span class="font-bold text-blue-600">1. โปรแกรมอ่าน IP เครื่องตัวเองอัตโนมัติ</span><br>
        <span id="step1ExampleIp" class="text-xs text-slate-500 font-mono">(ตรวจพบอัตโนมัติจาก Default Route & DHCP)</span>
      </div>
      <i class="ph-bold ph-arrow-down text-slate-400 text-sm"></i>

      <!-- Box 2 -->
      <div id="flowStep2" class="neu-step-box w-full max-w-md p-3.5 rounded-2xl text-center">
        <span class="font-bold text-blue-600">2. คำนวณขอบเขตวง LAN (Subnet) อัตโนมัติ</span><br>
        <span id="step2ExampleRange" class="text-xs text-slate-500 font-mono">คำนวณตาม Netmask จริง (รองรับ /22, /23, /24, /20)</span>
      </div>
      <i class="ph-bold ph-arrow-down text-slate-400 text-sm"></i>

      <!-- Box 3 -->
      <div id="flowStep3" class="neu-step-box w-full max-w-md p-3.5 rounded-2xl text-center">
        <span class="font-bold text-blue-600">3. ส่งคำขอคู่ขนานแบบ Async (ความเร็วสูง)</span><br>
        <span id="step3ExampleSpeed" class="text-xs text-slate-500 font-mono">Async Parallel HTTP & Port Probe สแกนทั้ง Subnet รวดเร็ว</span>
      </div>
      <i class="ph-bold ph-arrow-down text-slate-400 text-sm"></i>

      <!-- Box 4 -->
      <div id="flowStep4" class="neu-step-box w-full max-w-md p-3.5 rounded-2xl text-center">
        <span class="font-bold text-blue-600">4. จำแนกเครื่องที่เป็น PHP & Node.js</span><br>
        <span class="text-xs text-slate-500">ตรวจสอบ Fingerprints, Headers, Cookies และ Brotli Compression</span>
      </div>
      <i class="ph-bold ph-arrow-down text-slate-400 text-sm"></i>

      <!-- Box 5 -->
      <div id="flowStep5" class="neu-step-box w-full max-w-md p-3.5 rounded-2xl text-center">
        <span class="font-bold text-emerald-600">5. แสดงผลตรวจช่องโหว่ความปลอดภัยทันที!</span><br>
        <span class="text-xs text-slate-500">ประเมิน php2shell (CVE-2024-4577) และ Node2Shell (CVE-2026-111497 Brotli)</span>
      </div>

    </div>

    <div class="mt-6 pt-4 border-t border-slate-200/70 flex justify-end">
      <button id="btnWorkflowCloseDone" class="neu-pill-btn active px-4 py-2 rounded-xl text-xs font-semibold">
        เข้าใจแล้ว
      </button>
    </div>

  </div>
</div>
