<!--
  @component FormStealthHeaders
  Markup ported 1:1 from the original GUI.html (lines 1685-1736).
  Element ids are preserved: the controllers in src/lib/controllers bind to them.
-->
<!-- Row 4: Stealth & Anti-Detection Headers -->
<div class="p-3.5 rounded-2xl neu-concave-card border border-indigo-200/80 bg-gradient-to-br from-indigo-50/40 via-white to-blue-50/30 space-y-3">
  <div class="flex items-center justify-between">
    <label class="font-bold text-indigo-900 text-xs flex items-center gap-1.5">
      <i class="ph-bold ph-mask-happy text-indigo-600"></i>
      <span>กำหนด Header เพื่ออำพรางตัว (Stealth & Anti-Detection Headers)</span>
    </label>
    <span class="text-[10px] text-indigo-700 bg-indigo-100 font-bold px-2 py-0.5 rounded-full border border-indigo-200">WAF Bypass / Camouflage</span>
  </div>

  <!-- User-Agent Selection -->
  <div>
    <label class="block font-semibold text-slate-700 mb-1 text-[11px]">เลือก User-Agent ในการสแกน:</label>
    <select id="profileFormUaPreset" class="w-full px-3 py-2 rounded-xl border border-slate-300 focus:border-indigo-500 focus:ring-1 focus:ring-indigo-500 bg-white font-medium text-xs cursor-pointer">
      <option value="chrome">🌐 Google Chrome บน Windows 10 (Mozilla/5.0 Windows NT 10.0...)</option>
      <option value="edge">🌐 Microsoft Edge (Edg/124.0...)</option>
      <option value="safari">🍏 Safari บน Apple macOS</option>
      <option value="ios">📱 Safari บน iPhone / iOS</option>
      <option value="googlebot">🤖 Googlebot Web Crawler (Googlebot/2.1)</option>
      <option value="official">🏢 Vendor Official Agent (ThaiCERT-OPScaner/2.0 Audit)</option>
      <option value="custom">✏️ กำหนด User-Agent เอง (Custom)</option>
    </select>
    <div id="profileFormCustomUaWrapper" class="hidden mt-2">
      <input 
        id="profileFormCustomUa" 
        type="text" 
        placeholder="ระบุ User-Agent string แบบกำหนดเอง..." 
        class="w-full px-3 py-1.5 rounded-xl border border-indigo-300 font-mono text-[11px] bg-white focus:outline-none focus:ring-1 focus:ring-indigo-500"
      />
    </div>
  </div>

  <!-- Custom Headers Injection -->
  <div>
    <div class="flex items-center justify-between mb-1">
      <label class="block font-semibold text-slate-700 text-[11px]">Custom Request Headers (คั่นด้วยบรรทัดใหม่):</label>
      <div class="flex items-center gap-1">
        <button type="button" id="btnHeaderPresetXff" class="px-2 py-0.5 rounded-lg bg-white hover:bg-indigo-50 text-indigo-700 font-mono text-[9.5px] border border-indigo-200 cursor-pointer transition shadow-xs">+ X-Forwarded-For</button>
        <button type="button" id="btnHeaderPresetRef" class="px-2 py-0.5 rounded-lg bg-white hover:bg-indigo-50 text-indigo-700 font-mono text-[9.5px] border border-indigo-200 cursor-pointer transition shadow-xs">+ Internal Referer</button>
        <button type="button" id="btnHeaderPresetProxy" class="px-2 py-0.5 rounded-lg bg-white hover:bg-indigo-50 text-indigo-700 font-mono text-[9.5px] border border-indigo-200 cursor-pointer transition shadow-xs">+ Bypass Proxy</button>
        <button type="button" id="btnClearCustomHeaders" class="px-2 py-0.5 rounded-lg bg-white hover:bg-rose-50 text-slate-500 hover:text-rose-600 font-mono text-[9.5px] border border-slate-200 cursor-pointer transition" title="ล้าง Headers ทั้งหมด"><i class="ph-bold ph-trash"></i> ล้าง</button>
      </div>
    </div>
    <textarea 
      id="profileFormCustomHeaders" 
      rows="3" 
      placeholder="เช่น&#10;X-Forwarded-For: 127.0.0.1&#10;Referer: https://internal.company.corp/&#10;Accept-Language: th-TH,th;q=0.9,en-US;q=0.8" 
      class="w-full px-3 py-2 rounded-xl border border-slate-300 focus:border-indigo-500 focus:ring-1 focus:ring-indigo-500 font-mono text-[11px] bg-white resize-none"
    ></textarea>
    <span class="text-[10px] text-slate-400 block mt-0.5">ช่วยอำพรางตัวผ่าน Internal WAF, Rate Limiting และ Security Reverse Proxy</span>
  </div>
</div>
