<!--
  @component FormBasicInfo
  Markup ported 1:1 from the original GUI.html (lines 1591-1612).
  Element ids are preserved: the controllers in src/lib/controllers bind to them.
-->
<!-- Row 1: Title & Description -->
<div class="grid grid-cols-1 sm:grid-cols-2 gap-3">
  <div>
    <label class="block font-bold text-slate-700 mb-1">ชื่อ Profile (Title) <span class="text-rose-500">*</span></label>
    <input 
      id="profileFormTitle" 
      type="text" 
      placeholder="เช่น สำนักงานใหญ่ หรือ DataCenter Subnet" 
      class="w-full px-3 py-2 rounded-xl border border-slate-300 focus:border-blue-500 focus:ring-1 focus:ring-blue-500 focus:outline-none bg-white font-medium text-xs"
      required 
    />
  </div>
  <div>
    <label class="block font-bold text-slate-700 mb-1">คำอธิบาย (Description)</label>
    <input 
      id="profileFormDesc" 
      type="text" 
      placeholder="บันทึกช่วยจำ เช่น ทดสอบ Server โซน DMZ" 
      class="w-full px-3 py-2 rounded-xl border border-slate-300 focus:border-blue-500 focus:ring-1 focus:ring-blue-500 focus:outline-none bg-white text-xs"
    />
  </div>
</div>
