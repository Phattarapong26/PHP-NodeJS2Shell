<!--
  @component Tooltips
  Floating tooltips used by the charts (fixed position, ported 1:1 from
  GUI.html lines 6974-7024). They live outside the layout flow on purpose.
-->
<!-- Floating Tooltip for ThaiCERT Security Assessment -->
<div id="globalThaiCertTooltip" class="fixed hidden flex-col w-84 max-w-[90vw] p-3.5 rounded-2xl bg-slate-900/95 text-white text-xs shadow-2xl border border-slate-700/80 backdrop-blur-md z-[99999] pointer-events-none transition-opacity duration-150">
  <div class="flex items-center justify-between gap-2 pb-2 mb-2 border-b border-slate-700/60">
    <span class="font-bold text-amber-400 flex items-center gap-1.5 text-[11px]">
      <i class="ph-bold ph-shield-check text-sm text-amber-400"></i>
      <span>การประเมินความปลอดภัย (ThaiCERT)</span>
    </span>
    <span id="tipSevPill" class="px-2 py-0.5 rounded text-[10px] font-mono font-bold border">SECURE</span>
  </div>
  <div class="text-[11px] text-slate-400 font-mono mb-1.5 flex items-center gap-1.5">
    <i class="ph-bold ph-hard-drives text-xs text-slate-400"></i>
    <span id="tipTarget">192.168.1.1:80</span>
  </div>
  <p class="text-slate-100 text-xs leading-relaxed mb-2 font-normal" id="tipNote">รายละเอียดข้อค้นพบ</p>
  <div id="tipCveSection" class="hidden pt-2 border-t border-slate-800 text-[11px] text-slate-300">
    <div class="font-semibold text-slate-400 mb-1 flex items-center gap-1">
      <i class="ph-bold ph-bug text-xs text-rose-400"></i>
      <span>ช่องโหว่ CVE ที่ตรวจพบ:</span>
    </div>
    <div id="tipCveList" class="flex flex-wrap gap-1 mt-1"></div>
  </div>
  <div class="text-[10px] text-slate-400 pt-2 flex items-center gap-1.5 border-t border-slate-800/80 opacity-80 mt-1.5">
    <i class="ph ph-cursor-click text-amber-400"></i>
    <span>คลิกปุ่ม "ตรวจเจาะลึก" ด้านขวา เพื่อดูการตั้งค่าและคำสั่ง Host-Check</span>
  </div>
</div>

<!-- Floating Tooltip for ThaiCERT Radar, Lollipop & Top CVE Charts -->
<div id="chartHoverTooltip" class="fixed hidden flex-col p-3 rounded-2xl bg-slate-900/95 text-white text-xs shadow-2xl border border-slate-700/80 backdrop-blur-md z-[99999] pointer-events-none transition-opacity duration-150 max-w-xs">
  <div class="flex items-center justify-between gap-2 pb-1.5 mb-1.5 border-b border-slate-700/60">
    <span class="flex items-center gap-1.5 min-w-0">
      <span id="chartTipBadge" class="font-bold text-[10px] font-mono px-1.5 py-0.5 rounded bg-teal-500/20 text-teal-300 border border-teal-400/40 flex-shrink-0">ก.1</span>
      <span id="chartTipTitle" class="font-bold text-slate-100 truncate">เว็บไซต์ / CMS</span>
    </span>
    <span id="chartTipRiskPill" class="px-2 py-0.5 rounded text-[10px] font-mono font-bold border border-emerald-400/60 bg-emerald-500/10 text-emerald-300 flex-shrink-0">SECURE</span>
  </div>
  <div class="text-[11px] text-slate-300 flex items-center justify-between gap-3 mb-1">
    <span id="chartTipTotalLabel" class="text-slate-400">จำนวนเครื่องที่ตรวจพบ:</span>
    <span id="chartTipTotal" class="font-bold font-mono text-teal-400">0 เครื่อง</span>
  </div>
  <div id="chartTipVulnRow" class="hidden text-[11px] text-rose-300 items-center justify-between gap-3 mb-1">
    <span id="chartTipVulnLabel" class="text-rose-400 font-semibold">มีความเสี่ยง / ช่องโหว่:</span>
    <span id="chartTipVuln" class="font-bold font-mono text-rose-300">0 เครื่อง</span>
  </div>
  <p class="text-[10px] text-slate-400 border-t border-slate-800/80 pt-1.5 mt-1 leading-relaxed" id="chartTipNote">
    เกณฑ์การตรวจ: WordPress, Drupal, Joomla, CMS
  </p>
  <div id="chartTipActionWrap" class="text-[9px] text-blue-300 font-semibold pt-1 flex items-center gap-1">
    <i class="ph ph-cursor-click"></i>
    <span id="chartTipActionText">คลิกเพื่อกรองอุปกรณ์เฉพาะกลุ่มนี้</span>
  </div>
</div>
