<!--
  @component AnalyticsCharts
  Markup ported 1:1 from the original GUI.html (lines 547-609).
  Element ids are preserved: the controllers in src/lib/controllers bind to them.
-->
<!-- Visual Analytics Charts View (Radar + Horizontal Lollipop + Top CVEs Horizontal Bars) -->
<div id="thaicertChartsContainer" class="p-3 sm:p-4 rounded-2xl bg-white/95 border border-slate-200/90 shadow-xs mb-1">
  <div class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-3.5 items-stretch">
    
    <!-- Left Chart: Radar Web Chart (Octagonal) -->
    <div class="flex flex-col justify-between relative p-3 rounded-xl bg-slate-50/60 border border-slate-200/60">
      <div class="w-full flex items-center justify-between mb-1 px-1">
        <span class="text-xs font-bold text-slate-700 flex items-center gap-1.5">
          <i class="ph-bold ph-chart-polar text-teal-600"></i>
          <span>Radar Web (กระจาย 8 กลุ่ม)</span>
        </span>
        <span class="text-[10px] text-slate-400 font-mono">สเกลเครื่อง</span>
      </div>
      <div class="relative w-full max-w-[340px] aspect-[1/0.92] flex items-center justify-center mx-auto my-auto">
        <svg id="radarChartSvg" viewBox="0 0 460 410" class="w-full h-full overflow-visible select-none"></svg>
      </div>
    </div>

    <!-- Middle Chart: Horizontal Lollipop Chart (Cleveland Dot Plot) -->
    <div class="flex flex-col justify-between relative p-3 rounded-xl bg-slate-50/60 border border-slate-200/60">
      <div class="w-full flex items-center justify-between mb-1 px-1">
        <span class="text-xs font-bold text-slate-700 flex items-center gap-1.5">
          <i class="ph-bold ph-chart-bar-horizontal text-teal-600"></i>
          <span>Lollipop (จัดอันดับตามปริมาณ)</span>
        </span>
        <span class="text-[10px] text-slate-400 font-mono">Dot Plot</span>
      </div>
      <div class="relative w-full h-[320px] flex items-center justify-center my-auto">
        <svg id="lollipopChartSvg" viewBox="0 0 500 310" class="w-full h-full overflow-visible select-none"></svg>
      </div>
    </div>

    <!-- Right Chart: Top Detected CVEs Horizontal Bar Chart -->
    <div class="flex flex-col justify-between relative p-3 rounded-xl bg-slate-50/60 border border-slate-200/60 overflow-hidden">
      <div class="w-full flex items-center justify-between mb-1 px-1">
        <span class="text-xs font-bold text-slate-700 flex items-center gap-1.5">
          <i class="ph-bold ph-bug text-rose-600"></i>
          <span>Top CVEs (ความถี่ช่องโหว่)</span>
        </span>
        <div class="flex items-center gap-1.5 text-[10px]">
          <span class="inline-flex items-center gap-1 font-semibold text-rose-700"><span class="w-2 h-2 rounded-full bg-rose-500"></span>วิกฤต</span>
          <span class="inline-flex items-center gap-1 font-semibold text-orange-700"><span class="w-2 h-2 rounded-full bg-orange-500"></span>สูง</span>
        </div>
      </div>
      <div class="relative w-full h-[320px] flex items-center justify-center my-auto">
        <svg id="cveBarChartSvg" viewBox="0 0 500 310" class="w-full h-full overflow-visible select-none"></svg>

        <!-- Empty State Dimmed Overlay matching user reference image -->
        <div id="cveEmptyOverlay" class="absolute inset-0 bg-slate-900/55 backdrop-blur-[2px] rounded-xl flex flex-col items-center justify-center p-4 text-center cursor-pointer transition-opacity duration-200">
          <div class="w-12 h-12 rounded-2xl bg-white/10 text-emerald-400 flex items-center justify-center mb-2 shadow-inner">
            <i class="ph-bold ph-shield-check text-2xl"></i>
          </div>
          <div class="text-white text-base sm:text-lg font-extrabold tracking-wide drop-shadow-md">ไม่มีรายการที่ค้นพบ</div>
          <div class="text-emerald-300 text-xs font-medium mt-1">ปลอดภัย ไม่พบช่องโหว่ความเสี่ยงในเครือข่าย</div>
          <div class="text-[10px] text-slate-300/80 mt-2 bg-white/10 px-2.5 py-0.5 rounded-full border border-white/20 select-none">
            ชี้เมาส์เพื่อดูการประเมินความปลอดภัย
          </div>
        </div>
      </div>
    </div>

  </div>
</div>
