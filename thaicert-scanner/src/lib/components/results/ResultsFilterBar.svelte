<!--
  @component ResultsFilterBar
  Markup ported 1:1 from the original GUI.html (lines 612-638).
  Element ids are preserved: the controllers in src/lib/controllers bind to them.
-->
<!-- Filter & Search Tool Bar -->
<div class="px-6 py-2.5 bg-white/70 border-b border-slate-200/60 flex flex-wrap items-center justify-between gap-3 text-xs backdrop-blur-sm">
  <div class="flex items-center gap-1.5 flex-wrap">
    <span class="font-semibold text-slate-600 text-[11px]">หมวดหมู่:</span>
    <button class="filter-tab neu-pill-btn px-3 py-1 rounded-full text-slate-600 active text-xs" data-filter="all_online">
      <i class="ph-bold ph-broadcast text-blue-500 mr-1"></i>อุปกรณ์ออนไลน์ทั้งหมด (<span id="countTabAllOnline">0</span>)
    </button>
    <button class="filter-tab neu-pill-btn px-3 py-1 rounded-full text-slate-600 text-xs" data-filter="php_only">
      <i class="ph-bold ph-file-php text-indigo-500 mr-1"></i>เซิร์ฟเวอร์ PHP (<span id="countTabPhp">0</span>)
    </button>
    <button class="filter-tab neu-pill-btn px-3 py-1 rounded-full text-slate-600 text-xs" data-filter="node_only">
      <i class="ph-bold ph-brackets-curly text-emerald-600 mr-1"></i>เซิร์ฟเวอร์ Node.js (<span id="countTabNode">0</span>)
    </button>
    <button class="filter-tab neu-pill-btn px-3 py-1 rounded-full text-slate-600 text-xs" data-filter="vulnerable">
      <i class="ph-bold ph-warning text-rose-500 mr-1"></i>มีความเสี่ยง (<span id="countTabVuln">0</span>)
    </button>
    <button class="filter-tab neu-pill-btn px-3 py-1 rounded-full text-slate-600 text-xs" data-filter="workstations">
      <i class="ph-bold ph-desktop text-slate-500 mr-1"></i>เครื่องลูกข่ายทั่วไป (<span id="countTabWorkstation">0</span>)
    </button>
  </div>
  <div class="flex items-center gap-2">
    <div class="relative">
      <input id="inputSearchHost" type="text" placeholder="ค้นหา IP / บริการ..." class="neu-pill-inset pl-7 pr-3 py-1 rounded-full text-xs text-slate-700 placeholder-slate-400 focus:outline-none w-40 sm:w-48">
      <i class="ph ph-magnifying-glass absolute left-2.5 top-1/2 -translate-y-1/2 text-slate-400 text-xs"></i>
    </div>
  </div>
</div>
