<!--
  @component HeroSearch
  Markup ported 1:1 from the original GUI.html (lines 310-350).
  Element ids are preserved: the controllers in src/lib/controllers bind to them.
-->
<!-- Title Area matching Image: ThaiCERT SCANER -->
<div class="text-center mb-5 select-none w-full max-w-md mx-auto">
  <h1 class="embossed-title text-4xl sm:text-5xl font-extrabold tracking-tight">
    ThaiCERT
  </h1>
  <p class="embossed-sub text-base sm:text-lg font-bold tracking-[0.35em] mt-1 uppercase">
    SCANER
  </p>

  <!-- Search Input Bar under SCANER -->
  <div class="mt-3 px-2 sm:px-4">
    <div class="relative flex items-center shadow-sm rounded-full bg-white/80 backdrop-blur-md border border-white/90 p-1 pl-3.5 focus-within:ring-2 focus-within:ring-blue-500/40 focus-within:border-blue-400 focus-within:bg-white transition-all duration-200 hover:shadow-md">
      <i class="ph-bold ph-magnifying-glass text-slate-400 text-base mr-2 flex-shrink-0"></i>
      <input 
        id="heroSearchInput" 
        type="text" 
        placeholder="กรอกชื่อ Domain หรือ IP (เช่น thaicert.or.th)..." 
        class="w-full bg-transparent text-slate-800 placeholder-slate-400 text-xs sm:text-sm font-medium focus:outline-none select-text"
        autocomplete="off"
        spellcheck="false"
      />
      <button 
        id="btnHeroSearch" 
        class="ml-1.5 px-3.5 py-1.5 rounded-full bg-gradient-to-r from-blue-600 to-indigo-600 hover:from-blue-700 hover:to-indigo-700 text-white font-medium text-xs shadow-sm flex items-center gap-1.5 transition-all active:scale-95 flex-shrink-0 cursor-pointer"
        title="กด Enter หรือคลิกเพื่อเริ่มสแกน"
      >
        <span>สแกน</span>
        <i class="ph-bold ph-arrow-right text-[11px]"></i>
      </button>
    </div>
    <!-- Faint message: สำหรับตรวจสอบdomain -->
    <p class="text-[11px] text-slate-400/80 font-normal mt-1.5 tracking-wide text-center">
      สำหรับตรวจสอบdomain
    </p>
  </div>

  <div class="inline-flex items-center gap-2 mt-2 px-3.5 py-1 rounded-full bg-white/40 text-slate-600 text-xs tracking-wider border border-white/60 shadow-sm">
    <i class="ph-bold ph-shield-check text-blue-600"></i>
    <span>PHP & NODE.JS LAN DISCOVERY & SECURITY AUDITOR</span>
  </div>
</div>
