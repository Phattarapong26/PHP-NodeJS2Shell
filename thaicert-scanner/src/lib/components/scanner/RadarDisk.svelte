<!--
  @component RadarDisk
  Markup ported 1:1 from the original GUI.html (lines 352-411).
  Element ids are preserved: the controllers in src/lib/controllers bind to them.
-->
<!-- Central Radar / Neumorphic Scanner Disk -->
<div class="relative flex items-center justify-center">
  
  <!-- Outermost Neumorphic Plate -->
  <div class="outer-dish w-[280px] h-[280px] sm:w-[330px] sm:h-[330px] rounded-full flex items-center justify-center p-3 relative">
    
    <!-- Outer Rotating SVG Radar Graphics (Arcs & Dots like the image) -->
    <svg id="radarSvg" class="absolute inset-0 w-full h-full animate-spin-radar transition-all duration-700" viewBox="0 0 400 400" fill="none">
      <!-- Thick arc top-right -->
      <path d="M 120 70 A 155 155 0 0 1 290 85" stroke="#3b82f6" stroke-width="4.5" stroke-linecap="round" stroke-dasharray="120 40" opacity="0.95"/>
      <!-- Medium arc bottom-left -->
      <path d="M 85 275 A 155 155 0 0 1 180 345" stroke="#2563eb" stroke-width="5" stroke-linecap="round" opacity="0.9"/>
      <!-- Fine dashed arcs -->
      <path d="M 290 85 A 155 155 0 0 1 345 230" stroke="#93c5fd" stroke-width="2.5" stroke-dasharray="3 9" stroke-linecap="round"/>
      <path d="M 60 210 A 155 155 0 0 1 120 70" stroke="#60a5fa" stroke-width="2.5" stroke-dasharray="4 8" stroke-linecap="round"/>
      
      <!-- Orbital Accent Dots -->
      <circle cx="305" cy="115" r="3.5" fill="#3b82f6" />
      <circle cx="340" cy="180" r="2.5" fill="#60a5fa" />
      <circle cx="346" cy="225" r="3" fill="#2563eb" />
      <circle cx="75" cy="265" r="3.5" fill="#3b82f6" />
      <circle cx="160" cy="342" r="2" fill="#93c5fd" />
      <circle cx="230" cy="336" r="3" fill="#60a5fa" />
      <circle cx="250" cy="328" r="2" fill="#93c5fd" />
    </svg>

    <!-- Middle Intermediate Dish with Soft Glow -->
    <div class="w-[225px] h-[225px] sm:w-[265px] sm:h-[265px] rounded-full border border-blue-200/50 flex items-center justify-center relative bg-gradient-to-b from-white/60 to-white/10 shadow-inner">
      
      <!-- Secondary Counter-Rotating Fine Ring -->
      <div id="radarInnerRing" class="absolute inset-2 rounded-full border border-dashed border-blue-300/40 animate-spin-reverse pointer-events-none"></div>

      <!-- Pulsing Wave Ripple (Active while scanning) -->
      <div id="scanningRipple" class="absolute inset-0 rounded-full border-2 border-blue-400 opacity-0 pointer-events-none"></div>

      <!-- Inner Concave Dish -->
      <div class="inner-dish w-[165px] h-[165px] sm:w-[195px] sm:h-[195px] rounded-full flex items-center justify-center p-2.5 relative">
        
        <!-- Center Round Push Button (Scan / Stop) -->
        <button 
          id="btnScan" 
          class="btn-scan-sphere w-24 h-24 sm:w-28 sm:h-28 rounded-full flex flex-col items-center justify-center text-white font-bold cursor-pointer group focus:outline-none"
        >
          <div id="btnScanContent" class="flex flex-col items-center">
            <i class="ph-bold ph-radar text-xl sm:text-2xl mb-0.5 group-hover:scale-110 transition-transform"></i>
            <span class="text-lg sm:text-xl font-bold tracking-wide drop-shadow">Scan</span>
          </div>

          <!-- Active Spinner (Hidden by default) -->
          <div id="btnScanSpinner" class="hidden flex-col items-center">
            <i class="ph-bold ph-spinner animate-spin text-2xl sm:text-3xl"></i>
            <span id="scanPercentText" class="text-xs font-semibold mt-0.5 tracking-wider text-blue-100">0%</span>
            <span class="text-[10px] text-rose-200 hover:text-white font-medium">กดเพื่อหยุด</span>
          </div>
        </button>

      </div>
    </div>
  </div>
</div>
